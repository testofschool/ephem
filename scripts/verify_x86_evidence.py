#!/usr/bin/env python3
"""Check the stored, bounded x86 native receipts without executing the runtime."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ROOT / 'evidence/x86-independent-v1'
# Exact original bytes from ephem-x86-reproduction.zip; no regenerated summaries.
FILE_PINS = {
    'binary-sha256.txt': (193, 'bc54efdc4b852acdbb392cc41bd306326c5a5320ef9a9604b84780d3b60d5587'),
    'env.txt': (111, '2277976124af3aa0c936165f6b789f100b75e979c6c3d1e2e85c8953916d2e4e'),
    'cargo-test.log': (10764, '2a73a7ad41b26576809186f2c8e0fdc2485d7c0724cba155561fbe3d1d166303'),
    'upstream-commit.txt': (63, '2df8506d55d54b641fe54b5b357650ce9cba4605c99bda6072d856fc6e4554cc'),
    'warm-native.stderr.log': (0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    'cargo-build.log': (3773, '74ea2a3ac115bf0814e19ff05943907be2fe8f373adfe66350729069b2f552ea'),
    'X86_REPRODUCTION.json': (1972, '413a52bdd5d1496ae320f8af6ca36b4fdab515199a1ec7a8b2c6b13ec0e52741'),
    'warm-native.json': (23796, 'a06da461c759c8a55a9266b8f641b1c55618c9f53dbf17fede3656a5b203ba13'),
}
COMMIT = '1320713d065f04ae701026e14edf46226e71af6d'
TAG = 'v0.3.0-stateful-alpha'
NATIVE_SCOPE = ('Native callback only; dispatch, fork, seccomp, state round trip, '
                'private scratch MADV_DONTNEED, output EOF and waitpid receipt. '
                'Startup excluded. No web/PHP overhead claim.')
LIFECYCLE_NAMES = (
    'cow_reset', 'segv', 'seccomp', 'signal-broker', 'fcntl-signal-broker',
    'fcntl-async', 'execve', 'execveat', 'signal-high-tgid', 'signal-high-tid',
    'timeout', 'verifier', 'truncated-state',
)
UNRUN_REPORTED = {
    'php_http_adapter_path': ('libphp8.3 embed not installed in this container '
                              '\u2192 stateful/PHP gate not reproduced (would be exit 77)'),
    'verify_phase3_run_full': ('requires --stateful artifact; native-only comparison '
                             'done by hand above'),
    'postgresql_live': 'not run',
    'bpf_lsm': 'not run',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), f'invalid {label} fields')


def integer(value, label):
    require(type(value) is int, f'invalid integer: {label}')
    return value


def number(value, label):
    require(type(value) in (int, float) and math.isfinite(value),
            f'non-finite/non-numeric {label}')
    return value


def strict_json(content):
    """Reject duplicate keys, non-standard constants and overflowing JSON floats."""
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f'duplicate JSON key: {key}')
            result[key] = value
        return result

    def constant(value):
        raise ValueError(f'non-finite JSON constant: {value}')

    result = json.loads(content, object_pairs_hook=pairs, parse_constant=constant)

    def walk(value):
        if type(value) is float:
            require(math.isfinite(value), 'non-finite JSON float')
        elif type(value) is dict:
            for item in value.values():
                walk(item)
        elif type(value) is list:
            for item in value:
                walk(item)
    walk(result)
    return result


def pinned_files(root):
    """Bound reads to regular files; reject changed, missing and linked evidence."""
    result = {}
    for name, (size, expected_hash) in FILE_PINS.items():
        path = root / name
        require(not path.is_symlink(), f'symlink evidence is not allowed: {name}')
        flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode), f'not regular evidence: {name}')
            require(metadata.st_size == size, f'byte size mismatch: {name}')
            content = stream.read(size + 1)
        require(len(content) == size, f'byte size mismatch: {name}')
        require(hashlib.sha256(content).hexdigest() == expected_hash,
                f'SHA-256 mismatch: {name}')
        result[name] = content
    return result


def verify_semantics(report, native, text_files):
    """Validate meaning separately from byte pins so mutation tests exercise both."""
    exact_keys(native, ('benchmark', 'iterations', 'lifecycle_checks', 'max_ms',
                       'p50_ms', 'p95_below_2ms', 'p95_ms', 'p99_ms', 'samples_ms',
                       'scope', 'warmup'), 'native report')
    require(native['benchmark'] == 'warm_native_fork_state_ipc_output_eof_reap',
            'unknown native benchmark')
    require(native['scope'] == NATIVE_SCOPE, 'native measurement scope changed')
    require(integer(native['iterations'], 'iterations') == 1000, 'expected 1000 iterations')
    require(integer(native['warmup'], 'warmup') == 100, 'expected 100 excluded warmups')
    samples = native['samples_ms']
    require(type(samples) is list and len(samples) == 1000, 'native sample count mismatch')
    for value in samples:
        require(number(value, 'native sample') > 0, 'nonpositive native sample')
    require(samples == sorted(samples), 'native samples must retain their sorted order')
    statistics = {}
    for name, fraction in (('p50', .50), ('p95', .95), ('p99', .99), ('max', 1.0)):
        value = samples[math.ceil(len(samples) * fraction) - 1]
        require(number(native[name + '_ms'], name) == value,
                f'{name} disagrees with raw samples')
        statistics[name] = value
    require(native['p95_below_2ms'] is True and statistics['p95'] < 2,
            'native p95 <2ms gate failed')

    checks = native['lifecycle_checks']
    require(type(checks) is list and len(checks) == len(LIFECYCLE_NAMES),
            'native lifecycle check count mismatch')
    require(all(type(check) is dict for check in checks), 'invalid lifecycle check')
    require([check.get('request') for check in checks] == list(LIFECYCLE_NAMES),
            'native lifecycle checks missing, duplicated or reordered')
    workers = []

    def receipt(worker):
        exact_keys(worker, ('output', 'reaped', 'state_eof', 'status', 'stdout_eof',
                            'worker_pid'), 'worker receipt')
        require(worker['reaped'] is True and worker['state_eof'] is True
                and worker['stdout_eof'] is True, 'incomplete worker lifecycle')
        require(integer(worker['worker_pid'], 'worker_pid') > 0, 'invalid worker PID')
        require(type(worker['output']) is list
                and all(type(byte) is int and 0 <= byte <= 255 for byte in worker['output']),
                'invalid worker output bytes')
        require(type(worker['status']) is dict, 'invalid worker status')
        workers.append(worker)

    def clean(worker):
        receipt(worker)
        exact_keys(worker['status'], ('kind', 'code'), 'clean status')
        require(worker['status']['kind'] == 'exited'
                and integer(worker['status']['code'], 'exit code') == 0,
                'COW/recovery did not exit cleanly')
        require(worker['output'] == [48], 'COW/recovery private state did not reset')

    for check in checks:
        name = check['request']
        if name == 'cow_reset':
            exact_keys(check, ('request', 'receipts'), 'COW check')
            require(type(check['receipts']) is list and len(check['receipts']) == 2,
                    'COW reset receipts missing')
            for worker in check['receipts']:
                clean(worker)
            continue
        signaled = name not in ('timeout', 'verifier', 'truncated-state')
        exact_keys(check, ('request', 'receipt', 'recovery') if signaled
                   else ('request', 'receipt'), 'fault check')
        worker = check['receipt']
        receipt(worker)
        require(worker['output'] == [], 'failed worker released output')
        status = worker['status']
        if signaled:
            exact_keys(status, ('kind', 'signal', 'core_dumped'), 'signal status')
            require(status['kind'] == 'signaled'
                    and integer(status['signal'], 'signal') == (11 if name == 'segv' else 31)
                    and status['core_dumped'] is False, f'wrong native fault signal: {name}')
            clean(check['recovery'])
        elif name == 'timeout':
            require(status == {'kind': 'timed_out'}, 'wrong timeout status')
        else:
            kind, message = {
                'verifier': ('verifier_failed', 'deliberate verifier rejection'),
                'truncated-state': ('protocol_failure', 'truncated state exchange'),
            }[name]
            require(status == {'kind': kind, 'message': message}, f'wrong fault status: {name}')
    pids = [worker['worker_pid'] for worker in workers]
    require(len(workers) == 23 and len(set(pids)) == 23, 'worker PID reuse/count mismatch')

    exact_keys(report, ('report', 'date_utc', 'tier', 'upstream', 'environment', 'steps',
                        'native_lifecycle_ms', 'lifecycle_checks_executed', 'reference_arm64',
                        'UNRUN_here', 'binary_sha256'), 'summary report')
    require(report['report'] == 'EPHEM Phase 3 \u2014 independent x86_64 host reproduction',
            'unknown supplied report')
    require(report['tier'] == ('INDEPENDENT_HOST_REPRODUCTION '
                              '(different machine + different architecture from upstream arm64 evidence)'),
            'supplied report tier changed')
    require(report['date_utc'] == '2026-10-23T01:34:01.496432Z', 'report date changed')
    require(report['upstream'] == {'repo': 'https://github.com/testofschool/ephem',
                                   'commit': COMMIT, 'tag': TAG}, 'source identity mismatch')
    require(text_files['upstream-commit.txt'].splitlines() == [COMMIT, TAG],
            'source identity disagrees with upstream-commit.txt')
    exact_keys(report['environment'], ('arch', 'kernel', 'rustc', 'user', 'cgroup2'),
               'environment')
    environment = report['environment']
    require(environment['arch'] == 'x86_64' and environment['kernel'] == '6.18.44-fc-v140'
            and environment['rustc'] == '1.99.1' and environment['user'] == 'root'
            and environment['cgroup2'] is True, 'unexpected reported environment')
    match = re.fullmatch(r'arch=(\S+) kernel=(\S+) rustc=rustc (\S+) '
                         r'\(58cf8f9c3 2026-10-13\) started=2026-10-23T10:30:28\+09:00\n',
                         text_files['env.txt'])
    require(match is not None and match.groups() ==
            (environment['arch'], environment['kernel'], environment['rustc']),
            'summary environment disagrees with env.txt')
    summary = report['native_lifecycle_ms']
    exact_keys(summary, ('p50', 'p95', 'p99', 'max', 'p95_below_2ms'), 'latency summary')
    for name, value in statistics.items():
        require(number(summary[name], 'summary ' + name) == value,
                f'summary {name} disagrees with raw samples')
    require(summary['p95_below_2ms'] is True, 'summary p95 gate disagrees')
    require(report['lifecycle_checks_executed'] == list(LIFECYCLE_NAMES),
            'summary lifecycle names disagree')
    require(report['reference_arm64'] == {'p50': .448963, 'p95_original': .684507,
                                        'p95_release_align': .520076, 'p99': .916343},
            'historical reference changed')
    require(report['UNRUN_here'] == UNRUN_REPORTED, 'missing or changed reported UNRUN scope')
    require(report['steps'] == {
        'cargo_test_locked_workspace': 'RC=0 (16+5 passed, 0 failed, 1 ignored=real PostgreSQL)',
        'cargo_build_release_deliverables': 'RC=0',
        'native_lifecycle': ('ephem-warm-pool --iterations 1000 --warmup 100 '
                             '--lifecycle-check --require-p95-ms 2 \u2192 RC=0'),
    }, 'reported step outcomes changed')
    test_log = text_files['cargo-test.log']
    build_log = text_files['cargo-build.log']
    for log, marker in ((test_log, 'TEST_RC'), (build_log, 'BUILD_RC')):
        require(re.findall(r'^' + marker + r'=(\d+)$', log, re.MULTILINE) == ['0']
                and log.rstrip().endswith(marker + '=0'), f'missing/nonzero {marker}')
        require(re.search(r'^\s*error(?:\[|:)', log, re.MULTILINE) is None,
                'build/test log contains error')
    totals = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                         r'(\d+) measured; (\d+) filtered out;', test_log, re.MULTILINE)
    require(len(totals) == 8 and tuple(map(sum, zip(*(map(int, row) for row in totals))))
            == (21, 0, 1, 0, 0), 'cargo test counts disagree')
    require('Finished `test` profile [unoptimized + debuginfo]' in test_log,
            'test profile missing')
    require('Finished `release` profile [optimized]' in build_log, 'release profile missing')
    require('real PostgreSQL UNRUN by default' in test_log, 'ignored PostgreSQL scope missing')
    require(text_files['warm-native.stderr.log'] == '', 'native stderr is not empty')
    binary_lines = text_files['binary-sha256.txt'].splitlines()
    require(type(report['binary_sha256']) is list and report['binary_sha256'] == binary_lines,
            'binary hash strings disagree')
    require(len(binary_lines) == 2, 'binary hash record count mismatch')
    binaries = {}
    for line, binary in zip(binary_lines, ('ephem-warm-pool', 'ephem-stateful')):
        match = re.fullmatch(r'([0-9a-f]{64})  (target/release/' + binary + ')', line)
        require(match is not None, 'invalid binary hash record')
        binaries[match.group(2)] = match.group(1)

    return {
        'status': 'PASS',
        'scope': 'Bounded stored x86_64 native samples and lifecycle receipts only',
        'runtime_reexecuted': False,
        'independent_security_audit': False,
        'binary_bytes_verified': False,
        'production_status': 'HOLD',
        'upstream_declared': report['upstream'],
        'environment_reported': environment,
        'native_measurement_scope': NATIVE_SCOPE,
        'iterations': len(samples), 'warmup_excluded_reported': native['warmup'],
        'native_lifecycle_ms': statistics,
        'p95_below_2ms': True,
        'samples_at_or_above_2ms': sum(value >= 2 for value in samples),
        'lifecycle_checks': list(LIFECYCLE_NAMES),
        'lifecycle_check_count': len(checks), 'retained_worker_receipts': len(workers),
        'unique_worker_pids': len(set(pids)),
        'cargo_test_logged': {'passed': 21, 'failed': 0, 'ignored': 1, 'return_code': 0},
        'cargo_release_build_logged': {'return_code': 0, 'profile': 'release optimized'},
        'binary_sha256_recorded_only': binaries,
        'UNRUN': {name: 'UNRUN' for name in UNRUN_REPORTED},
        'reported_UNRUN_here': report['UNRUN_here'],
        'limitations': [
            'Stored-evidence consistency check; no live runtime reproduction in this invocation.',
            'Reported source identity is not a clean-tree or build attestation.',
            'Reported binary hash strings agree; binary bytes were not supplied.',
            'Root and cgroup2 are summary assertions without separate host evidence.',
            'Native command is abbreviated: mandatory --root path and command transcript absent.',
            'Native return code is reported in the summary, not a standalone command log.',
            'Detailed CPU, VM, distribution, governor, memory, storage and load metadata absent.',
            'Classic seccomp fixture only; no PHP, end-to-end parity or BPF LSM conclusion.',
            'Production throughput and tails remain UNMEASURED.',
        ],
    }


def verify(root):
    files = pinned_files(Path(root))
    report = strict_json(files['X86_REPRODUCTION.json'])
    native = strict_json(files['warm-native.json'])
    texts = {name: content.decode('utf-8') for name, content in files.items()
             if not name.endswith('.json')}
    result = verify_semantics(report, native, texts)
    result['original_file_bytes_verified'] = {
        name: {'size': size, 'sha256': digest} for name, (size, digest) in FILE_PINS.items()
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT,
                        help='directory containing the eight original evidence files')
    args = parser.parse_args(argv)
    try:
        result = verify(args.root)
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError) as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error),
                          'runtime_reexecuted': False, 'production_status': 'HOLD'},
                         allow_nan=False), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
