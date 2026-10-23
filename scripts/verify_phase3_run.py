#!/usr/bin/env python3
"""Validate fresh bounded Phase 3 evidence; historical timings are references."""
import argparse
import json
import math
from pathlib import Path
import sys

MAX_REPORT_BYTES = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_report(path):
    with Path(path).open('rb') as stream:
        content = stream.read(MAX_REPORT_BYTES + 1)
    require(len(content) <= MAX_REPORT_BYTES, f'report exceeds 16 MiB: {path}')
    return json.loads(content)


def number(value):
    require(type(value) in (int, float) and math.isfinite(value), 'non-finite/non-numeric latency')
    return value


def quantile(values, percentile):
    require(bool(values), 'missing latency samples')
    return sorted(number(v) for v in values)[math.ceil(len(values) * percentile) - 1]


def check_summary(values, summary, suffix=''):
    for label, fraction in [('p50', .50), ('p95', .95), ('p99', .99)]:
        require(math.isclose(number(summary[label + suffix]), quantile(values, fraction),
                             rel_tol=1e-9, abs_tol=1e-9), f'{label} disagrees with raw samples')
    require(math.isclose(number(summary['max' + suffix]), max(values),
                         rel_tol=1e-9, abs_tol=1e-9), 'maximum disagrees with raw samples')


def reaped(worker):
    require(worker['reaped'] is True and worker['stdout_eof'] is True
            and worker['state_eof'] is True, 'incomplete worker lifecycle')


def clean(worker):
    reaped(worker)
    require(worker['status'] == {'kind': 'exited', 'code': 0}, 'recovery did not exit cleanly')
    require(worker['output'] == [48], 'COW state did not reset')


def check_stateful_receipts(stateful, bench, faults):
    """Cross-check summaries against every admitted request in the fixed fixture."""
    fault_order = ('segv', 'syscall', 'exit', 'timeout', 'verifier')
    initial_clean = stateful['consecutive_clean_requests']
    measured_and_warmup = bench['pairs'] + bench['warmup_pairs_excluded']
    successful_workers = initial_clean + len(fault_order) + 2 + measured_and_warmup
    expected_workers = successful_workers + len(fault_order)
    receipts = stateful['receipts']
    require(len(receipts) == expected_workers + 2, 'raw request receipt count mismatch')
    require([r['request_id'] for r in receipts] == list(range(1, len(receipts) + 1)),
            'raw request receipt identity/order mismatch')
    workers = [r['worker'] for r in receipts if 'worker' in r]
    require(len(workers) == expected_workers and workers == stateful['worker_receipts'],
            'worker summaries disagree with raw receipts')
    require(stateful['final_committed_keys'] == successful_workers * 2,
            'final committed key count disagrees with fixture requests')
    require(stateful['clean_committed_keys'] == initial_clean * 2,
            'initial committed key count disagrees with clean requests')

    # The fixture sends two incomplete admissions; neither may create a worker.
    sequence = [('clean', f'clean-{i:03}') for i in range(initial_clean)]
    for fault in fault_order:
        sequence.extend([('fault', fault), ('clean', f'recover-{fault}')])
    sequence.extend([('admission', None), ('clean', 'recover-disconnect'),
                     ('admission', None), ('clean', 'recover-header')])
    sequence.extend(('clean', f'bench-{i:04}') for i in range(measured_and_warmup))
    indexed_faults = {fault['fault']: fault['receipt'] for fault in faults}
    for receipt, (kind, identifier) in zip(receipts, sequence):
        if kind == 'clean':
            require(receipt['http_status'] == 200 and receipt['commit_status'] == 'committed'
                    and receipt['committed_mutations'] == 2 and receipt['burned_reason'] is None,
                    'clean raw receipt did not commit exactly two mutations')
            worker = receipt['worker']
            require(worker['status'] == {'kind': 'exited', 'code': 0},
                    'committed raw worker did not exit cleanly')
            require(json.loads(bytes(worker['output'])) == {'id': identifier, 'ok': True},
                    'committed worker output/request identity mismatch')
        else:
            require(receipt['http_status'] == 500 and receipt['commit_status'] == 'burned'
                    and receipt['committed_mutations'] == 0 and bool(receipt['burned_reason']),
                    'failed raw receipt did not burn with known zero mutations')
            if kind == 'fault':
                require(receipt == indexed_faults[identifier],
                        'fault summary disagrees with raw receipt')
            else:
                require('worker' not in receipt, 'incomplete admission created a worker')


def verify(reference, stateful, native):
    require(reference['schema'] == 'ephem.phase3.validation.v1', 'unknown reference schema')
    require(reference['production_status'] == stateful['production_status'] == 'HOLD', 'production must remain HOLD')
    require(stateful['schema'] == 'ephem.phase3.stateful-isolation.v1', 'unknown stateful schema')
    expected = reference['checks']['sqlite_http']
    require(stateful['functional_status'] == expected['functional_status'] == 'PASS', 'functional checks failed')
    for key in ['consecutive_clean_requests', 'clean_committed_keys', 'corrupted_committed_keys',
                'admission_disconnect', 'absolute_admission_deadline']:
        require(stateful[key] == expected[key], f'reference invariant mismatch: {key}')
    require(stateful['corrupted_committed_keys'] == 0, 'corrupted committed keys')
    require(stateful['application_sha256_before'] == stateful['application_sha256_after']
            == stateful['application_sha256_inside_rootfs'], 'application changed')
    require(stateful['universal_2ms_target'].startswith('UNVERIFIED'), 'universal overhead is unverified')
    workers = stateful['worker_receipts']
    require(len(workers) >= 100, 'missing worker receipts')
    pids = [w['worker_pid'] for w in workers]
    require(all(type(pid) is int and pid > 0 for pid in pids), 'invalid worker PID')
    require(len(set(pids)) == len(pids) == stateful['unique_worker_pids'], 'worker PID reuse/count mismatch')
    for worker in workers:
        reaped(worker)
    faults = stateful['fault_injection']
    require(len(faults) == 5 and {f['fault'] for f in faults} ==
            {'segv', 'syscall', 'exit', 'timeout', 'verifier'}, 'missing/duplicate PHP fault types')
    for fault in faults:
        receipt = fault['receipt']
        require(fault['http_status'] == receipt['http_status'] == 500
                and receipt['committed_mutations'] == 0 and receipt['commit_status'] == 'burned'
                and fault['subsequent_request'] == 'PASS', f'fault did not burn/recover: {fault["fault"]}')
        reaped(receipt['worker'])
        status = receipt['worker']['status']
        kind = {'segv': 'signaled', 'syscall': 'signaled', 'exit': 'exited',
                'timeout': 'timed_out', 'verifier': 'verifier_failed'}[fault['fault']]
        require(status['kind'] == kind, 'unexpected fault outcome')
        if fault['fault'] in ('segv', 'syscall'):
            require(status['signal'] == (11 if fault['fault'] == 'segv' else 31), 'wrong fault signal')
        if fault['fault'] == 'exit':
            require(status['code'] != 0, 'fault exited zero')

    bench = stateful['benchmark']
    recorded = reference['latency']['php_http_ms']
    require(bench['pairs'] == recorded['pairs'] == len(bench['samples']), 'paired sample count mismatch')
    require(bench['warmup_pairs_excluded'] == recorded['warmup_pairs_excluded'], 'PHP warmup mismatch')
    require(bench['order_seed'] == 20261023, 'paired order seed mismatch')
    require([s['index'] for s in bench['samples']] == list(range(bench['pairs'])), 'invalid pair indices')
    for sample in bench['samples']:
        require(sorted(sample['order']) == ['baseline', 'isolated'], 'invalid pair ordering')
        require(number(sample['isolated_ms']) >= 0 and number(sample['baseline_ms']) >= 0,
                'negative request latency')
        require(math.isclose(number(sample['isolated_ms']) - number(sample['baseline_ms']),
                             number(sample['delta_ms']), abs_tol=1e-9), 'invalid paired delta')
    for name in ['baseline', 'isolated', 'paired_delta']:
        column = 'delta_ms' if name == 'paired_delta' else name + '_ms'
        check_summary([s[column] for s in bench['samples']], bench[name + '_ms'])
    require(bench['p95_under_2ms'] is True and bench['paired_delta_ms']['p95'] < 2,
            'bounded PHP paired-delta p95 gate failed')
    check_stateful_receipts(stateful, bench, faults)

    require(native['benchmark'] == 'warm_native_fork_state_ipc_output_eof_reap', 'unknown native benchmark')
    observed = reference['latency']['native_lifecycle_ms']
    require(native['iterations'] == observed['iterations'] == len(native['samples_ms']), 'native sample count mismatch')
    require(native['warmup'] == observed['warmup'], 'native warmup mismatch')
    require(all(number(v) >= 0 for v in native['samples_ms']), 'negative native latency')
    check_summary(native['samples_ms'], native, '_ms')
    require(native['p95_below_2ms'] is True and native['p95_ms'] < 2, 'native p95 gate failed')
    checks = native['lifecycle_checks']
    names = {'cow_reset', 'segv', 'seccomp', 'signal-broker', 'fcntl-signal-broker',
             'fcntl-async', 'execve', 'execveat', 'signal-high-tgid', 'signal-high-tid',
             'timeout', 'verifier', 'truncated-state'}
    require(len(checks) == len(names) and {c['request'] for c in checks} == names,
            'native lifecycle checks missing/duplicated')
    for check in checks:
        name = check['request']
        if name == 'cow_reset':
            require(len(check['receipts']) == 2, 'COW reset receipts missing')
            for worker in check['receipts']:
                clean(worker)
            require(check['receipts'][0]['worker_pid'] != check['receipts'][1]['worker_pid'], 'COW PID reused')
            continue
        reaped(check['receipt'])
        status = check['receipt']['status']
        kind = {'timeout': 'timed_out', 'verifier': 'verifier_failed',
                'truncated-state': 'protocol_failure'}.get(name, 'signaled')
        require(status['kind'] == kind, f'native fault not rejected: {name}')
        if kind == 'signaled':
            require(status['signal'] == (11 if name == 'segv' else 31), 'wrong native signal')
            clean(check['recovery'])
    return [
        '[EPHEM VERIFICATION COMPLETED]',
        f'- Native Lifecycle p95: {native["p95_ms"]:.6f}ms (PASS: <2.0ms gate; recorded {observed["p95_ms"]:.6f}ms)',
        f'- Contained PHP HTTP p95: {bench["isolated_ms"]["p95"]:.6f}ms (recorded {recorded["isolated_ms"]["p95"]:.6f}ms)',
        f'- Bounded paired PHP delta p95: {bench["paired_delta_ms"]["p95"]:.6f}ms (PASS: <2.0ms; confounded baseline)',
        '- Fault Injections: 5/5 PHP cases burned with recovery; native lifecycle checks PASS',
        '- Corrupted Committed Keys: 0 (SQLite fixture)',
        '- PostgreSQL live/paused backend and BPF LSM: UNRUN by this script; see retained validation',
        '- Production Status: HOLD (integration, response disclosure, silent corruption and commit ambiguity boundaries)',
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--stateful', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    args = parser.parse_args()
    try:
        lines = verify(load_report(args.reference), load_report(args.stateful), load_report(args.native))
    except (OSError, ValueError, KeyError, TypeError, IndexError, RecursionError) as error:
        print(f'FAIL: Phase 3 evidence verification: {error}', file=sys.stderr)
        return 1
    green, reset = ('\033[32m', '\033[0m') if sys.stdout.isatty() else ('', '')
    print(green + '\n'.join(lines) + reset)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
