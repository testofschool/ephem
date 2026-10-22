#!/usr/bin/env python3
"""Actual Linux replay of the strict public-root profile and its refusal paths.

Run with --gate --jail --cgroup-root --report NEW_JSON. Stored results never
substitute for running this integration suite. All canaries are synthetic.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
CANARY = b'SYNTHETIC_SECRET_VISIBLE_TO_WORKER\n'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def request(path, body):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(6)
        connection.connect(str(path))
        connection.sendall(b'POST /run HTTP/1.1\r\nHost: zero-profile-test\r\nContent-Length: '
                           + str(len(body)).encode() + b'\r\n\r\n' + body)
        response = bytearray()
        while True:
            block = connection.recv(65536)
            if not block:
                break
            response.extend(block)
            assert len(response) <= 2 * 1048576, 'oversized test response'
    head, payload = bytes(response).split(b'\r\n\r\n', 1)
    lines = head.decode('ascii').split('\r\n')
    headers = dict((k.lower(), v.strip()) for k, v in (line.split(':', 1) for line in lines[1:]))
    assert len(payload) == int(headers['content-length']), 'truncated or excessive body'
    return {'request_hex': body.hex(), 'status': int(lines[0].split()[1]),
            'headers': headers, 'body_hex': payload.hex(), 'body_sha256': hashlib.sha256(payload).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gate', type=Path, required=True)
    parser.add_argument('--jail', type=Path, required=True)
    parser.add_argument('--cgroup-root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    for name in ('gate', 'jail', 'cgroup_root', 'report'):
        setattr(args, name, getattr(args, name).absolute())
    registration = args.report.with_suffix(args.report.suffix + '.preregistration.json')
    if os.path.lexists(args.report) or os.path.lexists(registration):
        parser.error('report and preregistration must be new')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'ephem-public-root-replay-v1', 'status': 'UNRUN',
              'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'platform': platform.platform(), 'probes': [], 'responses': [], 'gate_logs': [],
              'scope': 'Ambient root-file denial only; current plaintext request remains readable and returnable; no physical erasure claim.'}
    if platform.system() != 'Linux' or os.geteuid() != 0:
        report.update(status='UNAVAILABLE', reason='dedicated Linux root VM required', exit_code=77)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        return 77
    processes = []
    counter = 0
    try:
        with tempfile.TemporaryDirectory(prefix='.ephem-public-root-', dir='/root') as directory:
            base = Path(directory)
            historical = base / 'historical'
            built = subprocess.run(['sh', str(REPO / 'tests/ephem/build-rootfs.sh'), str(historical)],
                                   capture_output=True, check=True, timeout=90)
            report['fixture_build'] = {'stdout': built.stdout.decode(), 'stderr': built.stderr.decode()}
            sources = [Path(__file__), REPO / 'packaging/build-minimal-root.py',
                       REPO / 'crates/ephem-gate/src/root_manifest.rs', REPO / 'crates/ephem-gate/src/main.rs',
                       REPO / 'tests/ephem/fixture.c', REPO / 'tests/ephem/build-rootfs.sh']
            plan = {'source_sha256': {str(p): digest(p) for p in sources},
                    'artifact_sha256': {str(p): digest(p) for p in (args.gate, args.jail, historical / 'worker')},
                    'original_request_hex': b'READSECRET'.hex(),
                    'metric': 'responses containing ambient root synthetic secret',
                    'planned_probes': ['READSECRET before/after', 'public ECHO', 'extra file', 'renamed canary',
                        'binary canary', 'symlink', 'hardlink', 'FIFO', 'modified worker', 'writable worker',
                        'mutated manifest', 'unknown schema field', 'duplicate manifest path', 'noncanonical manifest path',
                        'late root injection', 'late manifest change', 'empty extra FDs/capabilities',
                        'scratch non-reuse', 'crash output quarantine', 'current input remains exposed'],
                    'deployment': 'dedicated test VM only'}
            registration.write_text(json.dumps(plan, indent=2) + '\n')
            report['preregistration_sha256'] = digest(registration)
            report['artifact_sha256'] = plan['artifact_sha256']

            def prepare(label):
                root, manifest = base / (label + '-root'), base / (label + '-manifest.json')
                command = [sys.executable, str(REPO / 'packaging/build-minimal-root.py'),
                           '--worker', str(historical / 'worker'), '--root', str(root), '--manifest', str(manifest)]
                result = subprocess.run(command, check=True, capture_output=True, timeout=30)
                return root, manifest, json.loads(result.stdout)

            def start(root, manifest=None, refused=False):
                nonlocal counter
                counter += 1
                sock = base / ('gate-%d.sock' % counter)
                logpath = base / ('gate-%d.log' % counter)
                command = [str(args.gate), '--socket', str(sock), '--jail', str(args.jail), '--root', str(root),
                           '--worker', '/worker', '--cgroup-root', str(args.cgroup_root), '--deadline-ms', '1000']
                if manifest is not None:
                    command += ['--root-manifest', str(manifest)]
                log = logpath.open('w+b')
                # Synthetic ambient credential: the worker must not inherit it.
                env = dict(os.environ, EPHEM_TEST_AMBIENT_SECRET='SYNTHETIC_PARENT_ENV_CANARY')
                # An extra descriptor intentionally reaches the gate; the launcher
                # must not pass it through to a worker. Content is synthetic.
                with (base / 'outside-root-canary').open('a+b') as ambient:
                    ambient.write(b'SYNTHETIC_INHERITED_FD_CANARY')
                    ambient.flush()
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                               env=env, pass_fds=(ambient.fileno(),))
                state = (process, log, logpath, command)
                processes.append(state)
                until = time.monotonic() + 8
                while not sock.is_socket() and process.poll() is None and time.monotonic() < until:
                    time.sleep(.01)
                if refused:
                    if process.poll() is None:
                        raise AssertionError('invalid root/manifest was not refused before bind: %r' % command)
                    assert process.returncode != 0 and not sock.exists(), 'invalid policy created socket'
                else:
                    assert process.poll() is None and sock.is_socket(), 'valid gate failed startup: ' + logpath.read_text()
                return process, sock, state

            def stop(state):
                process, log, logpath, command = state
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                        raise AssertionError('gate failed bounded graceful shutdown')
                log.flush()
                report['gate_logs'].append({'argv': command, 'exit_code': process.returncode, 'log': logpath.read_text()})
                log.close()
                processes.remove(state)

            def record(name, answer, status, expected=None):
                report['responses'].append(dict(answer, name=name))
                assert answer['status'] == status, '%s status %s' % (name, answer['status'])
                body = bytes.fromhex(answer['body_hex'])
                if expected is not None:
                    assert body == expected, '%s wrong response body' % name
                report['probes'].append({'name': name, 'status': 'PASS'})
                return body

            old, oldsock, oldstate = start(historical)
            before = request(oldsock, b'READSECRET')
            record('historical_READSECRET_returns_readable_canary', before, 200, CANARY)
            stop(oldstate)
            strict, manifest, build = prepare('strict')
            assert digest(historical / 'worker') == digest(strict / 'worker'), 'changed worker invalidates replay'
            report['minimal_root_build'] = build
            gate, sock, state = start(strict, manifest)
            after = request(sock, b'READSECRET')
            record('strict_READSECRET_cannot_read_absent_ambient_file', after, 500, b'execution rejected\n')
            record('public_echo_still_useful', request(sock, b'ECHO hello from ephem'), 200, b'hello from ephem')
            record('worker_has_no_extra_descriptors', request(sock, b'FD'), 200, b'extra_fds=0\n')
            capabilities = record('worker_has_no_capabilities', request(sock, b'CAP'), 200)
            assert capabilities == b'effective=0000000000000000 permitted=0000000000000000 inheritable=0000000000000000\n'
            record('scratch_write', request(sock, b'DIRTY'), 200, b'written\n')
            record('next_worker_has_no_scratch_marker', request(sock, b'CLEAN'), 200, b'absent\n')
            record('crash_output_withheld', request(sock, b'CRASH'), 500, b'execution rejected\n')
            record('current_input_plaintext_still_returnable', request(sock, b'ECHO CURRENT_REQUEST_CANARY'), 200, b'CURRENT_REQUEST_CANARY')
            injected = strict / 'app/innocent.dat'
            injected.write_bytes(CANARY)
            os.chmod(injected, 0o444)
            record('late_root_injection_refuses_before_spawn', request(sock, b'ECHO healthy'), 500, b'execution rejected\n')
            injected.unlink()  # Only this suite's synthetic file in its owned temporary root.
            record('admin_removed_injection_restores_valid_profile', request(sock, b'ECHO healthy'), 200, b'healthy')
            original = manifest.read_bytes()
            os.chmod(manifest, 0o644)
            manifest.write_bytes(original + b' ')
            os.chmod(manifest, 0o444)
            record('late_manifest_change_refuses_request', request(sock, b'ECHO healthy'), 500, b'execution rejected\n')
            os.chmod(manifest, 0o644)
            manifest.write_bytes(original)
            os.chmod(manifest, 0o444)
            record('admin_restored_manifest_recovers_profile', request(sock, b'ECHO healthy'), 200, b'healthy')
            stop(state)

            def manifest_edit(path, update):
                document = json.loads(path.read_text())
                update(document)
                os.chmod(path, 0o644)
                path.write_text(json.dumps(document) + '\n')
                os.chmod(path, 0o444)

            def extra(root, payload, name='cache'):
                path = root / 'app' / name
                path.write_bytes(payload)
                os.chmod(path, 0o444)

            def modified_worker(root):
                path = root / 'worker'
                data = bytearray(path.read_bytes())
                data[-1] ^= 1
                path.write_bytes(data)

            cases = [
                ('extra_file', lambda r, m: extra(r, b'innocent')),
                ('renamed_canary', lambda r, m: extra(r, CANARY, 'public-looking.txt')),
                ('binary_canary', lambda r, m: extra(r, b'\x00\xff' + CANARY + b'\x00', 'image.bin')),
                ('symlink', lambda r, m: (r / 'app/cache').symlink_to('/etc/passwd')),
                ('hardlinked_worker', lambda r, m: os.link(r / 'worker', base / 'worker-hardlink')),
                ('special_fifo', lambda r, m: os.mkfifo(r / 'app/channel', 0o444)),
                ('modified_worker', lambda r, m: modified_worker(r)),
                ('writable_worker', lambda r, m: os.chmod(r / 'worker', 0o755)),
                ('mutated_manifest', lambda r, m: manifest_edit(m, lambda d: d.update(version=2))),
                ('unknown_schema_field', lambda r, m: manifest_edit(m, lambda d: d.update(approved=True))),
                ('duplicate_manifest_path', lambda r, m: manifest_edit(m, lambda d: d['entries'].append(dict(d['entries'][-1])))),
                ('noncanonical_manifest_path', lambda r, m: manifest_edit(m, lambda d: d['entries'][1].update(path='/app/../app'))),
            ]
            for label, mutate in cases:
                badroot, badmanifest, _ = prepare(label)
                mutate(badroot, badmanifest)
                _, _, refusedstate = start(badroot, badmanifest, refused=True)
                stop(refusedstate)
                report['probes'].append({'name': 'startup_refuses_' + label, 'status': 'PASS', 'socket_bound': False})
            report['replay'] = {'input_hex': b'READSECRET'.hex(),
                                'worker_sha256_before': digest(historical / 'worker'),
                                'worker_sha256_after': digest(strict / 'worker'),
                                'metric': 'responses containing ambient synthetic root secret',
                                'before': int(CANARY in bytes.fromhex(before['body_hex'])),
                                'after': int(CANARY in bytes.fromhex(after['body_hex'])),
                                'runs_per_arm': 1, 'fresh_worker_per_request': True}
            assert report['replay']['before'] == 1 and report['replay']['after'] == 0
            # A separate benign static probe measures inherited environment;
            # the original READSECRET replay above retains its unchanged fixture.
            env_source = base / 'env-probe.c'
            env_source.write_text('#include <stdlib.h>\n#include <unistd.h>\n'
                                  'int main(void) { if (getenv("EPHEM_TEST_AMBIENT_SECRET")) return 91; '
                                  'return write(1, "absent\\n", 7) == 7 ? 0 : 92; }\n')
            env_worker = base / 'env-probe'
            compiled = subprocess.run([os.environ.get('CC', 'cc'), '-O2', '-Wall', '-Wextra', '-Werror',
                                       '-static', '-fno-pie', '-no-pie', str(env_source), '-o', str(env_worker)],
                                      check=True, capture_output=True, timeout=90)
            os.chmod(env_worker, 0o555)
            env_root, env_manifest = base / 'env-root', base / 'env-manifest.json'
            subprocess.run([sys.executable, str(REPO / 'packaging/build-minimal-root.py'), '--worker', str(env_worker),
                            '--root', str(env_root), '--manifest', str(env_manifest)],
                           check=True, capture_output=True, timeout=30)
            _, envsock, envstate = start(env_root, env_manifest)
            record('worker_does_not_inherit_parent_secret_environment', request(envsock, b'probe'), 200, b'absent\n')
            stop(envstate)
            report['environment_probe'] = {'source_sha256': digest(env_source), 'worker_sha256': digest(env_worker),
                                            'compile_stderr': compiled.stderr.decode()}
            # cgroup v2 always exposes control files. Only child directories
            # represent remaining request groups; neither those nor tasks may remain.
            remaining = [p.name for p in args.cgroup_root.iterdir() if p.is_dir()]
            report['remaining_request_cgroups'] = remaining
            assert not remaining, 'request cgroups remain after test'
            assert not (args.cgroup_root / 'cgroup.procs').read_text().strip(), 'tasks remain in cgroup root'
            report['status'] = 'PASS'
            report['exit_code'] = 0
    except Exception as error:
        report.update(status='FAIL', error='%s: %s' % (type(error).__name__, error), exit_code=1)
    finally:
        for process, log, logpath, command in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            log.flush()
            # TemporaryDirectory may have removed logs after a failure.
            report['gate_logs'].append({'argv': command, 'exit_code': process.returncode,
                                        'log': logpath.read_text() if logpath.exists() else 'removed after failed test'})
            log.close()
        report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'probes': len(report['probes']), 'report': str(args.report)}))
    return report['exit_code']


if __name__ == '__main__':
    sys.exit(main())
