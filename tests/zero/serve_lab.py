#!/usr/bin/env python3
"""Own a temporary Linux gate + opaque relay session for a separate host client.

stdout emits only fixed readiness/lifecycle metadata. stdin accepts restart/stop;
EOF stops. This never receives or logs a client plaintext, key or retrieval token.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import shutil
import signal
import stat
import subprocess
import sys
import time

NODE = Path('/opt/ephem-zero-node-v26.8.2/bin/node')
MINIMAL_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}


class LabFailure(Exception):
    pass


def trusted(path, directory=False):
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise LabFailure('noncanonical_install_path')
    first = True
    for current in (path, *path.parents):
        info = current.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise LabFailure('untrusted_install_path')
        expected_dir = directory if first else True
        if not (stat.S_ISDIR(info.st_mode) if expected_dir else stat.S_ISREG(info.st_mode)):
            raise LabFailure('invalid_install_path_type')
        first = False


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def process_identity(process, executable):
    if process.poll() is not None:
        raise LabFailure('owned_process_exited')
    raw = Path('/proc', str(process.pid), 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    if os.readlink('/proc/%d/exe' % process.pid) != str(executable):
        raise LabFailure('owned_process_identity_mismatch')
    return {'pid': process.pid, 'start_ticks': int(fields[19]), 'executable': str(executable)}


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


def interrupted(_signum, _frame):
    raise InterruptedError()


def stop_owned(process, expected=None):
    if process is None:
        return None
    if process.poll() is None:
        if expected is not None:
            observed = process_identity(process, Path(expected['executable']))
            if observed != expected:
                raise LabFailure('owned_process_identity_changed')
        process.terminate()
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    return process.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', type=Path, default=Path('/opt/ephem-zero-lab-v1'))
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--ttl-ms', type=int, default=1500)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    report = {'schema': 'ephem-separated-client-lab-session-v1', 'status': 'UNRUN',
              'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'sessions': [], 'binary_sha256': {}, 'cleanup': {}}
    if args.report is not None and os.path.lexists(args.report):
        parser.error('report must be a NEW path')
    gate = relay = None
    gate_identity = relay_identity = None
    run_dir = Path('/run/ephem-zero-session-%d' % os.getpid())
    cgroup = Path('/sys/fs/cgroup/ephem-zero-session-%d' % os.getpid())
    owns_run_dir = owns_cgroup = False
    run_inode = None
    gate_exit = relay_exit = None
    code = 1
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise LabFailure('dedicated_linux_root_required')
        if not 0 <= args.port <= 65535 or not 1 <= args.ttl_ms <= 60000:
            raise LabFailure('invalid_listener_configuration')
        swaps = Path('/proc/swaps').read_text().splitlines()
        pattern = Path('/proc/sys/kernel/core_pattern').read_text().strip()
        if len(swaps) != 1 or not swaps[0].startswith('Filename') or not pattern or pattern.startswith('|'):
            raise LabFailure('host_memory_policy_refused')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise LabFailure('core_limit_readback_failed')
        trusted(args.install, directory=True)
        files = {'node': NODE, 'gate': args.install / 'bin/ephem-gate',
                 'jail': args.install / 'bin/ephem-jail',
                 'manifest': args.install / 'root-manifest.json',
                 'worker': args.install / 'rootfs/worker',
                 'relay': args.install / 'zero/relay.mjs',
                 'store': args.install / 'zero/store.mjs',
                 'envelope': args.install / 'zero/envelope.mjs',
                 'zero_entrypoint': args.install / 'packaging/zero-entrypoint.sh',
                 'entrypoint': args.install / 'packaging/entrypoint.sh',
                 'prepare_cgroup': args.install / 'packaging/prepare-cgroup.sh'}
        for label, path in files.items():
            trusted(path)
            report['binary_sha256'][label] = sha256(path)
        trusted(args.install / 'rootfs', directory=True)
        if os.path.lexists(run_dir) or os.path.lexists(cgroup):
            raise LabFailure('session_paths_must_be_new')
        os.mkdir(run_dir, 0o700)
        os.chmod(run_dir, 0o700)
        owns_run_dir = True
        run_inode = (run_dir.stat().st_dev, run_dir.stat().st_ino)
        # We exclusively own this previously absent, fixed PID-derived path.
        owns_cgroup = True
        prepared = subprocess.run(['sh', str(files['prepare_cgroup']), str(cgroup)],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, env=MINIMAL_ENV, timeout=8)
        if prepared.returncode != 0:
            raise LabFailure('owned_cgroup_prepare_failed')
        socket = run_dir / 'gate.sock'
        gate_env = dict(MINIMAL_ENV, EPHEM_GATE=str(files['gate']), EPHEM_JAIL=str(files['jail']),
                        EPHEM_ROOT=str(args.install / 'rootfs'), EPHEM_WORKER='/worker',
                        EPHEM_ROOT_MANIFEST=str(files['manifest']), EPHEM_CGROUP_ROOT=str(cgroup),
                        EPHEM_SOCKET=str(socket))
        gate = subprocess.Popen(['sh', str(files['zero_entrypoint']), '--deadline-ms', '1000'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=gate_env)
        until = time.monotonic() + 8
        while not socket.is_socket():
            if gate.poll() is not None or time.monotonic() >= until:
                raise LabFailure('gate_startup_failed')
            time.sleep(.01)
        gate_identity = process_identity(gate, files['gate'])
        report['gate_identity'] = gate_identity

        def start_relay():
            process = subprocess.Popen([str(NODE), str(files['relay']), '--gate-socket', str(socket),
                                        '--root-manifest-sha256', report['binary_sha256']['manifest'],
                                        '--port', str(args.port), '--ttl-ms', str(args.ttl_ms)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, env=MINIMAL_ENV)
            # Return handle immediately to the outer cleanup owner even if
            # readiness fails; it must not orphan a listener on a test error.
            return process

        def ready_relay(process):
            data = bytearray()
            until = time.monotonic() + 8
            while b'\n' not in data:
                if process.poll() is not None or time.monotonic() >= until:
                    raise LabFailure('relay_startup_failed')
                available, _, _ = select.select([process.stdout], [], [], .1)
                if available:
                    block = os.read(process.stdout.fileno(), 1024)
                    if not block:
                        raise LabFailure('relay_startup_failed')
                    data.extend(block)
                    if len(data) > 2048:
                        raise LabFailure('invalid_relay_readiness')
            try:
                notice = json.loads(bytes(data).split(b'\n', 1)[0])
            except (ValueError, UnicodeError):
                raise LabFailure('invalid_relay_readiness') from None
            if notice.get('event') != 'listening' or notice.get('host') != '127.0.0.1' or not isinstance(notice.get('port'), int):
                raise LabFailure('invalid_relay_readiness')
            if args.port and notice['port'] != args.port:
                raise LabFailure('relay_port_mismatch')
            if not 1 <= notice['port'] <= 65535:
                raise LabFailure('relay_port_mismatch')
            args.port = notice['port']
            identity = process_identity(process, NODE)
            state = {'event': 'ready', 'port': args.port, 'relay_pid': identity['pid'],
                     'relay_start_ticks': identity['start_ticks'], 'node_executable': str(NODE),
                     'gate_pid': gate.pid, 'manifest_sha256': report['binary_sha256']['manifest'],
                     'run_dir': str(run_dir)}
            report['sessions'].append(state)
            emit(state)
            return identity

        relay = start_relay()
        relay_identity = ready_relay(relay)
        for line in sys.stdin:
            command = line.strip()
            if command in ('restart', 'restart-short'):
                if command == 'restart-short':
                    args.ttl_ms = 1500
                relay_exit = stop_owned(relay, relay_identity)
                if relay.stdout is not None:
                    relay.stdout.close()
                relay = start_relay()
                relay_identity = None
                relay_identity = ready_relay(relay)
            elif command == 'stop':
                break
            else:
                raise LabFailure('unsupported_control_command')
        report['status'] = 'PASS'
        code = 0
    except InterruptedError:
        report.update(status='STOPPED', reason='session_interrupted')
        code = 1
    except LabFailure as error:
        report.update(status='FAIL', reason=str(error))
    except (OSError, ValueError, subprocess.SubprocessError):
        report.update(status='FAIL', reason='session_operation_unavailable')
    finally:
        for label, process, expected in (('relay', relay, relay_identity), ('gate', gate, gate_identity)):
            try:
                exit_code = stop_owned(process, expected)
                report['cleanup'][label + '_exit_code'] = exit_code
                if process is not None and process.stdout is not None:
                    process.stdout.close()
            except (LabFailure, OSError, subprocess.SubprocessError):
                report['cleanup'][label + '_stopped'] = False
                report.update(status='FAIL', reason='owned_process_cleanup_failed')
                code = 1
        if owns_cgroup and cgroup.exists():
            try:
                # Scope is exclusively the NEW cgroup this session created.
                children = list(cgroup.iterdir())
                groups = [p for p in children if p.is_dir()]
                if groups or (cgroup / 'cgroup.procs').read_text().strip():
                    (cgroup / 'cgroup.kill').write_text('1\n')
                    until = time.monotonic() + 3
                    while (cgroup / 'cgroup.events').read_text().find('populated 1') >= 0:
                        if time.monotonic() >= until:
                            raise LabFailure('owned_cgroup_not_empty')
                        time.sleep(.01)
                    for group in groups:
                        group.rmdir()
                report['cleanup']['cgroup_empty_before_remove'] = not (cgroup / 'cgroup.procs').read_text().strip() and not any(p.is_dir() for p in cgroup.iterdir())
                cgroup.rmdir()
            except (OSError, LabFailure):
                report.update(status='FAIL', reason='owned_cgroup_cleanup_failed')
                code = 1
        report['cleanup']['cgroup_absent'] = not cgroup.exists()
        if owns_run_dir:
            try:
                info = run_dir.lstat()
                if (info.st_dev, info.st_ino) != run_inode or info.st_uid != 0 or not stat.S_ISDIR(info.st_mode):
                    raise LabFailure('owned_session_directory_changed')
                shutil.rmtree(run_dir)  # Only the exact newly created session inode.
            except (OSError, LabFailure):
                report.update(status='FAIL', reason='owned_session_directory_cleanup_failed')
                code = 1
        report['cleanup']['run_dir_absent'] = not run_dir.exists()
        report['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        report['exit_code'] = code
        if args.report is not None:
            try:
                with args.report.open('x') as target:
                    json.dump(report, target, indent=2)
                    target.write('\n')
            except OSError:
                code = 1
        emit({'event': 'stopped', 'status': report['status'], 'cgroup_absent': report['cleanup']['cgroup_absent'],
              'run_dir_absent': report['cleanup']['run_dir_absent'], 'exit_code': code})
    return code


if __name__ == '__main__':
    sys.exit(main())
