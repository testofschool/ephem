#!/usr/bin/env python3
"""Stop a launcher before exec, let its expected gate die, then resume it.

The test becomes a child subreaper so it can reap its own orphan exactly.
No preexisting process is signaled. Requires root in the dedicated Linux lab.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--jail', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('preserve evidence')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'subreaper')
    identity_read, identity_write = os.pipe()
    output_read, output_write = os.pipe()
    expected_gate = os.fork()
    if expected_gate == 0:
        os.close(identity_read)
        os.close(output_read)
        launcher = os.fork()
        if launcher == 0:
            expected = os.getppid()
            os.dup2(output_write, 1)
            os.dup2(output_write, 2)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execve(str(args.jail), [str(args.jail), '--root', '/not-used', '--worker', '/worker'],
                      {'PATH': '/usr/bin:/bin', 'EPHEM_GATE_PID': str(expected)})
        _, stopped = os.waitpid(launcher, os.WUNTRACED)
        assert os.WIFSTOPPED(stopped)
        os.write(identity_write, str(launcher).encode())
        os._exit(0)
    os.close(identity_write)
    os.close(output_write)
    launcher = int(os.read(identity_read, 64))
    os.close(identity_read)
    os.waitpid(expected_gate, 0)
    os.kill(launcher, signal.SIGCONT)
    _, status = os.waitpid(launcher, 0)
    message = os.read(output_read, 4096).decode()
    os.close(output_read)
    passed = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 125 and 'explicitly identified' in message
    args.report.write_text(json.dumps({'status': 'PASS' if passed else 'FAIL',
        'probe': 'gate-death-before-launcher-main', 'expected_gate_pid': expected_gate,
        'reaped_launcher_pid': launcher, 'launcher_exit': os.waitstatus_to_exitcode(status),
        'stderr': message, 'scope': 'controlled pre-exec orphan; no worker starts'}, indent=2) + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
