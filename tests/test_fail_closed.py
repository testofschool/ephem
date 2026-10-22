#!/usr/bin/env python3
"""Negative startup controls: failure must precede binding or worker execution."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gate', type=Path, required=True)
    parser.add_argument('--jail', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('preserve prior evidence')
    observations = []
    with tempfile.TemporaryDirectory(prefix='.ephem-preflight-', dir='/root') as tmp:
        root = Path(tmp)
        sock = root / 'gate.sock'
        base = [str(args.gate), '--socket', str(sock), '--jail', str(args.jail),
                '--root', str(root), '--worker', '/worker']
        for label, flags in [
            ('missing-cgroup', []),
            ('ordinary-directory', ['--cgroup-root', str(root)]),
            ('relative-cgroup', ['--cgroup-root', 'relative']),
            ('absent-cgroup', ['--cgroup-root', '/sys/fs/cgroup/ephem-does-not-exist']),
        ]:
            result = subprocess.run(base + flags, capture_output=True, timeout=5)
            observations.append({'probe': label, 'returncode': result.returncode,
                                 'bound_socket': sock.exists(),
                                 'pass': result.returncode != 0 and not sock.exists()})
        for label, expected in [('missing-parent', None), ('wrong-parent', '2147483647')]:
            env = {'PATH': '/usr/bin:/bin'}
            if expected:
                env['EPHEM_GATE_PID'] = expected
            result = subprocess.run([str(args.jail), '--root', str(root), '--worker', '/worker'],
                                    input=b'', capture_output=True, env=env, timeout=5)
            observations.append({'probe': label, 'returncode': result.returncode,
                                 'pass': result.returncode == 125 and b'explicitly identified' in result.stderr})
    report = {'status': 'PASS' if all(row['pass'] for row in observations) else 'FAIL',
              'observations': observations}
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
