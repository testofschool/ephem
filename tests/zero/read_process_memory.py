#!/usr/bin/env python3
"""Stream bounded private writable memory from one explicitly owned lab Node.

The caller supplies the fresh PID/start identity from serve_lab.py and consumes
stdout as binary internally. No search needles enter this program. No dump is
written. This is a sampled process-memory observation, not a forensic proof.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import stat
import struct
import sys
import time

NODE = '/opt/ephem-zero-node-v26.8.2/bin/node'
MAX_BYTES = 512 * 1024 * 1024
CHUNK = 64 * 1024


class Refused(Exception):
    pass


def identity(pid, expected_ticks, expected_executable):
    process = Path('/proc') / str(pid)
    raw = (process / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    if len(fields) < 20 or int(fields[19]) != expected_ticks:
        raise Refused('identity_mismatch')
    if os.readlink(process / 'exe') != expected_executable:
        raise Refused('identity_mismatch')
    if (process / 'status').stat().st_uid != 0:
        raise Refused('identity_mismatch')
    return fields[0]


def executable_policy(path):
    if path != NODE:
        raise Refused('unrecognized_lab_executable')
    current = Path(path)
    first = True
    while True:
        info = current.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise Refused('untrusted_lab_executable')
        if (first and not stat.S_ISREG(info.st_mode)) or (not first and not stat.S_ISDIR(info.st_mode)):
            raise Refused('untrusted_lab_executable')
        if current == Path('/'):
            break
        first = False
        current = current.parent


def interrupt(_signum, _frame):
    raise InterruptedError()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--start-ticks', type=int, required=True)
    parser.add_argument('--executable', required=True)
    args = parser.parse_args()
    result = {'bytes_scanned': 0, 'mappings_scanned': 0, 'complete': False,
              'scope': 'readable-writable-private mappings of exactly identified owned lab Node'}
    pidfd = None
    stopped = False
    output = sys.stdout.buffer
    failure = None
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupt)
    try:
        if sys.platform != 'linux' or os.geteuid() != 0 or args.pid <= 1 or args.start_ticks <= 0:
            raise Refused('linux_root_and_positive_owned_identity_required')
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise Refused('pidfd_signal_unavailable')
        executable_policy(args.executable)
        identity(args.pid, args.start_ticks, args.executable)
        pidfd = os.pidfd_open(args.pid, 0)
        identity(args.pid, args.start_ticks, args.executable)
        # pidfd binds all signals to this process identity even if it later dies.
        signal.pidfd_send_signal(pidfd, signal.SIGSTOP, None, 0)
        stopped = True
        until = time.monotonic() + 2
        while identity(args.pid, args.start_ticks, args.executable) not in ('T', 't'):
            if time.monotonic() >= until:
                raise Refused('target_did_not_stop')
            time.sleep(.005)
        maps = (Path('/proc') / str(args.pid) / 'maps').read_text()
        targets = []
        for line in maps.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 5:
                raise Refused('invalid_memory_map')
            permissions = parts[1]
            if len(permissions) != 4 or permissions[0] != 'r' or permissions[1] != 'w' or permissions[3] != 'p':
                continue
            start, end = (int(x, 16) for x in parts[0].split('-', 1))
            if start >= end:
                raise Refused('invalid_memory_map')
            targets.append((start, end))
        identity(args.pid, args.start_ticks, args.executable)
        fd = os.open('/proc/%d/mem' % args.pid, os.O_RDONLY | os.O_CLOEXEC)
        try:
            for start, end in targets:
                at = start
                while at < end:
                    available = MAX_BYTES - result['bytes_scanned']
                    if available == 0:
                        raise Refused('scan_byte_cap_reached')
                    amount = min(CHUNK, end - at, available)
                    try:
                        data = os.pread(fd, amount, at)
                    except OSError as error:
                        if error.errno in (errno.EIO, errno.EFAULT, errno.ESRCH):
                            raise Refused('readable_mapping_not_fully_readable') from None
                        raise
                    if len(data) != amount:
                        raise Refused('short_memory_read')
                    output.write(struct.pack('>Q', len(data)))
                    output.write(data)
                    result['bytes_scanned'] += len(data)
                    at += len(data)
                result['mappings_scanned'] += 1
            output.flush()
        finally:
            os.close(fd)
        identity(args.pid, args.start_ticks, args.executable)
        result['complete'] = True
    except Refused as error:
        failure = str(error)  # Fixed local reason identifiers only.
    except BrokenPipeError:
        failure = 'consumer_disconnected'
    except InterruptedError:
        failure = 'scan_interrupted'
    except (OSError, ValueError):
        failure = 'memory_observation_unavailable'
    finally:
        if stopped and pidfd is not None:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGCONT, None, 0)
            except OSError:
                result['complete'] = False
                failure = 'target_resume_unavailable'
        if pidfd is not None:
            os.close(pidfd)
        if failure is not None:
            result['complete'] = False
            result['reason'] = failure
        try:
            output.write(struct.pack('>Q', 0))
            output.write((json.dumps(result, separators=(',', ':')) + '\n').encode())
            output.flush()
        except (BrokenPipeError, OSError):
            return 1
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    sys.exit(main())
