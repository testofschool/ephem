#!/usr/bin/env python3
"""Separated trusted client (host) and ciphertext service (owned Linux VM).

Uses the actual client CLI, SSH loopback forwarding, real gate and real workers.
Keys and plaintext are never copied to the VM. Memory inspection streams only
the freshly owned relay process back to this client and records counts, not data.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import select
import shutil
import shlex
import socket
import struct
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]


def line(process, timeout=20):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError('owned service readiness deadline')
    raw = process.stdout.readline()
    if not raw:
        raise RuntimeError('owned service exited before readiness')
    return json.loads(raw)


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        block = stream.read(size - len(data))
        if not block:
            raise RuntimeError('truncated audit stream')
        data.extend(block)
    return bytes(data)


def http(port, method, path, body=None):
    client = HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        headers = {'Connection': 'close'}
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'Content-Length': str(len(body))})
        client.request(method, path, body, headers)
        response = client.getresponse()
        data = response.read(1024 * 1024)
        return response.status, data
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lab-helper', type=Path, required=True)
    parser.add_argument('--install', default='/opt/ephem-zero-lab-v1')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('preserve prior reports')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    node = shutil.which('node')
    if not node:
        parser.error('trusted local Node.js is required')
    with socket.socket() as free:
        free.bind(('127.0.0.1', 0)); port = free.getsockname()[1]
    service = tunnel = None
    report = {'schema': 'ephem-separated-blind-relay-v1', 'status': 'UNRUN', 'probes': [],
              'scope': 'Trusted separately installed client, encrypted-only one-shot relay; not arbitrary plaintext computation or physical erasure.'}
    def passed(name, **details):
        report['probes'].append({'name': name, 'status': 'PASS', **details})
    try:
        with tempfile.TemporaryDirectory(prefix='ephem-trusted-client-') as tmp:
            base = Path(tmp)
            # No payload or client key appears in this fixed control command.
            helper_command = shlex.join(['python3', '/home/felix.guest/ephem-release/tests/zero/serve_lab.py',
                '--install', args.install, '--port', str(port), '--ttl-ms', '60000',
                '--report', '/home/felix.guest/ephem-release/evidence/zero/server-' + args.report.name])
            command = ('set -eu; ephem_original_core=$(cat /proc/sys/kernel/core_pattern); '
                       'trap \'printf "%s\\n" "$ephem_original_core" > /proc/sys/kernel/core_pattern\' EXIT; '
                       'printf "core\\n" > /proc/sys/kernel/core_pattern; '
                       + helper_command)
            control_log = (base / 'control.log').open('wb')
            service = subprocess.Popen([str(args.lab_helper), 'shell', 'sudo', 'bash', '-c', command],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=control_log)
            ready = line(service)
            if ready.get('event') != 'ready':
                raise RuntimeError('service not ready')
            report['server_ready'] = ready
            config = args.lab_helper.parent / 'lima/ephem/ssh.config'
            tunnel_log = (base / 'tunnel.log').open('wb')
            tunnel = subprocess.Popen(['ssh', '-F', str(config), '-o', 'BatchMode=yes',
                '-o', 'ExitOnForwardFailure=yes', '-N', '-L',
                f'127.0.0.1:{port}:127.0.0.1:{port}', 'lima-ephem'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=tunnel_log)
            until = time.monotonic() + 10
            while True:
                try:
                    status, body = http(port, 'GET', '/health')
                    assert status == 200 and json.loads(body)['objects'] == 0
                    break
                except (OSError, AssertionError):
                    if tunnel.poll() is not None or time.monotonic() >= until:
                        raise RuntimeError('owned loopback tunnel failed')
                    time.sleep(.05)
            def cli(*options, expected=0):
                result = subprocess.run([node, str(REPO / 'zero/client.mjs'), *options],
                    capture_output=True, timeout=8)
                assert result.returncode == expected, 'client operation returned unexpected status'
                return result
            url = f'http://127.0.0.1:{port}'
            plaintext = b'EPHEM_LIVE_CLIENT_ONLY_' + os.urandom(48).hex().encode() + b'\x00\xff'
            source = base / 'original'; source.write_bytes(plaintext); source.chmod(0o600)
            envelope, key, receipt = (base / name for name in ('sealed.json', 'client-key.json', 'receipt.json'))
            cli('seal', '--input', str(source), '--envelope', str(envelope), '--key', str(key))
            key_record = json.loads(key.read_text())
            wire = envelope.read_bytes()
            assert plaintext not in wire and key_record['key'].encode() not in wire
            cli('put', '--url', url, '--envelope', str(envelope), '--receipt', str(receipt))
            passed('trusted_client_only_sends_ciphertext', plaintext_matches_on_wire=0, key_matches_on_wire=0)
            status, data = http(port, 'GET', '/health')
            assert status == 200 and json.loads(data)['objects'] == 1
            passed('real_gate_accepted_and_retained_ciphertext')

            # The needles stay on this host. The VM receives only PID/start/exe.
            import base64
            needles = [plaintext, base64.b64decode(key_record['key']), key_record['key'].encode()]
            audit = subprocess.Popen([str(args.lab_helper), 'shell', 'sudo', 'python3',
                '/home/felix.guest/ephem-release/tests/zero/read_process_memory.py',
                '--pid', str(ready['relay_pid']), '--start-ticks', str(ready['relay_start_ticks']),
                '--executable', ready['node_executable']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            hits = [0, 0, 0]; overlap = b''; total = 0
            while True:
                size = struct.unpack('>Q', exact(audit.stdout, 8))[0]
                if size == 0: break
                assert size <= 65536
                block = exact(audit.stdout, size); total += size
                assert total <= 512 * 1024 * 1024
                joined = overlap + block
                for i, needle in enumerate(needles):
                    # Count a boundary occurrence only when it ends in new data.
                    offset = 0
                    while True:
                        found = joined.find(needle, offset)
                        if found < 0: break
                        if found + len(needle) > len(overlap): hits[i] += 1
                        offset = found + 1
                overlap = joined[-(max(map(len, needles)) - 1):]
            audit_summary = json.loads(audit.stdout.readline())
            assert audit.wait(timeout=10) == 0 and audit_summary['complete'] and audit_summary['bytes_scanned'] == total
            assert hits == [0, 0, 0], 'owned relay memory contains client plaintext or key'
            passed('owned_relay_private_writable_memory_scan', bytes_scanned=total,
                   mappings_scanned=audit_summary['mappings_scanned'], plaintext_hits=0, raw_key_hits=0, encoded_key_hits=0)

            taken, opened = base / 'taken.json', base / 'opened'
            cli('take', '--url', url, '--receipt', str(receipt), '--envelope', str(taken))
            cli('open', '--envelope', str(taken), '--key', str(key), '--output', str(opened))
            assert opened.read_bytes() == plaintext
            passed('actual_client_roundtrip_recovers_exact_binary', bytes=len(plaintext), sha256=hashlib.sha256(plaintext).hexdigest())
            cli('take', '--url', url, '--receipt', str(receipt), '--envelope', str(base / 'second'), expected=1)
            assert not (base / 'second').exists()
            passed('second_take_cannot_recover_object')

            concurrent_receipt = base / 'concurrent-receipt'
            cli('put', '--url', url, '--envelope', str(envelope), '--receipt', str(concurrent_receipt))
            token_body = json.dumps({'token': json.loads(concurrent_receipt.read_text())['token']}, separators=(',', ':')).encode()
            with ThreadPoolExecutor(max_workers=8) as pool:
                answers = list(pool.map(lambda _: http(port, 'POST', '/v1/take', token_body), range(8)))
            assert [answer[0] for answer in answers].count(200) == 1
            assert [answer[0] for answer in answers].count(404) == 7
            passed('concurrent_take_is_at_most_once', contenders=8, successful_claims=1)

            service.stdin.write(b'restart-short\n'); service.stdin.flush()
            short_ready = line(service)
            assert short_ready['relay_pid'] != ready['relay_pid']
            expires = base / 'expires-receipt'
            cli('put', '--url', url, '--envelope', str(envelope), '--receipt', str(expires))
            time.sleep(1.7)
            cli('take', '--url', url, '--receipt', str(expires), '--envelope', str(base / 'expired'), expected=1)
            assert json.loads(http(port, 'GET', '/health')[1])['objects'] == 0
            passed('expiry_removes_object', configured_ttl_ms=1500)

            restart_receipt = base / 'restart-receipt'
            cli('put', '--url', url, '--envelope', str(envelope), '--receipt', str(restart_receipt))
            service.stdin.write(b'restart\n'); service.stdin.flush()
            restarted = line(service)
            assert restarted['relay_pid'] != ready['relay_pid']
            cli('take', '--url', url, '--receipt', str(restart_receipt), '--envelope', str(base / 'after-restart'), expected=1)
            assert json.loads(http(port, 'GET', '/health')[1])['objects'] == 0
            passed('restart_has_no_durable_object_restore', new_process=True)
            invalid = dict(json.loads(wire), key=key_record['key'])
            # Use a fixed synthetic string here: no real key is sent even in a negative test.
            invalid['key'] = 'SYNTHETIC_FORBIDDEN_KEY_FIELD'
            status, _ = http(port, 'POST', '/v1/objects', json.dumps(invalid).encode())
            assert status == 400
            passed('key_field_rejected_before_worker')
            service.stdin.write(b'stop\n'); service.stdin.flush()
            assert service.wait(timeout=15) == 0
            report.update(status='PASS', client_key_location='trusted host only; not copied to VM',
                          deployment='installed files and live execution verified in owned Linux lab')
    except Exception as error:
        report.update(status='FAIL', error=type(error).__name__ + ': ' + str(error))
    finally:
        if service and service.poll() is None:
            try:
                service.stdin.write(b'stop\n'); service.stdin.flush(); service.wait(timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                service.terminate(); service.wait(timeout=5)
        if tunnel and tunnel.poll() is None:
            tunnel.terminate(); tunnel.wait(timeout=5)
        report['exit_code'] = 0 if report['status'] == 'PASS' else 1
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'probes': len(report['probes']), 'error': report.get('error')}))
    return report['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
