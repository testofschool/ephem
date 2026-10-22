#!/usr/bin/env python3
"""Refuse zero-profile packaging when retained source/evidence identities drift.

This is a consistency gate for the named experiments, not a security proof or a
production approval. Historical v0.2 alpha evidence has its own frozen verifier.
"""
import hashlib
import json
import re
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    errors = []

    def check(condition, message):
        if not condition:
            errors.append(message)

    def read(name):
        return json.loads((root / 'evidence/zero' / name).read_text())

    freeze = read('source-freeze-v3.json')['sha256']
    check(len(freeze) == 38, 'expected 38 executed runtime and test source files')
    for path, expected in freeze.items():
        check(hashlib.sha256((root / path).read_bytes()).hexdigest() == expected,
              'executed source changed: ' + path)

    replay = read('root-replay-v2.json')
    check(replay['status'] == 'PASS' and replay['exit_code'] == 0,
          'root replay failed')
    check(len(replay['probes']) == 26 and all(p['status'] == 'PASS' for p in replay['probes']),
          'root probes incomplete')
    arms = replay['replay']
    check(arms['input_hex'] == '52454144534543524554'
          and arms['before'] == 1 and arms['after'] == 0 and arms['runs_per_arm'] == 1,
          'original READSECRET before/after missing')
    check(arms['worker_sha256_before'] == arms['worker_sha256_after'],
          'replay changed the worker')
    responses = {r['name']: r for r in replay['responses']}
    for response in replay['responses']:
        check(hashlib.sha256(bytes.fromhex(response['body_hex'])).hexdigest() == response['body_sha256'],
              'raw response body digest mismatch: ' + response['name'])
    before = responses['historical_READSECRET_returns_readable_canary']
    after = responses['strict_READSECRET_cannot_read_absent_ambient_file']
    canary = b'SYNTHETIC_SECRET_VISIBLE_TO_WORKER\n'
    check(before['request_hex'] == after['request_hex'] == arms['input_hex']
          and before['status'] == 200 and after['status'] == 500,
          'raw original attack requests/statuses differ')
    check(bytes.fromhex(before['body_hex']) == canary
          and bytes.fromhex(after['body_hex']) == b'execution rejected\n'
          and int(canary in bytes.fromhex(before['body_hex'])) == arms['before']
          and int(canary in bytes.fromhex(after['body_hex'])) == arms['after'],
          'raw attack response does not reproduce the aggregate')
    check(replay['remaining_request_cgroups'] == [], 'request cgroups remain')
    prereg_path = root / 'evidence/zero/root-replay-v2.json.preregistration.json'
    check(hashlib.sha256(prereg_path.read_bytes()).hexdigest() == replay['preregistration_sha256'],
          'root replay preregistration changed')
    prereg = json.loads(prereg_path.read_text())
    for path, expected in prereg['source_sha256'].items():
        relative = path.split('/ephem-release/', 1)[1]
        check(freeze[relative] == expected, 'root replay source identity: ' + relative)

    live = read('live-client-v3.json')
    check(live['status'] == 'PASS' and live['exit_code'] == 0
          and len(live['probes']) == 9 and all(p['status'] == 'PASS' for p in live['probes']),
          'separated client replay incomplete')
    probes = {p['name']: p for p in live['probes']}
    memory = probes['owned_relay_private_writable_memory_scan']
    check(0 < memory['bytes_scanned'] <= 512 * 1024 * 1024 and memory['mappings_scanned'] > 0
          and memory['plaintext_hits'] == memory['raw_key_hits'] == memory['encoded_key_hits'] == 0,
          'bounded server memory observation missing')
    check(probes['concurrent_take_is_at_most_once']['contenders'] == 8
          and probes['concurrent_take_is_at_most_once']['successful_claims'] == 1,
          'one-shot claim race failed')
    check(probes['expiry_removes_object']['configured_ttl_ms'] == 1500,
          'expiry observation missing')
    server = read('server-live-client-v3.json')
    check(server['status'] == 'PASS' and server['exit_code'] == 0,
          'installed server execution failed')
    check(all(server['cleanup'][k] is True for k in (
        'cgroup_empty_before_remove', 'cgroup_absent', 'run_dir_absent')),
        'owned live session cleanup incomplete')
    installed = server['binary_sha256']
    for label, path in {'relay': 'zero/relay.mjs', 'store': 'zero/store.mjs',
                        'envelope': 'zero/envelope.mjs',
                        'zero_entrypoint': 'packaging/zero-entrypoint.sh',
                        'entrypoint': 'packaging/entrypoint.sh',
                        'prepare_cgroup': 'packaging/prepare-cgroup.sh'}.items():
        check(installed[label] == freeze[path], 'installed server drift: ' + label)
    for label, path in [('gate', 'target/release/ephem-gate'), ('jail', 'target/ephem-jail')]:
        runtime_hash = prereg['artifact_sha256']['/home/felix.guest/ephem-release/' + path]
        check(installed[label] == runtime_hash, 'build/replay/installed binary mismatch: ' + label)
    check(installed['worker'] == arms['worker_sha256_after']
          and installed['manifest'] == replay['minimal_root_build']['manifest_sha256']
          == live['server_ready']['manifest_sha256'], 'manifest/worker pin mismatch')

    client = read('client-install-v2.json')
    check(client['status'] == 'PASS' and client['roundtrip_matches'] is True,
          'local installed client readback failed')
    for name, expected in client['sha256'].items():
        check(freeze['zero/' + name] == expected, 'installed client drift: ' + name)
    for log in ('node-host-v3.log', 'node-linux-v3.log'):
        node_log = (root / 'evidence/zero' / log).read_text()
        tests = re.search(r'(?:#|ℹ) tests (\d+)', node_log)
        passed = re.search(r'(?:#|ℹ) pass (\d+)', node_log)
        check(bool(tests and passed) and int(tests[1]) == int(passed[1]) == 32
              and all(re.search(r'(?:#|ℹ) ' + label + r' 0\b', node_log)
                      for label in ('fail', 'skipped', 'cancelled', 'todo')),
              'Node unit checks incomplete: ' + log)
    build_log = (root / 'evidence/zero/build-linux-v2.log').read_text()
    check('7 passed; 0 failed' in build_log and 'BUILD_EXIT=0' in build_log,
          'Rust lint/build/unit receipt missing')
    for name in ('lifecycle', 'boundaries', 'seccomp', 'preflight', 'parent-race'):
        check(read('legacy-linux-v1/' + name + '.json')['status'] == 'PASS',
              'legacy regression: ' + name)
    check(read('root-replay-v1.json')['status'] == 'FAIL'
          and read('live-client-v1.json')['status'] == 'FAIL'
          and read('server-live-client-v1.json')['reason'] == 'untrusted_install_path',
          'failed attempt records must be preserved')
    print(json.dumps({'result': 'BOUNDED_ZERO_EVIDENCE_CONSISTENT' if not errors else 'HOLD',
                      'source_files': len(freeze), 'errors': errors,
                      'original_READSECRET': {'before': arms['before'], 'after': arms['after']},
                      'physical_erasure': 'UNPROVEN', 'arbitrary_plaintext_secrecy': 'NOT_PROVIDED',
                      'global_owner_census': 'BLOCKED: memory_list unavailable',
                      'production': 'HOLD'}, indent=2))
    return bool(errors)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'result': 'HOLD', 'error': str(error)}))
        raise SystemExit(1)
