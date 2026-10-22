#!/usr/bin/env python3
"""Check frozen local evidence consistency; never grant production approval."""
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    read = lambda p: json.loads((root / p).read_text())
    errors = []
    def check(condition, message):
        if not condition:
            errors.append(message)
    freeze = read('evidence/source-freeze.json')['sha256']
    check(len(freeze) == 24 and 'crates/ephem-gate/src/resources.rs' in freeze,
          'executed source freeze must contain the expected 24 files')
    for path, expected in freeze.items():
        check(hashlib.sha256((root / path).read_bytes()).hexdigest() == expected,
              'source changed: ' + path)
    lifecycle = read('evidence/arm64-v2/integration/lifecycle.json')
    check(lifecycle['status'] == 'PASS' and lifecycle['tests_run'] == 12
          and lifecycle['failures'] == lifecycle['errors'] == lifecycle['skipped'] == 0,
          'lifecycle suite incomplete')
    check(len(lifecycle['fifty_host_worker_pids']) == 50
          and len(set(lifecycle['fifty_host_worker_pids'])) == 50, 'worker count mismatch')
    check(lifecycle['cgroup_oom_and_disposal_verified'] is True, 'missing OOM/disposal proof')
    rows = lifecycle['resource_disposals']
    check(len(rows) == len({r['resource_scope'] for r in rows}) == 151
          and all(r['disposed'] is True for r in rows), 'disposal count mismatch')
    check(any(r['oom_kill'] > 0 and r['memory_peak_bytes'] == 134217728 for r in rows),
          'actual memory OOM observation absent')
    for observation in lifecycle['observations']:
        if observation['status'] == 200:
            check(observation['headers']['x-ephem-output-sha256'] == observation['response_sha256'],
                  'response body digest mismatch')
    for name in ['boundaries', 'seccomp', 'preflight', 'parent-race']:
        check(read('evidence/arm64-v2/integration/' + name + '.json')['status'] == 'PASS',
              name + ' failed')
    check(read('evidence/arm64-v2/core-refusal.json')['status'] == 'PASS', 'host refusal failed')
    php = read('evidence/arm64-v2/php.json')
    check(php['verdict'] == 'PASS' and len(php['observations']) == 4, 'PHP fixture failed')
    check(php['application_sha256_before'] == php['application_sha256_after']
          == hashlib.sha256((root / 'examples/php/receiver.php').read_bytes()).hexdigest(),
          'application bytes changed')
    receipt = read('evidence/build-v2/receipt.json')
    check(receipt['all_pass'] and len(receipt['commands']) == 5
          and all(row['returncode'] == 0 for row in receipt['commands']), 'build receipt failed')
    check(receipt['core_pattern_restored'] and receipt['active_swap_entries'] == 0
          and receipt['remaining_ephem_cgroups'] == [], 'host restoration receipt failed')
    for key, path in [('gate', 'target/release/ephem-gate'), ('jail', 'target/ephem-jail')]:
        check(lifecycle['artifact_sha256'][key] == receipt['artifact_sha256'][path],
              'build/runtime binary identity mismatch')
    print(json.dumps({'result': 'BOUNDED_EVIDENCE_CONSISTENT' if not errors else 'HOLD',
                      'source_files': len(freeze), 'errors': errors,
                      'production': 'HOLD', 'external_security_audit': 'UNRUN'}, indent=2))
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
