"""Stored x86 evidence must fail closed on changed bytes and invalid semantics."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('verify_x86_evidence',
                                            ROOT / 'scripts/verify_x86_evidence.py')
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class X86EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = VERIFY.pinned_files(VERIFY.DEFAULT_ROOT)
        cls.report = VERIFY.strict_json(cls.files['X86_REPRODUCTION.json'])
        cls.native = VERIFY.strict_json(cls.files['warm-native.json'])
        cls.texts = {name: content.decode('utf-8') for name, content in cls.files.items()
                     if not name.endswith('.json')}

    def rejected(self, mutate, pattern=None):
        report, native, texts = copy.deepcopy((self.report, self.native, self.texts))
        mutate(report, native, texts)
        context = self.assertRaisesRegex(ValueError, pattern) if pattern else self.assertRaises(ValueError)
        with context:
            VERIFY.verify_semantics(report, native, texts)

    def cli(self, root):
        return subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'scripts/verify_x86_evidence.py'),
                               '--root', str(root)], capture_output=True, text=True, timeout=10)

    def test_real_snapshot_passes_without_executing_or_rounding(self):
        before = {name: hashlib.sha256((VERIFY.DEFAULT_ROOT / name).read_bytes()).hexdigest()
                  for name in VERIFY.FILE_PINS}
        result = VERIFY.verify(VERIFY.DEFAULT_ROOT)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['native_lifecycle_ms'], {
            'p50': 0.44322300000000003, 'p95': 0.593124,
            'p99': 0.7238249999999999, 'max': 1.8941999999999999,
        })
        self.assertEqual(result['lifecycle_check_count'], 13)
        self.assertEqual(result['retained_worker_receipts'], 23)
        self.assertEqual(result['unique_worker_pids'], 23)
        for key in ('runtime_reexecuted', 'independent_security_audit', 'binary_bytes_verified'):
            self.assertIs(result[key], False)
        self.assertEqual(result['production_status'], 'HOLD')
        self.assertEqual(result['reported_UNRUN_here'], self.report['UNRUN_here'])
        self.assertEqual(set(result['UNRUN'].values()), {'UNRUN'})
        self.assertEqual(len(result['original_file_bytes_verified']), 8)
        after = {name: hashlib.sha256((VERIFY.DEFAULT_ROOT / name).read_bytes()).hexdigest()
                 for name in VERIFY.FILE_PINS}
        self.assertEqual(before, after)

    def test_semantic_helper_accepts_original_data_without_hash_gate(self):
        self.assertEqual(VERIFY.verify_semantics(self.report, self.native, self.texts)['status'], 'PASS')

    def test_cli_passes_and_preserves_exact_json_float_values(self):
        process = self.cli(VERIFY.DEFAULT_ROOT)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, '')
        result = json.loads(process.stdout)
        self.assertEqual(result['native_lifecycle_ms']['p50'], 0.44322300000000003)
        self.assertFalse(result['runtime_reexecuted'])

    def test_cli_rejects_same_size_corrupt_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'evidence'
            shutil.copytree(VERIFY.DEFAULT_ROOT, root)
            path = root / 'warm-native.json'
            original = path.read_bytes()
            changed = original.replace(b'0.37912', b'0.37913', 1)
            self.assertNotEqual(original, changed)
            self.assertEqual(len(original), len(changed))
            path.write_bytes(changed)
            process = self.cli(root)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(process.stdout, '')
            self.assertIn('SHA-256 mismatch: warm-native.json', process.stderr)

    def test_cli_rejects_missing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'evidence'
            shutil.copytree(VERIFY.DEFAULT_ROOT, root)
            (root / 'warm-native.json').unlink()
            process = self.cli(root)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(process.stdout, '')
            self.assertEqual(json.loads(process.stderr)['status'], 'FAIL')

    def test_byte_size_and_linked_evidence_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'evidence'
            shutil.copytree(VERIFY.DEFAULT_ROOT, root)
            path = root / 'env.txt'
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'byte size mismatch: env.txt'):
                VERIFY.verify(root)
            path.unlink()
            path.symlink_to(VERIFY.DEFAULT_ROOT / 'env.txt')
            with self.assertRaisesRegex(ValueError, 'symlink evidence'):
                VERIFY.verify(root)

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for content in (b'{"x":1,"x":2}', b'{"x":{"y":1,"y":2}}',
                        b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                        b'{"x":1e999}'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                VERIFY.strict_json(content)

    def test_sample_types_bounds_and_count_are_enforced(self):
        for value in (True, '0.4', float('nan'), float('inf'), -1.0, 0.0):
            with self.subTest(value=value):
                self.rejected(lambda r, n, t: n['samples_ms'].__setitem__(0, value))
        self.rejected(lambda r, n, t: n['samples_ms'].pop(), 'sample count')
        self.rejected(lambda r, n, t: n.__setitem__('iterations', True), 'integer')
        self.rejected(lambda r, n, t: n.__setitem__('iterations', 999), 'iterations')
        self.rejected(lambda r, n, t: n.__setitem__('warmup', 99), 'warmups')
        self.rejected(lambda r, n, t: n['samples_ms'].reverse(), 'sorted order')

    def test_percentiles_and_summary_must_match_raw_samples_exactly(self):
        self.rejected(lambda r, n, t: n.__setitem__('p95_ms', .1), 'p95 disagrees')
        self.rejected(lambda r, n, t: r['native_lifecycle_ms'].__setitem__('max', 2),
                      'summary max disagrees')
        self.rejected(lambda r, n, t: n.__setitem__('p50_ms', n['p50_ms'] + 1e-12),
                      'p50 disagrees')
        self.rejected(lambda r, n, t: n.__setitem__('p95_below_2ms', 1), 'p95 <2ms')
        self.rejected(lambda r, n, t: r['native_lifecycle_ms'].__setitem__('p95_below_2ms', False))

    def test_consistent_summaries_do_not_hide_a_failed_latency_gate(self):
        def mutate(report, native, texts):
            native['samples_ms'] = [value * 5 for value in native['samples_ms']]
            for name in ('p50', 'p95', 'p99', 'max'):
                native[name + '_ms'] *= 5
                report['native_lifecycle_ms'][name] *= 5
        self.rejected(mutate, 'p95 <2ms gate failed')

    def test_missing_duplicate_and_wrong_fault_cases_are_rejected(self):
        self.rejected(lambda r, n, t: n['lifecycle_checks'].pop(), 'check count')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][2].__setitem__('request', 'segv'),
                      'missing, duplicated')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][2]['receipt']['status'].__setitem__('signal', 11),
                      'wrong native fault signal')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][2]['receipt']['status'].__setitem__('core_dumped', True))
        self.rejected(lambda r, n, t: n['lifecycle_checks'][1].pop('recovery'), 'fault check fields')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][11]['receipt']['status'].__setitem__('kind', 'exited'))

    def test_every_receipt_requires_cleanup_and_strict_pid_types(self):
        for field in ('reaped', 'stdout_eof', 'state_eof'):
            for value in (False, 1):
                with self.subTest(field=field, value=value):
                    self.rejected(lambda r, n, t: n['lifecycle_checks'][2]['recovery'].__setitem__(field, value),
                                  'incomplete worker lifecycle')
        for value in (True, 0, -1, 4103.0):
            with self.subTest(pid=value):
                self.rejected(lambda r, n, t: n['lifecycle_checks'][0]['receipts'][1].__setitem__('worker_pid', value))

    def test_pid_reuse_and_released_fault_output_are_rejected(self):
        self.rejected(lambda r, n, t: n['lifecycle_checks'][0]['receipts'][1].__setitem__(
            'worker_pid', n['lifecycle_checks'][0]['receipts'][0]['worker_pid']), 'PID reuse')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][2]['receipt'].__setitem__('output', [1]),
                      'released output')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][2]['recovery'].__setitem__('output', [49]),
                      'private state did not reset')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][0]['receipts'][0]['status'].__setitem__('code', False),
                      'integer')
        self.rejected(lambda r, n, t: n['lifecycle_checks'][2]['recovery'].__setitem__('output', [256]),
                      'output bytes')

    def test_report_names_source_and_environment_must_agree(self):
        self.rejected(lambda r, n, t: r['lifecycle_checks_executed'].pop(), 'summary lifecycle')
        self.rejected(lambda r, n, t: r['upstream'].__setitem__('commit', '0' * 40), 'source identity')
        self.rejected(lambda r, n, t: t.__setitem__('upstream-commit.txt', 'wrong\n'), 'source identity')
        self.rejected(lambda r, n, t: r['environment'].__setitem__('arch', 'aarch64'), 'environment')
        self.rejected(lambda r, n, t: t.__setitem__('env.txt', t['env.txt'].replace('6.18.44', '6.18.45')),
                      'environment disagrees')
        self.rejected(lambda r, n, t: r['environment'].__setitem__('cgroup2', 1), 'environment')

    def test_failed_logs_cannot_inherit_summary_success(self):
        self.rejected(lambda r, n, t: t.__setitem__('cargo-test.log', t['cargo-test.log'].replace('TEST_RC=0', 'TEST_RC=1')),
                      'TEST_RC')
        self.rejected(lambda r, n, t: t.__setitem__('cargo-build.log', t['cargo-build.log'] + 'BUILD_RC=0\n'),
                      'BUILD_RC')
        self.rejected(lambda r, n, t: t.__setitem__('cargo-test.log', t['cargo-test.log'].replace('16 passed', '15 passed')),
                      'test counts')
        self.rejected(lambda r, n, t: t.__setitem__('cargo-build.log', t['cargo-build.log'].replace('[optimized]', '[unoptimized]')),
                      'release profile')
        self.rejected(lambda r, n, t: t.__setitem__('warm-native.stderr.log', 'runtime failure'), 'stderr')

    def test_unrun_scope_and_recorded_binary_hashes_cannot_be_promoted(self):
        self.rejected(lambda r, n, t: r['UNRUN_here'].pop('postgresql_live'), 'UNRUN scope')
        self.rejected(lambda r, n, t: r['UNRUN_here'].__setitem__('bpf_lsm', 'PASS'), 'UNRUN scope')
        self.rejected(lambda r, n, t: r['binary_sha256'].__setitem__(0, '0' * 64), 'hash strings disagree')


if __name__ == '__main__':
    unittest.main()
