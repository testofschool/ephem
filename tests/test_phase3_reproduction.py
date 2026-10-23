"""Regression checks against false success in release evidence verification."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('verify_phase3_run', ROOT / 'scripts/verify_phase3_run.py')
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ReproductionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = VERIFY.load_report(ROOT / 'reports/phase3/VALIDATION.json')
        cls.stateful = VERIFY.load_report(ROOT / 'reports/phase3/stateful-isolation-final.json')
        cls.native = VERIFY.load_report(ROOT / 'reports/phase3/warm-native-deliverable-final.json')

    def test_retained_evidence_meets_bounded_contract(self):
        lines = VERIFY.verify(self.reference, self.stateful, self.native)
        self.assertIn('HOLD', lines[-1])
        self.assertIn('UNRUN', lines[-2])

    def test_missing_fault_cannot_be_rounded_into_success(self):
        report = copy.deepcopy(self.stateful)
        report['fault_injection'].pop()
        with self.assertRaises(ValueError):
            VERIFY.verify(self.reference, report, self.native)

    def test_indeterminate_commit_is_not_burned(self):
        report = copy.deepcopy(self.stateful)
        report['fault_injection'][0]['receipt'].update(
            commit_status='indeterminate', committed_mutations=None)
        with self.assertRaises(ValueError):
            VERIFY.verify(self.reference, report, self.native)

    def test_zero_corruption_summary_does_not_hide_commit(self):
        report = copy.deepcopy(self.stateful)
        report['fault_injection'][0]['receipt']['committed_mutations'] = 1
        with self.assertRaises(ValueError):
            VERIFY.verify(self.reference, report, self.native)

    def test_tampered_percentile_is_rejected(self):
        report = copy.deepcopy(self.native)
        report['p95_ms'] = .1
        with self.assertRaises(ValueError):
            VERIFY.verify(self.reference, self.stateful, report)

    def test_nonfinite_and_negative_native_samples_are_rejected(self):
        for value in (float('nan'), float('inf'), -1):
            with self.subTest(value=value):
                report = copy.deepcopy(self.native)
                report['samples_ms'][0] = value
                with self.assertRaises(ValueError):
                    VERIFY.verify(self.reference, self.stateful, report)

    def test_missing_native_policy_probe_is_rejected(self):
        report = copy.deepcopy(self.native)
        report['lifecycle_checks'].pop()
        with self.assertRaises(ValueError):
            VERIFY.verify(self.reference, self.stateful, report)

    def test_unreaped_worker_is_rejected(self):
        report = copy.deepcopy(self.stateful)
        report['worker_receipts'][0]['reaped'] = False
        with self.assertRaises(ValueError):
            VERIFY.verify(self.reference, report, self.native)

    def test_truncated_worker_summary_is_rejected(self):
        report = copy.deepcopy(self.stateful)
        report['worker_receipts'].pop(0)
        report['unique_worker_pids'] -= 1
        with self.assertRaisesRegex(ValueError, 'worker summaries disagree'):
            VERIFY.verify(self.reference, report, self.native)

    def test_inconsistent_final_key_count_is_rejected(self):
        report = copy.deepcopy(self.stateful)
        report['final_committed_keys'] = 999999
        with self.assertRaisesRegex(ValueError, 'final committed key count'):
            VERIFY.verify(self.reference, report, self.native)

    def test_raw_clean_receipt_with_extra_mutations_is_rejected(self):
        report = copy.deepcopy(self.stateful)
        report['receipts'][0]['committed_mutations'] = 999
        with self.assertRaisesRegex(ValueError, 'exactly two mutations'):
            VERIFY.verify(self.reference, report, self.native)

    def test_historical_point_seven_is_not_a_new_run_gate(self):
        report = copy.deepcopy(self.native)
        report['samples_ms'] = [v * 1.5 for v in report['samples_ms']]
        for field in ('p50_ms', 'p95_ms', 'p99_ms', 'max_ms'):
            report[field] *= 1.5
        lines = VERIFY.verify(self.reference, self.stateful, report)
        self.assertIn('1.026760ms', lines[1])
        report['samples_ms'] = [v * 2 for v in report['samples_ms']]
        for field in ('p50_ms', 'p95_ms', 'p99_ms', 'max_ms'):
            report[field] *= 2
        with self.assertRaises(ValueError):
            VERIFY.verify(self.reference, self.stateful, report)


if __name__ == '__main__':
    unittest.main()
