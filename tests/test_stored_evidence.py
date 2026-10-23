"""Snapshot checks plus semantic mutation tests independent of byte pinning.

The semantic tests deliberately call validate_reports on decoded copies so a
file-hash failure cannot hide an arithmetic or status-validation defect.
Only fixture paths and the repository CLI entry point differ from the supplied tests.
"""

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


BASE = Path(__file__).resolve().parents[1]
SNAPSHOT = BASE / "docs" / "audit" / "stored-evidence-20261023"
MANIFEST = SNAPSHOT / "evidence_manifest.json"
SPEC = importlib.util.spec_from_file_location("evidence_gate", SNAPSHOT / "verify_stored_evidence.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class EvidenceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = gate.read_pinned_reports(BASE, MANIFEST)

    def setUp(self):
        self.reports = copy.deepcopy(self.original)

    def fails(self, pattern):
        with self.assertRaisesRegex((gate.EvidenceError, KeyError, TypeError), pattern):
            gate.validate_reports(self.reports)

    def test_actual_snapshot_preserves_scope_and_failed_gates(self):
        result = gate.validate_reports(self.reports)
        self.assertEqual(result["verdict"], "STORED_EVIDENCE_CONSISTENT")
        self.assertEqual(result["production_status"], "HOLD")
        self.assertFalse(result["runtime_reexecuted"])
        self.assertFalse(result["independent_security_audit"])
        self.assertEqual(result["php_p95_gate"], "FAIL")
        self.assertEqual(result["full_reproduce_script_exit_code"], 1)
        self.assertTrue(result["fault_worker_output_and_cleanup_fields_checked"])
        self.assertTrue(result["fault_worker_status_fields_checked"])
        self.assertFalse(result["native_receipt_semantics_checked"])
        self.assertEqual(result["staged_mutation_count"], "UNRECORDED")
        self.assertEqual(result["native_ms"][gate.RETAINED]["p95"], 0.520076)
        self.assertEqual(result["native_ms"][gate.SEPARATE]["p95"], 1.4441330000000001)
        self.assertEqual(result["php_ms"]["paired_delta_ms"]["p95"], 3.730803)

    def test_nearest_rank_uses_order_statistic_without_interpolation(self):
        self.assertEqual(gate.nearest_rank(list(range(100, 0, -1))),
                         {"p50": 50, "p95": 95, "p99": 99, "max": 100})
        self.assertEqual(gate.nearest_rank([-10, -5, 1]),
                         {"p50": -5, "p95": 1, "p99": 1, "max": 1})

    def test_forged_native_percentile_is_recomputed(self):
        self.reports[gate.RETAINED]["p95_ms"] = 0.01
        self.fails("reported percentile differs")

    def test_self_consistent_replacement_still_differs_from_pinned_observation(self):
        native = self.reports[gate.RETAINED]
        native["samples_ms"] = [1.0] * 1000
        for key in ("p50_ms", "p95_ms", "p99_ms", "max_ms"):
            native[key] = 1.0
        self.fails("differs from pinned observation")

    def test_forged_php_delta_percentile_is_recomputed(self):
        self.reports[gate.PHP]["benchmark"]["paired_delta_ms"]["p95"] = 1.0
        self.fails("reported percentile differs")

    def test_missing_raw_pair_and_missing_pair_arm_fail(self):
        benchmark = self.reports[gate.PHP]["benchmark"]
        benchmark["samples"].pop()
        self.fails("100 complete raw pairs")
        self.reports = copy.deepcopy(self.original)
        del self.reports[gate.PHP]["benchmark"]["samples"][0]["baseline_ms"]
        self.fails("baseline_ms")

    def test_stored_pair_delta_is_recomputed_from_both_arms(self):
        self.reports[gate.PHP]["benchmark"]["samples"][0]["delta_ms"] = 0.0
        self.fails("delta differs from isolated - baseline")

    def test_duplicate_pair_index_or_arm_fails(self):
        sample = self.reports[gate.PHP]["benchmark"]["samples"][1]
        sample["index"] = 0
        self.fails("PHP pair index")
        self.reports = copy.deepcopy(self.original)
        self.reports[gate.PHP]["benchmark"]["samples"][0]["order"] = ["baseline", "baseline"]
        self.fails("order must contain both arms")

    def test_counts_and_warmups_are_required(self):
        for path, key, value in ((gate.RETAINED, "iterations", 999),
                                 (gate.SEPARATE, "warmup", 99)):
            with self.subTest(path=path, key=key):
                self.reports = copy.deepcopy(self.original)
                self.reports[path][key] = value
                self.fails(key)
        for key in ("pairs", "warmup_pairs_excluded"):
            with self.subTest(key=key):
                self.reports = copy.deepcopy(self.original)
                self.reports[gate.PHP]["benchmark"][key] = 0
                self.fails("pair")

    def test_fault_nonzero_mutations_or_duplicate_type_fails(self):
        self.reports[gate.PHP]["fault_injection"][0]["receipt"]["committed_mutations"] = 1
        self.fails("committed mutations")
        self.reports = copy.deepcopy(self.original)
        faults = self.reports[gate.PHP]["fault_injection"]
        faults[1]["fault"] = faults[0]["fault"]
        self.fails("distinct fault types")

    def test_fault_burn_http_and_recovery_are_required(self):
        for location, key, value, pattern in (
            ("entry", "http_status", 200, "HTTP status"),
            ("entry", "subsequent_request", "FAIL", "recovery"),
            ("receipt", "commit_status", "committed", "commit status"),
            ("receipt", "http_status", 200, "HTTP status"),
        ):
            with self.subTest(key=key, location=location):
                self.reports = copy.deepcopy(self.original)
                fault = self.reports[gate.PHP]["fault_injection"][0]
                target = fault if location == "entry" else fault["receipt"]
                target[key] = value
                self.fails(pattern)

    def test_injected_receipts_must_match_ledger(self):
        self.reports[gate.PHP]["fault_injection"][0]["receipt"]["request_id"] = 999
        self.fails("exactly one receipt")

    def test_every_fault_requires_empty_worker_output_and_cleanup_fields(self):
        mutations = (("output", [65]), ("output", ""),
                     ("reaped", False), ("reaped", 1),
                     ("state_eof", False), ("state_eof", 1),
                     ("stdout_eof", False), ("stdout_eof", 1))
        for fault_index in range(5):
            for field, value in mutations:
                with self.subTest(fault_index=fault_index, field=field, value=value):
                    self.reports = copy.deepcopy(self.original)
                    worker = self.reports[gate.PHP]["fault_injection"][fault_index]["receipt"]["worker"]
                    worker[field] = value
                    self.fails("fault worker " + field)

    def test_fault_worker_status_cannot_be_replaced_with_success_even_in_ledger(self):
        for fault_index in range(5):
            with self.subTest(fault_index=fault_index):
                self.reports = copy.deepcopy(self.original)
                fault = self.reports[gate.PHP]["fault_injection"][fault_index]
                request_id = fault["receipt"]["request_id"]
                forged = {"kind": "exited", "code": 0}
                fault["receipt"]["worker"]["status"] = forged.copy()
                for receipt in self.reports[gate.PHP]["receipts"]:
                    if receipt["request_id"] == request_id:
                        receipt["worker"]["status"] = forged.copy()
                self.fails("fault worker status")

    def test_fault_status_fields_require_exact_typed_recorded_values(self):
        for field, value in (("signal", 0), ("kind", "exited"),
                             ("core_dumped", 0), ("extra", "unrecorded")):
            with self.subTest(field=field):
                self.reports = copy.deepcopy(self.original)
                self.reports[gate.PHP]["fault_injection"][0]["receipt"]["worker"]["status"][field] = value
                self.fails("fault worker status")

    def test_hold_and_zero_corruption_are_required(self):
        for path in (gate.PHP, gate.PRECHECK):
            with self.subTest(path=path):
                self.reports = copy.deepcopy(self.original)
                self.reports[path]["production_status"] = "READY"
                self.fails("production_status")
        self.reports = copy.deepcopy(self.original)
        self.reports[gate.PHP]["corrupted_committed_keys"] = 1
        self.fails("corrupted committed keys")

    def test_failed_php_gate_script_exit_and_unrun_are_preserved(self):
        self.reports[gate.PHP]["benchmark"]["p95_under_2ms"] = True
        self.fails("PHP p95 gate")
        for key, value in (("status", "PASS"), ("exit_code", 0)):
            with self.subTest(key=key):
                self.reports = copy.deepcopy(self.original)
                self.reports[gate.PRECHECK]["linux_checks"]["full_reproduce_script"][key] = value
                self.fails("full reproduce script")
        for key in gate.UNRUN:
            with self.subTest(unrun=key):
                self.reports = copy.deepcopy(self.original)
                self.reports[gate.PRECHECK]["linux_checks"][key] = "PASS"
                self.fails("preserved")

    def test_nan_infinite_boolean_and_nonnumeric_samples_fail(self):
        for invalid in (float("nan"), float("inf"), float("-inf"), "0.3", None, True):
            with self.subTest(invalid=invalid):
                self.reports = copy.deepcopy(self.original)
                self.reports[gate.RETAINED]["samples_ms"][0] = invalid
                self.fails("number")
        self.reports = copy.deepcopy(self.original)
        self.reports[gate.PHP]["benchmark"]["samples"][0]["baseline_ms"] = "7.58"
        self.fails("expected a number")

    def test_negative_duration_and_boolean_count_fail(self):
        self.reports[gate.RETAINED]["samples_ms"][0] = -1.0
        self.fails("negative duration")
        self.reports = copy.deepcopy(self.original)
        self.reports[gate.PHP]["corrupted_committed_keys"] = False
        self.fails("corrupted committed keys")

    def test_strict_json_rejects_nan_duplicates_and_overflow(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'{"x":1,"x":2}'):
            with self.subTest(raw=raw), self.assertRaises(gate.EvidenceError):
                gate.decode(raw, "fixture")

    def test_exact_byte_sha256_and_git_blob_pins(self):
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual(manifest["commit"], gate.COMMIT)
        for entry in manifest["files"]:
            with self.subTest(path=entry["path"]):
                data = (BASE / entry["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
                header = b"blob " + str(len(data)).encode("ascii") + b"\0"
                self.assertEqual(hashlib.sha1(header + data).hexdigest(), entry["git_blob_sha"])

    def cli(self, *args):
        completed = subprocess.run([sys.executable, str(BASE / "scripts" / "verify_stored_evidence.py"), *args],
                                   capture_output=True, text=True, check=False)
        self.assertEqual(completed.stderr, "")
        return completed.returncode, json.loads(completed.stdout)

    def test_portable_cli_positive_with_explicit_root_and_manifest(self):
        code, result = self.cli("--root", str(BASE),
                                "--manifest", str(MANIFEST))
        self.assertEqual(code, 0)
        self.assertEqual(result["verdict"], "STORED_EVIDENCE_CONSISTENT")

    def test_cli_rejects_single_byte_change_and_rehashed_substitute_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            for path in gate.PATHS:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(BASE / path, target)
            changed = root / gate.RETAINED
            data = changed.read_bytes().replace(b"0.520076", b"0.520077", 1)
            changed.write_bytes(data)
            code, result = self.cli("--root", str(root))
            self.assertEqual(code, 1)
            self.assertIn("SHA-256", result["error"])
            manifest = json.loads(MANIFEST.read_text())
            for entry in manifest["files"]:
                if entry["path"] == gate.RETAINED:
                    entry["sha256"] = hashlib.sha256(data).hexdigest()
                    entry["git_blob_sha"] = gate.git_blob_hash(data)
            forged = Path(directory) / "forged_manifest.json"
            forged.write_text(json.dumps(manifest, indent=2) + "\n")
            code, result = self.cli("--root", str(root), "--manifest", str(forged))
            self.assertEqual(code, 1)
            self.assertIn("manifest SHA-256 (local pin)", result["error"])

    def test_cli_missing_report_is_nonzero_with_scoped_result(self):
        with tempfile.TemporaryDirectory() as directory:
            code, result = self.cli("--root", directory)
        self.assertEqual(code, 1)
        self.assertEqual(result["verdict"], "STORED_EVIDENCE_INCONSISTENT")
        self.assertFalse(result["runtime_reexecuted"])
        self.assertFalse(result["independent_security_audit"])


if __name__ == "__main__":
    unittest.main()
