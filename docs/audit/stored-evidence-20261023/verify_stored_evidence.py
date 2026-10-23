#!/usr/bin/env python3
"""Check a pinned, stored report snapshot; Python 3 standard library only.

Trust boundary: this gate and its manifest digest are the local pins. The Git
blob identifiers came from research/ephem_next/source_index.json; SHA-256 and
size use the exact copied bytes. No network, runtime execution, source-code
analysis, or inference from report prose occurs. Passing means consistency of
these stored reports, not independent verification of the recorded events.
"""

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys


COMMIT = "1320713d065f04ae701026e14edf46226e71af6d"
MANIFEST_SHA256 = "247a28850da9e685e8e2bd2149f7e312b158bd41110253f0fef9707951f5d34f"
RETAINED = "reports/phase3/release-alignment-final/warm-native.json"
SEPARATE = "reports/phase3/remote-sync-run/warm-native.json"
PHP = "reports/phase3/remote-sync-run/stateful-verification.json"
PRECHECK = "reports/phase3/REMOTE_SYNC_PRECHECK.json"
PATHS = {RETAINED, SEPARATE, PHP, PRECHECK}
EXPECTED_STATS = {
    RETAINED: {"p50": 0.408537, "p95": 0.520076,
               "p99": 0.5900340000000001, "max": 0.9285720000000001},
    SEPARATE: {"p50": 0.610938, "p95": 1.4441330000000001,
               "p99": 2.111405, "max": 3.505912},
    "php_baseline": {"p50": 10.570422, "p95": 29.886462,
                     "p99": 86.668419, "max": 135.541051},
    "php_isolated": {"p50": 7.364921, "p95": 18.569558,
                     "p99": 37.198239, "max": 37.509707},
    "php_delta": {"p50": -3.080839, "p95": 3.730803,
                  "p99": 12.478680999999998, "max": 14.267237999999999},
}
UNRUN = {
    "native_stage_within_full_script": "UNRUN: script stopped after the PHP latency gate",
    "postgres_live_or_paused_backend": "UNRUN in remote sync; retained original evidence only",
    "bpf_lsm": "UNRUN in remote sync; retained exit77 only",
    "x86_64_phase3_lifecycle": "UNRUN locally; legacy public x86 checks are separate",
}
FAULT_STATUSES = {
    "segv": {"core_dumped": False, "kind": "signaled", "signal": 11},
    "syscall": {"core_dumped": False, "kind": "signaled", "signal": 31},
    "exit": {"code": 73, "kind": "exited"},
    "timeout": {"kind": "timed_out"},
    "verifier": {"kind": "verifier_failed", "message": "unsupported command or arity"},
}


class EvidenceError(ValueError):
    """A pin or report consistency check failed."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def equal(actual, expected, label):
    # bool is not accepted as an integer, despite Python's bool subclassing int.
    require(type(actual) is type(expected) and actual == expected,
            "{}: expected {!r}, got {!r}".format(label, expected, actual))


def number(value, label, nonnegative=False):
    require(type(value) in (int, float), label + ": expected a number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    require(finite, label + ": expected a finite number")
    require(not nonnegative or value >= 0, label + ": negative duration")
    return value


def reject_nonfinite(value, label):
    if isinstance(value, dict):
        for key, item in value.items():
            reject_nonfinite(item, label + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_nonfinite(item, "{}[{}]".format(label, index))
    elif type(value) is float:
        number(value, label)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise EvidenceError("invalid JSON numeric constant: " + value)


def decode(data, label):
    result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                        parse_constant=_invalid_constant)
    require(type(result) is dict, label + ": expected JSON object")
    reject_nonfinite(result, label)
    return result


def git_blob_hash(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def read_pinned_reports(root, manifest_path):
    manifest_bytes = manifest_path.read_bytes()
    equal(hashlib.sha256(manifest_bytes).hexdigest(), MANIFEST_SHA256,
          "manifest SHA-256 (local pin)")
    manifest = decode(manifest_bytes, "manifest")
    equal(manifest["schema"], "ephem.stored-evidence-manifest.v1", "manifest schema")
    equal(manifest["commit"], COMMIT, "manifest commit")
    entries = manifest["files"]
    require(type(entries) is list and len(entries) == 4, "manifest must contain four reports")
    require({entry["path"] for entry in entries} == PATHS, "manifest report paths differ")
    reports = {}
    for entry in entries:
        path = entry["path"]
        data = (root / path).read_bytes()
        equal(len(data), entry["size_bytes"], path + " byte count")
        equal(hashlib.sha256(data).hexdigest(), entry["sha256"], path + " SHA-256")
        equal(git_blob_hash(data), entry["git_blob_sha"], path + " Git blob SHA-1")
        reports[path] = decode(data, path)
    return reports


def nearest_rank(samples):
    """ceil(percentile * n / 100), one-based; no interpolation."""
    require(type(samples) is list and samples, "samples must be a nonempty list")
    ordered = sorted(number(value, "sample") for value in samples)
    n = len(ordered)
    result = {"p" + str(p): ordered[(p * n + 99) // 100 - 1] for p in (50, 95, 99)}
    result["max"] = ordered[-1]
    return result


def match_stats(reported, computed, pinned, label, suffix=""):
    for key, value in computed.items():
        actual = number(reported[key + suffix], label + "." + key + suffix)
        require(actual == value, label + "." + key + ": reported percentile differs from raw samples")
        require(value == pinned[key], label + "." + key + ": differs from pinned observation")


def validate_reports(reports):
    """Semantic checks on decoded reports; call read_pinned_reports first for authenticity pins."""
    require(set(reports) == PATHS, "expected exactly four reports")
    for path, report in reports.items():
        reject_nonfinite(report, path)
    native_stats = {}
    for path in (RETAINED, SEPARATE):
        report = reports[path]
        equal(report["benchmark"], "warm_native_fork_state_ipc_output_eof_reap", path + " benchmark")
        equal(report["iterations"], 1000, path + " iterations")
        equal(report["warmup"], 100, path + " warmup")
        samples = report["samples_ms"]
        require(type(samples) is list and len(samples) == 1000, path + ": need 1000 raw samples")
        for sample in samples:
            number(sample, path + " sample", nonnegative=True)
        stats = nearest_rank(samples)
        match_stats(report, stats, EXPECTED_STATS[path], path, suffix="_ms")
        equal(report["p95_below_2ms"], stats["p95"] < 2, path + " p95 gate")
        require(type(report["lifecycle_checks"]) is list and len(report["lifecycle_checks"]) == 13,
                path + ": expected 13 recorded lifecycle checks")
        native_stats[path] = stats

    php = reports[PHP]
    precheck = reports[PRECHECK]
    equal(php["schema"], "ephem.phase3.stateful-isolation.v1", "PHP schema")
    equal(precheck["schema"], "ephem.phase3.remote-sync-precheck.v1", "PRECHECK schema")
    for label, report in (("PHP", php), ("PRECHECK", precheck)):
        equal(report["production_status"], "HOLD", label + " production_status")
    equal(php["functional_status"], "PASS", "recorded PHP functional status")
    equal(php["consecutive_clean_requests"], 100, "clean requests")
    equal(php["corrupted_committed_keys"], 0, "corrupted committed keys")
    benchmark = php["benchmark"]
    equal(benchmark["pairs"], 100, "PHP pair count")
    equal(benchmark["warmup_pairs_excluded"], 20, "PHP excluded warmup pairs")
    samples = benchmark["samples"]
    require(type(samples) is list and len(samples) == 100, "PHP: need 100 complete raw pairs")
    baseline, isolated, deltas = [], [], []
    for index, sample in enumerate(samples):
        equal(sample["index"], index, "PHP pair index")
        require(sample["order"] in (["baseline", "isolated"], ["isolated", "baseline"]),
                "PHP pair order must contain both arms")
        base = number(sample["baseline_ms"], "PHP baseline", nonnegative=True)
        contained = number(sample["isolated_ms"], "PHP isolated", nonnegative=True)
        delta = contained - base
        require(number(sample["delta_ms"], "PHP pair delta") == delta,
                "PHP pair delta differs from isolated - baseline")
        baseline.append(base)
        isolated.append(contained)
        deltas.append(delta)
    php_stats = {}
    for name, values, expected in (("baseline_ms", baseline, "php_baseline"),
                                   ("isolated_ms", isolated, "php_isolated"),
                                   ("paired_delta_ms", deltas, "php_delta")):
        computed = nearest_rank(values)
        match_stats(benchmark[name], computed, EXPECTED_STATS[expected], "PHP " + name)
        php_stats[name] = computed
    equal(benchmark["p95_under_2ms"], False, "recorded PHP p95 gate")
    require(php_stats["paired_delta_ms"]["p95"] >= 2, "PHP p95 failure must remain a failure")

    faults = php["fault_injection"]
    require(type(faults) is list and len(faults) == 5, "expected five recorded faults")
    require({fault["fault"] for fault in faults} == {"segv", "syscall", "exit", "timeout", "verifier"},
            "expected five distinct fault types")
    receipts = php["receipts"]
    require(type(receipts) is list, "receipts must be a list")
    for fault in faults:
        equal(fault["http_status"], 500, "fault HTTP status")
        equal(fault["subsequent_request"], "PASS", "recorded fault recovery")
        receipt = fault["receipt"]
        equal(receipt["commit_status"], "burned", "fault commit status")
        equal(receipt["committed_mutations"], 0, "fault committed mutations")
        equal(receipt["http_status"], 500, "fault receipt HTTP status")
        worker = receipt["worker"]
        equal(worker["output"], [], "fault worker output")
        for field in ("reaped", "state_eof", "stdout_eof"):
            equal(worker[field], True, "fault worker " + field)
        status = worker["status"]
        expected_status = FAULT_STATUSES[fault["fault"]]
        require(type(status) is dict and set(status) == set(expected_status),
                "fault worker status fields differ from recorded fault type")
        for field, value in expected_status.items():
            equal(status[field], value, "fault worker status " + field)
        matching = [r for r in receipts if r["request_id"] == receipt["request_id"]]
        require(matching == [receipt], "fault receipt must match exactly one receipt in recorded ledger")
    for receipt in receipts:
        if receipt["commit_status"] == "burned":
            equal(receipt["committed_mutations"], 0, "burned ledger committed mutations")

    linux = precheck["linux_checks"]
    full_script = linux["full_reproduce_script"]
    equal(full_script["status"], "FAIL", "full reproduce script status")
    equal(full_script["exit_code"], 1, "full reproduce script exit code")
    # Literal status fields are preserved; their prose is not interpreted as proof.
    equal(full_script["stopped_at"], "PHP paired latency p95 gate", "full script stopped_at")
    for key, value in UNRUN.items():
        equal(linux[key], value, "preserved " + key)
    separate = linux["native_separate_command"]
    equal(separate["status"], "PASS", "separate native status")
    equal(separate["exit_code"], 0, "separate native exit code")
    equal(separate["iterations"], 1000, "PRECHECK native iterations")
    equal(separate["warmup"], 100, "PRECHECK native warmup")
    match_stats(separate["latency_ms"], native_stats[SEPARATE], EXPECTED_STATS[SEPARATE],
                "PRECHECK native", suffix="_ms")
    sqlite = linux["sqlite_php"]
    equal(sqlite["functional_status"], "PASS", "PRECHECK PHP functional status")
    equal(sqlite["clean_requests"], 100, "PRECHECK clean requests")
    equal(sqlite["fault_cases"], 5, "PRECHECK fault count")
    equal(sqlite["corrupted_committed_keys"], 0, "PRECHECK corrupted keys")
    equal(sqlite["paired_p95_gate"], "FAIL: p95 3.730803ms is not <2ms", "PRECHECK PHP p95 status")
    for name, source_name, expected in (("baseline_ms", "baseline_ms", "php_baseline"),
                                       ("contained_ms", "isolated_ms", "php_isolated"),
                                       ("paired_delta_ms", "paired_delta_ms", "php_delta")):
        match_stats(sqlite[name], php_stats[source_name], EXPECTED_STATS[expected], "PRECHECK " + name)
    return {
        "verdict": "STORED_EVIDENCE_CONSISTENT",
        "commit": COMMIT,
        "runtime_reexecuted": False,
        "independent_security_audit": False,
        "production_status": "HOLD",
        "native_ms": native_stats,
        "php_ms": php_stats,
        "php_p95_gate": "FAIL",
        "full_reproduce_script_exit_code": 1,
        "recorded_faults_checked": 5,
        "fault_worker_output_and_cleanup_fields_checked": True,
        "fault_worker_status_fields_checked": True,
        "native_receipt_semantics_checked": False,
        "fault_committed_mutations": 0,
        "staged_mutation_count": "UNRECORDED",
        "unrun_statuses_preserved": UNRUN,
        "scope": "Pinned report bytes, recorded outcomes, and arithmetic consistency only",
    }


def main(argv=None):
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=here / "evidence", help="root of copied report paths")
    parser.add_argument("--manifest", type=Path, default=here / "evidence_manifest.json",
                        help="manifest file; exact bytes must match the built-in SHA-256 pin")
    args = parser.parse_args(argv)
    try:
        result = validate_reports(read_pinned_reports(args.root, args.manifest))
    except (EvidenceError, OSError, UnicodeError, ValueError, KeyError, TypeError, IndexError) as error:
        result = {"verdict": "STORED_EVIDENCE_INCONSISTENT", "error": str(error),
                  "runtime_reexecuted": False, "independent_security_audit": False,
                  "production_status": "HOLD"}
        print(json.dumps(result, indent=2, allow_nan=False))
        return 1
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
