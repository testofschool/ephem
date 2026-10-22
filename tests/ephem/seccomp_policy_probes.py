#!/usr/bin/env python3
"""Five direct-kernel cases against the actual frozen seccomp BPF source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    frozen = args.report.with_suffix(args.report.suffix + ".preregistration.json")
    if args.report.exists() or frozen.exists():
        parser.error("preserve evidence: report paths must be new")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if platform.system() != "Linux" or os.geteuid() != 0:
        args.report.write_text(json.dumps({"status": "UNAVAILABLE", "exit_code": 77}) + "\n")
        return 77
    sources = [Path(__file__), ROOT / "tests/ephem/seccomp_probe.c",
               ROOT / "bpf/worker_containment.bpf.c", ROOT / "bpf/worker_containment.h"]
    cases = {"peer0": (0, "ENOTSOCK"), "peer1": (-signal.SIGSYS, "SIGSYS"),
             "vma0": (0, "EINVAL"), "vma-high": (-signal.SIGSYS, "SIGSYS"),
             "dumpable": (-signal.SIGSYS, "SIGSYS")}
    with tempfile.TemporaryDirectory(prefix=".ephem-policy-", dir="/root") as directory:
        binary = Path(directory) / "seccomp-probe"
        command = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
                   "-I" + str(ROOT / "bpf"), str(ROOT / "tests/ephem/seccomp_probe.c"),
                   str(ROOT / "bpf/worker_containment.bpf.c"), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, timeout=30)
        if compiled.returncode:
            args.report.write_text(json.dumps({"status": "FAIL", "compile_command": command,
                "compile_stderr": compiled.stderr.decode(errors="replace"), "exit_code": 1}, indent=2) + "\n")
            return 1
        registration = {"source_sha256": {str(p): digest(p) for p in sources},
            "binary_sha256": digest(binary), "compile_command": command,
            "expected": {name: {"returncode": value[0], "meaning": value[1]}
                         for name, value in cases.items()},
            "scope": "same-VM direct seccomp kernel probes; no external audit or generic correctness claim"}
        frozen.write_text(json.dumps(registration, indent=2) + "\n")
        report = {"platform": platform.platform(), "observations": [],
                  "preregistration_sha256": digest(frozen)}
        for name, expected in cases.items():
            started = time.perf_counter_ns()
            result = subprocess.run([str(binary), name], input=b"", capture_output=True, timeout=3)
            report["observations"].append({"argv": [str(binary), name], "probe": name,
                "returncode": result.returncode, "expected_returncode": expected[0],
                "stdout": result.stdout.decode(errors="replace"),
                "stderr": result.stderr.decode(errors="replace"),
                "elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000,
                "status": "PASS" if result.returncode == expected[0] else "FAIL"})
        report["frozen_sources_unchanged"] = all(digest(p) == registration["source_sha256"][str(p)] for p in sources)
        report["binary_unchanged"] = digest(binary) == registration["binary_sha256"]
        passed = all(row["status"] == "PASS" for row in report["observations"])
        report["status"] = "PASS" if passed and report["frozen_sources_unchanged"] and report["binary_unchanged"] else "FAIL"
        report["exit_code"] = 0 if report["status"] == "PASS" else 1
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
