#!/usr/bin/env python3
"""Linux integration contract for the bounded, fresh-exec fixture runtime.

Direct invocation exits 77 when prerequisites are unavailable. Importing the
module through unittest on another platform reports an explicit skipped class.
No host services or application containers are contacted or changed.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[1]
SOURCE_FILES = (
    Path(__file__),
    REPO / "tests/ephem/fixture.c",
    REPO / "tests/ephem/build-rootfs.sh",
)
SECRET = b"SECRET_UNCOMMITTED_OUTPUT"
INPUT_LIMIT = OUTPUT_LIMIT = 1048576
OPTIONS = argparse.Namespace(gate=None, jail=None, rootfs=None, report=None,
                             deadline_ms=1000, baseline_samples=50, cgroup_root=None)
OBSERVATIONS: list[dict] = []
PREREGISTRATION: dict = {}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unavailable_reason() -> str | None:
    if platform.system() != "Linux":
        return "Linux namespaces, seccomp, Landlock and /proc are required"
    if os.geteuid() != 0:
        return "the integration suite requires root in a dedicated Linux VM"
    if not Path("/proc/self/status").is_file():
        return "a mounted Linux /proc is required for host PID teardown checks"
    for key in ("gate", "jail"):
        value = getattr(OPTIONS, key)
        if not value or not Path(value).is_file() or not os.access(value, os.X_OK):
            return "missing executable --" + key
    if OPTIONS.rootfs:
        root = Path(OPTIONS.rootfs)
        if not root.is_absolute() or root == Path("/"):
            return "--rootfs must be an absolute dedicated fixture root"
        try:
            marker = (root / ".ephem-test-rootfs").read_text()
        except OSError:
            return "--rootfs lacks the dedicated test root marker"
        if marker != "ephem-test-rootfs-v1\n" or not (root / "worker").is_file():
            return "--rootfs is not the expected dedicated fixture root"
    return None


def http_exchange(path: str, request: bytes, timeout: float = 6.0) -> dict:
    started = time.perf_counter_ns()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(path)
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        received = bytearray()
        while b"\r\n\r\n" not in received:
            chunk = connection.recv(65536)
            if not chunk:
                raise AssertionError("peer closed without a complete HTTP response")
            received.extend(chunk)
            if len(received) > OUTPUT_LIMIT + 65536:
                raise AssertionError("response exceeded the client safety bound")
        header_bytes, body = bytes(received).split(b"\r\n\r\n", 1)
        lines = header_bytes.decode("ascii").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            key, value = line.split(":", 1)
            lower = key.lower()
            if lower in headers:
                raise AssertionError("duplicate response header: " + lower)
            headers[lower] = value.strip()
        if "transfer-encoding" in headers:
            raise AssertionError("fixture protocol requires a bounded Content-Length response")
        length = int(headers.get("content-length", "-1"))
        if length < 0 or length > OUTPUT_LIMIT + 256:
            raise AssertionError("missing or unbounded response Content-Length")
        while len(body) < length:
            chunk = connection.recv(min(65536, length - len(body)))
            if not chunk:
                raise AssertionError("truncated response")
            body += chunk
        if len(body) != length:
            raise AssertionError("response body length mismatch")
    return {"status": status, "headers": headers, "body": body,
            "client_elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000}


def run_request(path: str, body: bytes) -> dict:
    request = (b"POST /run HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n"
               + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    return http_exchange(path, request,
                         max(6.0, OPTIONS.deadline_ms / 1000 * 3 + 2))


def record(label: str, response: dict) -> None:
    OBSERVATIONS.append({
        "probe": label,
        "status": response["status"],
        "headers": response["headers"],
        "response_bytes": len(response["body"]),
        "response_sha256": hashlib.sha256(response["body"]).hexdigest(),
        "client_elapsed_ms": response["client_elapsed_ms"],
    })


class EphemeralLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        reason = unavailable_reason()
        if reason:
            raise unittest.SkipTest("UNAVAILABLE: " + reason)
        # The launcher rejects group/world-writable ancestors, including /tmp.
        # Tests require root in a dedicated VM and own this entire private tree.
        cls.temporary = tempfile.TemporaryDirectory(prefix=".ephem-test-", dir="/root")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.workdir = Path(cls.temporary.name)
        cls.rootfs = Path(OPTIONS.rootfs) if OPTIONS.rootfs else cls.workdir / "rootfs"
        if not OPTIONS.rootfs:
            built = subprocess.run(
                ["sh", str(REPO / "tests/ephem/build-rootfs.sh"), str(cls.rootfs)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            if built.returncode == 77:
                raise unittest.SkipTest("UNAVAILABLE: " + built.stderr.strip())
            if built.returncode:
                raise AssertionError("fixture build failed: " + built.stderr)
        cls.sentinel = (cls.rootfs / "app/sentinel").read_bytes()
        cls.sockpath = str(cls.workdir / "gate.sock")
        cls.log = open(cls.workdir / "gate.log", "w+b")
        cls.addClassCleanup(cls.log.close)
        cls.gate = subprocess.Popen([
            str(Path(OPTIONS.gate).resolve()), "--socket", cls.sockpath,
            "--jail", str(Path(OPTIONS.jail).resolve()), "--root", str(cls.rootfs),
            "--worker", "/worker", "--deadline-ms", str(OPTIONS.deadline_ms),
            "--max-input", str(INPUT_LIMIT), "--max-output", str(OUTPUT_LIMIT),
            "--max-inflight", "4", "--cgroup-root", OPTIONS.cgroup_root],
            stdin=subprocess.DEVNULL, stdout=cls.log, stderr=cls.log,
            start_new_session=True)
        cls.addClassCleanup(cls.stop_owned_gate)
        deadline = time.monotonic() + 5
        while not Path(cls.sockpath).is_socket():
            if cls.gate.poll() is not None or time.monotonic() >= deadline:
                cls.log.seek(0)
                raise AssertionError("gate did not start: " + cls.log.read().decode(errors="replace"))
            time.sleep(0.01)
        PREREGISTRATION["artifact_sha256"] = {
            "gate": sha256_file(Path(OPTIONS.gate)),
            "jail": sha256_file(Path(OPTIONS.jail)),
            "worker": sha256_file(cls.rootfs / "worker"),
        }

    @classmethod
    def stop_owned_gate(cls) -> None:
        if cls.gate.poll() is None:
            os.killpg(cls.gate.pid, signal.SIGTERM)
            try:
                cls.gate.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(cls.gate.pid, signal.SIGKILL)
                cls.gate.wait(timeout=3)
        cls.log.seek(0)
        PREREGISTRATION["gate_log"] = cls.log.read().decode(errors="replace")

    def invoke(self, command: bytes) -> dict:
        response = run_request(self.sockpath, command)
        record(command[:40].decode("ascii", errors="replace"), response)
        return response

    def assert_success(self, response: dict, body: bytes) -> int:
        self.assertEqual(response["status"], 200, response)
        self.assertEqual(response["body"], body)
        headers = response["headers"]
        self.assertEqual(headers.get("x-ephem-output-sha256"), hashlib.sha256(body).hexdigest())
        pid = int(headers["x-ephem-worker-pid"])
        self.assertGreater(pid, 1)
        elapsed = float(headers["x-ephem-elapsed-ms"])
        self.assertGreaterEqual(elapsed, 0)
        self.assertFalse(Path("/proc", str(pid)).exists(),
                         "accepted response preceded worker reaping")
        return pid

    def assert_burned(self, response: dict) -> None:
        self.assertEqual(response["status"], 500, response)
        self.assertNotIn(SECRET, response["body"])
        self.assertLessEqual(len(response["body"]), 256)
        self.assertNotIn("x-ephem-output-sha256", response["headers"])

    def test_01_fifty_fresh_workers_and_trusted_receipts(self) -> None:
        pids = []
        for index in range(50):
            body = ("request-%03d" % index).encode() + b"\x00binary\xff"
            pids.append(self.assert_success(self.invoke(b"ECHO " + body), body))
        self.assertEqual(len(set(pids)), 50, "host worker PID was reused")
        PREREGISTRATION["fifty_host_worker_pids"] = pids

    def test_02_identity_fds_and_capabilities(self) -> None:
        self.assert_success(self.invoke(b"ID"), b"pid=1 uid=65534 gid=65534\n")
        self.assert_success(self.invoke(b"FD"), b"extra_fds=0\n")
        self.assert_success(self.invoke(b"CAP"),
            b"effective=0000000000000000 permitted=0000000000000000 inheritable=0000000000000000\n")

    def test_03_tmp_state_does_not_cross_requests(self) -> None:
        for _ in range(5):
            self.assert_success(self.invoke(b"DIRTY"), b"written\n")
            self.assert_success(self.invoke(b"CLEAN"), b"absent\n")
            self.assert_burned(self.invoke(b"DIRTYCRASH"))
            self.assert_success(self.invoke(b"CLEAN"), b"absent\n")
        self.assertFalse((self.rootfs / "tmp/marker").exists())

    def test_04_crash_output_burn_and_recovery(self) -> None:
        for _ in range(5):
            self.assert_burned(self.invoke(b"CRASH"))
            self.assert_success(self.invoke(b"ECHO recovered"), b"recovered")

    def test_05_seccomp_forbidden_syscalls_burn_output(self) -> None:
        for command in (b"SOCKET", b"FORK", b"EXEC"):
            with self.subTest(command=command):
                self.assert_burned(self.invoke(command))
                self.assert_success(self.invoke(b"ECHO alive"), b"alive")

    def test_06_filesystem_denial_is_not_execution_attestation(self) -> None:
        # Landlock can return errno which an application handles. This positive
        # control prevents falsely equating every denied open with worker death.
        self.assert_success(self.invoke(b"HOSTWRITE"), b"denied\n")
        self.assertEqual((self.rootfs / "app/sentinel").read_bytes(), self.sentinel)

    def test_07_timeout_and_output_limit_burn(self) -> None:
        timed = self.invoke(b"HANG")
        self.assert_burned(timed)
        self.assertLess(timed["client_elapsed_ms"], OPTIONS.deadline_ms + 3000)
        self.assert_burned(self.invoke(b"OUTPUT"))
        self.assert_success(self.invoke(b"ECHO alive"), b"alive")

    def test_08_input_limit_and_malformed_http(self) -> None:
        cases = [
            ("duplicate-length", b"POST /run HTTP/1.1\r\nHost: fixture\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx"),
            ("chunked", b"POST /run HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"),
            ("missing-length", b"POST /run HTTP/1.1\r\nHost: fixture\r\n\r\nx"),
            ("negative-length", b"POST /run HTTP/1.1\r\nHost: fixture\r\nContent-Length: -1\r\n\r\n"),
            ("oversized-length", b"POST /run HTTP/1.1\r\nHost: fixture\r\nContent-Length: 1048577\r\n\r\n"),
            ("truncated-body", b"POST /run HTTP/1.1\r\nHost: fixture\r\nContent-Length: 16\r\n\r\nx"),
            ("header-limit", b"POST /run HTTP/1.1\r\nHost: fixture\r\nX-Large: " + b"a" * 65536 + b"\r\nContent-Length: 0\r\n\r\n"),
        ]
        for label, request in cases:
            with self.subTest(case=label):
                response = http_exchange(self.sockpath, request)
                record(label, response)
                self.assertIn(response["status"], (400, 408, 411, 413, 431, 500))
                self.assertNotIn(SECRET, response["body"])
                self.assertLessEqual(len(response["body"]), 256)
        self.assert_success(self.invoke(b"ECHO alive"), b"alive")

    def test_09_concurrent_requests_have_distinct_workers(self) -> None:
        bodies = [("parallel-%d" % index).encode() for index in range(4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda value: run_request(self.sockpath, b"ECHO " + value), bodies))
        pids = []
        for body, response in zip(bodies, results):
            record("concurrent", response)
            pids.append(self.assert_success(response, body))
        self.assertEqual(len(set(pids)), 4)

    def test_11_resource_oom_burn_and_cleanup(self) -> None:
        self.assert_burned(self.invoke(b"MEMORY"))
        self.assert_success(self.invoke(b"ECHO after-oom"), b"after-oom")
        self.assertEqual(list(Path(OPTIONS.cgroup_root).glob("request-*")), [])

    def test_12_clean_exit_does_not_prevent_response_exfiltration(self) -> None:
        self.assert_success(self.invoke(b"READSECRET"), b"SYNTHETIC_SECRET_VISIBLE_TO_WORKER\n")

    def test_10_raw_cold_exec_and_jail_timings(self) -> None:
        raw_times = []
        jail_times = []
        for _ in range(OPTIONS.baseline_samples):
            start = time.perf_counter_ns()
            baseline = subprocess.run([str(self.rootfs / "worker")], input=b"ECHO baseline",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            raw_times.append((time.perf_counter_ns() - start) / 1_000_000)
            self.assertEqual((baseline.returncode, baseline.stdout), (0, b"baseline"))
            response = self.invoke(b"ECHO baseline")
            self.assert_success(response, b"baseline")
            jail_times.append(response["client_elapsed_ms"])
        PREREGISTRATION["timings"] = {
            "description": "cold fixture exec versus complete UDS HTTP sandbox request; not warmed micro-fork overhead",
            "raw_cold_exec_ms": raw_times,
            "sandbox_request_ms": jail_times,
            "raw_median_ms": statistics.median(raw_times),
            "sandbox_median_ms": statistics.median(jail_times),
            "samples_per_condition": OPTIONS.baseline_samples,
            "performance_gate": "UNSPECIFIED: measurements only",
        }


def main() -> int:
    global OPTIONS, PREREGISTRATION
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", default=str(REPO / "target/release/ephem-gate"))
    parser.add_argument("--jail", default=str(REPO / "target/ephem-jail"))
    parser.add_argument("--rootfs")
    parser.add_argument("--cgroup-root", required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--deadline-ms", type=int, default=1000)
    parser.add_argument("--baseline-samples", type=int, default=50)
    OPTIONS = parser.parse_args()
    if OPTIONS.deadline_ms < 50 or OPTIONS.baseline_samples < 1:
        parser.error("deadline must be >=50 ms and baseline samples must be positive")
    PREREGISTRATION = {
        "schema": "ephem-lifecycle-v1", "platform": platform.platform(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_sha256": {str(path.relative_to(REPO)): sha256_file(path) for path in SOURCE_FILES},
        "contract": {"requests": 50, "deadline_ms": OPTIONS.deadline_ms,
            "max_input": INPUT_LIMIT, "max_output": OUTPUT_LIMIT,
            "max_inflight": 4, "baseline_samples": OPTIONS.baseline_samples},
        "empirical_status": "UNRUN",
    }
    if OPTIONS.report:
        OPTIONS.report.parent.mkdir(parents=True, exist_ok=True)
        # Freeze source hashes and the acceptance contract before any execution.
        frozen = OPTIONS.report.with_suffix(OPTIONS.report.suffix + ".preregistration.json")
        if frozen.exists() or OPTIONS.report.exists():
            parser.error("report and preregistration paths must be new; preserve prior evidence")
        frozen.write_text(json.dumps(PREREGISTRATION, indent=2) + "\n")
    reason = unavailable_reason()
    if reason:
        PREREGISTRATION.update(status="UNAVAILABLE", unavailable_reason=reason,
                               tests_run=0, failures=0, errors=0)
        exit_code = 77
        print("UNAVAILABLE: " + reason, file=sys.stderr)
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(EphemeralLifecycle)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        skipped = len(result.skipped)
        unavailable = result.testsRun == 0 and skipped > 0 and result.wasSuccessful()
        exit_code = 77 if unavailable else (0 if result.wasSuccessful() else 1)
        PREREGISTRATION.update(
            status="UNAVAILABLE" if unavailable else ("PASS" if result.wasSuccessful() else "FAIL"),
            empirical_status="UNRUN" if unavailable else "EXECUTED",
            tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
            skipped=skipped,
            failure_details=[{"test": str(test), "traceback": detail} for test, detail in result.failures],
            error_details=[{"test": str(test), "traceback": detail} for test, detail in result.errors],
            skip_details=[{"test": str(test), "reason": detail} for test, detail in result.skipped])
    PREREGISTRATION["observations"] = OBSERVATIONS
    resource_rows = []
    for line in PREREGISTRATION.get("gate_log", "").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if "resource_scope" in row:
            resource_rows.append(row)
    PREREGISTRATION["resource_disposals"] = resource_rows
    if exit_code == 0:
        resource_ok = (bool(resource_rows)
                       and all(row.get("disposed") is True for row in resource_rows)
                       and any(row.get("oom_kill", 0) > 0 for row in resource_rows))
        PREREGISTRATION["cgroup_oom_and_disposal_verified"] = resource_ok
        if not resource_ok:
            PREREGISTRATION["status"] = "FAIL"
            PREREGISTRATION["resource_error"] = "missing actual kernel OOM/disposal accounting"
            exit_code = 1
    PREREGISTRATION["source_hashes_unchanged"] = all(
        sha256_file(path) == PREREGISTRATION["source_sha256"][str(path.relative_to(REPO))]
        for path in SOURCE_FILES)
    if not PREREGISTRATION["source_hashes_unchanged"]:
        PREREGISTRATION["status"] = "FAIL"
        PREREGISTRATION["source_freeze_error"] = "test source changed after preregistration"
        exit_code = 1
    PREREGISTRATION["exit_code"] = exit_code
    if OPTIONS.report:
        OPTIONS.report.write_text(json.dumps(PREREGISTRATION, indent=2) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
