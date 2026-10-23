#!/usr/bin/env python3
"""Real Linux/PHP COW integration and paired latency evidence, with raw samples.

Run as root in an isolated test VM. No synthetic latency or skipped platform
check is counted as PASS. The baseline is explicitly an uncontained Python
supervisor, so its delta is not a universal PHP-FPM switching-cost claim.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def percentile(samples, p):
    require(bool(samples), "no samples")
    return sorted(samples)[max(0, math.ceil(len(samples) * p) - 1)]


def summary(samples):
    return {"p50": percentile(samples, .50), "p95": percentile(samples, .95),
            "p99": percentile(samples, .99), "max": max(samples)}


def wait_socket(path, process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        require(process.poll() is None, f"server exited {process.returncode}; see server logs")
        if path.exists():
            return
        time.sleep(.01)
    raise AssertionError(f"server did not bind {path}")


def request(path, identifier, fault=None):
    body = json.dumps({"id": identifier}, separators=(",", ":")).encode()
    headers = f"POST /run HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body)}\r\n"
    if fault:
        headers += f"X-Ephem-Fault: {fault}\r\n"
    wire = headers.encode() + b"\r\n" + body
    started = time.perf_counter_ns()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(path))
        client.sendall(wire)
        response = bytearray()
        while True:
            data = client.recv(65536)
            if not data:
                break
            response += data
            require(len(response) <= 2_000_000, "response limit")
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    header, payload = bytes(response).split(b"\r\n\r\n", 1)
    lines = header.decode("ascii").split("\r\n")
    status = int(lines[0].split()[1])
    sizes = [int(line.split(":", 1)[1]) for line in lines[1:] if line.lower().startswith("content-length:")]
    require(len(sizes) == 1 and len(payload) == sizes[0], "incomplete/ambiguous response")
    if status == 200:
        require(json.loads(payload) == {"id": identifier, "ok": True}, "application response mismatch")
    else:
        require(b'"ok":true' not in payload and b'"ok": true' not in payload, "worker output escaped quarantine")
    return status, elapsed


def rows(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
        return {bytes(key).decode(): bytes(value).decode() for key, value in
                connection.execute("SELECT key,value FROM ephem_kv WHERE value IS NOT NULL")}


def receipt_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def run(args, report):
    fixture = ROOT / "tests/fixtures/phase3/application.php"
    original = hashlib.sha256(fixture.read_bytes()).hexdigest()
    report["application_sha256_before"] = original
    report["environment"] = {"kernel": platform.release(), "machine": platform.machine(),
                             "python": platform.python_version()}
    with tempfile.TemporaryDirectory(prefix="ephem-stateful-") as temp_name:
        temp = Path(temp_name)
        rootfs = temp / "rootfs"
        (rootfs / "app").mkdir(parents=True)
        (rootfs / "app/application.php").write_bytes(fixture.read_bytes())
        rootfs.chmod(0o755)
        (rootfs / "app").chmod(0o755)
        (rootfs / "app/application.php").chmod(0o644)
        gate_socket, gate_db = temp / "gate.sock", temp / "gate.sqlite"
        base_socket, base_db = temp / "base.sock", temp / "base.sqlite"
        receipts = temp / "receipts.jsonl"
        processes = []
        logs = []
        try:
            commands = [
                [str(args.binary.resolve()), "--socket", str(gate_socket), "--root", str(rootfs),
                 "--database", str(gate_db), "--adapter", str(args.adapter.resolve()),
                 "--bootstrap", str(ROOT / "runtime/phase3/bootstrap.php"),
                 "--receipts", str(receipts), "--deadline-ms", "200", "--allow-fault-injection"],
                [sys.executable, str(ROOT / "runtime/phase3/baseline.py"),
                 "--socket", str(base_socket), "--database", str(base_db),
                 "--adapter", str(args.adapter.resolve()), "--bootstrap", str(ROOT / "runtime/phase3/bootstrap.php"),
                 "--application", str(fixture)],
            ]
            for index, command in enumerate(commands):
                log_path = args.output.parent / f"{args.output.stem}.server-{index}.log"
                log = log_path.open("wb")
                logs.append(log)
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True,
                                           env={"PATH": "/usr/bin:/bin"})
                processes.append(process)
                wait_socket([gate_socket, base_socket][index], process)
            report["server_commands"] = commands
            for i in range(100):
                require(request(gate_socket, f"clean-{i:03}")[0] == 200, f"clean request {i} failed")
            clean_rows = rows(gate_db)
            require(len(clean_rows) == 200, "100 clean requests must commit exactly 200 keys")
            report["consecutive_clean_requests"] = 100
            report["clean_committed_keys"] = len(clean_rows)
            faults = []
            for fault in ("segv", "syscall", "exit", "timeout", "verifier"):
                before = rows(gate_db)
                status, elapsed = request(gate_socket, f"corrupt-{fault}", fault)
                require(status == 500, f"{fault} did not fail closed")
                require(rows(gate_db) == before, f"{fault} changed persistent state")
                observed = receipt_lines(receipts)[-1]
                require(observed["committed_mutations"] == 0, f"{fault} receipt committed")
                if fault == "segv":
                    require(observed.get("worker", {}).get("status", {}).get("signal") == signal.SIGSEGV,
                            "deliberate memory fault must be SIGSEGV")
                if fault == "syscall":
                    require(observed.get("worker", {}).get("status", {}).get("signal") == signal.SIGSYS,
                            "forbidden socket must be killed by seccomp")
                require(request(gate_socket, f"recover-{fault}")[0] == 200, f"recovery failed after {fault}")
                faults.append({"fault": fault, "http_status": status, "elapsed_ms": elapsed,
                               "receipt": observed, "subsequent_request": "PASS"})
            report["fault_injection"] = faults
            # Incomplete declared input provides a deterministic admission barrier:
            # no application can start before this client disconnects.
            identifier = "disconnect-before-state"
            body = json.dumps({"id": identifier}).encode()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(gate_socket))
                client.sendall(f"POST /run HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len(body) + 1}\r\n\r\n".encode() + body)
            time.sleep(.25)
            require(f"row:{identifier}" not in rows(gate_db), "observed precommit disconnect changed state")
            require(request(gate_socket, "recover-disconnect")[0] == 200, "disconnect recovery failed")
            report["admission_disconnect"] = "PASS"
            # Per-byte activity must not extend the absolute admission deadline.
            started = time.monotonic()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(str(gate_socket))
                client.sendall(b"P")
                time.sleep(.12)
                client.sendall(b"O")
                response = client.recv(4096)
            require(b" 500 " in response, "slow header did not burn")
            require(time.monotonic() - started < 1, "activity extended total deadline")
            report["absolute_admission_deadline"] = "PASS"
            require(request(gate_socket, "recover-header")[0] == 200, "deadline recovery failed")
            samples = []
            rng = random.Random(20261023)
            for i in range(args.warmup + args.pairs):
                order = ["baseline", "isolated"]
                rng.shuffle(order)
                sample = {"index": i - args.warmup, "order": order}
                for variant in order:
                    path = base_socket if variant == "baseline" else gate_socket
                    status, elapsed = request(path, f"bench-{i:04}")
                    require(status == 200, f"{variant} benchmark request failed")
                    sample[variant + "_ms"] = elapsed
                sample["delta_ms"] = sample["isolated_ms"] - sample["baseline_ms"]
                if i >= args.warmup:
                    samples.append(sample)
            report["benchmark"] = {
                "pairs": args.pairs, "warmup_pairs_excluded": args.warmup,
                "order_seed": 20261023, "percentiles": "nearest rank; signed paired deltas",
                "event": "UDS HTTP connect through complete response EOF, identical warmed PHP script and two-key SQLite atomic transaction",
                "baseline_limit": "uncontained Python supervisor opens SQLite connection per request; Rust gate retains its connection; not stock PHP-FPM",
                "baseline_ms": summary([x["baseline_ms"] for x in samples]),
                "isolated_ms": summary([x["isolated_ms"] for x in samples]),
                "paired_delta_ms": summary([x["delta_ms"] for x in samples]),
                "samples": samples,
            }
            report["benchmark"]["p95_under_2ms"] = report["benchmark"]["paired_delta_ms"]["p95"] < 2.0
            report["universal_2ms_target"] = "UNVERIFIED: baseline supervisor/connection policy differs; stock PHP-FPM/Node/WSGI not measured"
            all_receipts = receipt_lines(receipts)
            workers = [r["worker"] for r in all_receipts if "worker" in r]
            pids = [w["worker_pid"] for w in workers]
            require(len(pids) == len(set(pids)), "worker PID reused within bounded run")
            require(all(w["reaped"] for w in workers), "unreaped worker")
            report["worker_receipts"] = workers
            report["unique_worker_pids"] = len(set(pids))
            final_rows = rows(gate_db)
            corrupted = [key for key in final_rows if "corrupt-" in key]
            require(not corrupted, "corrupted keys persisted")
            report["corrupted_committed_keys"] = len(corrupted)
            report["final_committed_keys"] = len(final_rows)
            report["application_sha256_inside_rootfs"] = hashlib.sha256((rootfs / "app/application.php").read_bytes()).hexdigest()
            require(report["application_sha256_inside_rootfs"] == original, "fixture changed in rootfs")
            report["functional_status"] = "PASS"
            report["receipts"] = all_receipts
        finally:
            if receipts.exists():
                retained = args.output.with_suffix('.receipts.jsonl')
                retained.write_bytes(receipts.read_bytes())
                report['receipt_file'] = str(retained)
            for process in processes:
                stop(process)
            for log in logs:
                log.close()
    report["application_sha256_after"] = hashlib.sha256(fixture.read_bytes()).hexdigest()
    require(report["application_sha256_after"] == original, "original application changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/ephem-stateful")
    parser.add_argument("--adapter", type=Path, default=ROOT / "target/phase3/libephem_php.so")
    parser.add_argument("--output", type=Path, default=ROOT / "reports/phase3/stateful-isolation.json")
    parser.add_argument("--pairs", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--require-p95", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print("UNRUN: requires root in a dedicated Linux VM", file=sys.stderr)
        return 77
    require(args.pairs >= 100 and args.warmup >= 0, "at least 100 measured pairs required")
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    require(not args.output.exists(), "refusing to overwrite retained evidence")
    report = {"schema": "ephem.phase3.stateful-isolation.v1", "functional_status": "FAIL",
              "production_status": "HOLD", "memory_claim": "signals detected; silent corruption on exit0 not detectable"}
    try:
        run(args, report)
    except Exception as error:
        report["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k in (
            "functional_status", "failure", "consecutive_clean_requests", "corrupted_committed_keys", "unique_worker_pids")}))
    print(json.dumps({k: v for k, v in report["benchmark"].items() if k != "samples"}, indent=2))
    return 0 if not args.require_p95 or report["benchmark"]["p95_under_2ms"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
