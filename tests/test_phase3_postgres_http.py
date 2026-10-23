#!/usr/bin/env python3
"""Real PostgreSQL/PHP HTTP integration in an isolated root Linux test VM.

This checks 100 clean requests, five real worker failure modes, and recovery.
It records no performance acceptance claim. The PostgreSQL cluster must have
been created specifically for this run with no TCP listener and a private UDS.
Only that explicitly supplied temporary cluster is stopped by this runner.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time

from test_stateful_isolation import request, require, stop, wait_socket

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receipts(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def query(args, dsn, statement):
    environment = {"PATH": "/usr/bin:/bin", "LD_LIBRARY_PATH": str(
        args.psql.resolve().parents[4] / "lib" / f"{platform.machine()}-linux-gnu")}
    # Connection strings are never placed in command arguments or report logs.
    environment["PGHOST"] = str(args.postgres_socket.resolve())
    environment["PGPORT"] = str(args.port)
    environment["PGUSER"] = "ephem"
    environment["PGDATABASE"] = "ephem"
    environment["PGCONNECT_TIMEOUT"] = "2"
    result = subprocess.run([str(args.psql), "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                             "-c", statement], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=environment, timeout=5, check=False)
    require(result.returncode == 0, "private PostgreSQL query failed: " + result.stderr.decode(errors="replace"))
    return result.stdout.decode().strip()


def rows(args, dsn):
    return json.loads(query(args, dsn,
        "SELECT COALESCE(jsonb_object_agg(convert_from(key,'UTF8'),convert_from(value,'UTF8')), '{}'::jsonb)::text "
        "FROM public.ephem_kv WHERE value IS NOT NULL"))


def assert_clean(receipt):
    require(receipt["http_status"] == 200, "clean receipt is not HTTP 200")
    require(receipt["commit_status"] == "committed", "clean commit status missing")
    require(receipt["committed_mutations"] == 2, "clean request must commit exactly two mutations")
    worker = receipt["worker"]
    require(worker["status"] == {"kind": "exited", "code": 0}, "clean worker did not exit zero")
    require(worker["reaped"] and worker["stdout_eof"] and worker["state_eof"], "incomplete clean worker lifecycle")


def stalled_backend_probe(args, dsn, address, receipt_path, command, process, temp, report):
    before = rows(args, dsn)
    identities = query(args, dsn, "SELECT pid::text FROM pg_stat_activity "
        "WHERE application_name='ephem-attestation' AND datname=current_database()").splitlines()
    require(len(identities) == 1, "expected one dedicated gate PostgreSQL actor connection")
    pid = int(identities[0])
    identity = Path(f"/proc/{pid}/stat").read_text()
    start_ticks = identity.rsplit(")", 1)[1].split()[19]
    pidfd = os.pidfd_open(pid)
    observed = []
    try:
        # A pidfd addresses this exact owned test backend generation. Pausing
        # the postmaster alone would not pause the per-connection query worker.
        signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
        for identifier in ("pg-corrupt-backend-stall", "pg-corrupt-quarantined"):
            status, elapsed = request(address, identifier)
            require(status == 500 and elapsed < 1000, "stalled PostgreSQL read did not return bounded HTTP 500")
            receipt = receipts(receipt_path)[-1]
            require(receipt["commit_status"] == "burned" and receipt["committed_mutations"] == 0,
                    "read timeout must have a known zero commit")
            require(receipt["worker"]["reaped"], "stalled read generation not reaped")
            observed.append({"identifier": identifier, "http_status": status,
                             "elapsed_ms": elapsed, "receipt": receipt})
    finally:
        signal.pidfd_send_signal(pidfd, signal.SIGCONT)
        os.close(pidfd)
    require(rows(args, dsn) == before, "stalled/quarantined backend changed PostgreSQL state")
    report["postgres_read_transport_deadline"] = {"status": "PASS", "paused_backend_pid": pid,
        "backend_start_ticks": start_ticks, "identity_mechanism": "pidfd SIGSTOP/SIGCONT",
        "attempts": observed, "automatic_reconnect": False}
    stop(process)
    recovery_address, recovery_receipt = temp / "recovery.sock", temp / "recovery-receipts.jsonl"
    recovery_command = command.copy()
    recovery_command[recovery_command.index("--socket") + 1] = str(recovery_address)
    recovery_command[recovery_command.index("--receipts") + 1] = str(recovery_receipt)
    report["backend_restart_server_command"] = recovery_command
    recovery_log = args.output.with_suffix(".recovery.server.log")
    with recovery_log.open("xb") as log:
        recovery_process = subprocess.Popen(recovery_command, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True, env={"PATH": "/usr/bin:/bin"})
        try:
            wait_socket(recovery_address, recovery_process)
            require(request(recovery_address, "pg-recover-backend-restart")[0] == 200,
                    "explicit daemon/backend restart did not recover")
            assert_clean(receipts(recovery_receipt)[-1])
            report["postgres_read_transport_deadline"]["explicit_restart_recovery"] = "PASS"
        finally:
            stop(recovery_process)
            if recovery_receipt.exists():
                retained = args.output.with_suffix(".recovery.receipts.jsonl")
                retained.write_bytes(recovery_receipt.read_bytes())
                report["backend_restart_receipt_file"] = str(retained)
    return receipts(receipt_path) + receipts(recovery_receipt)


def stop_private_postgres(args, report):
    data = args.pg_data.resolve()
    parent = data.parent
    require(parent.parent == Path("/tmp") and parent.name.startswith("ephem-pg-phase3.")
            and data.name == "data", "refusing to stop a cluster outside the dedicated temporary test prefix")
    require(args.postgres_socket.resolve() == parent / "socket", "private cluster/socket identity mismatch")
    stat = data.stat()
    require(stat.st_uid != 0 and stat.st_mode & 0o077 == 0, "private cluster must be nonroot-owned and mode 0700")
    pid_file = data / "postmaster.pid"
    require(pid_file.is_file(), "private PostgreSQL postmaster identity missing")
    pid = int(pid_file.read_text().splitlines()[0])
    command_line = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    require(os.fsencode(data) in command_line and Path(f"/proc/{pid}").stat().st_uid == stat.st_uid,
            "postmaster PID/command/owner identity mismatch")
    report["private_cluster_cleanup"] = {"postmaster_pid": pid, "data": str(data),
                                         "owner_uid": stat.st_uid, "status": "STOPPING"}
    command = ["/usr/bin/setpriv", "--reuid", str(stat.st_uid), "--regid", str(stat.st_gid),
               "--init-groups", str(args.pg_ctl), "-D", str(data), "-m", "fast", "-w", "stop"]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=10, check=False)
    report["private_cluster_cleanup"].update(returncode=result.returncode,
        output=result.stdout.decode(errors="replace"))
    require(result.returncode == 0 and not pid_file.exists(), "private PostgreSQL stop failed")
    report["private_cluster_cleanup"]["status"] = "PASS"


def run(args, report):
    fixture = ROOT / "tests/fixtures/phase3/application.php"
    report["application_sha256_before"] = sha256(fixture)
    report["bootstrap_sha256"] = sha256(ROOT / "runtime/phase3/bootstrap.php")
    report["adapter_sha256"] = sha256(args.adapter)
    report["binary_sha256"] = sha256(args.binary)
    report["environment"] = {"kernel": platform.release(), "machine": platform.machine(),
                             "python": platform.python_version()}
    # The private test cluster has no credentials to expose, but use the same
    # root-owned 0600 DSN-file handoff required for credential-bearing configs.
    dsn = f"host={args.postgres_socket.resolve()} port={args.port} user=ephem dbname=ephem"
    require(" " not in str(args.postgres_socket), "test socket path cannot contain spaces")
    report["postgres_version"] = query(args, dsn, "SELECT version()")
    report["postgres_listen_addresses"] = query(args, dsn, "SHOW listen_addresses")
    require(report["postgres_listen_addresses"] == "", "private cluster must have no TCP listeners")
    # Never truncate an arbitrary database. The newly created dedicated cluster
    # must already be empty after the separate adapter fixture cleaned its keys.
    require(query(args, dsn, "SELECT count(*) FROM public.ephem_kv") == "0", "dedicated PostgreSQL table is not empty")
    report["initial_rows"] = {}
    with tempfile.TemporaryDirectory(prefix="ephem-pg-http-") as directory:
        temp = Path(directory)
        rootfs = temp / "rootfs"
        (rootfs / "app").mkdir(parents=True)
        application = rootfs / "app/application.php"
        application.write_bytes(fixture.read_bytes())
        rootfs.chmod(0o755)
        (rootfs / "app").chmod(0o755)
        application.chmod(0o644)
        dsn_file = temp / "postgres.dsn"
        with dsn_file.open("x") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(dsn)
        require(dsn_file.stat().st_uid == 0 and dsn_file.stat().st_mode & 0o777 == 0o600,
                "DSN handoff ownership/mode mismatch")
        address = temp / "gate.sock"
        receipt_path = temp / "receipts.jsonl"
        command = [str(args.binary), "--socket", str(address), "--root", str(rootfs),
                   "--postgres-dsn-file", str(dsn_file), "--adapter", str(args.adapter),
                   "--bootstrap", str(ROOT / "runtime/phase3/bootstrap.php"),
                   "--receipts", str(receipt_path), "--deadline-ms", "200", "--allow-fault-injection"]
        report["server_command"] = command
        log_path = args.output.with_suffix(".server.log")
        report["server_log"] = str(log_path)
        process = None
        with log_path.open("xb") as log:
            try:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                    stderr=subprocess.STDOUT, start_new_session=True, env={"PATH": "/usr/bin:/bin"})
                wait_socket(address, process)
                for index in range(100):
                    require(request(address, f"pg-clean-{index:03}")[0] == 200, f"clean request {index} failed")
                    assert_clean(receipts(receipt_path)[-1])
                clean_rows = rows(args, dsn)
                require(len(clean_rows) == 200, "100 clean PostgreSQL requests must produce exactly 200 keys")
                for index in range(100):
                    identifier = f"pg-clean-{index:03}"
                    require(clean_rows[f"row:{identifier}"] == f"valid:{identifier}", "committed row value mismatch")
                    require(clean_rows[f"session:{identifier}"] == "active", "session value mismatch")
                report.update(consecutive_clean_requests=100, clean_committed_keys=200)
                faults = []
                for fault in ("segv", "syscall", "exit", "timeout", "verifier"):
                    before = rows(args, dsn)
                    status, elapsed = request(address, f"pg-corrupt-{fault}", fault)
                    require(status == 500, f"{fault} did not return HTTP 500")
                    after = rows(args, dsn)
                    require(after == before, f"{fault} changed real PostgreSQL state")
                    observed = receipts(receipt_path)[-1]
                    require(observed["commit_status"] == "burned" and observed["committed_mutations"] == 0,
                            f"{fault} must be a known zero commit")
                    worker = observed["worker"]
                    require(worker["reaped"], f"{fault} worker not reaped")
                    if fault == "segv":
                        require(worker["status"].get("signal") == signal.SIGSEGV, "memory probe did not produce SIGSEGV")
                    if fault == "syscall":
                        require(worker["status"].get("signal") == signal.SIGSYS, "socket probe did not produce SIGSYS")
                    require(request(address, f"pg-recover-{fault}")[0] == 200, f"{fault} recovery failed")
                    assert_clean(receipts(receipt_path)[-1])
                    faults.append({"fault": fault, "http_status": status, "elapsed_ms": elapsed,
                        "persistent_keys_before": len(before), "persistent_keys_after": len(after),
                        "receipt": observed, "subsequent_request": "PASS"})
                report["fault_injection"] = faults
                all_receipts = receipts(receipt_path)
                require(len(all_receipts) == 110, "expected 100 clean + five faults + five recoveries")
                workers = [receipt["worker"] for receipt in all_receipts]
                pids = [worker["worker_pid"] for worker in workers]
                require(len(pids) == len(set(pids)), "generation PID reused during bounded run")
                require(all(worker["reaped"] for worker in workers), "unreaped request generation")
                final = rows(args, dsn)
                corrupted = [key for key in final if "pg-corrupt-" in key]
                require(not corrupted and len(final) == 210, "final real PostgreSQL state mismatch")
                report.update(unique_worker_pids=len(set(pids)), final_committed_keys=len(final),
                    corrupted_committed_keys=len(corrupted), final_rows=final, receipts=all_receipts,
                    application_sha256_inside_rootfs=sha256(application))
                require(report["application_sha256_inside_rootfs"] == report["application_sha256_before"],
                        "application changed in isolated rootfs")
                all_receipts = stalled_backend_probe(args, dsn, address, receipt_path,
                    command, process, temp, report)
                workers = [receipt["worker"] for receipt in all_receipts]
                pids = [worker["worker_pid"] for worker in workers]
                require(len(all_receipts) == 113 and len(pids) == len(set(pids))
                        and all(worker["reaped"] for worker in workers), "final worker lifecycle mismatch")
                final = rows(args, dsn)
                corrupted = [key for key in final if "pg-corrupt-" in key]
                require(not corrupted and len(final) == 212, "backend deadline/restart state mismatch")
                report.update(unique_worker_pids=len(set(pids)), final_committed_keys=len(final),
                    corrupted_committed_keys=len(corrupted), final_rows=final, receipts=all_receipts)
                report["functional_status"] = "PASS"
            finally:
                if receipt_path.exists():
                    retained = args.output.with_suffix(".receipts.jsonl")
                    retained.write_bytes(receipt_path.read_bytes())
                    report["receipt_file"] = str(retained)
                if process is not None:
                    stop(process)
    report["application_sha256_after"] = sha256(fixture)
    require(report["application_sha256_after"] == report["application_sha256_before"], "original application changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/ephem-stateful")
    parser.add_argument("--adapter", type=Path, default=ROOT / "target/phase3/libephem_php.so")
    parser.add_argument("--psql", type=Path, required=True)
    parser.add_argument("--postgres-socket", type=Path, required=True)
    parser.add_argument("--port", type=int, default=55439)
    parser.add_argument("--pg-data", type=Path, required=True)
    parser.add_argument("--pg-ctl", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "reports/phase3/postgres-http-final.json")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print("UNRUN: requires root in a dedicated Linux VM", file=sys.stderr)
        return 77
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    require(not args.output.exists(), "refusing to overwrite retained PostgreSQL evidence")
    args.binary, args.adapter = args.binary.resolve(), args.adapter.resolve()
    report = {"schema": "ephem.phase3.postgres-http.v1", "functional_status": "FAIL",
        "production_status": "HOLD", "latency_acceptance": "UNMEASURED: correctness run only",
        "memory_claim": "kernel-observed signals tested; silent corruption on exit0 not detectable",
        "atomic_scope": "one PostgreSQL versioned KV table; no transparent SQL/MySQL/Redis or distributed atomicity",
        "lost_commit_ack": "indeterminate count is null; real lost-ACK network injection UNRUN"}
    failed = False
    try:
        run(args, report)
    except Exception as error:
        failed = True
        report["failure"] = f"{type(error).__name__}: {error}"
    finally:
        try:
            stop_private_postgres(args, report)
        except Exception as error:
            failed = True
            report["cleanup_failure"] = f"{type(error).__name__}: {error}"
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({key: value for key, value in report.items() if key in {
            "functional_status", "failure", "cleanup_failure", "consecutive_clean_requests",
            "corrupted_committed_keys", "final_committed_keys", "unique_worker_pids", "private_cluster_cleanup"}}))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
