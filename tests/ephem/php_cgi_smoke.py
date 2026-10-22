#!/usr/bin/env python3
"""A frozen benign upload against the unchanged receiver and actual PHP-CGI."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_ephemeral_lifecycle import http_exchange


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--jail", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--php-cgi", type=Path, required=True)
    parser.add_argument("--source-tar", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cgroup-root", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not sys.platform.startswith("linux"):
        parser.error("this integration run requires the owned Linux root VM")
    prereg_path = args.report.with_suffix(".preregistration.json")
    log_path = args.report.with_suffix(".gate.log")
    if any(path.exists() for path in [args.report, prereg_path, log_path]):
        parser.error("preserve existing evidence; choose a new report version")
    app_hash = digest(args.app)
    root_app = args.rootfs / "app/receiver.php"
    if app_hash != "c20a7b07a54d2341fca097d4e81e7e9d6ea1bcfda9b08deb62e1c9d4d711e681" or digest(root_app) != app_hash:
        parser.error("receiver bytes changed")
    source_hash = digest(args.source_tar)
    if source_hash != "c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53":
        parser.error("official patched source hash mismatch")
    version = subprocess.run([str(args.php_cgi), "-n", "-v"], check=True,
                             capture_output=True, text=True).stdout
    if not version.startswith("PHP 8.3.36 (cgi-fcgi)"):
        parser.error("patched PHP 8.3.36 CGI required")
    boundary = "ephem-benign-php-8-3-36"
    upload = b"ephem CGI benign upload\n"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nbenign\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"tiny.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\n").encode() + upload + f"\r\n--{boundary}--\r\n".encode()
    expected = {"receiver": "patched-php-fpm", "php_version": "8.3.36", "id": "", "pid": 1,
                "files": [{"name": "upload", "size": len(upload), "error": 0,
                           "sha256": hashlib.sha256(upload).hexdigest()}], "fields": 1}
    expected_body = json.dumps(expected, separators=(",", ":")).encode()
    expected_sha = hashlib.sha256(expected_body).hexdigest()
    request = ("POST /run HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n"
               f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    worker_args = ["-n", "-d", "expose_php=0", "-d", "error_log=/tmp/php.log",
                   "-d", "max_execution_time=0"]
    prereg = {"contract": "two sequential plus two concurrent benign uploads; no policy relaxation",
              "actual_sapi": "cgi-fcgi", "receiver_literal_is_historical": "patched-php-fpm",
              "php_version_output": version, "worker_args": worker_args,
              "gate_deadline_ms": 1000, "application_bytes": args.app.stat().st_size,
              "application_sha256": app_hash, "source_tar_sha256": source_hash,
              "official_release": "https://www.php.net/releases/index.php?json&version=8.3.36",
              "request_sha256": hashlib.sha256(request).hexdigest(),
              "request_bytes": len(request), "upload_bytes": len(upload),
              "upload_sha256": hashlib.sha256(upload).hexdigest(),
              "expected_response_json": expected, "expected_response_sha256": expected_sha,
              "binary_sha256": {"gate": digest(args.gate), "jail": digest(args.jail),
                                "php-cgi": digest(args.php_cgi)},
              "rootfs_manifest": json.loads((args.rootfs / ".ephem-php-rootfs.json").read_text()),
              "source_sha256": {str(Path(__file__).name): digest(__file__)}}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    prereg_path.write_text(json.dumps(prereg, indent=2) + "\n")
    report = {"verdict": "FAIL", "preregistration_sha256": digest(prereg_path),
              "observations": [], "application_sha256_before": app_hash}
    run_dir = Path(tempfile.mkdtemp(prefix="ephem-php-smoke-", dir="/run"))
    sock = run_dir / "gate.sock"
    command = [str(args.gate), "--socket", str(sock), "--jail", str(args.jail),
               "--root", str(args.rootfs), "--worker", "/usr/bin/php-cgi",
               "--cgi-script", "/app/receiver.php", "--deadline-ms", "1000",
               "--max-inflight", "4", "--cgroup-root", str(args.cgroup_root), "--"] + worker_args
    report["gate_command"] = command
    gate = None
    try:
        with log_path.open("wb") as log:
            gate = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=log, start_new_session=True,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            deadline = time.monotonic() + 5
            while not sock.is_socket():
                if gate.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("owned gate startup failed")
                time.sleep(0.01)
            def probe(label):
                response = http_exchange(str(sock), request)
                actual = response.pop("body")
                response["body_utf8"] = actual.decode("utf-8", errors="replace")
                response["body_sha256"] = hashlib.sha256(actual).hexdigest()
                response["probe"] = label
                response["checks"] = {
                    "status_200": response["status"] == 200,
                    "literal_response_bytes": actual == expected_body,
                    "trusted_response_digest": response["headers"].get("x-ephem-output-sha256") == expected_sha,
                    "namespace_pid_one": actual == expected_body,
                }
                return response
            for label in ["sequential-1", "sequential-2"]:
                report["observations"].append(probe(label))
            with ThreadPoolExecutor(max_workers=2) as pool:
                report["observations"].extend(pool.map(probe, ["concurrent-1", "concurrent-2"]))
            pids = [int(row["headers"].get("x-ephem-worker-pid", "-1")) for row in report["observations"]]
            report["distinct_fresh_host_pids"] = len(set(pids)) == 4 and min(pids) > 1
            report["application_sha256_after"] = digest(args.app)
            report["rootfs_application_sha256_after"] = digest(root_app)
            checks = [all(row["checks"].values()) for row in report["observations"]]
            if all(checks) and report["distinct_fresh_host_pids"] and digest(args.app) == digest(root_app) == app_hash:
                report["verdict"] = "PASS"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        if gate is not None and gate.poll() is None:
            gate.terminate()
            try:
                gate.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gate.kill()
                gate.wait(timeout=5)
        report["owned_gate_returncode"] = None if gate is None else gate.returncode
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        shutil.rmtree(run_dir)
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
