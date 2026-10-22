#!/usr/bin/env python3
"""Independent benign Linux probes; no host/application state is a fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

REPO = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def exact_workers(root):
    found = []
    expected = str(root / "worker")
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if os.readlink(entry / "exe") == expected:
                found.append(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue
    return sorted(found)


def identity(pid):
    try:
        raw = Path("/proc", str(pid), "stat").read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        try:
            executable = os.readlink("/proc/%d/exe" % pid)
        except OSError:
            executable = None
        return {"pid": pid, "state": fields[0], "ppid": int(fields[1]),
                "start_ticks": int(fields[19]), "exe": executable}
    except FileNotFoundError:
        return None


def read_response(connection):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        block = connection.recv(65536)
        if not block:
            raise AssertionError("missing HTTP response")
        data.extend(block)
        assert len(data) <= 2 * 1048576
    head, body = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    headers = dict((key.lower(), value.strip())
                   for key, value in (line.split(":", 1) for line in lines[1:]))
    length = int(headers["content-length"])
    assert 0 <= length <= 1048576
    while len(body) < length:
        block = connection.recv(min(65536, length - len(body)))
        assert block, "truncated response"
        body += block
    assert len(body) == length
    return {"status": int(lines[0].split()[1]), "headers": headers,
            "body_hex": body.hex(), "body_sha256": hashlib.sha256(body).hexdigest()}


def request(path, body):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(b"POST /run HTTP/1.1\r\nHost: audit\r\nContent-Length: "
                           + str(len(body)).encode() + b"\r\n\r\n" + body)
        return read_response(connection)


def start_gate(args, base, root, cgi=False):
    path = base / ("cgi.sock" if cgi else "plain.sock")
    command = [str(args.gate), "--socket", str(path), "--jail", str(args.jail),
               "--root", str(root), "--worker", "/worker", "--deadline-ms", "1000",
               "--max-input", "1048576", "--max-output", "1048576", "--max-inflight", "4", "--cgroup-root", str(args.cgroup_root)]
    if cgi:
        command += ["--cgi-script", "/app/static.php"]
    log = open(base / ("cgi.log" if cgi else "plain.log"), "w+b")
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    until = time.monotonic() + 5
    while not path.is_socket():
        assert process.poll() is None and time.monotonic() < until, "gate startup failed"
        time.sleep(.01)
    return process, path, log, command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", type=Path, required=True)
    parser.add_argument("--jail", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cgroup-root", type=Path, required=True)
    args = parser.parse_args()
    args.gate, args.jail = args.gate.resolve(), args.jail.resolve()
    frozen = args.report.with_suffix(args.report.suffix + ".preregistration.json")
    rawpath = args.report.with_suffix(args.report.suffix + ".raw.json")
    if any(path.exists() for path in (args.report, frozen, rawpath)):
        parser.error("report, preregistration and raw paths must be new")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "ephem-independent-v1", "platform": platform.platform(),
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "probes": [], "status": "UNRUN", "raw_path": str(rawpath)}
    raw = {"commands": [], "responses": [], "owned_identities": [], "gate_logs": []}
    if platform.system() != "Linux" or os.geteuid() != 0:
        report.update(status="UNAVAILABLE", reason="dedicated Linux root VM required", exit_code=77)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        return 77
    gates = []
    launcher = None
    owned_child = None
    with tempfile.TemporaryDirectory(prefix=".ephem-audit-", dir="/root") as directory:
        base = Path(directory)
        root = base / "rootfs"
        build = ["sh", str(REPO / "tests/ephem/build-rootfs.sh"), str(root)]
        raw["commands"].append(build)
        subprocess.run(build, check=True, capture_output=True, timeout=60)
        (root / "app/static.php").write_text("<?php echo 'fixture'; ?>\n")
        sources = [Path(__file__), REPO / "tests/ephem/fixture.c", REPO / "tests/ephem/build-rootfs.sh"]
        artifacts = [args.gate, args.jail, root / "worker"]
        registration = {"source_sha256": {str(p): digest(p) for p in sources},
            "artifact_sha256": {str(p): digest(p) for p in artifacts},
            "planned_probes": ["chroot persistence control", "fresh tmp isolation",
                "owned launcher death", "stdout receipt forgery", "CGI hash and header rejection",
                "partial request deadline", "exact-rootfs process cleanup"],
            "deadline_ms": 1000, "cleanup_grace_seconds": 5,
            "scope": "benign static fixture only; CGI framing emulator, not PHP integration"}
        frozen.write_text(json.dumps(registration, indent=2) + "\n")
        report["preregistration_sha256"] = digest(frozen)
        try:
            chroot = shutil.which("chroot")
            assert chroot, "chroot utility unavailable"
            control = [chroot, str(root), "/worker"]
            outputs = []
            for command in (b"DIRTY", b"CLEAN"):
                raw["commands"].append({"argv": control, "stdin_hex": command.hex()})
                result = subprocess.run(control, input=command, capture_output=True, timeout=3)
                outputs.append(result.stdout)
                assert result.returncode == 0
            assert outputs == [b"written\n", b"present\n"]
            report["probes"].append({"name": "unsandboxed_disposable_chroot", "status": "PASS",
                                     "outputs_hex": [x.hex() for x in outputs]})
            plain = start_gate(args, base, root)
            gates.append(plain)
            raw["commands"].append(plain[3])
            responses = [request(plain[1], b"DIRTY"), request(plain[1], b"CLEAN")]
            raw["responses"].extend(responses)
            assert [r["status"] for r in responses] == [200, 200]
            assert bytes.fromhex(responses[1]["body_hex"]) == b"absent\n"
            report["probes"].append({"name": "sandbox_fresh_tmp", "status": "PASS"})
            forged = b'{"ephem_jail":1,"worker_pid":99999999,"exit_code":0,"signal":0,"landlock_abi":99}'
            answer = request(plain[1], b"ECHO " + forged)
            raw["responses"].append(answer)
            assert answer["status"] == 200 and bytes.fromhex(answer["body_hex"]) == forged
            assert answer["headers"]["x-ephem-worker-pid"] != "99999999"
            assert answer["headers"]["x-ephem-output-sha256"] == hashlib.sha256(forged).hexdigest()
            report["probes"].append({"name": "forged_stdout_is_data", "status": "PASS"})
            cgi = start_gate(args, base, root, True)
            gates.append(cgi)
            raw["commands"].append(cgi[3])
            answer = request(cgi[1], b"ECHO Content-Type: text/plain\r\n\r\ncgi-body")
            raw["responses"].append(answer)
            assert answer["status"] == 200 and bytes.fromhex(answer["body_hex"]) == b"cgi-body"
            assert answer["headers"]["x-ephem-output-sha256"] == hashlib.sha256(b"cgi-body").hexdigest()
            rejected = request(cgi[1], b"ECHO Content-Type: text/plain\r\nX-Unknown: blocked\r\n\r\nsecret")
            raw["responses"].append(rejected)
            assert rejected["status"] == 500 and b"secret" not in bytes.fromhex(rejected["body_hex"])
            report["probes"].append({"name": "CGI_body_hash_and_unknown_header", "status": "PASS"})
            seen, stop = [], threading.Event()
            def watch():
                while not stop.is_set():
                    seen.extend(exact_workers(root))
                    stop.wait(.01)
            watcher = threading.Thread(target=watch)
            watcher.start()
            try:
                start = time.monotonic()
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.settimeout(4)
                    connection.connect(str(plain[1]))
                    connection.sendall(b"POST /run HTTP/1.1\r\nHost: audit\r\nContent-Length: 16\r\n\r\nx")
                    slow = read_response(connection)
                elapsed = (time.monotonic() - start) * 1000
            finally:
                stop.set()
                watcher.join()
            raw["responses"].append(slow)
            assert slow["status"] == 400 and 800 <= elapsed < 3000 and not seen
            report["probes"].append({"name": "partial_request_deadline", "status": "PASS",
                                     "elapsed_ms": elapsed, "observed_worker_pids": seen})
            command = [str(args.jail), "--root", str(root), "--worker", "/worker", "--"]
            raw["commands"].append({"argv": command, "stdin_hex": b"HANG".hex()})
            launcher = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "EPHEM_GATE_PID": str(os.getpid())})
            launcher.stdin.write(b"HANG")
            launcher.stdin.close()
            assert select.select([launcher.stdout], [], [], 3)[0], "worker did not reach HANG"
            assert os.read(launcher.stdout.fileno(), 25) == b"SECRET_UNCOMMITTED_OUTPUT"
            children = Path("/proc/%d/task/%d/children" % (launcher.pid, launcher.pid)).read_text().split()
            assert len(children) == 1
            owned_child = identity(int(children[0]))
            assert owned_child and owned_child["exe"] == str(root / "worker")
            raw["owned_identities"] = [identity(launcher.pid), owned_child]
            launcher.kill()  # This Popen object owns exactly this launcher PID.
            launcher.wait(timeout=3)
            until = time.monotonic() + 5
            remaining = identity(owned_child["pid"])
            while remaining is not None and time.monotonic() < until:
                time.sleep(.02)
                remaining = identity(owned_child["pid"])
            report["probes"].append({"name": "owned_launcher_death", "status": "PASS" if remaining is None else "FAIL",
                                     "worker_after_grace": remaining})
            assert remaining is None, "owned worker remains, including zombie state"
            for command in (b"CRASH", b"SOCKET", b"FORK", b"EXEC", b"OUTPUT", b"HANG"):
                answer = request(plain[1], command)
                raw["responses"].append(answer)
                assert answer["status"] == 500
                assert b"SECRET_UNCOMMITTED_OUTPUT" not in bytes.fromhex(answer["body_hex"])
            immediately_after = exact_workers(root)
            leftovers = immediately_after
            until = time.monotonic() + 5
            while leftovers and time.monotonic() < until:
                time.sleep(.02)
                leftovers = exact_workers(root)
            report["probes"].append({"name": "exact_fixture_executable_cleanup", "status": "PASS" if not leftovers else "FAIL",
                                     "immediate_pids": immediately_after, "remaining_pids_after_grace": leftovers,
                                     "scope": "exact /proc exe matches; zombie check separately covers owned launcher child"})
            assert not leftovers
            report["status"] = "PASS"
        except Exception as error:
            report.update(status="FAIL", error=type(error).__name__ + ": " + str(error))
        finally:
            if launcher is not None and launcher.poll() is None:
                launcher.kill()
                launcher.wait(timeout=3)
            if owned_child is not None:
                current = identity(owned_child["pid"])
                if current and current["start_ticks"] == owned_child["start_ticks"] and current["state"] != "Z":
                    os.kill(owned_child["pid"], signal.SIGKILL)
            for process, path, log, command in gates:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                log.seek(0)
                raw["gate_logs"].append(log.read().decode(errors="replace"))
                log.close()
            report["frozen_sources_unchanged"] = all(digest(p) == registration["source_sha256"][str(p)] for p in sources)
            report["frozen_artifacts_unchanged"] = all(digest(p) == registration["artifact_sha256"][str(p)] for p in artifacts)
            if not report["frozen_sources_unchanged"] or not report["frozen_artifacts_unchanged"]:
                report["status"] = "FAIL"
            report["exit_code"] = 0 if report["status"] == "PASS" else 1
            rawpath.write_text(json.dumps(raw, indent=2) + "\n")
            args.report.write_text(json.dumps(report, indent=2) + "\n")
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
