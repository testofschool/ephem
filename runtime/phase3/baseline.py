#!/usr/bin/env python3
"""Laboratory baseline: warmed embedded PHP, uncontained COW request forks.

This deliberately has no security boundary, sealed ledger, or pidfd verifier.
The PHP adapter, deployment bootstrap, application bytes, framed state protocol,
SQLite schema, WAL/FULL durability, and per-request atomic commit match the
contained path. Python supervision overhead remains part of the measured
baseline and must be disclosed when interpreting the paired latency delta.
The parent also opens a SQLite connection after each fork so the child inherits
no database descriptor; the contained Rust parent keeps its connection open.
Never expose this test server as a production service.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import sqlite3
import struct
import sys
import time

MAX_INPUT = 65_536
MAX_OUTPUT = 1_048_576
MAX_COMMANDS = 1024
MAX_VALUE = 32_768
ERROR_BODY = b"Transaction discarded\n"
SCHEMA = """CREATE TABLE IF NOT EXISTS ephem_kv (
    key BLOB PRIMARY KEY NOT NULL, value BLOB,
    expires_at_ms INTEGER, version INTEGER NOT NULL CHECK(version > 0)
) WITHOUT ROWID"""


class BaselineError(Exception):
    pass


class ServerStopping(BaseException):
    pass


def database(path: str, initialize: bool = False) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=0.1, isolation_level=None)
    try:
        if initialize:
            connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        if initialize:
            connection.execute(SCHEMA)
    except BaseException:
        connection.close()
        raise
    return connection


def exact(channel: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = channel.recv(size - len(result))
        if not part:
            raise BaselineError("incomplete HTTP input")
        result.extend(part)
    return bytes(result)


def http_request(client: socket.socket) -> bytes:
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        if len(header) >= 16_384:
            raise BaselineError("HTTP header limit")
        header.extend(exact(client, 1))
    try:
        lines = bytes(header[:-4]).decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise BaselineError("invalid HTTP headers") from error
    if lines.pop(0) != "POST /run HTTP/1.1":
        raise BaselineError("unsupported HTTP request")
    length = None
    host = False
    for line in lines:
        if ":" not in line:
            raise BaselineError("invalid HTTP header")
        key, value = line.split(":", 1)
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", key):
            raise BaselineError("invalid HTTP header name")
        if any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value):
            raise BaselineError("invalid HTTP header value")
        key, value = key.lower(), value.strip()
        if key == "content-length":
            if length is not None or not re.fullmatch(r"[0-9]+", value):
                raise BaselineError("invalid Content-Length")
            length = int(value)
        elif key == "host":
            if host or not value:
                raise BaselineError("invalid Host")
            host = True
        elif key in {"transfer-encoding", "expect", "upgrade", "trailer", "x-ephem-fault"}:
            raise BaselineError("unsupported baseline HTTP framing/fault selector")
    if not host or length is None or length > MAX_INPUT:
        raise BaselineError("HTTP body bound or required header")
    return exact(client, length)


def parse_resp(frame: bytes) -> list[bytes]:
    cursor = 0

    def line() -> bytes:
        nonlocal cursor
        end = frame.find(b"\r\n", cursor)
        if end < 0:
            raise BaselineError("incomplete RESP line")
        result = frame[cursor:end]
        cursor = end + 2
        return result

    header = line()
    if not re.fullmatch(rb"\*[1-4]", header):
        raise BaselineError("bounded RESP2 array required")
    result = []
    for _ in range(int(header[1:])):
        header = line()
        if not re.fullmatch(rb"\$[0-9]{1,7}", header):
            raise BaselineError("invalid RESP bulk length")
        size = int(header[1:])
        end = cursor + size
        if size > MAX_INPUT or end + 2 > len(frame) or frame[end:end + 2] != b"\r\n":
            raise BaselineError("incomplete RESP bulk string")
        result.append(frame[cursor:end])
        cursor = end + 2
    if cursor != len(frame):
        raise BaselineError("trailing RESP bytes")
    return result


def snapshot(connection: sqlite3.Connection, key: bytes) -> tuple[int, bytes | None, int | None]:
    row = connection.execute(
        "SELECT version,value,expires_at_ms FROM ephem_kv WHERE key=?", (key,)
    ).fetchone()
    if row is None:
        return 0, None, None
    version, value, expiry = row
    if expiry is not None and expiry <= time.time_ns() // 1_000_000:
        value = None
    if value is not None and len(value) > MAX_VALUE:
        raise BaselineError("backend value exceeds bound")
    return version, value, expiry


class Overlay:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        self.observed: dict[bytes, tuple[int, bytes | None, int | None]] = {}
        self.pending: dict[bytes, tuple[bytes | None, int | None]] = {}
        self.mutations: list[tuple[bytes, bytes | None, int | None]] = []
        self.commands = 0
        self.quit = False

    def current(self, key: bytes) -> tuple[bytes | None, int | None]:
        if not key or len(key) > 1024:
            raise BaselineError("key bound")
        if key not in self.observed:
            self.observed[key] = snapshot(self.connection, key)
        if key in self.pending:
            value, expiry = self.pending[key]
        else:
            _, value, expiry = self.observed[key]
        if expiry is not None and expiry <= time.time_ns() // 1_000_000:
            value = None
        return value, expiry

    def stage(self, key: bytes, value: bytes | None, expiry: int | None) -> None:
        if value is not None and len(value) > MAX_VALUE:
            raise BaselineError("value bound")
        self.pending[key] = value, expiry
        self.mutations.append((key, value, expiry))

    def execute(self, frame: bytes) -> bytes:
        if self.quit or self.commands >= MAX_COMMANDS:
            raise BaselineError("command budget or command after QUIT")
        self.commands += 1
        args = parse_resp(frame)
        command = args[0].upper()
        if command == b"PING" and len(args) == 1:
            return b"+PONG\r\n"
        if command == b"QUIT" and len(args) == 1:
            self.quit = True
            return b"+OK\r\n"
        if command == b"GET" and len(args) == 2:
            value, _ = self.current(args[1])
            return b"$-1\r\n" if value is None else b"$%d\r\n" % len(value) + value + b"\r\n"
        if command == b"SET" and len(args) == 3:
            self.current(args[1])
            self.stage(args[1], args[2], None)
            return b"+OK\r\n"
        if command == b"SETEX" and len(args) == 4:
            if not re.fullmatch(rb"[0-9]+", args[2]) or not 0 < int(args[2]) <= (2**63 - 1) // 1000:
                raise BaselineError("invalid SETEX expiry")
            expiry = time.time_ns() // 1_000_000 + int(args[2]) * 1000
            if expiry > 2**63 - 1:
                raise BaselineError("SETEX timestamp overflow")
            self.current(args[1])
            self.stage(args[1], args[3], expiry)
            return b"+OK\r\n"
        if command == b"DEL" and len(args) == 2:
            value, _ = self.current(args[1])
            self.stage(args[1], None, None)
            return b":0\r\n" if value is None else b":1\r\n"
        if command == b"INCR" and len(args) == 2:
            value, expiry = self.current(args[1])
            if value is None:
                number, expiry = 0, None
            elif re.fullmatch(rb"0|-[1-9][0-9]*|[1-9][0-9]*", value):
                number = int(value)
            else:
                raise BaselineError("noncanonical integer")
            if not -(2**63) <= number < 2**63 - 1:
                raise BaselineError("INCR overflow")
            number += 1
            self.stage(args[1], str(number).encode(), expiry)
            return b":%d\r\n" % number
        raise BaselineError("unsupported RESP command or arity")

    def commit(self) -> int:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            for key, expected in self.observed.items():
                if snapshot(self.connection, key) != expected:
                    raise BaselineError("optimistic transaction conflict or expiry")
            for key, value, expiry in self.mutations:
                self.connection.execute(
                    "INSERT INTO ephem_kv(key,value,expires_at_ms,version) VALUES(?,?,?,1) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "expires_at_ms=excluded.expires_at_ms, version=version+1",
                    (key, value, expiry),
                )
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        return len(self.mutations)


def write_fd(fd: int, body: bytes) -> None:
    remaining = memoryview(body)
    while remaining:
        size = os.write(fd, remaining)
        if size <= 0:
            raise BaselineError("output socket write")
        remaining = remaining[size:]


def kill_and_reap(pid: int) -> None:
    # The unreaped request PID reserves its identity while its process group is
    # killed. Descendants, if any, share the group in this trusted fixture.
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            os.waitpid(pid, 0)
            return
        except InterruptedError:
            continue
        except ChildProcessError:
            return


def run_request(adapter, listener: socket.socket, client: socket.socket,
                body: bytes, database_path: str, timeout: float) -> tuple[bytes, int, int]:
    state_parent, state_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    output_parent, output_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        pid = os.fork()
    except BaseException:
        for channel in (state_parent, state_child, output_parent, output_child):
            channel.close()
        raise
    if pid == 0:
        try:
            os.setpgid(0, 0)
            listener.close()
            client.close()
            state_parent.close()
            output_parent.close()
            output = ctypes.POINTER(ctypes.c_ubyte)()
            size = ctypes.c_size_t()
            input_buffer = ctypes.create_string_buffer(body)
            result = adapter.ephem_php_run(
                ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)), len(body),
                state_child.fileno(), ctypes.byref(output), ctypes.byref(size)
            )
            if result != 0 or size.value > MAX_OUTPUT or (size.value and not output):
                os._exit(70)
            write_fd(output_child.fileno(), ctypes.string_at(output, size.value))
            os._exit(0)
        except BaseException:
            os._exit(71)

    state_child.close()
    output_child.close()
    deadline = time.monotonic() + timeout
    reaped = False
    connection = None
    try:
        try:
            os.setpgid(pid, pid)
        except ProcessLookupError:
            pass
        # Crucially this descriptor is opened after the request fork. No worker
        # inherits SQLite's connection, lock state, WAL handle, or credentials.
        connection = database(database_path)
        overlay = Overlay(connection)
        state_parent.setblocking(False)
        output_parent.setblocking(False)
        state_buffer = bytearray()
        pending_reply = bytearray()
        stdout = bytearray()
        eof = set()
        status = None
        with selectors.DefaultSelector() as poll:
            poll.register(state_parent, selectors.EVENT_READ, "state")
            poll.register(output_parent, selectors.EVENT_READ, "output")
            while status is None or len(eof) < 2:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BaselineError("request deadline exceeded")
                for key, events in poll.select(min(remaining, 0.01)):
                    channel, kind = key.fileobj, key.data
                    if events & selectors.EVENT_WRITE:
                        try:
                            sent = channel.send(pending_reply)
                        except BlockingIOError:
                            sent = 0
                        if sent:
                            del pending_reply[:sent]
                        if not pending_reply:
                            poll.modify(channel, selectors.EVENT_READ, "state")
                    if events & selectors.EVENT_READ:
                        try:
                            part = channel.recv(65_536)
                        except BlockingIOError:
                            continue
                        if not part:
                            if kind == "state" and (state_buffer or pending_reply):
                                raise BaselineError("state IPC incomplete at EOF")
                            eof.add(kind)
                            poll.unregister(channel)
                            continue
                        if kind == "output":
                            stdout.extend(part)
                            if len(stdout) > MAX_OUTPUT:
                                raise BaselineError("stdout bound")
                        else:
                            state_buffer.extend(part)
                            if len(state_buffer) > MAX_INPUT + 4:
                                raise BaselineError("state frame bound")
                            while len(state_buffer) >= 4:
                                size = struct.unpack("!I", state_buffer[:4])[0]
                                if not 0 < size <= MAX_INPUT:
                                    raise BaselineError("state command size")
                                if len(state_buffer) < size + 4:
                                    break
                                frame = bytes(state_buffer[4:size + 4])
                                del state_buffer[:size + 4]
                                reply = overlay.execute(frame)
                                pending_reply.extend(struct.pack("!I", len(reply)) + reply)
                                if len(pending_reply) > MAX_OUTPUT:
                                    raise BaselineError("state reply bound")
                            if pending_reply:
                                poll.modify(state_parent, selectors.EVENT_READ | selectors.EVENT_WRITE, "state")
                if status is None:
                    # Observe without reaping so the request PID and process
                    # group identity remain reserved until every channel has
                    # drained or cleanup kills the group on a deadline.
                    observed = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if observed is not None:
                        status = (observed.si_status << 8) if observed.si_code == os.CLD_EXITED else observed.si_status
                        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                            raise BaselineError("worker terminated abnormally")
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                raise BaselineError("worker terminated abnormally")
            # The leader is an observed zombie, so killing its still-reserved
            # process group cannot alter its successful exit status. It also
            # removes any fixture descendants before releasing the PID.
            kill_and_reap(pid)
            reaped = True
        if time.monotonic() >= deadline:
            raise BaselineError("deadline exceeded before commit")
        # Match the contained server's precommit disconnect/pipelining check.
        client.setblocking(False)
        try:
            client.recv(1, socket.MSG_PEEK)
        except BlockingIOError:
            pass
        else:
            raise BaselineError("client disconnected or pipelined input")
        finally:
            client.settimeout(timeout)
        committed = overlay.commit()
        return bytes(stdout), committed, pid
    finally:
        if not reaped:
            kill_and_reap(pid)
        state_parent.close()
        output_parent.close()
        if connection is not None:
            connection.close()


def http_response(status: int, body: bytes) -> bytes:
    reason = "OK" if status == 200 else "Internal Server Error"
    content_type = "application/octet-stream" if status == 200 else "text/plain"
    return (f"HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--application", required=True)
    parser.add_argument("--timeout-ms", type=int, default=2000)
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or not 1 <= args.timeout_ms <= 60_000:
        parser.error("baseline requires Linux and timeout 1..60000 ms")
    for name in ("adapter", "bootstrap", "application"):
        path = Path(getattr(args, name))
        if not path.is_absolute() or not path.is_file():
            parser.error(f"--{name} must be an existing absolute file path")
    socket_path = Path(args.socket)
    if socket_path.exists() or socket_path.is_symlink():
        parser.error("refusing to replace an existing socket path")

    adapter = ctypes.CDLL(args.adapter, mode=os.RTLD_NOW | os.RTLD_LOCAL)
    adapter.ephem_php_boot.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    adapter.ephem_php_boot.restype = ctypes.c_int
    adapter.ephem_php_run.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                                    ctypes.c_int, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
                                    ctypes.POINTER(ctypes.c_size_t)]
    adapter.ephem_php_run.restype = ctypes.c_int
    if adapter.ephem_php_boot(os.fsencode(args.bootstrap), os.fsencode(args.application)) != 0:
        raise BaselineError("embedded PHP warm boot failed")
    # Initialize and close before any request fork; per-request connections are
    # separately opened by the parent after the corresponding child exists.
    database(args.database, initialize=True).close()

    def stop(_signal, _frame):
        raise ServerStopping()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound = False
    try:
        listener.bind(args.socket)
        bound = True
        os.chmod(args.socket, 0o600)
        listener.listen(128)
        print(json.dumps({"ready": True, "baseline": "trusted-uncontained-warm-php-python", "pid": os.getpid()}), flush=True)
        request_id = 0
        while True:
            client, _ = listener.accept()
            request_id += 1
            started = time.monotonic()
            details = {"request_id": request_id, "baseline": "trusted-uncontained-warm-php-python"}
            with client:
                client.settimeout(args.timeout_ms / 1000)
                try:
                    body = http_request(client)
                    output, count, pid = run_request(adapter, listener, client, body,
                                                     args.database, args.timeout_ms / 1000)
                    status = 200
                    details.update(committed_mutations=count, worker_pid=pid)
                except (BaselineError, OSError, sqlite3.Error, ValueError) as error:
                    output, status = ERROR_BODY, 500
                    details.update(committed_mutations=0, burned_reason=str(error))
                try:
                    client.sendall(http_response(status, output))
                except OSError as error:
                    details["response_delivery_error"] = str(error)
                details.update(http_status=status, elapsed_ms=(time.monotonic() - started) * 1000)
                print(json.dumps(details), flush=True)
    except ServerStopping:
        pass
    finally:
        listener.close()
        if bound:
            socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
