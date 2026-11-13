"""Bounded Windows-only integration test; uses only newly owned synthetic sessions.

Run: python test\\windows_readonly_tail.py --exe zig-out\\bin\\zmx.exe
Use --expect-missed-live to reproduce the unpatched Windows baseline.
Requires a Python executable path without spaces on the unpatched task launcher.
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid


K32 = ctypes.WinDLL("kernel32", use_last_error=True)
K32.PeekNamedPipe.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
K32.GetNamedPipeServerProcessId.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG),
]
K32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
K32.OpenProcess.restype = wintypes.HANDLE
K32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
K32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
K32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
K32.CloseHandle.argtypes = [wintypes.HANDLE]
K32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
K32.CreateFileW.restype = wintypes.HANDLE
LIMIT = 1024 * 1024


def until(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("bounded readiness/condition deadline expired")


def producer(root):
    (root / "producer.json").write_text(json.dumps({"pid": os.getpid()}))
    print("SYNTHETIC-READY", flush=True)
    emitted = False
    emitted_with_owner = False
    emitted_after_disconnect = False
    count = 0
    (root / "input-count").write_text("0")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        while msvcrt.kbhit():
            msvcrt.getwch()
            count += 1
            (root / "input-count").write_text(str(count))
        if not emitted and (root / "emit").exists():
            print("SYNTHETIC-LIVE", flush=True)
            emitted = True
        if not emitted_with_owner and (root / "emit-with-owner").exists():
            print("SYNTHETIC-WITH-OWNER", flush=True)
            emitted_with_owner = True
        if not emitted_after_disconnect and (root / "emit-after-disconnect").exists():
            print("SYNTHETIC-AFTER-DISCONNECT", flush=True)
            emitted_after_disconnect = True
        if (root / "finish").exists():
            print("SYNTHETIC-DONE", flush=True)
            return 7
        time.sleep(0.02)
    raise AssertionError("producer safety deadline expired")


class Wire:
    def __init__(self, endpoint):
        def connect():
            handle = K32.CreateFileW(endpoint, 0xC0000000, 0, None, 3, 0, None)
            if handle != wintypes.HANDLE(-1).value:
                self.handle = handle
                return True
            error = ctypes.get_last_error()
            if error == 231:  # ERROR_PIPE_BUSY: wait for a listening instance.
                return False
            raise ctypes.WinError(error)

        until(connect)
        fd = msvcrt.open_osfhandle(self.handle, os.O_RDWR | os.O_BINARY)
        self.file = os.fdopen(fd, "r+b", buffering=0)
        self.buffer = bytearray()
        self.frames = []
        self.sent = []
        self.total = 0

    def send(self, tag, payload=b""):
        self.sent.append(tag)
        self.file.write(struct.pack("<Q", tag | (len(payload) << 8)) + payload)

    def pump(self):
        available = wintypes.DWORD()
        if not K32.PeekNamedPipe(
            self.handle, None, 0, None, ctypes.byref(available), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if available.value:
            data = self.file.read(min(available.value, 65536))
            self.total += len(data)
            assert self.total <= LIMIT, "wire output cap exceeded"
            self.buffer.extend(data)
        while len(self.buffer) >= 8:
            value = struct.unpack_from("<Q", self.buffer)[0]
            tag, length = value & 255, (value >> 8) & 0xFFFFFFFF
            assert length <= LIMIT, "wire frame cap exceeded"
            if len(self.buffer) < 8 + length:
                break
            self.frames.append((tag, bytes(self.buffer[8:8 + length])))
            del self.buffer[:8 + length]
        return self.frames

    def history_ready(self):
        return (8, b"") in self.pump()

    def contains(self, marker):
        return marker in b"".join(p for t, p in self.pump() if t in (1, 8))

    def close(self):
        self.file.close()


class Fixture:
    def __init__(self, exe, root, detached_launcher):
        self.exe = str(exe)
        self.root = root
        self.name = "readonly-test-" + uuid.uuid4().hex
        self.env = dict(os.environ, ZMX_DIR=str(root / "ipc-root"))
        self.env.pop("ZMX_SESSION", None)
        self.env.pop("ZMX_SESSION_PREFIX", None)
        self.handles = {}
        self.clients = []
        self.observers = []
        self.detached_launcher = detached_launcher
        self.host = None
        self.log = open(root / "launcher.log", "wb")

    def track(self, pid):
        if pid not in self.handles:
            handle = K32.OpenProcess(0x00100000 | 0x1000 | 1, False, pid)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            self.handles[pid] = handle

    def command(self, *args):
        result = subprocess.run(
            [self.exe, *args], env=self.env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=8,
        )
        assert len(result.stdout) + len(result.stderr) <= LIMIT
        if result.returncode and b"AccessDenied" in result.stderr:
            raise PermissionError(result.stderr.decode(errors="replace"))
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result.stdout

    def connect(self):
        client = Wire(self.endpoint)
        self.clients.append(client)
        return client

    def host_alive(self):
        return K32.WaitForSingleObject(self.handles[self.server_pid], 0) == 0x102

    def start(self):
        # Keep the new host's exact process handle and diagnostics, including
        # failures before endpoint publication or producer readiness.
        prefix = (
            ["run", self.name, "-d"] if self.detached_launcher
            else ["--daemon", self.name]
        )
        launcher = subprocess.Popen(
            [self.exe, *prefix, sys.executable,
             str(Path(__file__).resolve()), "--producer", str(self.root)],
            env=self.env, stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if self.detached_launcher:
            self.observers.append(launcher)
        else:
            self.host = launcher
            self.track(self.host.pid)
        until(lambda: list((self.root / "ipc-root").rglob("*.endpoint"))
              or launcher.poll() not in (None, 0))
        assert launcher.poll() in (None, 0), (self.root / "launcher.log").read_text()
        records = list((self.root / "ipc-root").rglob("*.endpoint"))
        assert len(records) == 1
        self.endpoint = records[0].read_text().strip()
        client = self.connect()
        server_pid = wintypes.ULONG()
        assert K32.GetNamedPipeServerProcessId(client.handle, ctypes.byref(server_pid))
        self.server_pid = server_pid.value
        self.track(self.server_pid)
        client.send(6)  # Info: bind the fixture's shell-wrapper PID.
        until(lambda: any(t == 6 for t, _ in client.pump()))
        info = next(p for t, p in client.frames if t == 6)
        self.track(struct.unpack_from("<i", info, 8)[0])
        client.close()
        if self.detached_launcher:
            assert launcher.wait(timeout=8) == 0
        until(lambda: (self.root / "producer.json").exists()
              or not self.host_alive())
        assert self.host_alive(), (self.root / "launcher.log").read_text()
        self.track(json.loads((self.root / "producer.json").read_text())["pid"])
        until(lambda: b"SYNTHETIC-READY" in self.command("history", self.name))

    def tail(self):
        path = self.root / "tail.log"
        stream = open(path, "wb")
        process = subprocess.Popen(
            [self.exe, "tail", self.name], env=self.env, stdin=subprocess.DEVNULL,
            stdout=stream, stderr=self.log,
        )
        stream.close()
        self.observers.append(process)
        until(lambda: b"SYNTHETIC-READY" in path.read_bytes())
        return process, path

    def clients_count(self):
        client = self.connect()
        try:
            client.send(6)
            until(lambda: any(t == 6 for t, _ in client.pump()))
            info = next(p for t, p in client.frames if t == 6)
            return struct.unpack_from("<Q", info)[0]
        finally:
            client.close()

    def cleanup(self):
        for client in self.clients:
            if not client.file.closed:
                client.close()
        for process in self.observers:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        if hasattr(self, "server_pid") and self.host_alive():
            self.command("kill", self.name, "--force")
        remaining = []
        exits = {}
        for pid, handle in self.handles.items():
            if K32.WaitForSingleObject(handle, 5000) != 0:
                remaining.append(pid)
                assert K32.TerminateProcess(handle, 1)
                assert K32.WaitForSingleObject(handle, 5000) == 0
            code = wintypes.DWORD()
            assert K32.GetExitCodeProcess(handle, ctypes.byref(code))
            exits[pid] = code.value
            K32.CloseHandle(handle)
        if self.host is not None:
            self.host.wait(timeout=5)
        self.log.close()
        (self.root / "process-exits.json").write_text(json.dumps(exits))
        assert not remaining, f"fixture required forced PID cleanup: {remaining}"
        assert not list((self.root / "ipc-root").rglob("*.endpoint"))
        return exits


def qualify(exe, root, baseline, detached_launcher):
    fixture = Fixture(exe, root, detached_launcher)
    result = {}
    permission_failed = False
    try:
        fixture.start()
        subscribers = []
        owner = None
        tail, tail_path = fixture.tail()
        (root / "emit").touch()
        until(lambda: b"SYNTHETIC-LIVE" in fixture.command("history", fixture.name))
        if baseline:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                assert b"SYNTHETIC-LIVE" not in tail_path.read_bytes()
                assert tail.poll() is None
                time.sleep(0.02)
            result["missed_live_reproduced"] = True
        else:
            until(lambda: b"SYNTHETIC-LIVE" in tail_path.read_bytes())
            result["live_marker_without_owner"] = True
            # This owner is a new synthetic wire client, never a user terminal.
            owner = fixture.connect()
            owner.send(7, b"zmx-foreground-history")
            until(lambda: owner.contains(b"SYNTHETIC-READY"))
            for _ in range(2):
                client = fixture.connect()
                client.send(8)  # Empty History is the existing tail request.
                until(client.history_ready)
                subscribers.append(client)
            until(lambda: fixture.clients_count() == 4)
            (root / "emit-with-owner").touch()
            until(lambda: b"SYNTHETIC-WITH-OWNER" in tail_path.read_bytes())
            for client in subscribers + [owner]:
                until(lambda: client.contains(b"SYNTHETIC-WITH-OWNER"))
                assert b"".join(p for t, p in client.frames if t in (1, 8)).count(
                    b"SYNTHETIC-WITH-OWNER"
                ) == 1
            result["live_marker_all_four_clients"] = True
            subscribers[0].close()
            until(lambda: fixture.clients_count() == 3)
            owner.close()
            until(lambda: fixture.clients_count() == 2)
            (root / "emit-after-disconnect").touch()
            until(lambda: subscribers[1].contains(b"SYNTHETIC-AFTER-DISCONNECT"))
            until(lambda: b"SYNTHETIC-AFTER-DISCONNECT" in tail_path.read_bytes())
            # Silence is bounded observation, not task completion.
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                assert tail.poll() is None
                assert all(
                    K32.WaitForSingleObject(h, 0) == 0x102
                    for h in fixture.handles.values()
                )
                assert not any(t in (2, 13) for t, _ in subscribers[1].pump())
                time.sleep(0.02)
            assert (root / "input-count").read_text() == "0"
            assert subscribers[1].sent == [8]
            result["disconnect_and_silence_no_resize_input_or_completion"] = True
        (root / "finish").touch()
        until(lambda: b"SYNTHETIC-DONE" in fixture.command("history", fixture.name))
        if not baseline:
            assert tail.wait(timeout=8) == 7
            until(lambda: any(t == 13 for t, _ in subscribers[1].pump()))
            assert (13, b"\x07") in subscribers[1].frames
            assert subscribers[0].sent == subscribers[1].sent == [8]
            assert owner.sent == [7]
            assert (root / "input-count").read_text() == "0"
            result["natural_completion_exit_7"] = True
        result["owned_pids"] = list(fixture.handles)
        result["owned_observer_pids"] = [p.pid for p in fixture.observers]
        result["tail_bytes"] = tail_path.stat().st_size
        assert result["tail_bytes"] < LIMIT
        return result
    except PermissionError:
        permission_failed = True
        raise
    finally:
        if not permission_failed:
            result["owned_exit_codes"] = fixture.cleanup()
            result["all_owned_process_handles_signaled"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--expect-missed-live", action="store_true")
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--detached-launcher", action="store_true")
    args = parser.parse_args()
    if args.producer:
        return producer(args.producer)
    assert args.exe and args.exe.is_file()
    assert " " not in sys.executable, "task launcher prerequisite: unspaced Python path"
    directory = Path(tempfile.mkdtemp(prefix="zmx-readonly-"))
    print(f"New owned fixture: {directory}", flush=True)
    result = qualify(
        args.exe.resolve(), directory, args.expect_missed_live, args.detached_launcher
    )
    # No automatic permission-reset/retry cleanup on failure.
    shutil.rmtree(directory)
    result["exe_sha256"] = hashlib.sha256(args.exe.read_bytes()).hexdigest()
    if args.evidence:
        args.evidence.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
