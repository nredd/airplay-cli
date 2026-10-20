"""Bounded, silent native sender diagnostic; never captures raw child diagnostics.

References:
    ../src/cliairplay.c (CLI flags and machine status protocol).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import IO

VERSION = re.compile(rb"cliairplay v[0-9A-Za-z][0-9A-Za-z.+_-]{0,127} check\r?\n?$")
MACHINE = re.compile(rb"\[(STATUS|EVENT)\] ([A-Za-z][A-Za-z0-9_]{0,63})(?: |\r?$)")
AUDIO = re.compile(rb"buffered_ms=[1-9][0-9]{0,19}$")
MRP_STATUS = re.compile(rb"(?:-1|0|1|[1-5][0-9]{2})$")
SAFE_FIELDS: dict[str, dict[bytes, set[bytes]]] = {
    "mrp": {b"path": {b"channel", b"command"}},
    "homepod_remote_admission": {b"enabled": {b"0", b"1"}},
    "homepod_remote": {
        b"channel": {b"event", b"datastream"},
        b"frame_kind": {b"command", b"sync", b"reply", b"unknown"},
        b"classification": {b"command", b"protobuf", b"invalid", b"unknown"},
        b"command": {b"play", b"pause", b"toggle", b"next", b"previous", b"unknown"},
        b"dispatched": {b"0", b"1"},
    },
    "clock_ready": {
        b"mode": {b"ptp", b"ntp"},
        b"state": {b"cold", b"probing", b"ready", b"stalled"},
    },
    "route": {
        b"protocol": {b"raop", b"airplay2"},
        b"flow": {b"native", b"legacy", b"raop-compat"},
        b"timing": {b"ptp", b"ntp"},
    },
}
SAFE_NUMBERS = {
    b"ordinal": (1, 128),
    b"elapsed_ms": (0, 2**63 - 1),
    b"protobuf_type": (-1, 65535),
    b"bytes": (0, 65536),
}
NUMBER = re.compile(rb"(?:0|[1-9][0-9]{0,18}|-1)$")
COMMANDS = (
    b"TITLE=AirPlay relay probe\nARTIST=\nALBUM=\nITEMID=native-relay-probe\n"
    b"DURATION=0\nSTART_UNIX_MS=0\nACTION=SENDMETA\nACTION=START\n"
)


def emit(kind: str, **fields: object) -> None:
    """Write one flushed JSON protocol record, not a diagnostic log."""
    sys.stdout.write(json.dumps({"kind": kind, **fields}) + "\n")
    sys.stdout.flush()


def safe_fields(chunk: bytes, name: str) -> dict[str, str]:
    """Retain only fixed protocol enums and bounded MRP status codes."""
    result = {}
    allowed = SAFE_FIELDS.get(name, {})
    for field in chunk.split()[2:]:
        key, _, value = field.partition(b"=")
        numeric = (
            name == "homepod_remote"
            and key in SAFE_NUMBERS
            and NUMBER.fullmatch(value)
            and SAFE_NUMBERS[key][0] <= int(value) <= SAFE_NUMBERS[key][1]
        )
        if (
            numeric
            or value in allowed.get(key, set())
            or (name == "mrp" and key == b"status" and MRP_STATUS.fullmatch(value))
        ):
            result[key.decode("ascii")] = value.decode("ascii")
    return result


class Reader:
    """Drain bounded lines; retain only protocol names and latched state."""

    def __init__(self, stream: IO[bytes]) -> None:
        self.stream = stream
        self.records: queue.Queue[tuple[str, str, dict[str, str]]] = queue.Queue(
            maxsize=128
        )
        self.admission_enabled = threading.Event()
        self.admission_denied = threading.Event()
        self.connected = threading.Event()
        self.started = threading.Event()
        self.failed = threading.Event()
        self.audio = threading.Event()
        self.ptp_ready = threading.Event()
        self.ntp_seen = threading.Event()
        self.version = threading.Event()
        self.thread = threading.Thread(target=self.drain, daemon=True)
        self.thread.start()

    def drain(self) -> None:
        """Discard oversized lines and all unrecognized or sensitive fields."""
        oversized = False
        while chunk := self.stream.readline(1025):
            complete = chunk.endswith(b"\n")
            if oversized or len(chunk) > 1024:
                oversized = not complete
                continue
            oversized = not complete
            if VERSION.fullmatch(chunk):
                self.version.set()
            match = MACHINE.match(chunk)
            if not match:
                continue
            kind, name = (value.decode("ascii").lower() for value in match.groups())
            if kind == "status":
                fields = set(chunk.split()[2:])
                if name == "audio" and any(AUDIO.fullmatch(field) for field in fields):
                    self.audio.set()
                if name == "clock_ready":
                    if b"mode=ntp" in fields:
                        self.ntp_seen.set()
                    if {b"mode=ptp", b"state=ready"} <= fields:
                        self.ptp_ready.set()
                if name == "homepod_remote_admission":
                    if b"enabled=0" in fields:
                        self.admission_denied.set()
                    if b"enabled=1" in fields:
                        self.admission_enabled.set()
                if name == "connected":
                    self.connected.set()
                elif name == "started":
                    self.started.set()
                elif name in {"error", "stopped", "eof", "idle_timeout"}:
                    self.failed.set()
            try:
                self.records.put_nowait((kind, name, safe_fields(chunk, name)))
            except queue.Full:
                pass


def stop(child: subprocess.Popen[bytes]) -> None:
    """Reap the child, escalating TERM to KILL after three seconds."""
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
    child.wait()


def child_env(type130: int, experimental_homepod_remote: int = 0) -> dict[str, str]:
    """Pass only platform runtime variables, never inherited auth or tokens."""
    return (
        {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "TMPDIR")
            if key in os.environ
        }
        | {
            "CLIAIRPLAY_MRP": "1",
            "CLIAIRPLAY_MRP_TYPE130": str(type130),
            "CLIAIRPLAY_BUFFERED": "0",
        }
        | (
            {"CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE": "1"}
            if experimental_homepod_remote == 1
            else {}
        )
    )


def check_binary(binary: str, env: dict[str, str], deadline: float) -> None:
    """Validate bounded version output within the shared TTL and three seconds."""
    with subprocess.Popen(
        [binary, "--check"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env
    ) as child:
        assert child.stdout is not None
        reader = Reader(child.stdout)
        try:
            child.wait(timeout=max(0, min(3, deadline - time.monotonic())))
        finally:
            stop(child)
            reader.thread.join(timeout=1)
        if child.returncode != 0 or not reader.version.is_set():
            raise ValueError("Invalid `cliairplay --check` response")


def probe(opts: argparse.Namespace) -> bool:
    """Run one sender within one absolute TTL; always clean up the FIFO and child."""
    deadline = time.monotonic() + opts.duration
    env = child_env(opts.type130, opts.experimental_homepod_remote)
    check_binary(str(opts.binary), env, deadline)
    if time.monotonic() >= deadline:
        return False
    with tempfile.TemporaryDirectory(prefix="native-relay-probe-") as directory:
        fifo = Path(directory) / "commands"
        os.mkfifo(fifo, 0o600)
        fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        try:
            cmd = [
                str(opts.binary),
                "--protocol",
                "airplay2",
                "--ap2-native",
                "--timing",
                opts.timing,
                "--port",
                "7000",
                "--volume",
                "0",
                "--name",
                "AirPlay relay probe",
                "--dacp",
                "A17A00000000BEEF",
                "--txt",
                "model=AudioAccessory5,1 osvers=27.0 igl=1 features=0x4A7FCA00,0x3C354BD0",
                "--samplerate",
                "44100",
                "--bitdepth",
                "16",
                "--channels",
                "2",
                "--if",
                opts.bind,
                "--debug",
                str(opts.debug),
                "--cmdpipe",
                str(fifo),
                opts.host,
            ]
            with (
                Path("/dev/zero").open("rb") as silence,
                subprocess.Popen(
                    cmd,
                    stdin=silence,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                ) as child,
            ):
                assert child.stdout is not None
                reader = Reader(child.stdout)
                sent = ready = False
                emitted = 0
                connect_deadline = min(deadline, time.monotonic() + 20)
                try:
                    while time.monotonic() < deadline:
                        while emitted < 256:
                            try:
                                kind, name, fields = reader.records.get_nowait()
                            except queue.Empty:
                                break
                            emit(kind, name=name, **fields)
                            emitted += 1
                        if (
                            opts.experimental_homepod_remote == 1
                            and reader.admission_denied.is_set()
                        ):
                            break
                        if reader.failed.is_set() or (
                            opts.timing == "ptp" and reader.ntp_seen.is_set()
                        ):
                            break
                        clock_ready = opts.timing == "ntp" or reader.ptp_ready.is_set()
                        if (
                            reader.connected.is_set()
                            and reader.audio.is_set()
                            and clock_ready
                            and (
                                opts.experimental_homepod_remote == 0
                                or reader.admission_enabled.is_set()
                            )
                            and not sent
                        ):
                            if os.write(fd, COMMANDS) != len(COMMANDS):
                                raise OSError("Incomplete atomic FIFO write")
                            sent = True
                        if sent and reader.started.is_set() and not ready:
                            emit("ready", connected=True, started=True)
                            ready = True
                        if child.poll() is not None:
                            break
                        if not sent and time.monotonic() >= connect_deadline:
                            break
                        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
                    exited = child.poll()
                finally:
                    stop(child)
                    reader.thread.join(timeout=1)
                return (
                    ready
                    and not reader.failed.is_set()
                    and exited is None
                    and not (
                        opts.experimental_homepod_remote == 1
                        and reader.admission_denied.is_set()
                    )
                    and not (opts.timing == "ptp" and reader.ntp_seen.is_set())
                )
        finally:
            os.close(fd)


def ipv4(value: str) -> str:
    """Require a literal IPv4 address, never DNS."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError("Expected literal IPv4") from exc


def binary_path(value: str) -> Path:
    """Require an absolute, executable file before spawning anything."""
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError("Expected absolute executable file")
    return path.resolve()


def parser() -> argparse.ArgumentParser:
    """Build the deliberately small, credential-free CLI."""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--binary", type=binary_path, required=True)
    result.add_argument("--host", type=ipv4, required=True)
    result.add_argument("--bind", type=ipv4, required=True)
    result.add_argument("--type130", type=int, choices=(0, 1), required=True)
    result.add_argument(
        "--experimental-homepod-remote", type=int, choices=(0, 1), default=0
    )
    result.add_argument("--duration", type=int, choices=range(1, 121), default=45)
    result.add_argument("--debug", type=int, choices=(0, 1), default=0)
    result.add_argument("--timing", choices=("ntp", "ptp"), default="ntp")
    return result


def interrupted(signum: int, frame: object) -> None:
    """Route termination through normal child/FIFO cleanup."""
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    """Emit a sanitized final result even for runtime failure or interruption."""
    opts = parser().parse_args(argv)
    previous = signal.signal(signal.SIGTERM, interrupted)
    success = False
    reason = "not_started"
    try:
        success = probe(opts)
        reason = "completed" if success else "not_ready_or_terminal_error"
    except (OSError, ValueError, subprocess.SubprocessError):
        reason = "probe_failed"
    except KeyboardInterrupt:
        reason = "interrupted"
    finally:
        signal.signal(signal.SIGTERM, previous)
        emit("result", success=success, reason=reason)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
