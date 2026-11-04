"""Exercise the real current-image acknowledgement CLI without receiver I/O."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

NONCE = "0123456789abcdef0123456789abcdef"


def invoke(
    binary: Path, args: list[str], descriptor: int | None = None, *, bind: bool = True
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded invocation with only the requested inherited descriptor."""
    return subprocess.run(
        [str(binary), *args],
        executable=f"/proc/self/fd/{descriptor}"
        if bind and descriptor is not None and sys.platform == "linux"
        else None,
        pass_fds=(descriptor,) if descriptor is not None else (),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=5,
        check=False,
        env={"PATH": "/usr/bin:/bin"},
    )


def require_rejection(binary: Path, args: list[str]) -> None:
    """Require an invalid private invocation to fail before streaming setup."""
    result = invoke(binary, [*args, "--attest-only"])
    if result.returncode == 0 or result.stdout:
        raise AssertionError(f"invalid attestation invocation succeeded: {args!r}")


def require_hostname_cleanup(binary: Path, cmdpipe: Path) -> None:
    """Require a hostname-resolved loopback connection and bounded FIFO cleanup.

    Parameters:
        binary (Path): Absolute path to the CLI executable under test.
        cmdpipe (Path): Temporary FIFO path owned by this invocation.

    Raises:
        AssertionError: Connection, error reporting, or cleanup violates the contract.
        OSError: Listener setup or process creation fails.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        process = subprocess.Popen(
            [
                str(binary),
                "--protocol",
                "raop",
                "--port",
                str(listener.getsockname()[1]),
                "--cmdpipe",
                str(cmdpipe),
                "localhost",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin"},
        )
        connected = False
        timed_out = False
        try:
            try:
                connection, _ = listener.accept()
                with connection:
                    connected = True
            except TimeoutError:
                timed_out = True
                process.kill()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                stdout, stderr = process.communicate()
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
    if (
        not connected
        or timed_out
        or process.returncode != 1
        or b'[STATUS] error code=connect_failed http=0 detail="RAOP connect failed"'
        not in stderr
        or cmdpipe.exists()
    ):
        raise AssertionError(
            "localhost resolution or failed-connection cleanup changed: "
            f"connected={connected} timed_out={timed_out} "
            f"status={process.returncode} fifo_exists={cmdpipe.exists()} "
            f"stdout={stdout!r} stderr={stderr!r}"
        )


def main(binary: Path) -> None:
    """Validate parser rejection and Linux FD-bound acknowledgement semantics."""
    binary = binary.resolve(strict=True)
    checked = invoke(binary, ["--check"])
    if checked.returncode != 0 or not checked.stdout.endswith(b" check\n"):
        raise AssertionError("ordinary self-check changed")
    for args in (
        [],
        ["--attest-fd", "3"],
        ["--attest-nonce", NONCE],
        ["--attest-fd", "-1", "--attest-nonce", NONCE],
        ["--attest-fd", "3", "--attest-nonce", NONCE.upper()],
        ["--attest-fd", "3", "--attest-fd", "3", "--attest-nonce", NONCE],
    ):
        require_rejection(binary, args)
    result = invoke(binary, ["--help", "--attest-only"])
    if result.returncode == 0 or result.stdout:
        raise AssertionError("help bypassed attestation parser rejection")
    with tempfile.TemporaryDirectory() as directory:
        require_hostname_cleanup(binary, Path(directory) / "command")
    if sys.platform != "linux":
        return

    descriptor = os.open(binary, os.O_RDONLY)
    try:
        hasher = hashlib.sha256()
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            while block := stream.read(65536):
                hasher.update(block)
        digest = hasher.hexdigest()
        args = [
            "--attest-fd",
            str(descriptor),
            "--attest-nonce",
            NONCE,
            "--attest-only",
        ]
        result = invoke(binary, args, descriptor)
        if result.returncode != 0 or result.stderr:
            raise AssertionError("FD-bound image acknowledgement failed")
        output = result.stdout
        if output.count(b"\n") != 1 or not output.startswith(b"[ATTEST] "):
            raise AssertionError("acknowledgement was not exactly one line")
        expected_ack = {
            "version": 1,
            "kind": "current-image-match-at-ack",
            "nonce": NONCE,
            "exec_fd_sha256": digest,
            "self_sha256": digest,
        }
        if json.loads(output[len(b"[ATTEST] ") :]) != expected_ack:
            raise AssertionError("acknowledgement did not bind the running image")
        for continued in ([*args[:-1], "--check"], ["--check", *args[:-1]]):
            result = invoke(binary, continued, descriptor)
            lines = result.stdout.splitlines()
            if (
                result.returncode != 0
                or result.stderr
                or len(lines) != 2
                or not lines[0].startswith(b"[ATTEST] ")
                or json.loads(lines[0][len(b"[ATTEST] ") :]) != expected_ack
                or not lines[1].endswith(b" check")
            ):
                raise AssertionError(
                    "attestation did not precede continued --check output"
                )
    finally:
        os.close(descriptor)

    with tempfile.TemporaryDirectory() as directory:
        other = Path(directory) / "other"
        other.write_bytes(b"not the executing image")
        descriptor = os.open(other, os.O_RDONLY)
        try:
            result = invoke(
                binary,
                [
                    "--attest-fd",
                    str(descriptor),
                    "--attest-nonce",
                    NONCE,
                    "--attest-only",
                ],
                descriptor,
                bind=False,
            )
            if result.returncode == 0 or result.stdout:
                raise AssertionError("different executed image was accepted")
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: attestation_cli.py <built-cli>")
    main(Path(sys.argv[1]))
