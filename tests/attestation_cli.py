"""Exercise the real private attestation CLI without receiver or audio I/O.

References:
    https://man7.org/linux/man-pages/man2/execve.2.html
    https://man7.org/linux/man-pages/man2/pread.2.html
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

LOGGER = logging.getLogger(__name__)
NONCE = "0123456789abcdef0123456789abcdef"
MAX_OUTPUT = 1024


def invoke(
    binary: Path,
    args: list[str],
    descriptor: int | None = None,
    *,
    bind_execution: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run a bounded, environment-isolated preflight, never a streaming invocation."""
    command = [str(binary), *args]
    inherited = (descriptor,) if descriptor is not None and os.name == "posix" else ()
    result = subprocess.run(
        command,
        executable=f"/proc/self/fd/{descriptor}"
        if bind_execution and descriptor is not None and sys.platform == "linux"
        else None,
        pass_fds=inherited,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=5,
        check=False,
        env={"PATH": "/usr/bin:/bin"}
        | {
            key: os.environ[key]
            for key in ("ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS")
            if key in os.environ
        },
    )
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise AssertionError("Attestation output exceeded its bound")
    return result


def reject(binary: Path, args: list[str]) -> None:
    """Reject malformed private flags before any receiver or clock work."""
    result = invoke(binary, [*args, "--attest-only"])
    if result.returncode == 0 or result.stdout:
        raise AssertionError("Malformed attestation flags produced success or stdout")


def validate_ack(output: bytes, digest: str) -> None:
    """Require exactly one complete acknowledgement of the full image and nonce."""
    prefix = b"[ATTEST] "
    if (
        not output.startswith(prefix)
        or output.count(b"\n") != 1
        or not output.endswith(b"\n")
    ):
        raise AssertionError("Acknowledgement was not the only first stdout line")
    value = json.loads(output[len(prefix) :])
    expected = {
        "version": 1,
        "kind": "current-image-match-at-ack",
        "nonce": NONCE,
        "exec_fd_sha256": digest,
        "self_sha256": digest,
    }
    if value != expected or type(value.get("version")) is not int:
        raise AssertionError("Acknowledgement did not identify the exact current image")


def main(binary: Path) -> None:
    """Cover parser failures and supported/unsupported real executable preflights."""
    binary = binary.resolve(strict=True)
    checked = invoke(binary, ["--check"])
    if (
        checked.returncode != 0
        or not checked.stdout.startswith(b"cliairplay ")
        or not checked.stdout.endswith(b" check\n")
    ):
        raise AssertionError("Ordinary self-check behavior changed")
    later = invoke(binary, ["--check", "--unknown-after-check"])
    if later.returncode != 0 or later.stdout != checked.stdout:
        raise AssertionError("Ordinary self-check lost its historical short circuit")
    for bad_fd in ("-1", "0", "2", "2147483648", "+3", "0x3", "3x", "9" * 40):
        reject(binary, ["--attest-fd", bad_fd, "--attest-nonce", NONCE])
    for bad_nonce in ("", NONCE[:-1], NONCE + "0", NONCE.upper(), "g" * 32):
        reject(binary, ["--attest-fd", "3", "--attest-nonce", bad_nonce])
    for args in (
        [],
        ["--attest-fd", "3"],
        ["--attest-nonce", NONCE],
        ["--attest-fd", "3", "--attest-fd", "3", "--attest-nonce", NONCE],
        ["--attest-fd", "3", "--attest-nonce", NONCE, "--attest-nonce", NONCE],
        ["--attest-fd", "3", "--attest-nonce", NONCE, "--attest-only"],
    ):
        reject(binary, args)
    if sys.platform != "linux":
        reject(binary, ["--attest-fd", "3", "--attest-nonce", NONCE])
        LOGGER.info(
            "Real CLI parser and unsupported-platform fail-closed checks passed"
        )
        return
    descriptor = os.open(binary, os.O_RDONLY)
    try:
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            hasher = hashlib.sha256()
            for block in iter(lambda: stream.read(65536), b""):
                hasher.update(block)
            digest = hasher.hexdigest()
        end = os.lseek(descriptor, 0, os.SEEK_CUR)
        if end != binary.stat().st_size:
            raise AssertionError(
                "Fixture did not leave the inherited descriptor at EOF"
            )
        base = [
            "--attest-fd",
            str(descriptor),
            "--attest-nonce",
            NONCE,
            "--attest-only",
        ]
        for mode in ([], ["--ptp-daemon"], ["--pair"], ["--pair-setup"]):
            result = invoke(binary, [*base, *mode], descriptor)
            if result.returncode != 0 or result.stderr:
                raise AssertionError("Real FD-bound attestation preflight failed")
            validate_ack(result.stdout, digest)
            if os.lseek(descriptor, 0, os.SEEK_CUR) != end:
                raise AssertionError(
                    "Child changed the shared executable descriptor offset"
                )
    finally:
        os.close(descriptor)
    with tempfile.TemporaryDirectory(prefix="cliairplay-identity-") as directory:
        wrong = Path(directory) / "different-image"
        wrong.write_bytes(b"not the executing image")
        descriptor = os.open(wrong, os.O_RDONLY)
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
                bind_execution=False,
            )
            if result.returncode == 0 or result.stdout:
                raise AssertionError("An unexpected executed file was accepted")
        finally:
            os.close(descriptor)
    LOGGER.info("Real FD-bound CLI image and parser checks passed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 2:
        raise SystemExit("Usage: attestation_cli.py <built-cli>")
    main(Path(sys.argv[1]))
