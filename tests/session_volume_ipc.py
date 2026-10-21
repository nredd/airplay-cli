"""Exercise the test-only C encrypted driver and real FIFO command reader.

References:
    ../build/session-volume-contract.md.
    session_volume_harness.h.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import tempfile
import unittest
from pathlib import Path

BINARY = Path(__file__).resolve().parents[1] / "build/tests/test_live_metadata"


class SessionVolumeIpcTest(unittest.TestCase):
    """Run a synthetic backend across process and FIFO boundaries."""

    def test_committed_clamp(self) -> None:
        """Require the requested level to stay uncommitted until feedback."""
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp) / "commands"
            os.mkfifo(fifo)
            with subprocess.Popen(
                [str(BINARY), "--session-volume-harness", str(fifo)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as child:
                self.assertIsNotNone(child.stdout)
                if child.stdout is None:
                    self.fail("Missing harness stdout")
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        self.assertTrue(
                            selector.select(3), "Missing compiled handshake"
                        )
                        self.assertEqual(
                            child.stdout.readline(),
                            b"[STATUS] session_volume version=1\n",
                        )
                        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                        try:
                            # Split one staging key, then coalesce two complete
                            # transactions. No field can leak across ACTION.
                            os.write(fd, b"SESSION_VOLUME_GENER")
                            os.write(
                                fd,
                                b"ATION=7\nSESSION_VOLUME_OUTPUT_UID_HEX=500052\n"
                                b"SESSION_VOLUME_ENDPOINT_UID_HEX=\nACTION=SESSION_VOLUME_BIND\n"
                                b"SESSION_VOLUME_GENERATION=7\nSESSION_VOLUME_REVISION=1\n"
                                b"SESSION_VOLUME_KNOWN=1\nSESSION_VOLUME_MILLI=0\n"
                                b"ACTION=SESSION_VOLUME_STATE\n",
                            )
                            # communicate() reads the remaining stdout after
                            # sending a completion; block only until Set exists.
                            lines = []
                            while True:
                                line = child.stdout.readline()
                                self.assertTrue(line, "Harness exited before request")
                                lines.append(line)
                                if line.startswith(b"[EVENT] session_volume_set "):
                                    self.assertEqual(
                                        line,
                                        b"[EVENT] session_volume_set generation=7 ordinal=1 milli=630\n",
                                    )
                                    break
                            os.write(
                                fd,
                                b"SESSION_VOLUME_GENERATION=7\nSESSION_VOLUME_ORDINAL=1\n"
                                b"SESSION_VOLUME_RESULT=committed\nSESSION_VOLUME_REVISION=2\n"
                                b"SESSION_VOLUME_KNOWN=1\nSESSION_VOLUME_MILLI=610\n"
                                b"ACTION=SESSION_VOLUME_COMPLETE\n",
                            )
                        finally:
                            os.close(fd)
                    stdout, stderr = child.communicate(timeout=4)
                    self.assertEqual(child.returncode, 0, stderr.decode())
                    self.assertIn(
                        b"session_volume_harness committed=1 milli=610", stdout
                    )
                    self.assertNotIn(b"500052", stdout + stderr + b"".join(lines))
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate()


if __name__ == "__main__":
    unittest.main()
