"""Offline sender lifecycle tests; fake executable never opens a network socket.

References:
    ../scripts/native_sender_probe.py.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import native_sender_probe as probe


class NativeSenderProbeTest(unittest.TestCase):
    """Exercise real local child/FIFO handling without touching receivers."""

    def setUp(self) -> None:
        """Create an isolated executable whose behavior is controlled by the test."""
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.binary = Path(self.tmp.name) / "fake-sender"
        self.capture = Path(self.tmp.name) / "capture.json"
        self.make_binary()

    def make_binary(self, mode: str = "success") -> None:
        """Write a local stand-in implementing only the check and FIFO protocol."""
        self.binary.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent(f"""\
                import json, os, pathlib, signal, sys, time
                mode = {mode!r}
                if '--check' in sys.argv:
                    if mode == 'check_timeout':
                        time.sleep(10)
                    print('bad check' if mode == 'malformed' else 'cliairplay v1.2.3 check', flush=True)
                    sys.exit(0)
                args = sys.argv[1:]
                fifo = args[args.index('--cmdpipe') + 1]
                capture = pathlib.Path({str(self.capture)!r})
                data = {{'args': args, 'env': dict(os.environ), 'fifo': fifo, 'pid': os.getpid()}}
                capture.write_text(json.dumps(data))
                if mode == 'early_exit':
                    sys.exit(2)
                if mode == 'unreachable':
                    time.sleep(10)
                fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                try:
                    data['before_connected'] = os.read(fd, 4096).hex()
                except BlockingIOError:
                    data['before_connected'] = ''
                os.close(fd)
                print('RAW SECRET pairing token=do-not-emit', flush=True)
                print('[STATUS] connected secret=do-not-emit', flush=True)
                timing = args[args.index('--timing') + 1]
                if mode == 'fallback':
                    print('[STATUS] clock_ready mode=ntp state=ready', flush=True)
                elif mode != 'clock_not_ready':
                    print('[STATUS] clock_ready mode=' + timing + ' state=ready', flush=True)
                if mode != 'no_audio':
                    print('[STATUS] audio buffered_ms=100', flush=True)
                with open(fifo, 'rb', buffering=0) as commands:
                    data['commands'] = commands.read({len(probe.COMMANDS)}).decode()
                data['silence'] = sys.stdin.buffer.read(32).hex()
                capture.write_text(json.dumps(data))
                if mode == 'never_started':
                    time.sleep(10)
                print('[STATUS] started at_unix_ms=123', flush=True)
                if mode == 'clean_exit_after_start':
                    time.sleep(0.1)
                    sys.exit(0)
                if mode == 'error':
                    print('[STATUS] error detail=do-not-emit', flush=True)
                time.sleep(10)
                """),
            encoding="utf-8",
        )
        self.binary.chmod(0o700)

    def args(self, *extra: str) -> list[str]:
        """Return literal loopback arguments; the fake never connects anywhere."""
        return [
            "--binary",
            str(self.binary),
            "--host",
            "127.0.0.1",
            "--bind",
            "127.0.0.2",
            "--type130",
            "1",
            "--duration",
            "1",
            *extra,
        ]

    def run_probe(self, *extra: str) -> tuple[int, str]:
        """Capture the machine protocol without storing raw fake diagnostics."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = probe.main(self.args(*extra))
        return code, output.getvalue()

    def assert_cleaned(self) -> dict[str, object]:
        """Assert the FIFO directory and child process have disappeared."""
        data = json.loads(self.capture.read_text())
        self.assertFalse(Path(data["fifo"]).parent.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(data["pid"], 0)
        return data

    def test_success_silent_metadata_flags_and_sanitized_output(self) -> None:
        """Use the real local FIFO and child, checking privacy and fixed flags."""
        with patch.dict(
            os.environ, {"HA_TOKEN": "private", "CLIAIRPLAY_AUTH": "private"}
        ):
            code, output = self.run_probe()
        self.assertEqual(code, 0, output)
        records = [json.loads(line) for line in output.splitlines()]
        self.assertEqual(sum(record["kind"] == "ready" for record in records), 1)
        self.assertTrue(records[-1]["success"])
        self.assertEqual(records[0]["sender_relay"], 0)
        self.assertEqual(records[0]["multiselect"], 0)
        self.assertEqual(records[0]["ptp_follow"], "auto")
        self.assertNotIn("do-not-emit", output)
        data = self.assert_cleaned()
        self.assertEqual(data["before_connected"], "")
        self.assertEqual(data["commands"], probe.COMMANDS.decode())
        self.assertEqual(data["silence"], "00" * 32)
        args = data["args"]
        assert isinstance(args, list)
        expected = {
            "--volume": "0",
            "--timing": "ntp",
            "--dacp": "A17A00000000BEEF",
            "--port": "7000",
            "--if": "127.0.0.2",
            "--samplerate": "44100",
            "--bitdepth": "16",
            "--channels": "2",
            "--debug": "0",
        }
        for flag, value in expected.items():
            self.assertIn(
                [flag, value], [args[i : i + 2] for i in range(len(args) - 1)]
            )
        self.assertNotIn("private", str(data["env"]))
        self.assertIn("'CLIAIRPLAY_MRP_TYPE130': '1'", str(data["env"]))
        self.assertIn("'CLIAIRPLAY_BUFFERED': '0'", str(data["env"]))

    def test_probe_enums_and_environment_isolation(self) -> None:
        """Only explicit enums enter the child, never inherited probe settings."""
        keys = (
            "CLIAIRPLAY_PROBE_SENDER_RELAY",
            "CLIAIRPLAY_PROBE_MULTISELECT",
            "CLIAIRPLAY_PTP_FOLLOW",
        )
        with patch.dict(os.environ, dict.fromkeys(keys, "private")):
            for relay in (0, 1):
                for multi in (0, 1):
                    for follow in ("auto", "0", "1"):
                        with self.subTest(relay=relay, multi=multi, follow=follow):
                            env = probe.child_env(1, relay, multi, follow)
                            expected = {}
                            if relay:
                                expected[keys[0]] = "1"
                            if multi:
                                expected[keys[1]] = "1"
                            if follow != "auto":
                                expected[keys[2]] = follow
                            self.assertEqual(
                                {key: env[key] for key in keys if key in env}, expected
                            )
                            self.assertNotIn("private", str(env))
            self.assertTrue(set(keys).isdisjoint(probe.child_env(0)))
        for args in (
            (2, 0, 0, "auto"),
            (0, 2, 0, "auto"),
            (0, 0, 2, "auto"),
            (0, 0, 0, "yes"),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                probe.child_env(*args)

    def test_explicit_probe_options_and_safe_configuration(self) -> None:
        """Record fixed configuration enums and propagate options to the child."""
        code, output = self.run_probe(
            "--sender-relay", "1", "--multiselect", "1", "--ptp-follow", "0"
        )
        self.assertEqual(code, 0, output)
        cfg = json.loads(output.splitlines()[0])
        self.assertEqual(
            cfg,
            {
                "kind": "configuration",
                "type130": 1,
                "timing": "ntp",
                "debug": 0,
                "duration": 1,
                "sender_relay": 1,
                "multiselect": 1,
                "ptp_follow": "0",
            },
        )
        self.assertNotIn(str(self.binary), output)
        self.assertNotIn("127.0.0.1", output)
        env = self.assert_cleaned()["env"]
        assert isinstance(env, dict)
        self.assertEqual(env["CLIAIRPLAY_PROBE_SENDER_RELAY"], "1")
        self.assertEqual(env["CLIAIRPLAY_PROBE_MULTISELECT"], "1")
        self.assertEqual(env["CLIAIRPLAY_PTP_FOLLOW"], "0")

    def test_probe_option_defaults_and_rejection(self) -> None:
        """Defaults leave all probes off; malformed values fail before launch."""
        opts = probe.parser().parse_args(self.args())
        self.assertEqual(
            (opts.sender_relay, opts.multiselect, opts.ptp_follow), (0, 0, "auto")
        )
        for flag in ("--sender-relay", "--multiselect", "--ptp-follow"):
            for value in ("2", "yes", "private"):
                with (
                    self.subTest(flag=flag, value=value),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    probe.parser().parse_args(self.args(flag, value))

    def test_failures_and_cleanup(self) -> None:
        """Reject malformed checks, unreachable targets, missing starts and errors."""
        for mode in (
            "malformed",
            "early_exit",
            "unreachable",
            "never_started",
            "error",
        ):
            with self.subTest(mode=mode):
                self.capture.unlink(missing_ok=True)
                self.make_binary(mode)
                code, output = self.run_probe()
                self.assertEqual(code, 1, output)
                self.assertFalse(json.loads(output.splitlines()[-1])["success"])
                if self.capture.exists():
                    self.assert_cleaned()

    def test_ptp_success_and_readiness_failures(self) -> None:
        """PTP requires ready PTP clock plus audio; NTP fallback is a failure."""
        for mode, timing, expected in (
            ("success", "ptp", 0),
            ("clock_not_ready", "ptp", 1),
            ("fallback", "ptp", 1),
            ("no_audio", "ptp", 1),
            ("no_audio", "ntp", 1),
        ):
            with self.subTest(mode=mode, timing=timing):
                self.make_binary(mode)
                code, output = self.run_probe("--timing", timing)
                self.assertEqual(code, expected, output)
                data = self.assert_cleaned()
                if expected:
                    self.assertNotIn("commands", data)
                    self.assertNotIn('"kind": "ready"', output)

    def test_clean_exit_after_start_fails(self) -> None:
        """A silent sender must stay alive for the whole TTL, even after START."""
        self.make_binary("clean_exit_after_start")
        code, output = self.run_probe()
        self.assertEqual(code, 1, output)
        records = [json.loads(line) for line in output.splitlines()]
        self.assertTrue(any(record["kind"] == "ready" for record in records))
        self.assertFalse(records[-1]["success"])
        self.assertEqual(records[-1]["reason"], "not_ready_or_terminal_error")
        self.assert_cleaned()

    def test_check_timeout(self) -> None:
        """A hanging check is killed and never launches a sender."""
        self.make_binary("check_timeout")
        self.assertEqual(self.run_probe()[0], 1)
        self.assertFalse(self.capture.exists())

    def test_launch_open_and_write_failures(self) -> None:
        """Opening silence, spawning and FIFO writes all clean up acquired state."""
        for target in (
            "scripts.native_sender_probe.Path.open",
            "scripts.native_sender_probe.os.open",
            "scripts.native_sender_probe.subprocess.Popen",
            "scripts.native_sender_probe.os.write",
        ):
            with (
                self.subTest(target=target),
                patch.object(probe, "check_binary"),
                patch(target, side_effect=OSError("private detail")),
            ):
                code, output = self.run_probe()
                self.assertEqual(code, 1)
                self.assertNotIn("private detail", output)
        if self.capture.exists():
            self.assert_cleaned()

    def test_safe_status_fields(self) -> None:
        """Keep relay-path outcomes without arbitrary or credential fields."""
        self.assertEqual(
            probe.safe_fields(
                b"[STATUS] mrp path=channel status=1 token=hidden detail=hidden", "mrp"
            ),
            {"path": "channel", "status": "1"},
        )
        self.assertEqual(
            probe.safe_fields(b"[STATUS] mrp path=hidden status=hidden", "mrp"), {}
        )
        self.assertEqual(
            probe.safe_fields(
                b"[STATUS] clock_ready mode=ptp state=ready secret=hidden",
                "clock_ready",
            ),
            {"mode": "ptp", "state": "ready"},
        )
        self.assertEqual(
            probe.safe_fields(b"[EVENT] remote command=hidden", "remote"), {}
        )
        self.assertEqual(
            probe.safe_fields(
                b'[STATUS] error code=auth_required http=403 detail="hidden"', "error"
            ),
            {"code": "auth_required", "http": "403"},
        )
        self.assertEqual(
            probe.safe_fields(b"[STATUS] error code=hidden http=hidden", "error"), {}
        )

    def test_reader_bounds_and_terminal_latches(self) -> None:
        """Flooding and oversized secret lines cannot hide a terminal error."""
        stream = io.BytesIO(
            b"[STATUS] error secret="
            + b"x" * 5000
            + b"\n"
            + b"[EVENT] remote secret=hidden\n" * 1000
            + b"[STATUS] connected\n[STATUS] started\n[STATUS] error detail=hidden\n"
        )
        reader = probe.Reader(stream)
        reader.thread.join(timeout=1)
        self.assertEqual(reader.records.qsize(), 128)
        self.assertTrue(reader.connected.is_set())
        self.assertTrue(reader.started.is_set())
        self.assertTrue(reader.failed.is_set())
        self.assertNotIn("hidden", str(list(reader.records.queue)))

    def test_connection_deadline_and_no_ttl_extension(self) -> None:
        """Connection waiting stops at 20s even when the overall TTL is 120s."""
        self.make_binary("unreachable")
        opts = probe.parser().parse_args(self.args("--duration", "120"))
        clock = Mock(side_effect=range(0, 200, 5))
        with (
            patch.object(probe, "check_binary"),
            patch.object(probe.time, "monotonic", clock),
        ):
            self.assertFalse(probe.probe(opts))
        self.assertLess(clock.call_count * 5, 120)

    def test_expired_check_does_not_launch_sender(self) -> None:
        """A check exhausting the shared TTL must not start another child."""
        opts = probe.parser().parse_args(self.args())
        with (
            patch.object(probe, "check_binary"),
            patch.object(probe.time, "monotonic", side_effect=(0, 2)),
            patch.object(probe.subprocess, "Popen") as spawn,
        ):
            self.assertFalse(probe.probe(opts))
        spawn.assert_not_called()

    def test_escalation(self) -> None:
        """A child ignoring TERM gets KILL and is reaped."""
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("fake", 3), 0]
        probe.stop(child)
        child.terminate.assert_called_once()
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_count, 2)

    def test_interrupt_cleanup(self) -> None:
        """KeyboardInterrupt follows the same cleanup path as SIGTERM."""
        original_emit = probe.emit

        def interrupt_on_ready(kind: str, **fields: object) -> None:
            """Interrupt only after launch; do not patch subprocess's own sleeps."""
            if kind == "ready":
                raise KeyboardInterrupt
            original_emit(kind, **fields)

        with patch.object(probe, "emit", side_effect=interrupt_on_ready):
            code, output = self.run_probe()
        self.assertEqual(code, 1)
        self.assertIn("interrupted", output)
        if self.capture.exists():
            self.assert_cleaned()
        with self.assertRaises(KeyboardInterrupt):
            probe.interrupted(15, None)

    def test_validation(self) -> None:
        """Bad addresses, binaries, duration and mode fail before spawning."""
        for flag, value in (
            ("--host", "speaker.local"),
            ("--bind", "::1"),
            ("--binary", "./fake"),
            ("--duration", "0"),
            ("--duration", "121"),
            ("--duration", "1.5"),
            ("--type130", "2"),
            ("--debug", "2"),
            ("--timing", "auto"),
        ):
            with (
                self.subTest(flag=flag, value=value),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                probe.parser().parse_args(self.args(flag, value))


if __name__ == "__main__":
    unittest.main()
