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

    def test_session_volume_is_observation_only(self) -> None:
        """Allow fixed contract enums without retaining private IPC values."""
        cases = [
            ("session_volume", b"version=1", {"version": "1"}),
            (
                "session_volume_transport",
                b"ready=1 publication=0",
                {"ready": "1", "publication": "0"},
            ),
            ("session_volume_set", b"generation=7 ordinal=12 milli=630", {}),
            (
                "stream_volume_result",
                b"status=committed level=50",
                {"status": "committed"},
            ),
        ]
        for name, fields, expected in cases:
            chunk = (
                b"[EVENT] "
                + name.encode()
                + b" "
                + fields
                + b" uid=PRIVATE token=PRIVATE"
            )
            self.assertEqual(probe.safe_fields(chunk, name), expected)
            self.assertNotEqual(name, "remote")
        self.assertEqual(set(probe.TRANSPORT), {"play", "pause"})

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
                if mode == 'transport_privacy':
                    print('[STATUS] SecretStatusToken123 command=pause', flush=True)
                    print('[EVENT] SecretEventToken456 command=pause', flush=True)
                print('RAW SECRET pairing token=do-not-emit', flush=True)
                print('[STATUS] connected secret=do-not-emit', flush=True)
                if mode != 'old_binary':
                    enabled = '1' if os.environ.get('CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE') == '1' and mode != 'ineligible' else '0'
                    print('[STATUS] homepod_remote_admission enabled=' + enabled, flush=True)
                    print('[STATUS] homepod_remote ordinal=1 elapsed_ms=0 channel=event frame_kind=command classification=command command=play protobuf_type=-1 bytes=123 dispatched=1 secret=do-not-emit', flush=True)
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
                if mode == 'transport_pre':
                    print('[EVENT] remote command=pause', flush=True)
                    time.sleep(0.08)
                print('[STATUS] started at_unix_ms=123', flush=True)
                if mode.startswith('transport_'):
                    fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                    scenarios = {{
                        'transport_sequence': ['pause', 'play', 'play_pause'],
                        'transport_privacy': ['pause', 'play'],
                        'transport_volume': [],
                        'transport_duplicates': ['play', 'pause', 'pause', 'play', 'play'],
                        'transport_storm': ['play_pause'] * 1000,
                        'transport_spaced': ['play_pause', 'play_pause'],
                        'transport_navigation': ['next', 'previous'],
                        'transport_pre': [],
                        'transport_malicious': ['SECRET', 'pauseSECRET', 'pause command=SECRET', 'SECRET command=pause'],
                        'transport_exit': ['pause'],
                        'transport_error': ['pause'],
                    }}
                    data['actions'] = ''
                    capture.write_text(json.dumps(data))
                    if mode == 'transport_volume':
                        for channel in ('event', 'datastream'):
                            for message in ('receiver_telemetry', 'volume_set_candidate', 'volume_feedback', 'volume_get', 'volume_result', 'volume_capability', 'unknown', 'invalid'):
                                print('[STATUS] homepod_remote channel=' + channel + ' message=' + message + ' target=unresolved value_state=valid value_milli=500 available=1 capabilities=3 dispatched=0 command=pause SECRET_FIELD=SECRET_VALUE', flush=True)
                        print('[EVENT] homepod_remote message=volume_set_candidate command=pause', flush=True)
                        print('[EVENT] remote command=volume', flush=True)
                    for command in scenarios[mode]:
                        print('[EVENT] remote command=' + command + ' token=SECRET', flush=True)
                        if mode in ('transport_exit', 'transport_error'):
                            continue
                        if mode != 'transport_storm':
                            time.sleep(0.3 if mode == 'transport_spaced' else 0.06)
                    if mode == 'transport_exit':
                        os._exit(0)
                    if mode == 'transport_error':
                        print('[STATUS] error detail=SECRET', flush=True)
                    end = time.monotonic() + 2
                    while time.monotonic() < end:
                        try:
                            actions = os.read(fd, 4096).decode()
                        except BlockingIOError:
                            actions = ''
                        if actions:
                            data['actions'] += actions
                            for action in actions.splitlines():
                                print('[STATUS] paused' if action == 'ACTION=PAUSE' else '[STATUS] playing', flush=True)
                            capture.write_text(json.dumps(data))
                        time.sleep(0.01)
                    os.close(fd)
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

    def test_experimental_admission_is_explicit_and_required(self) -> None:
        """Never inherit admission; an old or ineligible binary cannot START."""
        with patch.dict(os.environ, {"CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE": "1"}):
            self.assertNotIn(
                "CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE", probe.child_env(1, 0)
            )
            env = probe.child_env(0, 1)
            self.assertEqual(env["CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE"], "1")
            self.assertEqual(env["CLIAIRPLAY_MRP_TYPE130"], "0")
        with patch.dict(os.environ, {"CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE": "1"}):
            code, output = self.run_probe()
        self.assertEqual(code, 0, output)
        data = self.assert_cleaned()
        env = data["env"]
        assert isinstance(env, dict)
        self.assertNotIn("CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE", env)
        for mode, expected in (("success", 0), ("old_binary", 1), ("ineligible", 1)):
            with self.subTest(mode=mode):
                self.make_binary(mode)
                code, output = self.run_probe("--experimental-homepod-remote", "1")
                self.assertEqual(code, expected, output)
                data = self.assert_cleaned()
                self.assertIn(
                    "'CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE': '1'", str(data["env"])
                )
                if expected:
                    self.assertNotIn("commands", data)
                else:
                    records = [json.loads(line) for line in output.splitlines()]
                    diagnostic = next(
                        r for r in records if r.get("name") == "homepod_remote"
                    )
                    self.assertEqual(diagnostic["dispatched"], "1")
                    self.assertEqual(diagnostic["bytes"], "123")
                    self.assertNotIn("do-not-emit", output)

    def test_posix_volume_observations_never_request_actions(self) -> None:
        """Real fake-producer telemetry cannot reach the owned action FIFO."""
        for respond in ("0", "1"):
            with self.subTest(respond=respond):
                self.make_binary("transport_volume")
                code, output = self.run_probe("--respond-transport", respond)
                self.assertEqual(code, 0, output)
                data = self.assert_cleaned()
                self.assertEqual(data["actions"], "")
                self.assertNotIn("SECRET", output)
                self.assertNotIn("534543524554", output)
                records = [json.loads(line) for line in output.splitlines()]
                observations = [r for r in records if r.get("name") == "homepod_remote"]
                self.assertTrue(
                    any(
                        r.get("message") == "volume_set_candidate" for r in observations
                    )
                )
                self.assertFalse(any(r.get("kind") == "fifo_action" for r in records))
                self.assertFalse(
                    any(
                        r.get("kind") == "event" and r.get("name") == "homepod_remote"
                        for r in records
                    )
                )

    def test_c_volume_diagnostic_contract(self) -> None:
        """Retain actual encrypted C fixture output without FIFO eligibility.

        `mrp_volume_fixture.h` checks these captured lines against real encrypted
        cases on every native test run, ignoring only local elapsed time.
        """
        golden = (
            Path(__file__).parent / "fixtures" / "homepod_volume_diagnostics.txt"
        ).read_bytes()
        lines = golden.splitlines()
        self.assertEqual(len(lines), 2)
        common = {
            "channel": "event",
            "frame_kind": "command",
            "classification": "protobuf",
            "command": "unknown",
            "dispatched": "0",
        }
        expected = [
            common
            | {
                "ordinal": "1",
                "elapsed_ms": "0",
                "protobuf_type": "51",
                "bytes": "85",
                "message": "volume_set_candidate",
                "target": "unresolved",
                "value_state": "valid",
                "value_milli": "500",
            },
            common
            | {
                "ordinal": "17",
                "elapsed_ms": "1",
                "protobuf_type": "17",
                "bytes": "74",
                "message": "volume_capability",
                "target": "missing",
                "value_state": "missing",
                "available": "1",
                "capabilities": "3",
            },
        ]
        self.assertEqual(
            [probe.safe_fields(line, "homepod_remote") for line in lines], expected
        )
        reader = probe.Reader(io.BytesIO(b"[STATUS] started\n" + golden), True)
        reader.thread.join(timeout=1)
        self.assertFalse(reader.thread.is_alive())
        self.assertTrue(reader.started.is_set())
        self.assertTrue(reader.commands.empty())
        self.assertEqual(
            list(reader.records.queue)[1:],
            [("status", "homepod_remote", fields) for fields in expected],
        )

    def test_volume_diagnostic_fields(self) -> None:
        """Only fixed enums and inclusive numeric bounds survive retention."""
        expected = {
            "message": "volume_feedback",
            "target": "unresolved",
            "value_state": "valid",
            "value_milli": "1000",
            "available": "0",
            "capabilities": "3",
        }
        self.assertEqual(
            probe.safe_fields(
                b"[STATUS] homepod_remote message=volume_feedback target=unresolved "
                b"value_state=valid value_milli=1000 available=0 capabilities=3 "
                b"SECRET_FIELD=SECRET_VALUE",
                "homepod_remote",
            ),
            expected,
        )
        for field in (
            b"message=SECRET",
            b"target=session_group",
            b"target=SECRET",
            b"value_state=SECRET",
            b"value_milli=-1",
            b"value_milli=1001",
            b"value_milli=NaN",
            b"value_milli=inf",
            b"available=2",
            b"capabilities=4",
            b"capabilities=-1",
        ):
            self.assertEqual(
                probe.safe_fields(
                    b"[STATUS] homepod_remote " + field, "homepod_remote"
                ),
                {},
            )
        for name in ("remote", "mrp", "route", "homepod_remote_admission"):
            self.assertEqual(
                probe.safe_fields(
                    b"[EVENT] remote value_milli=500 "
                    b"available=1 capabilities=3 message=volume_feedback",
                    name,
                ),
                {},
            )

    def test_diagnostic_allowlist_and_numeric_bounds(self) -> None:
        """Retain fixed classifications only; dispatched does not mean action executed."""
        safe = probe.safe_fields(
            b"[STATUS] homepod_remote ordinal=128 elapsed_ms=123 channel=datastream "
            b"frame_kind=sync classification=protobuf command=unknown protobuf_type=139 "
            b"bytes=65536 dispatched=0 type=SECRET value=SECRET token=SECRET",
            "homepod_remote",
        )
        self.assertEqual(safe["protobuf_type"], "139")
        self.assertEqual(safe["ordinal"], "128")
        self.assertNotIn("SECRET", str(safe))
        for field in (
            b"ordinal=129",
            b"elapsed_ms=-1",
            b"protobuf_type=65536",
            b"bytes=65537",
            b"bytes=01",
            b"bytes=999999999999999999999999",
            b"frame_kind=SECRET",
            b"command=SECRET",
            b"dispatched=2",
        ):
            self.assertEqual(
                probe.safe_fields(
                    b"[STATUS] homepod_remote " + field, "homepod_remote"
                ),
                {},
            )

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

    def test_reader_bounds_and_terminal_latches(self) -> None:
        """Flooding and oversized secret lines cannot hide a terminal error."""
        stream = io.BytesIO(
            b"[STATUS] error secret="
            + b"x" * 5000
            + b"\n"
            + b"[EVENT] remote secret=hidden\n" * 1000
            + b"[STATUS] homepod_remote_admission enabled=1\n"
            + b"[STATUS] connected\n[STATUS] started\n[STATUS] error detail=hidden\n"
        )
        reader = probe.Reader(stream)
        reader.thread.join(timeout=1)
        self.assertEqual(reader.records.qsize(), 128)
        self.assertTrue(reader.admission_enabled.is_set())
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

    def test_transport_actions_and_confirmations(self) -> None:
        """Only opt-in normalized events drive the same producer's FIFO after START."""
        for mode, extra, expected in (
            ("sequence", (), ""),
            ("sequence", ("--respond-transport", "0"), ""),
            (
                "sequence",
                ("--respond-transport", "1"),
                "ACTION=PAUSE\nACTION=PLAY\nACTION=PAUSE\n",
            ),
            ("duplicates", ("--respond-transport", "1"), "ACTION=PAUSE\nACTION=PLAY\n"),
            ("storm", ("--respond-transport", "1"), "ACTION=PAUSE\n"),
            ("spaced", ("--respond-transport", "1"), "ACTION=PAUSE\nACTION=PLAY\n"),
            ("navigation", ("--respond-transport", "1"), ""),
            ("pre", ("--respond-transport", "1"), ""),
            ("malicious", ("--respond-transport", "1"), ""),
        ):
            with self.subTest(mode=mode, extra=extra):
                self.make_binary("transport_" + mode)
                code, output = self.run_probe(*extra)
                self.assertEqual(code, 0, output)
                data = self.assert_cleaned()
                self.assertEqual(data["actions"], expected)
                self.assertNotIn("SECRET", output)
                records = [json.loads(line) for line in output.splitlines()]
                self.assertLessEqual(len(records), 258)
                actions = [r for r in records if r["kind"] == "fifo_action"]
                self.assertEqual(len(actions), len(expected.splitlines()))
                self.assertTrue(all(set(r) == {"kind", "action"} for r in actions))
                if expected:
                    self.assertTrue(any(r.get("name") == "paused" for r in records))
                if "ACTION=PLAY" in expected:
                    self.assertTrue(any(r.get("name") == "playing" for r in records))

    def test_transport_exit_and_failure_stop_writes(self) -> None:
        """A queued request cannot write after exit or a terminal status latch."""
        original_write = os.write
        for mode in ("transport_exit", "transport_error"):
            self.make_binary(mode)
            with patch.object(probe.os, "write", wraps=original_write) as writes:
                code, output = self.run_probe("--respond-transport", "1")
            self.assertEqual(code, 1, output)
            self.assertEqual(
                [call.args[1] for call in writes.call_args_list], [probe.COMMANDS]
            )
            self.assert_cleaned()

    def test_remote_enums_and_transport_queue_bounds(self) -> None:
        """Retain five public enums only, never telemetry commands or extra fields."""
        for command in ("play", "pause", "play_pause", "next", "previous"):
            self.assertEqual(
                probe.safe_fields(
                    f"[EVENT] remote command={command} secret=SECRET".encode(), "remote"
                ),
                {"command": command},
            )
        stream = io.BytesIO(
            b"[EVENT] remote command=pause\n"
            b"[STATUS] started\n"
            + b"[STATUS] remote command=pause\n" * 200
            + b"[EVENT] remote command=pause\n" * 1000
        )
        reader = probe.Reader(stream, True)
        reader.thread.join(timeout=1)
        self.assertEqual(reader.commands.qsize(), 128)
        self.assertEqual(reader.records.qsize(), 128)
        reader = probe.Reader(
            io.BytesIO(b"[STATUS] started\n[EVENT] remote command=pause\n")
        )
        reader.thread.join(timeout=1)
        self.assertTrue(reader.commands.empty())

    def test_reader_drops_unknown_machine_names(self) -> None:
        """Reject names before retention, with independent per-kind admission."""
        for respond in (False, True):
            with self.subTest(respond=respond):
                reader = probe.Reader(
                    io.BytesIO(
                        b"[STATUS] SecretStatusToken123 command=pause\n"
                        b"[EVENT] SecretEventToken456 command=pause\n"
                        b"[EVENT] started\n[STATUS] remote command=pause\n"
                        b"[STATUS] connected\n[STATUS] started\n"
                        b"[STATUS] homepod_remote_admission enabled=1\n"
                        b"[STATUS] homepod_remote command=play\n"
                        b"[EVENT] remote command=pause\n"
                        b"[STATUS] paused\n[STATUS] playing\n"
                    ),
                    respond,
                )
                reader.thread.join(timeout=1)
                records = list(reader.records.queue)
                serialized = json.dumps(records).lower()
                self.assertNotIn("secretstatustoken123", serialized)
                self.assertNotIn("secreteventtoken456", serialized)
                self.assertEqual(
                    [(kind, name) for kind, name, _ in records],
                    [
                        ("status", name)
                        for name in (
                            "connected",
                            "started",
                            "homepod_remote_admission",
                            "homepod_remote",
                        )
                    ]
                    + [
                        ("event", "remote"),
                        ("status", "paused"),
                        ("status", "playing"),
                    ],
                )
                self.assertTrue(reader.connected.is_set())
                self.assertTrue(reader.started.is_set())
                self.assertTrue(reader.admission_enabled.is_set())
                self.assertEqual(
                    list(reader.commands.queue), ["pause"] if respond else []
                )

    def test_posix_unknown_names_never_reach_json(self) -> None:
        """Injected child names stay private in observe and response modes."""
        for respond in ("0", "1"):
            with self.subTest(respond=respond):
                self.make_binary("transport_privacy")
                code, output = self.run_probe("--respond-transport", respond)
                self.assertEqual(code, 0, output)
                self.assertNotIn("secretstatustoken123", output.lower())
                self.assertNotIn("secreteventtoken456", output.lower())
                data = self.assert_cleaned()
                self.assertEqual(
                    data["actions"],
                    "ACTION=PAUSE\nACTION=PLAY\n" if respond == "1" else "",
                )
                records = [json.loads(line) for line in output.splitlines()]
                self.assertTrue(any(r.get("name") == "started" for r in records))
                self.assertTrue(any(r.get("command") == "pause" for r in records))
                if respond == "1":
                    self.assertTrue(any(r.get("name") == "paused" for r in records))
                    self.assertTrue(any(r.get("name") == "playing" for r in records))

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
            ("--respond-transport", "2"),
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
