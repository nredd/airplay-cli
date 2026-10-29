# /// script
# requires-python = ">=3.11"
# dependencies = ["pyatv==0.18.0"]
# ///
"""Read-only probe regression tests using public-interface fakes.

References:
    https://pyatv.dev/api/interface/
"""

from __future__ import annotations

import asyncio
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import AsyncMock, MagicMock, patch

import apple_session_probe as probe
from pyatv.const import DeviceState, FeatureName, FeatureState, Protocol
from pyatv.exceptions import NotSupportedError
from pyatv.interface import App, FeatureInfo, OutputDevice, Playing

HOST = "192.0.2.24"


def fake_atv() -> MagicMock:
    """Return a device whose only supported operations are reads and close."""
    atv = MagicMock()
    atv.metadata.playing = AsyncMock(
        return_value=Playing(
            device_state=DeviceState.Playing,
            title="Test title",
            artist="Artist",
            album="KCRW",
            total_time=120,
            position=12,
        )
    )
    atv.metadata.app = App("Music", "com.apple.Music")
    atv.audio.volume = 25.0
    atv.audio.output_devices = [OutputDevice("output-uid", "Speaker")]
    atv.features.get_feature.return_value = FeatureInfo(FeatureState.Available)
    atv.close.return_value = set()
    return atv


class SnapshotTests(unittest.IsolatedAsyncioTestCase):
    """Cover JSON fields, missing optional readings and strict assertions."""

    async def test_snapshot_and_validation(self) -> None:
        """Preserve public values and never invoke a mutating interface."""
        atv = fake_atv()
        data = await probe.snapshot(atv, HOST, "Speaker")
        self.assertEqual(
            data,
            {
                "host": HOST,
                "name": "Speaker",
                "app": {"id": "com.apple.Music", "name": "Music"},
                "title": "Test title",
                "artist": "Artist",
                "album": "KCRW",
                "state": "Playing",
                "duration": 120,
                "position": 12,
                "features": dict.fromkeys(probe.CONTROLS, "Available"),
                "volume": 25.0,
                "output_uids": ["output-uid"],
            },
        )
        self.assertEqual(probe.validate(data, True, "Test title"), [])
        data["features"]["Pause"] = "Unavailable"
        data["features"]["Play"] = "Unknown"
        self.assertEqual(len(probe.validate(data, True, "Wrong")), 3)
        self.assertEqual(probe.validate(data, False, None), [])
        self.assertEqual(json.loads(json.dumps(data)), data)
        self.assertEqual(atv.remote_control.mock_calls, [])
        self.assertEqual(atv.audio.method_calls, [])
        self.assertEqual(
            atv.features.get_feature.call_args_list[0].args, (FeatureName.Play,)
        )

    async def test_unsupported_fields_are_null(self) -> None:
        """Unsupported optional readings are not connection failures."""
        atv = fake_atv()
        del atv.metadata.app
        del atv.audio.volume
        del atv.audio.output_devices
        type(atv.metadata).app = property(
            lambda _: (_ for _ in ()).throw(NotSupportedError())
        )
        type(atv.audio).volume = property(
            lambda _: (_ for _ in ()).throw(NotSupportedError())
        )
        type(atv.audio).output_devices = property(
            lambda _: (_ for _ in ()).throw(NotSupportedError())
        )
        data = await probe.snapshot(atv, HOST, "Speaker")
        for key in ("app", "volume", "output_uids"):
            self.assertIsNone(data[key])


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    """Exercise connection lifecycle, deadlines and sanitized errors."""

    def setUp(self) -> None:
        """Patch only network entry points; no speaker is contacted."""
        self.atv = fake_atv()
        self.scan = AsyncMock(return_value=[MagicMock(name="cfg")])
        self.scan.return_value[0].name = "Speaker"
        self.scan.return_value[0].address = probe.ip_address(HOST)
        self.service = self.scan.return_value[0].get_service.return_value
        self.service.properties = {
            "flags": "0x4",
            "sf": "0x4",
            "gid": "group-id",
            "pgid": "parent-group-id",
            "igl": "1",
            "tsid": "session-id",
            "features": "0x123,0x456",
            "model": "AudioAccessory6,1",
            "osvers": "27.0",
            "srcvers": "900.1",
            "deviceid": "00:11:22:33:44:55",
            "pk": "secret-public-key-must-not-escape",
            "credentials": "secret-credentials-must-not-escape",
            "unknown": "not-allowlisted",
        }
        self.connect = AsyncMock(return_value=self.atv)
        self.enterContext(patch.object(probe.pyatv, "scan", self.scan))
        self.enterContext(patch.object(probe.pyatv, "connect", self.connect))

    async def test_success_and_strict_failure_close(self) -> None:
        """Read once over AirPlay, then close regardless of assertion results."""
        result = await probe.probe(HOST, True, "Wrong title")
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"], ["Title mismatch"])
        self.assertEqual(self.scan.call_args.kwargs["protocol"], Protocol.AirPlay)
        self.assertEqual(self.connect.call_args.kwargs["protocol"], Protocol.AirPlay)
        self.atv.close.assert_called_once()
        self.assertTrue(self.connect.call_args.kwargs["session"].closed)

    async def test_discovery_allowlist(self) -> None:
        """Expose only approved present properties, preserving their values."""
        result = await probe.probe(HOST)
        self.assertTrue(result["ok"])
        expected = {
            key: value
            for key, value in self.service.properties.items()
            if key not in ("pk", "credentials", "unknown")
        }
        self.assertEqual(result["discovery"], expected)
        self.scan.return_value[0].get_service.assert_called_once_with(Protocol.AirPlay)
        serialized = json.dumps(result)
        self.assertNotIn("secret-", serialized)
        self.assertNotIn("unknown", serialized)
        self.service.properties = {"model": "AudioAccessory6,1", "pk": "secret-key"}
        self.assertEqual(
            (await probe.probe(HOST))["discovery"], {"model": "AudioAccessory6,1"}
        )
        self.scan.return_value[0].get_service.return_value = None
        self.assertEqual((await probe.probe(HOST))["discovery"], {})

    async def test_nonseekable_radio_passes_required_controls(self) -> None:
        """Report unavailable seeking without rejecting live radio controls."""
        self.atv.features.get_feature.side_effect = lambda feature: FeatureInfo(
            FeatureState.Unavailable
            if feature == FeatureName.SetPosition
            else FeatureState.Available
        )
        output = io.StringIO()
        with redirect_stdout(output):
            status = await probe.run([HOST], True, "Test title")
        result = json.loads(output.getvalue())[0]
        self.assertEqual(status, 0)
        self.assertEqual(result["features"]["SetPosition"], "Unavailable")
        self.assertEqual(result["errors"], [])
        self.assertEqual(self.atv.remote_control.mock_calls, [])
        self.assertEqual(self.atv.audio.method_calls, [])
        for missing in probe.REQUIRED_CONTROLS:
            with self.subTest(missing=missing):
                self.atv.features.get_feature.side_effect = (
                    lambda feature, missing=missing: FeatureInfo(
                        FeatureState.Unavailable
                        if feature.name == missing
                        else FeatureState.Available
                    )
                )
                result = await probe.probe(HOST, True)
                self.assertFalse(result["ok"])
                self.assertEqual(
                    result["errors"], [f"Required control `{missing}` unavailable"]
                )

    async def test_no_device(self) -> None:
        """No matching device is a failed observation, not an empty success."""
        self.scan.return_value = []
        self.assertFalse((await probe.probe(HOST))["ok"])
        self.connect.assert_not_called()

    async def test_mismatched_scan_address_never_connects(self) -> None:
        """Fail closed when discovery returns another device's address."""
        self.scan.return_value[0].address = probe.ip_address("192.0.2.25")
        result = await probe.probe(HOST)
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"], ["Scan returned a different address"])
        self.connect.assert_not_called()

    async def test_failures_are_sanitized(self) -> None:
        """Never serialize exception messages that might contain credentials."""
        for phase in ("scan", "connect", "read", "close"):
            with self.subTest(phase=phase):
                target = {
                    "scan": self.scan,
                    "connect": self.connect,
                    "read": self.atv.metadata.playing,
                    "close": self.atv.close,
                }[phase]
                target.side_effect = RuntimeError("secret-token-must-not-escape")
                result = await probe.probe(HOST)
                self.assertFalse(result["ok"])
                self.assertNotIn("secret-token", json.dumps(result))
                self.assertIn(phase.capitalize(), str(result["errors"]))
                target.side_effect = None
        self.assertTrue(self.connect.call_args.kwargs["session"].closed)

    async def test_deadlines(self) -> None:
        """Cancel stalled scan, connect, read and close operations promptly."""

        async def stall(*args: object, **kwargs: object) -> None:
            """Block until the probe cancels this fake operation."""
            await asyncio.Event().wait()

        with (
            patch.object(probe, "SCAN_SECONDS", 0.001),
            patch.object(probe, "CONNECT_SECONDS", 0.001),
            patch.object(probe, "READ_SECONDS", 0.001),
            patch.object(probe, "CLOSE_SECONDS", 0.001),
        ):
            for target in (self.scan, self.connect, self.atv.metadata.playing):
                target.side_effect = stall
                result = await asyncio.wait_for(probe.probe(HOST), 2)
                self.assertFalse(result["ok"])
                target.side_effect = None
            task = asyncio.create_task(stall())
            self.atv.close.return_value = {task}
            result = await asyncio.wait_for(probe.probe(HOST), 2)
            self.assertEqual(result["errors"], ["Close failed or timed out"])
            self.assertTrue(task.cancelled())

    async def test_multi_host_json_and_exit_status(self) -> None:
        """Emit parseable JSON, deduplicate hosts and aggregate failures."""
        output = io.StringIO()
        with redirect_stdout(output):
            status = await probe.run([HOST, HOST], True, "Test title")
        self.assertEqual(status, 0)
        self.assertEqual(len(json.loads(output.getvalue())), 1)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(await probe.run([HOST], False, "Wrong"), 1)

    def test_bad_host_rejected_before_network(self) -> None:
        """Require IP literals, with no DNS or shell interpretation."""
        with self.assertRaises(ValueError):
            probe.ip_address("not-a-host")
        with self.assertRaises(probe.argparse.ArgumentTypeError):
            probe.host_argument("not-a-host")
        self.assertEqual(probe.host_argument(HOST), HOST)
        self.scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
