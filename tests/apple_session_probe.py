# /// script
# requires-python = ">=3.11"
# dependencies = ["pyatv==0.18.0"]
# ///
"""Read native AirPlay session state without sending playback commands.

References:
    https://pyatv.dev/api/interface/
    https://pyatv.dev/development/scan_connect/
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from ipaddress import ip_address
from typing import TypedDict

import pyatv
from aiohttp import ClientSession
from pyatv.const import FeatureName, FeatureState, Protocol
from pyatv.exceptions import NotSupportedError
from pyatv.interface import AppleTV

LOGGER = logging.getLogger(__name__)
REQUIRED_CONTROLS = ("Play", "Pause", "PlayPause", "Volume", "SetVolume")
CONTROLS = (*REQUIRED_CONTROLS, "SetPosition")
DISCOVERY_FIELDS = (
    "flags",
    "sf",
    "gid",
    "pgid",
    "igl",
    "tsid",
    "features",
    "model",
    "osvers",
    "srcvers",
    "deviceid",
)
SCAN_SECONDS = 4
CONNECT_SECONDS = 8
READ_SECONDS = 5
CLOSE_SECONDS = 3


class Snapshot(TypedDict):
    """JSON-safe session fields; unsupported optional readings are null."""

    host: str
    name: str
    app: dict[str, str | None] | None
    title: str | None
    artist: str | None
    album: str | None
    state: str
    duration: int | None
    position: int | None
    features: dict[str, str]
    volume: float | None
    output_uids: list[str] | None


async def snapshot(atv: AppleTV, host: str, name: str) -> Snapshot:
    """Read one session. Returns: Snapshot with public pyatv fields only."""
    playing = await atv.metadata.playing()
    app = None
    volume = None
    outputs = None
    try:
        current_app = atv.metadata.app
        if current_app is not None:
            app = {"id": current_app.identifier, "name": current_app.name}
    except NotSupportedError:
        pass
    try:
        volume = atv.audio.volume
    except NotSupportedError:
        pass
    try:
        outputs = [device.identifier for device in atv.audio.output_devices]
    except NotSupportedError:
        pass
    return {
        "host": host,
        "name": name,
        "app": app,
        "title": playing.title,
        "artist": playing.artist,
        "album": playing.album,
        "state": playing.device_state.name,
        "duration": playing.total_time,
        "position": playing.position,
        "features": {
            name: atv.features.get_feature(FeatureName[name]).state.name
            for name in CONTROLS
        },
        "volume": volume,
        "output_uids": outputs,
    }


def validate(
    data: Snapshot, require_controls: bool, expect_title: str | None
) -> list[str]:
    """Return validation failures without echoing expected or received values."""
    errors = []
    if require_controls:
        errors.extend(
            f"Required control `{name}` unavailable"
            for name in REQUIRED_CONTROLS
            if data["features"][name] != FeatureState.Available.name
        )
    if expect_title is not None and data["title"] != expect_title:
        errors.append("Title mismatch")
    return errors


class ProbeError(RuntimeError):
    """A sanitized observation failure, never containing library diagnostics."""


async def probe(
    host: str, require_controls: bool = False, expect_title: str | None = None
) -> dict[str, object]:
    """Return JSON-safe success or a sanitized per-host failure."""
    try:
        return await _probe(host, require_controls, expect_title)
    except ProbeError as exc:
        return {"host": host, "ok": False, "errors": [str(exc)]}


async def _probe(
    host: str, require_controls: bool, expect_title: str | None
) -> dict[str, object]:
    """Bound discovery, connect, read and cleanup. Raises: ProbeError on failure."""
    result: dict[str, object] = {"host": host}
    errors: list[str] = []
    atv = None
    phase = "scan"
    try:
        ip_address(host)
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(SCAN_SECONDS + 1):
            devices = await pyatv.scan(
                loop, hosts=[host], protocol=Protocol.AirPlay, timeout=SCAN_SECONDS
            )
        if len(devices) != 1:
            return result | {"ok": False, "errors": ["Expected one AirPlay device"]}
        cfg = devices[0]
        service = cfg.get_service(Protocol.AirPlay)
        properties = service.properties if service is not None else {}
        result["discovery"] = {
            key: properties[key] for key in DISCOVERY_FIELDS if key in properties
        }
        phase = "connect"
        async with ClientSession() as session:
            try:
                async with asyncio.timeout(CONNECT_SECONDS):
                    atv = await pyatv.connect(
                        cfg, loop, protocol=Protocol.AirPlay, session=session
                    )
                phase = "read"
                async with asyncio.timeout(READ_SECONDS):
                    data = await snapshot(atv, host, cfg.name)
                result |= dict(data)
                errors.extend(validate(data, require_controls, expect_title))
            finally:
                if atv is not None:
                    try:
                        tasks = atv.close()
                        if tasks:
                            async with asyncio.timeout(CLOSE_SECONDS):
                                await asyncio.gather(*tasks)
                    except Exception as exc:
                        raise ProbeError("Close failed or timed out") from exc
    except ProbeError:
        raise
    except Exception as exc:
        # Never serialize the exception chain: diagnostics can contain credentials.
        raise ProbeError(f"{phase.capitalize()} failed or timed out") from exc
    return result | {"ok": not errors, "errors": errors}


async def run(hosts: list[str], require_controls: bool, title: str | None) -> int:
    """Write a JSON array to stdout. Returns: int process exit status."""
    results = [
        await probe(host, require_controls, title) for host in dict.fromkeys(hosts)
    ]
    sys.stdout.write(json.dumps(results, allow_nan=False, indent=2) + "\n")
    return int(any(not result["ok"] for result in results))


def host_argument(value: str) -> str:
    """Validate a literal IP before discovery. Returns: str canonical address."""
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("`--host` requires an IP address") from exc


def main() -> int:
    """Parse read-only options. Returns: int process exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", action="append", required=True, type=host_argument)
    parser.add_argument("--require-controls", action="store_true")
    parser.add_argument("--expect-title")
    opts = parser.parse_args()
    # Never expose pyatv/aiohttp diagnostics, even when a remote returns secrets.
    logging.disable(logging.CRITICAL)
    try:
        return asyncio.run(run(opts.host, opts.require_controls, opts.expect_title))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
