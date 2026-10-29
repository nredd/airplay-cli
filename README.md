# cliairplay

Unified AirPlay streaming CLI for Music Assistant. One binary speaks RAOP
(AirPlay 1) and AirPlay 2 — both the RAOP-compatible flow and the native HAP
flow — replacing the previous `cliraop` and `cliap2` binaries.

Music Assistant spawns one `cliairplay` process per player and feeds it a
single, persistent PCM stream on the process stdin for the whole process
lifetime. Seek and next-track flush the live stream in place (cmdpipe
`ACTION=FLUSH`) and re-anchor it with a new `ACTION=START` — the connection and
the input are never re-opened. For synchronized multi-room AirPlay 2 playback it
also runs one `cliairplay --ptp-daemon` per host.

Protocol and architecture detail lives in `DESIGN.md`; open work in `TODO.md`.

## Features

- **RAOP (AirPlay 1)** via libraop: ALAC (compressed by default), NTP timing,
  optional RSA payload encryption, legacy Apple TV pairing.
- **AirPlay 2 RAOP-compat**: auth-setup + the RAOP flow — the fallback for
  AirPlay 2 receivers that can neither pair-verify nor pair transiently.
- **AirPlay 2 native**: HAP pairing (transient, or pair-verify with stored
  credentials), encrypted RTSP, binary-plist SETUP, ChaCha20-Poly1305 audio,
  realtime (type 96) streaming with PTP or NTP timing, and buffered
  (type 103, RTP over TCP + `SETRATEANCHORTIME`) auto-selected on receivers
  that advertise it.
- **Apple MediaRemote metadata**: Apple targets (pair-verified, or
  transient-paired Apple receivers such as HomePods) receive the full
  now-playing client, playback-state, transport-command, text and artwork
  sequence used by current Apple senders, and their Siri / touch-surface
  commands are reported as `[EVENT] remote command=`.
- **PTP timing**: an in-process gPTP-dialect grandmaster engine, plus a
  shared-clock daemon mode (`--ptp-daemon`/`--ptp-shared`) for multi-room.
- **Route auto-selection** (`--protocol auto`): the binary picks RAOP vs
  AirPlay 2, native vs compat, transient vs pair-verify, and PTP vs NTP from
  the device's mDNS TXT records.
- **Hi-res audio**: 24-bit ALAC (44.1 kHz and 48 kHz) on the native realtime
  stream.
- **Commanded group starts**: on every protocol, `START_UNIX_MS` schedules the
  first sample to be audible at an exact wall-clock instant, so every member of
  a sync group is handed the same instant and aligns by construction.

## Usage

```bash
# RAOP command-only session (or let --protocol auto decide from --txt):
./bin/cliairplay-macos-arm64 --protocol raop --port 5000 \
  --volume 50 --cmdpipe /tmp/raop-cap 192.168.1.50

# AirPlay 2 native command-only session:
./bin/cliairplay-macos-arm64 --protocol airplay2 --port 7000 \
  --auth <192-hex-credentials> --volume 50 \
  --cmdpipe /tmp/ap2-cap 192.168.1.50
```

Every streaming protocol requires `--cmdpipe`; the raw interleaved PCM arrives
on the process stdin, which is the single persistent audio input for the whole
process lifetime. The format is selected with
`--samplerate`/`--bitdepth`/`--channels` (default s16le 44100 stereo). At
`--bitdepth 24` the input must be **s32le**; the binary truncates it to the
24-bit samples the ALAC encoder consumes.

### Private current-image attestation contract

This private branch accepts `--attest-fd <inherited-readonly-asset-fd>` and
`--attest-nonce <32-lowercase-hex>` only as a pair. The FD must be at least 3,
read-only, regular, non-empty, stable across hashing, and no larger than 64 MiB. Hashing
uses positional reads, so the parent's prior hash may leave its inherited FD at
EOF. On Linux, before receiver, PTP, pairing, or audio readiness I/O, the CLI
also reads `/proc/self/exe`, requires both SHA-256 values to match, and emits
exactly one first stdout line:

```text
[ATTEST] {"version":1,"kind":"current-image-match-at-ack","nonce":"...","exec_fd_sha256":"...","self_sha256":"..."}
```

It fails closed when self-image reading is unsupported or denied. `--attest-only`
requires that pair and exits successfully immediately after this acknowledgement;
it performs no receiver, PTP, pairing, or PCM setup. Without these flags, CLI
behavior is unchanged. This is a point-in-time image proof only: the launcher
must compare the nonce and both hashes to its pinned asset before connecting
stderr or treating the child as ready.

### Read-only Apple session probe

```bash
uv run tests/apple_session_probe.py --host 192.168.1.50
uv run tests/apple_session_probe.py --host 192.168.1.50 --host 192.168.1.51 \
  --require-controls --expect-title 'Expected title'
```

Requires `uv` and Python 3.11+; the script pins `pyatv==0.18.0` inline.
It scans the requested IP and fails closed unless pyatv returns that exact address,
then opens a transient AirPlay controller connection, reads state, and closes without
sending playback, seek, volume or grouping commands. This is not passive: opening the
controller connection and taking snapshots can perturb receiver UI. It is not a
phone-rail oracle. Stdout is a JSON array with host/name, now-playing app, metadata,
state, duration/position, control availability, volume and output UIDs. Unsupported
optional readings are `null`. `discovery`
contains only present public AirPlay mDNS properties from this allowlist:
`flags`, `sf`, `gid`, `pgid`, `igl`, `tsid`, `features`, `model`, `osvers`,
`srcvers`, `deviceid`. No keys, credentials or raw diagnostics are emitted.
Discovery/connect/read/close deadlines are 5/8/5/3 seconds per host.

`--require-controls` requires protocol availability of `Play`, `Pause`,
`PlayPause`, `Volume` and `SetVolume`. `SetPosition` is reported separately,
not required: live radio can be nonseekable. `--expect-title` checks exact equality.
Required-control failures, title mismatches and connection/read/close failures
exit nonzero with sanitized per-host errors.

A successful probe does not prove visibility in iPhone **All Speakers & TVs**.
HomePods can expose metadata and transport controls to a direct controller while
remaining absent from that native UI. Compare `discovery` and session fields
against an Apple-source session, then verify visibility and controls on the
Apple devices themselves.

Run fake-only probe tests with `uv run --script tests/test_apple_session_probe.py`.
For full updater/probe discovery, run
`uv run --python 3.13 --with pyatv==0.18.0 python -m unittest discover -s tests -v`.
CI runs the same discovery in a uv-managed Python 3.13 environment with
`pyatv==0.18.0`, and checks only the two probe files with Ruff 0.17.1 and ty 0.0.89.
None of these checks contact speakers. Run `make test STATIC=1` from the
repository root for native fixtures; the Python half of the captured diagnostic
contract runs in unittest discovery and CI, not in that Make target.

### Experimental HomePod remote admission

`CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE=1` is a strict literal-`1`, default-off
experimental opt-in, not production deployment or a full relay claim.
It snapshots eligibility before session SETUP: exact `AudioAccessory5,1`, known
OS major 27 (`osvers`/`ov`, no firmware or future-OS guess), encrypted native
MediaRemote, MRP enabled, a registered remote callback, actual PTP and realtime
(not buffered). Only eligible sessions emit both `senderSupportsRelay=true` and
`isMultiSelectAirPlay=true`. All other session SETUP bytes remain unchanged.
An admitted attempt requires an attached encrypted reverse-event/MRP context
before connect succeeds; failure uses `connect_failed` and connection cleanup.
The opt-in neither enables type 130 nor changes PTP follow/clock policy.

In this mode `/command` advertises only implemented Play/Pause/Toggle/Next/
Previous, in live and non-live metadata and across transitions. It does not
advertise volume, seek, shuffle, repeat or stop. Admission alone leaves DataStream
ACK-only; the separately enabled logical-volume backend is described below. Native MRP/group volume and CLI stream gain are separate
knobs; telemetry is not routed to group volume.

On `1c95c1a`, an owner found the existing HomePod mini in the native iPhone
remote-speaker picker and paused/resumed the muted probe. Encrypted reverse-event
traces recorded Pause then Play, matching the owned FIFO actions and producer
Paused/Playing confirmations. The 120-second run completed and the supported MA
installation was restored. Type 130 was off; no clock-policy change was needed.
This validates one OS 27 HomePod/iPhone transport path, not MA radio metadata,
group routing/volume, physical touch, other Apple controllers or a production
rollout. Those remain separate acceptance checks.

Eligible sessions emit at most 128 bounded diagnostic records per MRP context,
then continue servicing traffic. Records contain fixed classifications,
recognized command names, bounded protobuf field-1 types, lengths, local
ordinal/relative monotonic time and `dispatched`. That field means recognized
and callback invoked, NOT that Music Assistant executed an action. No bodies,
arbitrary type/value strings, keys, tokens, metadata or IDs are included.
Reverse-event logging, including debug, now contains only fixed classifications
and lengths, never arbitrary type/value/content-type strings or body hex.
See `DESIGN.md` §8 for classifier limits.

The default fork-only volume classifier is observe-only, NOT group-volume support.
Root `receiverVolumeDidChange` is telemetry regardless of its value. Exact root
`params.data` envelopes can be classified against public pyatv volume schemas,
with matching protobuf type/extension, bounded structural validation and normalized
finite values only. Fixed `message`, `target` and `value_state` fields, optional
`value_milli` (0..1000), `available` (0..1) and `capabilities` (0..3) share the same
128-record budget. A target UID is only `unresolved`, never a session/group claim;
UID bytes and unknown fields are not retained; invalid parses clear the target.
A type-51 set candidate requires a valid normalized float. Missing optional
feedback/result levels remain missing, never zero or a command; optional
availability is omitted when absent. Extra extensions are rejected by this narrow
classifier, which is not a full MRP decoder. All volume observations have
`dispatched=0`, with no callbacks, actions or publication from the classifier. DataStream remains
ACK-only unless the separate logical-volume backend below is explicitly enabled. Receiver MRP volume 50 and muted CLI stream gain 0 are separate knobs.

These are known-schema fixtures, not measured native-slider requests or scope.
The owner corrected the volume evidence: the native volume slider was greyed out;
no valid slider gesture occurred. No request or UI identity binding was measured.
The offline operational backend below does NOT solve that native UI limitation. The existing iPhone visibility/pause-play acceptance above stands.
No upstream submission is authorized: inherited OHF policy requires human review
before any upstream contribution; the owner will open an upstream draft after review.

### Experimental logical session volume (default off)

`CLIAIRPLAY_SESSION_VOLUME=mrp130` requests a public-MRP DataStream backend
*only* on an already eligible experimental HomePod remote session. Explicit
`CLIAIRPLAY_MRP_TYPE130=0|false|off` still kills DataStream; explicit force keeps
its existing diagnostic semantics and never broadens volume eligibility.
Optional attachment failure retains reverse-event pause/play. Existing metadata
stays on `POST /command`, with no DataStream now-playing pushes in volume mode.

Every command reader emits `[STATUS] session_volume version=1`, an additive
compiled IPC handshake, NOT transport readiness. A requested eligible attempt
separately reports `[STATUS] session_volume_transport ready=0|1 publication=0`;
attached channel loss reports `ready=0` and invalidates the backend binding.
Older consumers can ignore both. The diagnostic helper observes these names but
never enables volume or responds to session/group requests.

The version-1 IPC names and shapes are frozen:
- Bind with `SESSION_VOLUME_GENERATION`, `SESSION_VOLUME_OUTPUT_UID_HEX`,
  explicitly present `SESSION_VOLUME_ENDPOINT_UID_HEX` (may be empty), then
  `ACTION=SESSION_VOLUME_BIND`. UIDs are private exact byte strings, 1..128
  output bytes and 0..128 endpoint bytes; generations are positive uint64.
- Reconcile with `SESSION_VOLUME_GENERATION`, `SESSION_VOLUME_REVISION`,
  `SESSION_VOLUME_KNOWN=0|1`, and `SESSION_VOLUME_MILLI=0..1000` *only* when
  known, then `ACTION=SESSION_VOLUME_STATE`. Unknown is NOT zero. Revisions
  strictly increase inside a generation.
- Requests emit `[EVENT] session_volume_set generation=7 ordinal=12 milli=630`.
  This is intent, never committed state. Complete with generation, ordinal,
  `SESSION_VOLUME_RESULT=committed|rejected|failed|unknown`, revision, known and
  optional milli as above, then `ACTION=SESSION_VOLUME_COMPLETE`. Committed
  requires known actual state; noncommitted results require unknown. A request for
  630 may commit an authoritative actual 610. Failed/uncertain operations never
  manufacture success. `ACTION=SESSION_VOLUME_UNBIND` takes only generation.
- Checked device gain uses a SEPARATE ordinal namespace:
  `STREAM_VOLUME_GENERATION`, `STREAM_VOLUME_ORDINAL`, `STREAM_VOLUME_LEVEL=0..100`,
  then `ACTION=STREAM_VOLUME_APPLY`. Output is
  `[EVENT] stream_volume_result generation=7 ordinal=3 status=committed level=50`,
  or `status=failed|unknown` without level. Native RTSP must accept a 2xx before
  commit; legacy RAOP requires an active transport and its checked 200 receipt.
  An uncertain RAOP failure is `unknown`, not a guessed rejection. These are raw
  device percentages, NOT normalized group volume. Legacy `VOLUME=` is unchanged.

Write every complete transaction in one atomic pipe write (within `PIPE_BUF`).
Fields are unique, bounded, strict decimal/hex, never logged, and cleared after
EVERY attempted ACTION, including malformed attempts. No leftovers or mixed
namespaces are accepted. The driver holds one executing Set plus one coalesced
trailing Set, a 3-second backend deadline and a 16-identifier replay window.
Timeout clears known state and blocks more work until newer reconciliation;
it is not cancellation, and late completions cannot become success.

Public Get49/ext53 serves only the authoritative cache, with exact field-2
correlation and eight bounded replies per drain. There are no outgoing Gets or
outstanding-Get registry. Unsolicited type50 results, type52 feedback and `dvlc`
never dispatch. There is no invented SetVolumeResult or private UI protocol.

Native availability and ALL current-state publication remain OFF in production,
including Get results and committed-change messages, even with a bound, known
backend. The native output/UI identity binding is unverified. Test-only synthetic
identity permits encrypted GetResult50/ext54 and committed Change52/ext56 tests;
it is absent from the runtime binary. Offline operational success is NOT native
slider acceptance. See `DESIGN.md` for the offline FIFO integration harness.

For developer-only cross-process acceptance, from the MA source root run
`.venv/bin/python -m scripts.check_native_airplay_volume --harness /absolute/path/to/airplay-cli/build/tests/test_live_metadata`.
Supply an already-built executable; the command never builds or installs anything.
It requires MA's source fixtures/venv, runs real encrypted C requests through the real
MA controller with two fake confirmed actuators and real FIFO feedback, then requires
the decrypted committed 610 witness for a requested 630. It emits bounded public JSON
and exits nonzero on failure or timeout. It uses no network or hardware and is not
part of ordinary MA tests. Synthetic verified identity is offline proof only, NOT
native UI binding or native volume availability.

### The start contract

`START_UNIX_MS=<ms>` followed by `ACTION=START` means: **the first sample is
audible exactly at that unix-epoch instant** for legacy RAOP, RAOP-compatible
AirPlay 2, and native AirPlay 2. The first `ACTION=START` begins the session; a
`START` after an `ACTION=FLUSH` re-anchors the same live stream to a new instant
without reconnecting. A caller can wait for the one-shot
`[STATUS] audio buffered_ms=<ms>` line — emitted once the (new) track has a
complete audio packet buffered, or its final short packet reaches EOF — before
it commands the start, then send the same start value to every member of a sync
group. A `START_UNIX_MS` of 0 or one the transport cannot honor is corrected
forward to the earliest feasible instant (250 ms minimum lead, 200 ms on RAOP)
and the `[STATUS] started` ack always reports the true scheduled instant.

**Late joins: wait for the receiver's clock instead of guessing a headroom.**
A receiver that has just connected cannot seat an anchor yet — it begins
probing our PTP clock about a second after connect, on its own schedule, and
its servo needs roughly 2.3 s more. That is a property of the device, so any
fixed join headroom is either too short or needlessly slow. The binary reports
what it measures, from connect:

```
[STATUS] clock_ready mode=<ptp|ntp> state=<cold|probing|ready|stalled> streak_ms=<u64> exchanges=<u32> ready_in_ms=<u64> ready_at_unix_ms=<u64>
```

The first line arrives right after `[STATUS] connected`, whatever the state, so
a caller never blocks on a line that will not come; further lines follow only
when the state or the projected instant changes, ending at the first
`state=ready`. Plan a join anchor at or after `ready_at_unix_ms` (valid only
when `state` is `probing` or `ready`). `mode=ntp` means readiness is not
measurable for this session — legacy RAOP, or a PTP session that fell back to
the NTP responder — so do not wait for it. `state=cold` can also persist
indefinitely for a receiver past the timing engine's 8-peer limit, so keep a
timeout. `FLUSH` and `START` re-arm the reporting for the next cycle.

`state=stalled` means our clock has gone unanswered for 5 s — since the last
probe if there ever was one, since connect if there was not. That is over four
times the slowest first probe measured, so it is not a slow device and not a
blip. The receiver is not slaved to us, so it can seat no render position and
plays **silence** however healthy the session looks. Treat it as a failure to
report rather than something to wait out; the usual cause is UDP 319/320 not
reaching this host from the speaker. It is not final, though: a receiver that
starts probing late, or picks up again, reports `probing` and then `ready`.

Starting before readiness is still supported and still corrected — see
`START_JOIN=1` below.

Delivery is not gated on the start time: frames are released up to the
receiver's queue depth ahead of each frame's deadline (600 ms by default — see
`--latency` below), itself bounded by the device-reported `latencyMax` less a
250 ms margin, or by 1.75 s when the receiver reports no window. Receiver
buffers therefore fill before a scheduled start and the start cannot underrun.

`--latency <ms>` overrides the receiver's queue depth on the native AirPlay 2
splice timeline (default 600 ms, maximum 3000 ms — deeper values are clamped
with a warning). That depth is the audible latency of every warm seek and
track change, so it stays shallow; raise it only for a receiver whose renderer
starves at the stock depth and plays silence behind a perfectly healthy
session. A window the device reports at stream SETUP still clamps the
effective depth, but the 1.75 s stand-in for a window it never reported does
not — a caller naming a depth knows the device better than an assumption does.

The effective depth (`warm_lead_ms`), the render lead and the device window are
printed as a `[STATUS] latency ...` line so the caller can plan group starts
from real device capabilities.

### Pairing

- **Apple TV / HomePod (AirPlay 2, PIN)**:
  `cliairplay --pair-setup <ip> --port 7000 --dacp <id>` runs full HomeKit
  pair-setup — the device shows a PIN, and on success the credentials are
  printed on stdout (`CREDENTIALS: <192 hex chars>`). Stream later with
  `--auth <creds>` and the **same `--dacp`** (the pairing identity is derived
  from it).
- **Sonos and most third-party AirPlay 2 receivers** need no pairing step: the
  native flow uses transient pairing automatically.
- **Legacy Apple TV (RAOP)**: `cliairplay --pair` produces the `--secret` used
  by the RAOP flow.

### Multi-room (shared PTP clock)

Only one process per host can bind the privileged PTP ports (UDP 319/320), and
every receiver in a sync group must lock to the same grandmaster:

```bash
# One per host (root, or CAP_NET_BIND_SERVICE on Linux):
cliairplay --ptp-daemon [--if <ip>] &

# Grant only the privileged-port capability instead of running as root:
sudo setcap cap_net_bind_service=+ep /path/to/cliairplay

# Per device, connect a command-only session. --ptp selects PTP timing (or pass
# --txt and let the SupportsPTP bit do it); --ptp-shared then attaches the
# daemon's clock instead of running an in-process engine.
cliairplay --protocol airplay2 --ptp --ptp-shared --cmdpipe /tmp/cap1 ... <ip1>
cliairplay --protocol airplay2 --ptp --ptp-shared --cmdpipe /tmp/cap2 ... <ip2>

# Wait until both report [STATUS] audio, then send the same start to both:
# START_UNIX_MS=<T>
# ACTION=START
```

The daemon binds 319/320 once, runs the PTP engine, publishes the elected
clock to POSIX shared memory (`/cliairplay-ptp`), and serves a localhost UDP
control channel (`127.0.0.1:9010`) where streams register their receiver IPs.
Streams started with `--ptp-shared` attach the shm read-only and never bind
319/320; when no live daemon is present they fall back to the in-process
engine, identical to a single-device session. MA starts the daemon when the
first PTP stream begins and stops it (SIGTERM) when the last one ends.

## Command-line reference

```
cliairplay [options] --cmdpipe <path> <host_ip>
```

### Protocol selection

| Option | Description |
|--------|-------------|
| `--protocol <auto\|raop\|airplay2\|airplay2-compat>` | Streaming protocol (default: `auto`, which resolves the full route — RAOP vs AirPlay 2, native vs compat, PTP vs NTP — from the mDNS TXT records in `--txt`). `raop`/`airplay2` force the protocol; `airplay2` picks native vs RAOP-compat on the same terms as `auto`, and goes native when `--txt` advertises no features at all (an AirPlay-2-only receiver); `airplay2-compat` forces the auth-setup + RAOP flow outright. |

### Common

| Option | Description |
|--------|-------------|
| `--port <port>` | Device RTSP port (default: 5000; AirPlay 2 devices use 7000). |
| `--volume <0-100>` | Initial volume. Mapped linear-in-dB onto -30..0 dB (the AirPlay ecosystem convention); 0 mutes. |
| `--latency <ms>` | Receiver queue depth on the native AirPlay 2 splice timeline (default: 600, maximum: 3000). Raise only for receivers whose renderer starves at the stock depth; a device-reported window still clamps it. |
| `--samplerate <rate>` | Input sample rate (default: 44100). |
| `--bitdepth <16\|24>` | Input bit depth (default: 16). 24 requires the native AirPlay 2 flow and s32le input. |
| `--channels <n>` | Input channel count (default: 2). |
| `--if <ip>` | Local interface IP to bind all sockets to (multi-homed hosts). |
| `--dacp <id>` | DACP ID advertised for remote-control callbacks; also the HAP pairing identity. |
| `--activeremote <id>` | Active-Remote ID for DACP callbacks. |
| `--cmdpipe <path>` | Required named pipe for runtime commands and metadata (see below). Audio is not carried here — it is the process stdin. |
| `--udn <name>` | UDN / instance name used for mDNS. |
| `--debug <0-9>` | Log verbosity (default: 3). |

### RAOP

| Option | Description |
|--------|-------------|
| `--raw` | Force uncompressed ALAC frames. Default is compressed ALAC; the binary also falls back to uncompressed when the device's `cn` field lacks ALAC. |
| `--encrypt` | Enable RAOP audio-payload encryption (default: clear). |
| `--password <pw>` | Device password, if the receiver requires one. Used for RAOP digest authentication and as the AirPlay 2 transient pairing secret (DESIGN.md §3a). |
| `--secret <secret>` | Legacy Apple TV pairing secret (from `--pair`). |
| `--et <v>` `--md <v>` `--am <v>` `--pk <v>` `--pw <v>` `--cn <v>` | mDNS TXT fields from the receiver's `_raop._tcp` record (encryption types, metadata types, model, public key, password flag, codec types). |

### AirPlay 2

| Option | Description |
|--------|-------------|
| `--auth <hex>` | HAP credentials (192 hex chars, from `--pair-setup`). Selects the native flow with pair-verify. |
| `--ap2-native` | Force the native flow without credentials (transient pairing), whatever the TXT advertises. |
| `--txt <k=v ...>` | mDNS TXT records of the `_airplay._tcp` service; drives route auto-selection. |
| `--publish-ip <ip>` | Address advertised to devices (timing-peer lists) when it differs from the bind address (Docker bridge, NAT). |
| `--name <name>` | Device name (native flow). |
| `--hostname <host>` | Device hostname (native flow). |
| `--ptp` | Force PTP grandmaster timing (binds UDP 319/320, needs privilege). Default: auto by the SupportsPTP feature bit. |
| `--timing <auto\|ptp\|ntp>` | Session timing. `auto` (default) follows the SupportsPTP bit (or `--ptp`); `ntp` forces the NTP responder — the escape for receivers that advertise PTP but never answer a clock probe (e.g. AirPlay-2 video-class TVs). An NTP-timed route never selects the buffered stream. |
| `--buffered` | Force the buffered stream (type 103, RTP over TCP + PTP anchor) on a native PTP route. Default: auto by the SupportsBufferedAudio feature bit (in-code deny-list for measured-hostile models). `CLIAIRPLAY_BUFFERED=0\|1` outranks both — kill switch / fleet A/B lever. |
| `--ptp-shared` | Prefer the shared PTP daemon clock (multi-room): attach the daemon's shm instead of running an engine; fall back to the in-process engine when no daemon is live. Picks the clock *source*, not the timing mode — pair it with `--ptp` or a `--txt` advertising SupportsPTP. |
| `CLIAIRPLAY_PTP_FOLLOW=0\|1` (env) | Override for following a receiver's **own** PTP clock instead of serving it ours. Default: auto — a standalone HomePod on HomePod OS 27+ (`model=AudioAccessory*`, `igl=1`, no `pgid`, no `tsid`, `osvers`>=27) is followed, because it keeps announcing its own grandmaster for the whole session and never renders audio anchored to the sender's timeline; every other receiver is served our grandmaster as before. `0` never follows (kill switch), `1` follows every receiver. Per receiver: the engine (or the `--ptp-daemon`) stays grandmaster for the other peers, so mixed multi-room keeps working. |
| `CLIAIRPLAY_PTP_STRICT_PEERS=1` (private trial env) | On context creation, admit PTP receive-side effects only from the current registered timing peers: Delay/Pdelay replies, exchange accounting, BMCA, followed-clock dispatch and unicast grants. Exact `1` enables it; unset or every other value preserves ordinary PTP behavior. `SETPEERS` and daemon registration updates are serialized with admission, so a peer retired before admission cannot act. The `--ptp-daemon` ready line attests the effective value as `strict-peers=on` or `strict-peers=off` so a supervisor can verify the gate is live rather than trust the environment it passed. This is an isolation experiment, not an allowlist claim for mDNS, MA discovery or household-wide traffic, and must remain off outside the private trial. |
| `CLIAIRPLAY_NATIVE_VOLUME_RAIL=1` (private trial env) | Under an eligible experimental HomePod-remote session, attach the type-130 DataStream receive-only: the registration (`DEVICE_INFO`, connection state, updates config) and nothing else. Live A/B on a HomePod (2026-10-28) showed its native volume rail (Control Center, Home app, touch, Siri) is grey without this registration and live with it, while the volume changes themselves arrive on DACP `dmcp.device-volume` either way. No now-playing, volume or availability is published on the DataStream; `POST /command` publication is unchanged; an explicit `CLIAIRPLAY_MRP_TYPE130=0|false|off` kill still wins. Strict literal `1`. |

### Utility / daemon modes

| Option | Description |
|--------|-------------|
| `--check` | Print `cliairplay <version> check` and exit (binary validation). |
| `--pair` | Legacy Apple TV RAOP pairing; produces the `--secret` for the RAOP flow. |
| `--pair-setup` | HomeKit pair-setup against `<host_ip>` (with `--port` and `--dacp`): the device shows a PIN, and on success the `--auth` credentials are printed on stdout. Stream later with the same `--dacp`. |
| `--ptp-daemon` | Run **only** the shared PTP clock: bind UDP 319/320 once, run the engine, publish the elected master to shared memory, serve the control channel until SIGINT/SIGTERM. One per host; needs privilege. Honors `--if`; takes no host/audio args. |

### Runtime commands (`--cmdpipe`)

Newline-terminated `KEY=VALUE` lines written to the command pipe control a
running stream. The raw PCM audio is **not** carried here — it is the process
stdin, the single persistent audio input for the whole process lifetime.

- Start / re-anchor: `START_UNIX_MS=<unix epoch ms>` then `ACTION=START`. The
  first `START` begins the session; a `START` after an `ACTION=FLUSH` re-anchors
  the same live stream (no reconnect). `START_UNIX_MS=0` starts as soon as
  possible. The start contract is VERIFIED: a feasible instant is scheduled
  exactly, an infeasible one is corrected forward to the earliest feasible
  instant (audio always flows), and the ack
  `[STATUS] started requested_unix_ms=<ms> at_unix_ms=<ms>` always carries the
  true scheduled instant — the caller compares the two, logs any correction,
  and re-aligns a sync group by re-STARTing every member at the largest
  reported instant. `START_JOIN=1` marks a late join onto an already-live group
  timeline; on the first START to a receiver whose clock is still cold the ack
  is withheld until that clock is measured (up to the anchor, never longer) so
  it reports an instant the receiver can actually seat. Wait for the ack rather
  than assuming it is immediate; exactly one arrives per START.
- `ACTION=FLUSH` — in-place warm flush for seek/next: it discards the internal
  ring and drains stdin to empty, acks with `[STATUS] flushed`, and keeps
  buffering the next track until the next `START`. The one-shot
  `[STATUS] audio buffered_ms=<ms>` line
  fires again when the next track's feed has a complete packet buffered, or its
  final short packet reaches EOF.
  Every native AirPlay 2 session runs a splice timeline: nothing is sent to the
  receiver, its queued audio — kept shallow, reported as `warm_lead_ms` on the
  `[STATUS] latency` line — simply plays out, and the next `START` splices the
  new track at the commanded instant, filling the gap with encoded silence so
  the bitstream stays contiguous on one immutable anchor line. Apple receivers
  require it (any discard, re-anchor or stamp jump makes them emit a short
  noise burst) and it measured clean on every other receiver class, so it is
  the default for all of them. On a live splice timeline the ack carries
  `head_unix_ms=<ms>`, the audible instant of the frozen delivery head: a
  commanded start at or behind a member's head is
  corrected forward to that head plus 250 ms, so anchor every warm START beyond
  all members' heads and check `[STATUS] started at_unix_ms=` against what you
  asked for.
  The RAOP paths flush the receiver for real (RTSP FLUSH), go quiet until the
  next `START`, and ack without the field — as does a flush that arrives before
  the first `START`, when there is no head yet.
- Session lifecycle: `ACTION=STANDBY` (silence the receiver, keep the connection
  warm), `ACTION=DISCONNECT` (end the session).
- Transport: `ACTION=PLAY|PAUSE|STOP`.
- `VOLUME=<0-100>`.
- Metadata: `TITLE=`, `ARTIST=`, `ALBUM=`, `DURATION=<s>`, `PROGRESS=<s>`,
  `ITEMID=<stable per-track id>`,
  `ARTWORKFILE=<local file path or http:// imageproxy URL>` (staged; an empty
  value clears the staging), followed by `ACTION=SENDMETA` to push the set —
  metadata and the staged artwork as one bundle; the staged path is consumed
  by that push. `ARTWORK=<local file path or http:// imageproxy URL>` pushes
  artwork on its own, outside a track change.
- Explicit live metadata: `IS_LIVE=0|1` (default `0`) stages intent for the next
  `ACTION=SENDMETA` bundle. Send it only when that stream reports
  `[STATUS] capabilities ... live_metadata=1`; missing/unknown means unsupported.
  Live mode clears finite duration and advertises only Play/Pause/Toggle/Next/
  Previous, not seek, shuffle or repeat. Send `0` to restore non-live behavior.
  This prepares radio semantics, not native iPhone session visibility; receiver
  acceptance still needs hardware confirmation. See `DESIGN.md` §8.

`[STATUS] stopped` acknowledges `ACTION=STOP` once playback has been torn down.
`STOP` is terminal: the audio loop exits, the connection is torn down and the
process exits 0, the same shape as `ACTION=DISCONNECT`. To keep a session
reusable, use `ACTION=FLUSH` (warm seek/next) or `ACTION=STANDBY` (warm park) —
both leave the process and the connection up for a later `ACTION=START`.

`[STATUS] eof` means the stdin input ended — the whole feed is done, not just
one track.

Status lines are split across both streams: the lifecycle lines on stderr, and
the one-shot setup lines (`route`, `capabilities`, `latency`) plus
remote-control events on stdout — so a parser has to read both. `DESIGN.md` §12
lists every line, the stream it uses, and when it fires.

Some receivers (notably Sonos) do not emit audio until they have received
metadata; the binary pushes an initial metadata set at the first commanded
start, so audio starts regardless of whether the caller ever sends `SENDMETA`.
Native Apple sessions (pair-verified or transient) additionally mirror these
updates over MediaRemote `POST /command`, including explicit play/pause/stop
state. Set `CLIAIRPLAY_MRP=0` only to disable that path for comparison or
diagnosis.
`ITEMID` keys the now-playing item identity: metadata re-sent under the same
id updates the item in place (a tag refinement never presents as a new
track), while a new id is a track change that starts at 0:00; without ids,
identity falls back to the title/artist/album tuple. Byte-identical artwork
keeps its identity even across a track change, redundant `ARTWORK=` re-sends
are ignored, and a `PROGRESS=` correction — like the pause/resume timeline —
rides a lean merge update on MediaRemote sessions, so neither a seek nor a
track change on one album redraws the receiver's now-playing screen.
Metadata strings are encoded as Unicode binary-plist strings; artwork is
signature-checked and capped at 5 MiB. MA imageproxy URLs are normalized to a
supported `size=512&fmt=jpeg` request.

The DMAP path receives the detected image type and original bytes. Before MRP
staging, a bounded metadata probe requires `image/jpeg`, SOI, and a terminal
EOI, then extracts dimensions/profile best-effort without decoding or rejecting
JPEG internals. No Apple TV byte or profile cutoff is assumed.
Baseline/progressive and grayscale/color cases are logged with exact bytes,
dimensions, SOF marker, component count, and `/command` response. A
1 MiB internal staging-allocation guard bounds the copied input and plist; it
is not a receiver capability claim. Non-JPEG, over-bound, or incomplete-envelope
MRP artwork is omitted without withholding it from DMAP and clears stale state.

`tests/mrp_artwork_matrix.py` generates the controlled Apple TV size/profile
matrix or records/sends any existing JPEG cache path with its SHA-256, profile,
dimensions, and full Pillow/libjpeg decode result; see `DESIGN.md` §8.

## Native sender diagnostic

`scripts/native_sender_probe.py` is a standalone stdlib-only diagnostic, not a
passive observer. **It replaces the selected receiver session.** Get explicit
authorization and use an idle target, never a receiver playing another session.
It sends 44.1 kHz signed 16-bit stereo silence at volume zero, forces native AP2
with `--timing ntp` by default (no shared PTP conflict), and uses a separate fixed
DACP identity. `CLIAIRPLAY_BUFFERED=0` forces controlled realtime streaming.
It does not inspect or make claims about receiver UI state.

Authorized idle-target example (run by the operator on the HA host only):

```bash
python3 scripts/native_sender_probe.py \
  --binary /data/airplay-native-probe/cliairplay-linux-aarch64 \
  --host 192.168.1.50 --bind 192.168.1.10 --type130 1 --duration 45
```

Use only an independently verified binary. `--host` and `--bind` require literal
IPv4; `--type130` is required (`0` or `1`). `--duration` is 1..120 seconds (default
45), including the three-second `--check` and connection/setup wait (at most 20
seconds). `--timing ptp` requires `clock_ready mode=ptp state=ready`; an NTP
fallback fails the test. Both modes require connected + buffered audio before
metadata and START. PTP needs exclusive access to ports 319/320: the operator may
briefly stop stable MA, run both type-130 values under the same PTP flow, and MUST
restart MA in their cleanup. This helper neither stops nor restarts MA.
There are no retries or TTL extensions. Teardown may take three extra seconds
before KILL. `--debug 0` (default) or `1` does not suppress machine status.
Metadata and START are sent atomically only after setup readiness. JSON stdout emits
bounded, per-kind allowlisted status/event names (unknown names are dropped before
retention or state handling) plus allowlisted route, clock and MRP-path enums/status
codes, one `ready` on `started`, and a final `result`;
exit zero requires connected + started with no terminal failure and the child
still running at the full TTL (even a clean early exit fails). Neither raw
child output nor metadata fields/pairing material are emitted or persisted;
credentials are not accepted and inherited auth/token environment is excluded.
SIGTERM, Ctrl-C and failures reap the child and remove the FIFO.

`--respond-transport 0` (default) observes remote callbacks without responding.
Opt in with `--respond-transport 1` to test native-phone Pause/Play against this
muted producer without deploying custom MA. Only normalized `[EVENT] remote`
`play`, `pause`, and `play_pause` events received after the C `started` status can
write constant `ACTION=PLAY`/`ACTION=PAUSE` to this owned child's FIFO. Local intent
suppresses duplicate play/pause; a monotonic 250 ms guard suppresses toggle storms.
`next`/`previous` remain observations only: no queue/playlist simulation, volume,
group, API, or other-process actions. The command queue is capped at 128 and JSON
output at 256 status/event/action records. `fifo_action` records report only FIFO
writes; C `paused`/`playing` statuses confirm producer transitions, not MA actions
or UI execution. Failure, child exit, TTL and cleanup stop responses. Readiness,
admission, clock policy, mute, strict child environment and cleanup stay unchanged.
This is a pause/play/toggle test consumer, not a full remote relay.

The helper accepts `--experimental-homepod-remote {0,1}` (default `0`). Only
explicit `1` sets the child opt-in; it is never inherited from the environment.
When requested, `[STATUS] homepod_remote_admission enabled=1` is mandatory before
START, in addition to normal readiness. Ineligible (`enabled=0`) or older binaries
fail without sending metadata/START. Use `--timing ptp` for an eligible attempt;
NTP remains the helper's default. Fixed diagnostic enums/numeric fields are
retained in bounded JSON, never raw receiver strings. Existing `--type130` remains
an independent, required option.

Keep any Apple-source reference playing on a different receiver. This helper
does not authorize live playback by itself.

## Building

```bash
# macOS (native)
make STATIC=1

# Linux cross-compile (example)
make HOST=linux PLATFORM=aarch64 CC=aarch64-linux-gnu-gcc STATIC=1

# Focused native regression tests
make test STATIC=1
```

Requires the libraop submodule with pre-built static libraries (OpenSSL,
libcodecs, libmdns).

## Platforms and CI

CI (`.github/workflows/build.yml`) cross-builds four targets on every push —
`linux-x86_64`, `linux-aarch64`, `macos-arm64`, `macos-x86_64` — validates
`--check` on the natively runnable ones, and uploads the binaries as
artifacts. Pushing a `v*` tag additionally runs a release job. The release is
published only after the four binaries and `SHA256SUMS` are ready, at which
point GitHub locks its tag and assets. The manually dispatched **Auto Release**
workflow calculates the next patch version, creates its tag, and runs the same
release pipeline with generated release notes. After verifying the published
assets, CI hashes `SHA256SUMS` and opens or updates a non-auto-merge PR against
the server `dev` branch with both Dockerfile pins. Same-repository tags and
releases use the built-in `GITHUB_TOKEN`. The private `music-assistant-bot`
GitHub App (slug `musicassistant-bot`) uses the
`MUSIC_ASSISTANT_BOT_CLIENT_ID` organization variable and
`MUSIC_ASSISTANT_BOT_PRIVATE_KEY` organization secret to mint separate,
short-lived tokens: administration read access for this repository's immutable
release preflight, and contents/issues/pull requests write access scoped only
to the server repository for its pin-update PR.

## Architecture

```
src/cliairplay.c      CLI entry, route dispatch, playback loops, cmdpipe,
                      --pair-setup and --ptp-daemon modes
src/ap2_client.c      AP2 orchestrator: route resolution, RAOP-compat + native
                      flows, the realtime sender, anchor & pacing
src/ap2_session.c     Protocol-neutral single-stdin flush-and-refill engine
                      (persistent input reader + ring) used by legacy RAOP and
                      both AirPlay 2 flows
src/raop_session.c    Legacy RAOP commit / flush / standby scheduling
src/ap2_hap.c         HAP pair-verify, transient and PIN pair-setup, encrypted
                      RTSP framing (ChaCha20-Poly1305)
src/ap2_io.c          Absolute-deadline socket I/O shared by RTSP and MRP
src/ap2_mrp.c         MediaRemote now-playing sender: /command builders,
                      proto2 + bplist emitters, type-130 DataStream channel
src/ap2_plist.c       Binary plist writer (nested streams array)
src/ap2_bplist.cpp    Binary plist reader (keyed offset-table traversal)
src/ap2_ptp.c         NTP responder + PTP engine (gPTP dialect, BMCA,
                      hold-grandmaster, unicast grants) + daemon loop
src/ap2_ptp_shm.c     Shared PTP clock: POSIX shm double-buffer + control channel
src/alac_ext.cpp      ALAC encoder override with proper 24-bit support
libraop/              Upstream philippe44/libraop (RAOP protocol + crypto)
```

## Credits and references

This binary follows the trail blazed by **Brad Keifer**
([@bradkeifer](https://github.com/bradkeifer)), whose earlier `cliap2` — the
standalone AirPlay 2 streaming client for Music Assistant (adapting OwnTone
into a dedicated client) — proved a CLI streamer was viable and directly
inspired this unified RAOP + AirPlay 2 binary.

**Built on**

- **[philippe44/libraop](https://github.com/philippe44/libraop)** — bundled as a
  submodule and the foundation of the RAOP/AirPlay 1 path: the `raopcl` client,
  the cross-platform helpers, the binary-plist code, and the ALAC codec. The
  `cliairplay` entry point derives from libraop's `cliraop` tool (© Philippe44;
  the original RAOP work © 2004 Shiro Ninomiya).
- **Apple Lossless (ALAC)** — audio codec, via libraop's bundled encoder.

**Referenced** for the AirPlay 2 / HAP / MediaRemote work — studied for wire
formats and receiver behaviour to build our own implementation; no source was
copied:

- **[OwnTone](https://github.com/owntone/owntone-server)** — AirPlay 2 / HAP
  reference; specifically the RTP sync-packet layout (`rtp_common.c`) and the
  gPTP grandmaster dataset that iOS senders announce (`libairptp`).
- **[pyatv](https://github.com/postlund/pyatv)** — the MediaRemote / DataStream
  remote-control channel and the protobuf message/field numbers, plus AirPlay 2
  protocol detail ([pyatv.dev](https://pyatv.dev/documentation/protocols/)).
- **[openairplay/airplay2-receiver](https://github.com/openairplay/airplay2-receiver)**
  — AirPlay 2 receiver-side reverse engineering, and the basis for the local
  MediaRemote capture rig used to derive the real now-playing sequence.
- **[shairport-sync](https://github.com/mikebrady/shairport-sync)** —
  receiver-side anchor/timing math, used to get the realtime start anchor right.
- **[Emanuele Cozzi's AirPlay 2 notes](https://emanuelecozzi.net/docs/airplay2/)**
  — AirPlay 2 protocol documentation (stream types, channel setup, pairing).

## License

This project as a whole — and the released binaries — are distributed under
the **GNU General Public License, version 3** ([LICENSE](LICENSE)). That
follows from what the binary contains: the RAOP core descends from the
GPL-2.0-or-later raop_play, and the bundled mDNS discovery client (mdnssd)
is GPL-3.0.

The sources written for this project (`src/`) carry per-file
`SPDX-License-Identifier: Apache-2.0` headers and may be reused under that
license on their own. The one exception is `src/cliairplay.c`, which derives
from libraop's `cliraop.c` and is therefore GPL-2.0-or-later.

Every bundled third-party component, with its copyright notices and license
texts, is inventoried in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
which also ships with every binary release.
