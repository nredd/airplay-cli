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

## Optional RAOP library write callback

The CLI-local `patches/libraop-media-write-callback.patch` is applied to build-local
copies after the existing thread-join fix. The pinned submodule and its gitlink
remain unchanged. Both public `raop_client.h` copies are patched identically;
compilation uses the generated header (`ap2_client.c`, `ap2_ptp.c` and
`cliairplay.c` include that generated `raop_client.h`, not the pinned copy). The
success callback has no CLI consumer of its own: the optional private receipt
collector below uses the separate outcome hook the same patch adds. Native
AirPlay 2 has a separate optional hook described below.

`raopcl_set_media_write_cb(client, callback, ctx)` defaults to NULL. Install before
media starts. The synchronous callback reports only full successful audio
`sendto` writes following positive socket readiness: `RAOP_MEDIA_FRESH` from
`raopcl_send_chunk`, or `RAOP_MEDIA_BACKLOG` from resumed `raopcl_accept_frames`,
the full datagram size including the RTP header, and the actual destination.
Origin identifies the caller path, not the content or stimulus. Sync, timing and
RTX writes are excluded. Non-streaming, closed, non-ready, failed/short writes
and select errors do not notify. Existing send attempts, return values, pacing,
volume and retry behavior are unchanged, including the legacy select-error
path that may still attempt a write without producing a notification.

Both media callers hold the same client mutex through the callback. Copy only
bounded data; do not perform I/O, block, retain the borrowed destination pointer,
or reenter libraop. The pointer is valid only until callback return. The setter
uses that mutex too: replacing or clearing waits for an in-flight callback.
Keep the old context alive until the setter returns; clearing also clears the
stored context. Before freeing the client, clear the callback, stop/join *all*
API callers (including setters), then destroy with exclusive ownership. RTP
thread joins do not join application media callers.

This is success-only kernel write acceptance, NOT complete error/drop accounting,
NIC egress, receiver receipt or playback evidence. It supplies no timestamps,
START epochs, complete receipt, cross-process clock proof or final-output owner.

`make test-raop-media STATIC=1` exercises the actual patched production unit,
real fresh/backlog public caller paths and real UDP writes to owned loopback
sockets with no receiver process. Test-only syscall hooks cover error/short/
EINTR/non-ready paths, sync/RTX exclusions and concurrent unregister/context
lifetime. `make test-raop-media-red STATIC=1` requires an intended callback
assertion failure from a matched baseline-behavior fixture: it retains the new
API solely to compile but drops notifications, as the old source did. This is
not an assertion that the old source had the new API. Both targets run in
`make test`, including the existing Linux ASan/UBSan CI gate.

## Optional native AP2 write callback

`ap2cl_set_media_write_cb(client, callback, ctx)` defaults to NULL and has no
CLI consumer or new output. `ap2cl_send_chunk_tagged(client, pcm, frames, origin,
tag)` accepts caller labels `AP2_MEDIA_FRESH`, `AP2_MEDIA_IDLE`,
`AP2_MEDIA_BACKLOG`, or `AP2_MEDIA_UNKNOWN`, plus an opaque `uint64_t` scalar.
The old `ap2cl_send_chunk` remains compatible and labels writes UNKNOWN/0,
including ordinary idle silence. Labels are NOT content proof or applied START
epochs. This does not change return values, retry/drop rules, pacing, volume,
anchors or session behavior. RAOP-compatible sends do not invoke this hook.

Each borrowed `ap2_media_write_t` describes one successful original native media
unit: route `AP2_MEDIA_REALTIME_UDP` only after `AP2_SEND_SENT` for the full
original datagram, or `AP2_MEDIA_BUFFERED_TCP` only when the final byte of the
length-prefixed encrypted frame is accepted by `send`. `bytes` includes the RTP
header, encrypted payload, auth tag and nonce, plus the TCP length prefix when
buffered. Queuing, partial writes, drops, errors, sync/control and RTX do not
notify. `audio_packets_sent` can advance while a TCP tail remains unwritten;
it is NOT a completion counter. A later successful tail drain invokes exactly
once with the original frame's snapshotted origin, scalar and total bytes,
including when draining during quiesce. Discarding a wholly unwritten frame or
disconnecting/canceling an incomplete tail never produces completion. A hard
TCP write error also invalidates that frame's notification, even if an API caller
later retries and drains its tail; this hook cannot certify completeness.

UDP destination is the actual `sendto` sockaddr, not the RTSP port. TCP snapshots
`getpeername` on the live data connection when queueing; disconnect closes that
connection and discards its pending frame before reconnect. Failed peer lookup
is explicit as `destination_known=false` and a zero destination, not a guessed
peer. A known tuple is local socket evidence, not independently observed egress.

Unlike libraop's internally locked setter, the native media API already relies
on **caller-owned serialization**. Use the SAME external mutex or exclusive
ownership for registration/clear, send/accept, flush/standby/resume/stop,
connect/disconnect and destruction. The CLI uses `g_audio_send_lock` and its
session quiesce bracket; a future consumer must call the setter within that
bracket too. The setter does not join callers or acquire a new internal lock.
Under this contract, clearing/replacing returns with no old callback in flight,
so the old context can be freed immediately. Pending frames store no callback
or userdata pointer. Every setter call, even an identical registration,
invalidates notification for any parked TCP frame without altering its bytes.
Later drain is deliberately suppressed, NOT attributed to a new context; a frame
queued while unregistered is never adopted. This trades completeness across
registration changes for a small lifetime-safe opt-in API. Calling the setter
concurrently without the shared serialization is outside the API contract.

Callbacks run synchronously inside the caller's media serialization. Copy only
bounded values; do not block, perform I/O, reenter the client, or retain pointers.
Clear, stop/join ALL API callers (setters included), then destroy exclusively.
No new lock spans blocking socket I/O and existing bounded stop is unchanged.
This remains success-only kernel acceptance, not complete error/drop accounting,
NIC egress, receiver receipt, playback, timestamps, applied epochs, cross-process
clock proof or a final receipt. Suppression and late errors require separate
future completeness accounting; this PR adds no collector or binary pin change.

`make test-ap2-media STATIC=1` uses the production client, encoder, encryption,
IO and pending-flush paths with owned loopback UDP/TCP sockets. It covers full
writes on both routes, caller/default labels, real TCP backpressure, injected
EINTR/EAGAIN/timeout/short UDP/hard errors, final-byte completion, warm
flush/resume, quiesce/discard, reconnect/cancel and serialized context clearing.
`make test-ap2-media-red STATIC=1` runs the same built fixture with an intentional
false completion assertion: the queued counter advances with an unwritten tail
while the new callback remains zero. It must fail at that assertion, not build.
The negative fixture clears registration, destroys its client and closes the
peer before the intentional assertion exits, so Linux LeakSanitizer can retain
its normal leak checks. The target still requires exit 1, the exact assertion
and no sanitizer report. Rejected controls print the exit status and at most
20 log lines of 240 characters, with path tokens redacted; the full local log
remains in `build/tests/ap2-media-red.log`.
Both targets run under the unchanged normal and Linux sanitizer `make test`
gates; architecture CI gates remain unchanged.

## Optional private media-write receipt (`--private-media-receipt`)

Disabled by default: without the flag no hook is registered, no applied-epoch
observer is installed, ordinary stdout stays blocking and nothing is emitted.
With it, one fixed collector (`src/media_receipt.c`, no allocation or I/O from
callbacks, saturating `uint32` counters) counts full sender-side datagram writes
for **one** STOP-terminated applied session epoch and emits one closed record on
stdout at the very end of the process. It is a source-level mechanism for a
private owned child, not a binary adoption, a deployment or audio acceptance.

What a record is, and is not:

- Kernel write acceptance by this process for the serialized qualifying writes
  after the *actually applied* START (`ap2_session_ops_t::applied`, called inside
  `ap2_session_start` after the epoch increments and PLAYING is set, under the
  existing send and session locks, never for a failed or ended START) and before
  the STOP freeze (taken under the send lock BEFORE the transport is stopped).
  It is not egress, delivery, receiver playback or independent-observer
  evidence. `fault=false` means coverage was installed throughout and no unknown
  or error outcome was seen, not network losslessness.
- Child-reported scalars from the same trusted child, no crypto and no
  caller-token echo. The destination is the actual `sendto` address (copied in
  the callback) and must equal the SETUP media port, parsed separately
  (`raopcl_media_setup_port`, `ap2cl_media_setup_port`), plus a single stored
  IPv4 address. The parent still compares the address to its own admitted target.

Coverage and accounting (each path is a real call path, not a test-only hook):

- Legacy RAOP and the nested client of the AirPlay 2 RAOP-compatible flow use a
  separate RAOP *outcome* hook (`raopcl_set_media_outcome_cb`) next to the
  unchanged success hook. Every audio attempt, fresh or backlog, yields exactly
  one outcome: `SENT`, `NOT_READY`, `SELECT_ERROR`, `SEND_ERROR` or `UNAVAILABLE`.
  A select error is reported even when the legacy path still sent, and is never
  a qualifying write. Legacy send behavior and return values are unchanged.
  `ap2cl_set_raop_media_outcome_cb` bridges the nested client and is cleared in
  `ap2_raop_session_cleanup` before the nested destroy.
- Native realtime UDP keeps the success hook and adds `ap2cl_set_media_outcome_cb`
  for `DROPPED` and `FATAL` (state, sync, encode, encrypt, allocation or send).
  Each content invocation yields one full-write event or one failure outcome.
  `ap2cl_send_chunk_tagged` carries an explicit `FRESH` (tag = applied epoch) or
  `IDLE` origin; `BACKLOG` and `IDLE` units are counted separately, never fresh.
- Actual buffered TCP is explicitly **unsupported**: nothing is registered, the
  record reports `route=buffered` and `fault=true`, transport behavior is
  unchanged. A parked frame is never counted (`audio_packets_sent` advances at
  queue time); supporting it needs a separate design for queue-time generation
  and every completion/discard path.
- One lifecycle: WAIT -> ACTIVE (epoch 1) -> FROZEN. A second applied START, an
  unknown origin or destination, a second destination, a port mismatch, a
  registration change (`*_media_registration_generation`, bumped by every hook
  set) or counter saturation sets a sticky fault. After the freeze a sticky
  terminal-invalid latches on any START (successful or failed, even one already
  buffered behind STOP), FLUSH/STANDBY/PAUSE/PLAY/DISCONNECT/ANNOUNCE, a second
  STOP, a missing client, a changed registration, a signal, a failed playback
  loop, a session ended without STOP or a failed client destroy/disconnect
  observed by `finish_run`. The owner's one explicit unregister after the
  command thread joins is normal and only in that teardown phase.
- The nested RAOP hook reports every non-backlog send as fresh and cannot label
  idle silence. Silence needs a hot splice line, which only the native flow has,
  so the compat lane never sends it today; if it ever did, `ap2_send_silence_chunk`
  makes an ACTIVE collector incomplete rather than counting it as fresh. That one
  case therefore does not use the RAOP hook's origin.
- Two more places depart from the original design, both on purpose. Native
  failure outcomes are reported from `ap2cl_send_chunk_tagged` (one failure per
  failed content invocation, including state/socket failures before any send),
  not from `ap2_native_send_chunk`/`ap2_io_send_datagram_deadline`, because the
  wrapper is the single exit every native content call passes through; the
  success hook stays where it was. Registration loss is detected with a
  per-client generation counter bumped by every hook set (polled at the STOP
  freeze and at teardown start) rather than by comparing callback pointers, so
  an identical re-registration is caught too. A compat content send with the
  nested client already gone reports no outcome, but the live generation then
  reads 0, which differs from the installed one and faults the record.

The record is written exactly once, by `finish_run` (called from `main`), after the command thread
joined, the callbacks were cleared and `ap2cl_destroy`/`raopcl_destroy` returned.
That also joins the AirPlay 2 feedback worker, the only thread that can reach
`remote_command_event`, so no other stdout writer exists. In order: stdout must
be a pipe with `PIPE_BUF >= 512`; `O_NONBLOCK` is set (after `F_GETFL`) BEFORE
any flush; one `fflush(stdout)` must succeed with no stream error; the record is
formatted into a fixed 512-byte buffer; one `write(2)` with no retry for `EINTR`,
`EAGAIN` or a partial write. Any failure omits the record and never waits; the
pipe stays non-blocking. This is not a wall-clock deadline: scheduling, STOP and
transport teardown, destructor joins and stdio internals can all be late, so a
consumer must validate EOF against its own drain/observe deadlines and treat a
late or missing record as incomplete.

`O_NONBLOCK` is only established at this terminal step; the child's *earlier*
stdout writes (the `[STATUS] route` line at startup, and on AirPlay 2 the MRP
status and remote-command lines) are ordinary blocking `printf` + `fflush`. A
reader that stalls long enough to fill the pipe can therefore hold the child in
one of those writes before the terminal step is ever reached; the record is then
missing and the consumer's own deadline and forced containment apply. The legacy
RAOP route has no stdout writer between the route line and the final.
`make test-cli-real-receipt` demonstrates both halves against the real binary
(`early-full-stdout-blocks` is a manual experiment, not in the default run).

```
@MEDIA1 {"v":1,"terminal":"stop","route":"raop","epoch":1,"fresh_units":1,"fresh_bytes":128,"idle_units":0,"backlog_units":0,"fault":false,"overflow":false,"addr":"192.0.2.10","port":6001,"setup_port":6001}
```

One ASCII line, at most 512 bytes including prefix and LF, fixed key order, no
other `@MEDIA` lines, never on stderr. `terminal` is `stop|abnormal` (only `stop`
qualifies); `route` is `raop|compat|udp|buffered|unknown`; `epoch` is 0 or 1;
counts and bytes include the RTP header; `addr` is null with no fresh unit. A
post-freeze invalidation, signal or failure is merged into `fault`. The endpoint
is private: keep it out of logs, public text and fixtures (tests use
documentation addresses only).

Tests use production code paths with owned loopback sockets, no receiver:

- `make test-raop-media test-raop-media-red STATIC=1`: the patched libraop
  outcome matrix (fresh/backlog, negative/short/EINTR send, nonready, select
  error with a still-successful send, unavailable), exactly one per attempt,
  setup-port parsing and the generation counter.
- `make test-ap2-media STATIC=1`: native UDP drop/fatal/encode/state failures
  with one-event-per-invocation, the real collector adapters, freeze, port
  binding, and buffered TCP never counted.
- `make test-compat-media STATIC=1`: the real nested client through the
  `ap2cl` bridge (fresh, backlog, select error, re-registration, cleanup clear).
- `make test-media-receipt test-media-receipt-red STATIC=1`: state machine,
  exact record, and the emitter against real pipes (including a full pipe, a
  `fcntl`/flush failure and `EINTR`/partial/`EAGAIN` writes); the red target
  swaps in a success-only observer and must fail the select-error assertion.
- `make test-cli-media-receipt STATIC=1`: the production `cliairplay.c` command
  path with the real session engine: applied epoch, STOP freeze before the
  transport stop, post-freeze START success and failure, registration changes,
  and the production `finish_run` sequence after a real STOP: hooks cleared
  under the lock, a stand-in remote-command stdout writer joined by the client
  destroy, then exactly one final line on a real pipe, with a failed destroy and
  a failed result merged, plus a control where an unjoined writer blocks the
  emitter. The same sequence also runs with the PRODUCTION feedback worker: a
  real `ap2cl` whose real worker services a real encrypted MRP event channel
  and writes through `remote_command_event`, joined by the real `ap2cl_destroy`
  before exactly one last final line, with a control where skipping the join
  lets a remote command follow the final. That is the real worker and MRP code
  on a scripted channel, not a paired AirPlay 2 session.
- `make test-cli-real-receipt STATIC=1`: the REAL `cliairplay` executable
  (legacy RAOP route) spawned with a real command FIFO, PCM stdin pipe and
  stdout pipe against an owned loopback RTSP/UDP fixture: START, PCM, STOP gives
  one `@MEDIA1` whose unit and byte counts, target and setup port equal what the
  fixture's UDP socket received; no flag emits nothing; STOP without START never
  qualifies; a buffered `STOP\nSTART\n` read leaves an invalid record; and a
  stdout pipe too full for the record lets the child exit without blocking, with
  the record omitted. It is skipped under `SANITIZE=thread`: the real binary
  trips four races inside upstream libraop (its timing/control threads against
  connect, disconnect and sync, on lines the patches do not touch), and a
  by-function suppression would also hide the setup-port store this repo adds to
  `raopcl_analyse_setup`. The collector is TSan-covered by the in-process cases.
- `tests/test_ap2_session.c` covers the applied observer (failed commit, commit
  then ENDED, second START, send lock held).

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

The private trial launcher may invoke `--attest-fd <inherited-readonly-asset-fd>`
and `--attest-nonce <32-lowercase-hex>` with `--attest-only`. The CLI requires
that pair, hashes the inherited regular file and its Linux `/proc/self/exe` image
through positional reads, and exits successfully only when both stable SHA-256
values match. Its only stdout is one JSON acknowledgement:

```text
[ATTEST] {"version":1,"kind":"current-image-match-at-ack","nonce":"...","exec_fd_sha256":"...","self_sha256":"..."}
```

The mode fails closed if the descriptor is unsafe, the image is unstable or a
platform cannot read the current executable. It performs no receiver, PTP,
pairing, or audio I/O. Launchers must compare the nonce and both digests with
their pinned asset before treating the child as ready. All ordinary CLI behavior
is unchanged without the three attestation flags.

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
| `CLIAIRPLAY_PTP_STRICT_PEERS=1` (private trial env) | On context creation, admit PTP receive-side effects only from the current registered timing peers: Delay/Pdelay replies, exchange accounting, BMCA, followed-clock dispatch and unicast grants. Exact `1` enables it; unset or every other value preserves ordinary PTP behavior. `SETPEERS` and daemon registration updates are serialized with admission, so a peer retired before admission cannot act. The `--ptp-daemon` ready line attests the effective value as `strict-peers=on` or `strict-peers=off` so a supervisor can verify the gate is live rather than trust the environment it passed. This filters source IPv4 addresses, not cryptographic identities, and does not prevent IP spoofing or isolate discovery or other lifecycle traffic. Admission is not draining: a previously admitted packet may finish after removal returns. Keep it off outside the private trial. See `DESIGN.md` for boundaries and offline regression coverage. |

### Private diagnostics

| Option | Description |
|--------|-------------|
| `--private-media-receipt` | Enable the private bounded media-write receipt collector and its single terminal `@MEDIA1` stdout record (default off). See [Optional private media-write receipt](#optional-private-media-write-receipt---private-media-receipt). |

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

`[STATUS] stopped` acknowledges `ACTION=STOP` once playback has been torn down.
The main-loop control-health decision is synchronized with STOP, so its intentional
disconnection is not reported as a control-channel failure.

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

## Building

```bash
# macOS (native)
make STATIC=1

# Linux cross-compile (example)
make HOST=linux PLATFORM=aarch64 CC=aarch64-linux-gnu-gcc STATIC=1

# Linux/aarch64 artifact with no ELF interpreter or dynamic dependencies
make HOST=linux PLATFORM=aarch64 CC=aarch64-linux-gnu-gcc \
  CXX=aarch64-linux-gnu-g++ STATIC=1 FULL_STATIC=1

# Focused native regression tests
make test STATIC=1
```

Requires the libraop submodule with pre-built static libraries (OpenSSL,
libcodecs, libmdns), plus `patch`. The build applies
`patches/libraop-raop-client-thread-join.patch` to `build/patched/raop_client.c`,
leaving the pinned submodule source unchanged. Both legacy RAOP and AirPlay 2
RAOP-compat use this copy: failed connects only join successfully created RTP
threads, and repeated cleanup does not rejoin them. A failed `pthread_create`
also fails the connect cleanly. A second build-local patch,
`patches/libraop-rtsp-setup-cleanup.patch`, frees the SETUP request's Transport
header on failure; the SETUP 500 sanitizer regression exposed that leak.
`patches/libraop-logtime-bounds.patch` bounds timestamp formatting with
`snprintf`, including the Windows path. Production and tests compile the same
build-local logging source; pinned dependency files remain unchanged. This also
keeps sanitizer builds compatible with SDKs that deprecate `sprintf`.

`make test-stop-health STATIC=1` compiles the CLI source and exercises its STOP
handler on a command thread before the main-loop health decision. It verifies
that intentional STOP exits cleanly while real control failures still fail.
This regression also runs in the full test target.

Both RAOP connection paths resolve IPv4 destinations through `getaddrinfo`,
copying a validated IPv4 socket address rather than dereferencing legacy
`hostent` pointer storage. `make test-net-address STATIC=1` covers resolver errors,
invalid address records and bounded copying; the full loopback suite exercises
real numeric-host resolution.

The RTSP patch also closes a connection when a required initial response read
returns timeout, EOF, or error. The response boundary is then unknown, so
cleanup must not send FLUSH/TEARDOWN and wait again on that stream. Complete
RTSP error responses and optional-response requests retain their existing
handling. The build-local
`libraop-http-read-poll.patch` prevents failed or interrupted `poll()` calls
from entering a blocking `recv()` without readiness.

`make test-http-read test-rtsp-response STATIC=1` exercises actual dependency
source with deterministic syscall/response seams. It checks interrupted and
failed polling, timeout, normal reads, EOF and EAGAIN, plus RTSP timeout/error
invalidation, normal 200/401 responses, and unchanged optional-response
handling. These are also part of `make test`.
They do not establish a total handshake deadline or reliable signal
cancellation: per-character/header waits, body reads, and signal delivery
remain separate concerns. Positive line reads are not newly validated for
newline termination by this patch. Closing a failed transport proves local resource
release, not receiver teardown.

`make test STATIC=1` checks real loopback refusal, ANNOUNCE 401, peer close,
SETUP failure, injected thread-creation failures, reconnect/repair, and reaping
already-exited threads. It also runs both CLI routes against refusal/401/close,
requiring exit code 1, a `connect_failed` status, and command FIFO removal.
The same suite runs under ASan/UBSan on Linux with
`make test STATIC=1 CC=gcc CXX=g++ SANITIZE=address,undefined` after `make clean`.

## Platforms and CI

Both macOS targets use the supported `macos-15` ARM64 hosted runner, listed
[here](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
ARM64 runs the full native test suite and `--check`; x86_64 is cross-compiled
with `-arch x86_64` and architecture-checked. This replaces the retired
`macos-14` host without changing target architectures or validation coverage.

CI (`.github/workflows/build.yml`) cross-builds four targets on every push —
`linux-x86_64`, `linux-aarch64`, `macos-arm64`, `macos-x86_64` — validates
`--check` on the natively runnable ones, and uploads the binaries as
artifacts. It separately builds `linux-aarch64-static` with `FULL_STATIC=1`.
That optional trial artifact preserves the ordinary dynamic artifact names and
ABI, rejects `PT_INTERP` and `DT_NEEDED`, and exercises the real attestation
and localhost-resolution paths under emulated ARM64 Alpine and Debian. It is
not included in release assets until explicitly adopted. Pushing a `v*` tag additionally runs a release job. The release is
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

### Required RAOP response deadline

The build-local RTSP adapter routes required responses (`get_response == 1`)
through `src/raop_response.c`. It uses the existing shared `ap2_io` monotonic
clock and nonblocking deadline reads: one ten-second budget spans status,
headers, and body. Bytes arriving slowly do not reset that budget. An incomplete
status/header/body, allocation failure, invalid length, or malformed response
closes and invalidates the local transport. Partial headers/body are released;
no partial body or advertised-but-unread body length is returned. Complete
non-200 responses are drained within the same budget and return false while
retaining the transport, including OPTIONS 501 keepalive responses.

Limits are 2047 bytes per line, 64 KiB total status/header wire bytes, 63 headers,
and a 1 MiB body. Status lines require RTSP/1.0; lines require exact CRLF.
Invalid header-name tokens, negative, malformed, duplicate or oversized
Content-Length and folded headers fail closed. These are explicit supported-response limits,
not observed receiver capabilities. Optional metadata/auth-challenge response
handling remains on the existing path. Connection establishment, request
writes, optional responses, and reliable external-signal cancellation remain
outside this response deadline. Closing a transport is not wire TEARDOWN or
proof of receiver restoration.

`make test-rtsp-response STATIC=1` compiles the actual RTSP adapter and response
reader with deterministic byte/time seams. It checks complete and truncated
bodies, missing header termination, trickled data crossing the absolute budget,
length bounds/syntax/duplicates, empty bodies, error statuses, partial status
lines and folded headers. Production source uses production compiler flags;
the assertions compile separately with `-Wall -Wextra -Werror`.

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
