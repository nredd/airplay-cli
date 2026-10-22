# Private native-volume observation

Phase 1 is passive observability, not a native-volume implementation, acceptance proof, or UI fix.

## Enable

Set both of these only for an already eligible experimental HomePod-remote session:

```text
CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE=1
CLIAIRPLAY_PRIVATE_NATIVE_VOLUME_CAPTURE=1
```

The capture flag is strict literal `1`. It does not request type 130, alter session declarations, client-update subscriptions, attachment, command dispatch, callbacks, publication, metadata, audio, or authorization. Production volume publication remains hard-closed outside `AP2_VOLUME_TESTING`.

At MRP teardown, stderr receives one bounded allowlisted line:

```text
[STATUS] native_volume_capture version=1 ...
```

It has aggregate event/DataStream ingress and ACK-egress counts; separate `volume_get`, `volume_result`, `volume_set_candidate`, `volume_feedback`, `volume_availability`, and `volume_capabilities` counts; transport/other and parser classes; saturation overflow; plane connection state; fixed-baseline `dacp=outside_cli subscription=0 publication=0 capability=0` values; `generation_at_cutoff` and `binding_at_cutoff`; and candidate-present/exact-match booleans split by protobuf `endpoint` and `output` fields for the in-memory sender-device, session and group role IDs. The capability/subscription/publication fields describe this current capture baseline only. A match is only exact byte equality against the valid scoped schema field currently being observed. Endpoint/output role is reported, but remains ambiguous and is not authority. It does not normalize, register, alias, or establish authority for any ID.

The line retains no raw frames, IDs, hashes, credentials, names, URLs, headers or arbitrary strings. Invalid envelopes or volume schemas increment `parser_invalid` and cannot supply endpoint/output equality evidence. Counters are constant-memory saturating `uint64_t`; `overflow=1` means a counter saturated, so do not treat a zero count as no traffic when overflow is set. `event` and `datastream` report `connected`, `closed`, or `unattached`; unattached/closed planes are incomplete coverage. DACP ingress is in Music Assistant and is always `dacp=outside_cli`, requiring a separate capture.

## Seams and correlation

The event observation runs after decryption and before the existing five-command reverse-event whitelist. The DataStream observation runs after decryption/frame parsing and before its existing volume-target rejection. ACKs are counted only after their existing successful write. No stderr I/O or backend callback runs under the receive-path capture lock. Frozen summary fields are immutable before that lock is released for output.

This is one aggregate-per-session summary, not stage-correlated capture or a full end-to-end UI loop. Stop entry freezes counters and snapshots plane attachment/connection plus binding/generation before graceful disconnect; `*_at_cutoff` reports that snapshot even though the summary is emitted after closure. Traffic after that cutoff is excluded. Graceful teardown is required: force-kill can lose the summary. Outgoing counts are ACKs only. For a hardware phase, correlate the final summary with owner-recorded native before/after state, UI enabled/disabled state and acoustic observation. A summary cannot prove that a slider interaction was sent, that a HomePod relayed it, that a candidate is an output identity, or that MA executed a change. If every connected CLI plane has zero relevant ingress with `overflow=0`, that only bounds these sender-side planes; it says nothing about phone-to-HomePod traffic or DACP. Coordinator-driven gentle finalization and cross-plane capture remain future work.
