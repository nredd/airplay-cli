# Private now-playing DataStream publisher

This is a default-off, office-pod-only hypothesis test. It is not private capture, a rail fix, a UI success claim, or a native session-volume publication or authority change.

## Enable

Set all of these for an already admitted experimental HomePod-remote office-pod session:

```text
CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE=1
CLIAIRPLAY_NATIVE_VOLUME_RAIL=1
CLIAIRPLAY_PRIVATE_NOW_PLAYING_DATASTREAM=1
```

`CLIAIRPLAY_PRIVATE_NOW_PLAYING_DATASTREAM` is strict literal `1`. It is inert unless the existing HomePod admission and receive-only native rail are both active. It does not request type-130 DataStream setup itself: the rail's existing admission-first request remains responsible for that attach.

The experiment is suppressed when either of these is active:

```text
CLIAIRPLAY_PRIVATE_NATIVE_VOLUME_CAPTURE=1
CLIAIRPLAY_SESSION_VOLUME=mrp130
```

An explicit `CLIAIRPLAY_MRP_TYPE130=0|false|off` still prevents the rail attachment, so it also prevents this experiment.

## Wire scope

The existing rail handshake is `DEVICE_INFO`, `SET_CONNECTION_STATE`, and client updates configuration. Only with this arm does the attached DataStream add `SET_NOW_PLAYING_CLIENT` and `SET_STATE`, including its existing periodic now-playing updates. `/command` publication remains unchanged. Private capture and session-volume modes keep the DataStream receive-only for now-playing and do not gain these writes.

The attach log labels only the negotiated mode. It does not assert receiver UI behavior or experimental success.
