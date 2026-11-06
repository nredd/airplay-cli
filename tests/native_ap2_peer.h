/*
 * Owned loopback AirPlay 2 receiver for the real-binary receipt test.
 *
 * Speaks just enough of the NATIVE AirPlay 2 control protocol for the real
 * cliairplay binary to connect, stream and tear down: plain GET /info, HAP
 * transient pair-setup (SRP-6a, fixed PIN, M1-M4), then ChaCha20-Poly1305
 * framed RTSP (SETUP x2, RECORD, SET_PARAMETER, FLUSH, POST /feedback and
 * /command, TEARDOWN). It counts the datagrams that arrive on its own UDP data
 * socket. Synthetic: a fresh random SRP salt/ephemeral per run, no credentials,
 * nothing real is contacted. It does not decrypt or decode the audio.
 */
#ifndef NATIVE_AP2_PEER_H
#define NATIVE_AP2_PEER_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int rtsp_fd, audio_fd, ctrl_fd;
    uint16_t rtsp_port, audio_port, ctrl_port;
    atomic_bool stop;
    atomic_uint teardowns, pairings;
    atomic_uint audio_units;
    atomic_ulong audio_bytes;
    pthread_t rtsp_thread, audio_thread;
    bool rtsp_started, audio_started;   /* threads that need a join */
} native_peer_t;

/* Bind the owned loopback sockets and start the serving threads. */
bool native_peer_start(native_peer_t *peer);
/* Stop and join; safe to call after a failed start. */
void native_peer_stop(native_peer_t *peer);

#endif
