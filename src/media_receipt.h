/*
 * Optional private media-write receipt collector.
 *
 * Disabled by default. When enabled (private owned child only) it keeps fixed
 * bounded state and counts full sender-side datagram writes for exactly one
 * STOP-terminated applied session epoch, then emits ONE closed `@MEDIA1` record
 * on stdout after every other stdout writer has been joined.
 *
 * What a record is: kernel write acceptance by this process for the serialized
 * qualifying writes of one epoch, plus a sticky fault. It is NOT egress,
 * delivery, receiver playback, acoustic or independent-observer evidence, and
 * `fault=false` means only that coverage was installed throughout and no
 * unknown/error outcome was observed, not network losslessness. Child-reported
 * scalars are same-trusted-child evidence; nothing here is a crypto proof or a
 * caller-token echo.
 *
 * Lifecycle: WAIT -> ACTIVE (actual applied session epoch 1) -> FROZEN (STOP,
 * under the send lock, BEFORE the transport is stopped). No reactivation. The
 * measured interval closes at the freeze; eligibility is separate: a sticky
 * terminal_invalid latches on any later START/command/registration change/
 * signal/failure until the final record is sealed.
 *
 * Threading contract (no locks and no I/O inside this module's event entry
 * points; they are safe to call from the transport callbacks):
 *   - applied/sent/failure/freeze/teardown/seal run under the caller's single
 *     media send lock (the CLI's g_audio_send_lock); applied additionally runs
 *     under the session lock (send lock -> session lock; never the reverse).
 *   - note_command may run on the command thread without the send lock and only
 *     touches atomics; signal() is async-signal-safe.
 *   - emit() runs after all producers and stdout writers have been joined.
 *
 * Copyright (C) 2024-2026 Music Assistant Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __MEDIA_RECEIPT_H_
#define __MEDIA_RECEIPT_H_

#include <netinet/in.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "ap2_client.h"
#include "raop_client.h"

/* Wire cap: one record is at most this many bytes including prefix and LF. */
#define MEDIA_RECEIPT_MAX_LINE 512

typedef enum {
    MR_ROUTE_UNKNOWN = 0,
    MR_ROUTE_RAOP,       /* legacy RAOP client */
    MR_ROUTE_COMPAT,     /* AirPlay 2 client driving the nested RAOP client */
    MR_ROUTE_UDP,        /* native AP2 realtime UDP */
    MR_ROUTE_BUFFERED,   /* native buffered TCP: unsupported, never complete */
} mr_route_t;

typedef enum {
    MR_ORIGIN_UNKNOWN = 0,
    MR_ORIGIN_FRESH,
    MR_ORIGIN_IDLE,
    MR_ORIGIN_BACKLOG,
} mr_origin_t;

typedef enum {
    MR_WAIT = 0,
    MR_ACTIVE,
    MR_FROZEN,
} mr_state_t;

typedef struct {
    bool enabled;                 /* set once at startup, before any thread */
    bool configured;              /* route and registration were recorded */
    mr_route_t route;
    uint16_t setup_port;          /* separately parsed SETUP media port */
    uint32_t reg_gen;             /* installed registration generation */

    _Atomic int state;            /* mr_state_t */
    _Atomic bool terminal_invalid;/* sticky until sealed */
    _Atomic bool torn_down;       /* explicit owner unregister phase began */
    volatile sig_atomic_t signaled;

    bool stop_frozen;             /* the freeze came from a commanded STOP */
    uint32_t applied_count;
    uint64_t applied_epoch;       /* the one applied epoch, 0 when none */
    bool fault;
    bool overflow;
    uint32_t fresh_units, fresh_bytes, idle_units, backlog_units;
    bool have_dest;
    struct sockaddr_in dest;
} media_receipt_t;

/* Zero state. Does not enable. */
void mr_init(media_receipt_t *mr, bool enabled);

/* After mr_configure: a hook path that disagrees with the route the CLI
 * resolved up front is a sticky fault (UNKNOWN means not checked). */
void mr_expect_route(media_receipt_t *mr, mr_route_t resolved);

/* Record the actual route and registered coverage before any media. A buffered
 * or unknown route, an absent setup port or a zero generation set the fault. */
void mr_configure(media_receipt_t *mr, mr_route_t route, uint16_t setup_port,
                  uint32_t registration_generation);

/* Applied-session-epoch observer (see ap2_session_ops_t::applied). */
void mr_applied(media_receipt_t *mr, uint64_t epoch);

/* One full successful datagram observed with its caller origin. `epoch_tag` must
 * equal the applied epoch for FRESH. `setup_port` is the path's parsed SETUP
 * port as seen by the producer. dest is copied immediately. */
void mr_sent(media_receipt_t *mr, mr_origin_t origin, size_t bytes,
             const struct sockaddr_in *dest, uint16_t setup_port,
             uint64_t epoch_tag);

/* Any non-success outcome (error, drop, nonready, unavailable, select error). */
void mr_failure(media_receipt_t *mr);

/* STOP: freeze counters and endpoint, under the send lock, BEFORE the transport
 * is stopped. current_generation is the live registration generation. */
void mr_freeze_for_stop(media_receipt_t *mr, uint32_t current_generation);

/* Entry of any other transport command (START, FLUSH, STANDBY, PAUSE, PLAY,
 * DISCONNECT, ANNOUNCE): latches terminal_invalid when already frozen. */
void mr_note_command(media_receipt_t *mr);

/* Latch terminal_invalid (idempotent, sticky). */
void mr_latch_invalid(media_receipt_t *mr);

/* Async-signal-safe abnormal-signal flag. */
void mr_signal(media_receipt_t *mr);

/* Begin the explicit owner teardown phase (after the command thread joined and
 * before the owner clears its callbacks): checks the registration, then makes
 * the expected clear a normal event. Idempotent. */
void mr_begin_teardown(media_receipt_t *mr, uint32_t current_generation);

/* Producers' view of the applied epoch for tagging, 0 while waiting. */
uint64_t mr_current_epoch(const media_receipt_t *mr);

/* Format the closed record for the sealed state. `playback_ok` is false when the
 * run loops reported a playback failure, a failed command join/cleanup or an
 * ended session without a commanded STOP. Returns the length (no NUL counted)
 * or 0 on a formatting error/overflow. */
size_t mr_format(const media_receipt_t *mr, bool playback_ok, char *buf,
                 size_t buf_size);

/* Terminal emitter. Only after every stdout writer joined. In order: require
 * stdout-like `out` to be a pipe with PIPE_BUF >= 512; F_GETFL then set
 * O_NONBLOCK BEFORE fflush; one fflush(out) that must succeed with no stream
 * error; format into a fixed buffer; ONE write(2) with no retry for EINTR,
 * EAGAIN or a partial write. Any failure omits the record (returns false) and
 * never waits. The pipe stays non-blocking. This is not a wall-clock deadline
 * guarantee. */
bool mr_emit(const media_receipt_t *mr, bool playback_ok, FILE *out);

/* Transport hook adapters: pass the collector as the hook context. */
void mr_raop_outcome_cb(void *ctx, raop_media_outcome_t outcome,
                        raop_media_origin_t origin, size_t datagram_bytes,
                        const struct sockaddr_in *destination,
                        uint16_t setup_port);
void mr_ap2_write_cb(void *ctx, const ap2_media_write_t *write);
void mr_ap2_outcome_cb(void *ctx, ap2_media_outcome_t outcome,
                       ap2_media_origin_t origin, uint64_t tag);

#endif /* __MEDIA_RECEIPT_H_ */
