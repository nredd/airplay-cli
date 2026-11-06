/*
 * Optional private media-write receipt collector, see media_receipt.h.
 *
 * Copyright (C) 2024-2026 Music Assistant Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "media_receipt.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MR_PREFIX "@MEDIA1 "

static mr_state_t mr_state(const media_receipt_t *mr)
{
    return (mr_state_t)atomic_load(&mr->state);
}

void mr_init(media_receipt_t *mr, bool enabled)
{
    memset(mr, 0, sizeof(*mr));
    mr->enabled = enabled;
    atomic_init(&mr->state, MR_WAIT);
    atomic_init(&mr->terminal_invalid, false);
    atomic_init(&mr->start_attempts, 0);
    atomic_init(&mr->caller_origin, MR_ORIGIN_UNKNOWN);
    atomic_init(&mr->torn_down, false);
}

/* Saturating u32 add; saturation is an explicit overflow, never a wrap. */
static void sat_add(media_receipt_t *mr, uint32_t *counter, uint32_t amount)
{
    if (*counter > UINT32_MAX - amount) {
        *counter = UINT32_MAX;
        mr->overflow = true;
    } else {
        *counter += amount;
    }
}

void mr_configure(media_receipt_t *mr, mr_route_t route, uint16_t setup_port,
                  uint32_t registration_generation)
{
    if (!mr->enabled) return;
    mr->configured = true;
    mr->route = route;
    mr->setup_port = setup_port;
    mr->reg_gen = registration_generation;
    /* Buffered TCP is explicitly unsupported and an unknown route has no
     * coverage: both are incomplete from the start. No port or generation means
     * the destination cannot be bound or a registration change not detected. */
    if (route == MR_ROUTE_BUFFERED || route == MR_ROUTE_UNKNOWN ||
        setup_port == 0 || registration_generation == 0)
        mr->fault = true;
}

void mr_expect_route(media_receipt_t *mr, mr_route_t resolved)
{
    if (!mr->enabled || !mr->configured || resolved == MR_ROUTE_UNKNOWN) return;
    if (mr->route != resolved) mr->fault = true;
}

void mr_applied(media_receipt_t *mr, uint64_t epoch)
{
    if (!mr->enabled) return;
    mr_state_t state = mr_state(mr);
    if (state == MR_FROZEN) {
        /* A START applied after the freeze: not a counted interval. */
        atomic_store(&mr->terminal_invalid, true);
        return;
    }
    if (mr->applied_count < UINT32_MAX) mr->applied_count++;
    if (state == MR_ACTIVE || mr->applied_count > 1) {
        /* One-start private profile: a second applied START is incomplete. */
        mr->fault = true;
        return;
    }
    if (epoch != 1) {
        mr->fault = true;
        return;
    }
    mr->applied_epoch = epoch;
    atomic_store(&mr->state, MR_ACTIVE);
}

void mr_sent(media_receipt_t *mr, mr_origin_t origin, size_t bytes,
             const struct sockaddr_in *dest, uint16_t setup_port,
             uint64_t epoch_tag)
{
    if (!mr->enabled) return;
    mr_state_t state = mr_state(mr);
    if (state == MR_FROZEN) return; /* post-freeze write never enters counts */
    if (state == MR_WAIT) {
        /* Before the applied transition only silence/backlog is expected. */
        if (origin == MR_ORIGIN_FRESH || origin == MR_ORIGIN_UNKNOWN)
            mr->fault = true;
        return;
    }
    if (origin == MR_ORIGIN_UNKNOWN || !dest || dest->sin_family != AF_INET ||
        bytes == 0 || bytes > UINT32_MAX) {
        mr->fault = true;
        return;
    }
    uint16_t port = ntohs(dest->sin_port);
    if (mr->setup_port == 0 || setup_port != mr->setup_port ||
        port != mr->setup_port) {
        mr->fault = true;
        return;
    }
    if (!mr->have_dest) {
        mr->dest = *dest;
        mr->have_dest = true;
    } else if (mr->dest.sin_addr.s_addr != dest->sin_addr.s_addr ||
               mr->dest.sin_port != dest->sin_port) {
        mr->fault = true;
        return;
    }
    switch (origin) {
    case MR_ORIGIN_FRESH:
        if (epoch_tag != mr->applied_epoch) {
            mr->fault = true;
            return;
        }
        sat_add(mr, &mr->fresh_units, 1);
        sat_add(mr, &mr->fresh_bytes, (uint32_t)bytes);
        break;
    case MR_ORIGIN_IDLE:
        sat_add(mr, &mr->idle_units, 1);
        break;
    case MR_ORIGIN_BACKLOG:
        sat_add(mr, &mr->backlog_units, 1);
        break;
    default:
        mr->fault = true;
        break;
    }
}

void mr_failure(media_receipt_t *mr)
{
    if (!mr->enabled) return;
    /* Only the measured interval is affected; before the transition and after
     * the freeze an outcome is not part of the epoch. */
    if (mr_state(mr) == MR_ACTIVE) mr->fault = true;
}

void mr_freeze_for_stop(media_receipt_t *mr, uint32_t current_generation)
{
    if (!mr->enabled) return;
    mr_state_t state = mr_state(mr);
    if (state == MR_FROZEN) {
        /* Unexpected second STOP. */
        atomic_store(&mr->terminal_invalid, true);
        return;
    }
    if (mr->configured && current_generation != mr->reg_gen) mr->fault = true;
    mr->stop_frozen = true;
    atomic_store(&mr->state, MR_FROZEN);
}

void mr_note_command(media_receipt_t *mr)
{
    if (!mr->enabled) return;
    if (mr_state(mr) == MR_FROZEN) atomic_store(&mr->terminal_invalid, true);
}

void mr_origin_scope_enter(media_receipt_t *mr, mr_origin_t origin)
{
    if (!mr->enabled) return;
    atomic_store(&mr->caller_origin, origin);
}

void mr_origin_scope_exit(media_receipt_t *mr)
{
    if (!mr->enabled) return;
    atomic_store(&mr->caller_origin, MR_ORIGIN_UNKNOWN);
}

void mr_note_start(media_receipt_t *mr)
{
    if (!mr->enabled) return;
    /* Exactly one START command attempt: any second entry is incomplete, even
     * when the first failed before activating an epoch. */
    uint32_t seen = atomic_load(&mr->start_attempts);
    while (seen < UINT32_MAX &&
           !atomic_compare_exchange_weak(&mr->start_attempts, &seen, seen + 1))
        ;
    if (seen >= 1) atomic_store(&mr->terminal_invalid, true);
}

void mr_latch_invalid(media_receipt_t *mr)
{
    if (!mr->enabled) return;
    atomic_store(&mr->terminal_invalid, true);
}

void mr_signal(media_receipt_t *mr)
{
    mr->signaled = 1;
}

void mr_begin_teardown(media_receipt_t *mr, uint32_t current_generation)
{
    if (!mr->enabled || atomic_load(&mr->torn_down)) return;
    if (mr->configured && current_generation != mr->reg_gen) {
        if (mr_state(mr) == MR_FROZEN)
            atomic_store(&mr->terminal_invalid, true);
        else
            mr->fault = true;
    }
    atomic_store(&mr->torn_down, true);
}

uint64_t mr_current_epoch(const media_receipt_t *mr)
{
    return mr->applied_epoch;
}

static const char *route_name(mr_route_t route)
{
    switch (route) {
    case MR_ROUTE_RAOP: return "raop";
    case MR_ROUTE_COMPAT: return "compat";
    case MR_ROUTE_UDP: return "udp";
    case MR_ROUTE_BUFFERED: return "buffered";
    default: return "unknown";
    }
}

size_t mr_format(const media_receipt_t *mr, bool playback_ok, char *buf,
                 size_t buf_size)
{
    bool stopped = mr->stop_frozen && !mr->signaled && playback_ok;
    bool fault = mr->fault || atomic_load(&mr->terminal_invalid) ||
                 mr->signaled || !playback_ok || !mr->stop_frozen;
    char addr[INET_ADDRSTRLEN] = "";
    bool have_addr = mr->have_dest && mr->fresh_units > 0 &&
                     inet_ntop(AF_INET, &mr->dest.sin_addr, addr, sizeof(addr));
    unsigned port = have_addr ? ntohs(mr->dest.sin_port) : 0;
    char addr_json[INET_ADDRSTRLEN + 3];
    if (have_addr) snprintf(addr_json, sizeof(addr_json), "\"%s\"", addr);
    else snprintf(addr_json, sizeof(addr_json), "null");

    int n = snprintf(
        buf, buf_size,
        MR_PREFIX "{\"v\":1,\"terminal\":\"%s\",\"route\":\"%s\",\"epoch\":%u,"
        "\"fresh_units\":%u,\"fresh_bytes\":%u,\"idle_units\":%u,"
        "\"backlog_units\":%u,\"fault\":%s,\"overflow\":%s,\"addr\":%s,"
        "\"port\":%u,\"setup_port\":%u}\n",
        stopped ? "stop" : "abnormal", route_name(mr->route),
        mr->applied_epoch == 1 ? 1u : 0u, mr->fresh_units, mr->fresh_bytes,
        mr->idle_units, mr->backlog_units, fault ? "true" : "false",
        mr->overflow ? "true" : "false", addr_json, port,
        (unsigned)mr->setup_port);
    if (n <= 0 || (size_t)n >= buf_size || (size_t)n > MEDIA_RECEIPT_MAX_LINE)
        return 0;
    return (size_t)n;
}

bool mr_emit(const media_receipt_t *mr, bool playback_ok, FILE *out)
{
    if (!mr->enabled || !mr->configured || !out) return false;
    int fd = fileno(out);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode)) return false;
    long pipe_buf = fpathconf(fd, _PC_PIPE_BUF);
    if (pipe_buf < MEDIA_RECEIPT_MAX_LINE) return false;
    /* Non-blocking BEFORE any flush so no blocked pipe can wait here. */
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return false;
    /* One flush, no clear-and-retry: failure (EAGAIN included) omits the line. */
    if (fflush(out) != 0 || ferror(out)) return false;
    char buf[MEDIA_RECEIPT_MAX_LINE];
    size_t len = mr_format(mr, playback_ok, buf, sizeof(buf));
    if (len == 0) return false;
    /* One write: no retry for EINTR/EAGAIN, no loop for a partial write. */
    ssize_t written = write(fd, buf, len);
    return written >= 0 && (size_t)written == len;
}

static mr_origin_t map_raop_origin(raop_media_origin_t origin)
{
    switch (origin) {
    case RAOP_MEDIA_FRESH: return MR_ORIGIN_FRESH;
    case RAOP_MEDIA_BACKLOG: return MR_ORIGIN_BACKLOG;
    default: return MR_ORIGIN_UNKNOWN;
    }
}

mr_origin_t mr_origin_from_ap2(ap2_media_origin_t origin)
{
    switch (origin) {
    case AP2_MEDIA_FRESH: return MR_ORIGIN_FRESH;
    case AP2_MEDIA_IDLE: return MR_ORIGIN_IDLE;
    case AP2_MEDIA_BACKLOG: return MR_ORIGIN_BACKLOG;
    default: return MR_ORIGIN_UNKNOWN;
    }
}

void mr_raop_outcome_cb(void *ctx, raop_media_outcome_t outcome,
                        raop_media_origin_t origin, size_t datagram_bytes,
                        const struct sockaddr_in *destination,
                        uint16_t setup_port)
{
    media_receipt_t *mr = ctx;
    if (outcome != RAOP_MEDIA_OUTCOME_SENT) {
        mr_failure(mr);
        return;
    }
    /* The RAOP lanes carry no tag: the producer is under the send lock with the
     * applied epoch current, so the collector's own epoch is the fresh tag.
     * Libraop's FRESH only means "not backlog": the CLI's scoped input origin
     * is the real label (UNKNOWN, hence a fault, when no send scope is open). */
    mr_origin_t label = map_raop_origin(origin);
    if (label == MR_ORIGIN_FRESH)
        label = (mr_origin_t)atomic_load(&mr->caller_origin);
    mr_sent(mr, label, datagram_bytes, destination,
            setup_port, mr_current_epoch(mr));
}

void mr_ap2_write_cb(void *ctx, const ap2_media_write_t *write)
{
    media_receipt_t *mr = ctx;
    if (write->route != AP2_MEDIA_REALTIME_UDP || !write->destination_known) {
        /* Buffered TCP and unknown peers are unsupported/incomplete. */
        mr_failure(mr);
        return;
    }
    mr_sent(mr, mr_origin_from_ap2(write->origin), write->bytes, &write->destination,
            mr->setup_port, write->tag);
}

void mr_ap2_outcome_cb(void *ctx, ap2_media_outcome_t outcome,
                       ap2_media_origin_t origin, uint64_t tag)
{
    (void)outcome;
    (void)origin;
    (void)tag;
    mr_failure(ctx);
}
