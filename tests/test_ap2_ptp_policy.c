/* Exercise the production receive loop and daemon emitter with inert socket,
 * thread and shared-memory boundaries. No network or daemon is started.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define socket fixture_socket
#define bind fixture_bind
#define setsockopt fixture_setsockopt
#define close fixture_close
#define sendto fixture_sendto
#define recvfrom fixture_recvfrom
#define poll fixture_poll
#define pthread_create fixture_thread_create
#define pthread_join fixture_thread_join
#define ap2_ptp_shm_writer_open fixture_writer_open
#define ap2_ptp_shm_publish fixture_publish
#define ap2_ptp_shm_writer_close fixture_writer_close
#define ap2_ptp_ctrl_server_open fixture_ctrl_open
/* Headers above already declared libc functions, so declare exact wrappers. */
int fixture_socket(int, int, int);
int fixture_bind(int, const struct sockaddr *, socklen_t);
int fixture_setsockopt(int, int, int, const void *, socklen_t);
int fixture_close(int);
ssize_t fixture_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t fixture_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
int fixture_poll(struct pollfd *, nfds_t, int);
int fixture_thread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int fixture_thread_join(pthread_t, void **);
#ifndef FIXTURE_SOURCE
#define FIXTURE_SOURCE "../src/ap2_ptp.c"
#endif
#include FIXTURE_SOURCE
/* Later fixture cleanup uses the real descriptor close. */
#undef close

static log_level fixture_level = lSILENCE;
log_level *loglevel = &fixture_level;
static struct ap2_ptp_ctx *active;
static uint8_t packet[128];
static size_t packet_len;
static struct in_addr packet_source;
static bool pending;
static int direct_replies;
static int daemon_starts;
static bool expected_strict;
static bool change_env_at_start;

int fixture_socket(int domain, int type, int protocol)
{ assert(domain == AF_INET && type == SOCK_DGRAM && protocol == 0); return 100; }
int fixture_bind(int fd, const struct sockaddr *addr, socklen_t len)
{ (void)fd; (void)addr; (void)len; return 0; }
int fixture_setsockopt(int fd, int level, int opt, const void *v, socklen_t len)
{ (void)fd; (void)level; (void)opt; (void)v; (void)len; return 0; }
int fixture_close(int fd) { assert(fd >= 0); return 0; }
int fixture_thread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*fn)(void *), void *arg)
{
    (void)thread; (void)attr;
    assert(fn == ptp_thread_func);
    assert(ap2_ptp_strict_peers(arg) == expected_strict);
    daemon_starts++;
    if (change_env_at_start)
        assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", expected_strict ? "0" : "1", 1) == 0);
    return 0;
}
int fixture_thread_join(pthread_t thread, void **value)
{ (void)thread; (void)value; return 0; }
bool fixture_writer_open(struct ap2_ptp_shm_writer *w)
{ memset(w, 0, sizeof(*w)); return true; }
void fixture_publish(struct ap2_ptp_shm_writer *w, struct ap2_ptp_shm_sample s)
{ (void)w; (void)s; }
void fixture_writer_close(struct ap2_ptp_shm_writer *w) { (void)w; }
int fixture_ctrl_open(void) { return 200; }
void get_mac(uint8_t mac[]) { memset(mac, 0x42, 6); }

ssize_t fixture_sendto(int fd, const void *buf, size_t len, int flags,
                       const struct sockaddr *dst, socklen_t dst_len)
{
    (void)fd; (void)flags; (void)dst; (void)dst_len;
    const uint8_t *b = buf;
    if (len >= PTP_HDR_LEN && b[30] == 2 && b[31] == 188) direct_replies++;
    return (ssize_t)len;
}
ssize_t fixture_recvfrom(int fd, void *buf, size_t len, int flags,
                         struct sockaddr *src, socklen_t *src_len)
{
    (void)fd; (void)flags;
    assert(pending && len >= packet_len && *src_len >= sizeof(struct sockaddr_in));
    memcpy(buf, packet, packet_len);
    struct sockaddr_in from = {.sin_family = AF_INET, .sin_addr = packet_source};
    memcpy(src, &from, sizeof(from));
    *src_len = sizeof(from);
    pending = false;
    return (ssize_t)packet_len;
}
int fixture_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    (void)timeout;
    assert(active && count == 2);
    if (!pending) { active->ptp_running = false; return 0; }
    fds[0].revents = POLLIN;
    fds[1].revents = 0;
    return 1;
}

/* Run one packet through the actual production poll/recvfrom/dispatch loop. */
static void dispatch(struct ap2_ptp_ctx *ctx, uint8_t type, const char *ip)
{
    memset(packet, 0, sizeof(packet));
    packet_len = PTP_HDR_LEN + 30;
    ptp_write_hdr(packet, type, (uint16_t)packet_len, 0, 0x1234, 700, 0, 0);
    ptp_write_ts(packet + PTP_HDR_LEN, ap2_ptp_now_ns(ctx));
    packet[PTP_HDR_LEN + 13] = 1;
    packet[PTP_HDR_LEN + 14] = 1;
    packet[PTP_HDR_LEN + 25] = 0x12;
    packet[PTP_HDR_LEN + 26] = 0x34;
    if (type == PTP_MSG_SIGNALING) {
        packet[44] = 0; packet[45] = 4;
        packet[46] = 0; packet[47] = 6;
        packet[48] = 0x10; packet[49] = 0; packet[53] = 1;
    }
    assert(inet_pton(AF_INET, ip, &packet_source) == 1);
    active = ctx;
    pending = true;
    direct_replies = 0;
    ctx->ptp_running = true;
    ptp_thread_func(ctx);
    assert(!pending);
    active = NULL;
}

/* Exercise every receive-side effect, plus exact membership/removal. */
static void test_effect(uint8_t type, bool follow, int membership, bool strict)
{
    assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", strict ? "1" : "0", 1) == 0);
    struct ap2_ptp_ctx *ctx = ap2_ptp_create();
    assert(ctx && ap2_ptp_strict_peers(ctx) == strict);
    ctx->clock_id = 0x4242;
    ctx->hold_master = false;
    ctx->event_sock = ctx->general_sock = -1;
    const char *peers[] = {"127.0.0.1"};
    if (membership) ap2_ptp_set_peers(ctx, peers, 1);
    if (membership == 2) ap2_ptp_set_peers(ctx, NULL, 0);
    const char *source = membership == 3 ? "127.0.0.2" : "127.0.0.1";
    bool allowed = !strict || membership == 1;
    if (follow) {
        ap2_ptp_follow_receiver(ctx, source);
        if (type != PTP_MSG_ANNOUNCE) {
            struct in_addr addr;
            assert(inet_pton(AF_INET, source, &addr) == 1);
            assert(ptp_follow_slot(ctx, addr, true));
        }
    }
    if (!follow && (type == PTP_MSG_SYNC || type == PTP_MSG_FOLLOW_UP)) {
        ctx->is_grandmaster = false;
        ctx->pending_sync_valid = type == PTP_MSG_FOLLOW_UP;
        ctx->pending_sync_seq = 700;
        ctx->pending_sync_rx_ns = ap2_ptp_now_ns(ctx);
    }
    if (follow && type == PTP_MSG_FOLLOW_UP) {
        ctx->follow[0].pending_sync_valid = true;
        ctx->follow[0].pending_sync_seq = 700;
        ctx->follow[0].pending_sync_rx_ns = ap2_ptp_now_ns(ctx);
    }
    dispatch(ctx, type, source);
    if (type == PTP_MSG_DELAY_REQ || type == PTP_MSG_PDELAY_REQ) {
        struct ap2_ptp_exchange ex;
        assert((direct_replies > 0) == allowed);
        assert(ap2_ptp_peer_exchange(ctx, source, &ex) == allowed);
    } else if (type == PTP_MSG_SIGNALING) {
        assert((direct_replies > 0) == allowed);
        assert(ctx->unicast_granted == allowed);
    } else if (follow) {
        if (type == PTP_MSG_ANNOUNCE) assert(ctx->follow[0].have_clock == allowed);
        else assert(ctx->follow[0].have_offset == allowed);
        if (type == PTP_MSG_SYNC) {
            struct ap2_ptp_exchange ex;
            assert(ap2_ptp_peer_exchange(ctx, source, &ex) == allowed);
        }
    } else if (type == PTP_MSG_ANNOUNCE) {
        assert(ctx->have_peer == allowed);
        assert(ctx->is_grandmaster != allowed);
    } else assert(ctx->have_offset == allowed);
    ap2_ptp_destroy(ctx);
}

/* Real daemon aggregation helpers feed the same engine membership setter. */
static void test_daemon_registration(void)
{
    assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", "1", 1) == 0);
    struct ap2_ptp_ctx *ctx = ap2_ptp_create();
    assert(ctx);
    struct ptp_peerset ps = {0};
    struct in_addr addr;
    assert(inet_pton(AF_INET, "127.0.0.1", &addr) == 1);
    assert(!ptp_peer_is_registered(ctx, addr));
    peerset_add(&ps, "127.0.0.1"); peerset_add(&ps, "127.0.0.1");
    peerset_apply(&ps, ctx);
    assert(ptp_peer_is_registered(ctx, addr));
    peerset_remove(&ps, "127.0.0.1"); peerset_apply(&ps, ctx);
    assert(ptp_peer_is_registered(ctx, addr));
    peerset_remove(&ps, "127.0.0.1"); peerset_apply(&ps, ctx);
    assert(!ptp_peer_is_registered(ctx, addr));
    ap2_ptp_destroy(ctx);
}

/* This is an emitted protocol-field assertion, not a provider implementation.
 * The actual logger writes into a temporary file; no copied format is emitted.
 * Change the environment AFTER engine initialization to prove context binding. */
static void test_ready_line(bool strict)
{
    expected_strict = strict;
    change_env_at_start = true;
    assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", strict ? "1" : "0", 1) == 0);
    FILE *capture = tmpfile();
    assert(capture);
    int saved_stderr = dup(STDERR_FILENO);
    assert(saved_stderr >= 0);
    assert(fflush(stderr) == 0);
    assert(dup2(fileno(capture), STDERR_FILENO) >= 0);
    fixture_level = lINFO;
    volatile bool stopped = true;
    struct in_addr bind_addr = {.s_addr = htonl(INADDR_LOOPBACK)};
    int starts = daemon_starts;
    assert(ap2_ptp_run_daemon(bind_addr, 0x4242, &stopped) == 0);
    assert(daemon_starts == starts + 1);
    assert(fflush(stderr) == 0);
    assert(dup2(saved_stderr, STDERR_FILENO) >= 0);
    assert(close(saved_stderr) == 0);
    rewind(capture);
    char line[1024];
    int ready_lines = 0;
    while (fgets(line, sizeof(line), capture)) {
        if (!strstr(line, "[PTP] daemon up:")) continue;
        ready_lines++;
        assert(strstr(line, strict ? "strict-peers=on\n" : "strict-peers=off\n"));
        assert(!strstr(line, strict ? "strict-peers=off" : "strict-peers=on"));
    }
    assert(ready_lines == 1);
    assert(fclose(capture) == 0);
    fixture_level = lSILENCE;
    change_env_at_start = false;
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        assert(strcmp(argv[1], "emit-on") == 0 || strcmp(argv[1], "emit-off") == 0);
        expected_strict = strcmp(argv[1], "emit-on") == 0;
        assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", expected_strict ? "1" : "0", 1) == 0);
        fixture_level = lINFO;
        volatile bool stopped = true;
        struct in_addr bind_addr = {.s_addr = htonl(INADDR_LOOPBACK)};
        /* Actual full production function, inert socket/thread/writer boundaries.
         * stopped=true avoids its daemon service loop. No daemon is spawned. */
        assert(ap2_ptp_run_daemon(bind_addr, 0x4242, &stopped) == 0);
        assert(daemon_starts == 1);
        return 0;
    }
    assert(argc == 1);
    const uint8_t types[] = {PTP_MSG_DELAY_REQ, PTP_MSG_PDELAY_REQ, PTP_MSG_SIGNALING,
                            PTP_MSG_ANNOUNCE, PTP_MSG_SYNC, PTP_MSG_FOLLOW_UP};
    int cases = 0;
    for (int strict = 0; strict <= 1; strict++) {
        for (int membership = 0; membership <= 3; membership++) {
            for (size_t i = 0; i < sizeof(types); i++) {
                test_effect(types[i], false, membership, strict != 0); cases++;
                if (types[i] == PTP_MSG_ANNOUNCE || types[i] == PTP_MSG_SYNC ||
                    types[i] == PTP_MSG_FOLLOW_UP) {
                    test_effect(types[i], true, membership, strict != 0); cases++;
                }
            }
        }
    }
    test_daemon_registration();
    const char *disabled[] = {"", "0", "true", "01", "1 "};
    for (size_t i = 0; i < sizeof(disabled) / sizeof(disabled[0]); i++) {
        assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", disabled[i], 1) == 0);
        struct ap2_ptp_ctx *ctx = ap2_ptp_create();
        assert(ctx && !ap2_ptp_strict_peers(ctx));
        ap2_ptp_destroy(ctx);
    }
    assert(unsetenv("CLIAIRPLAY_PTP_STRICT_PEERS") == 0);
    struct ap2_ptp_ctx *ctx = ap2_ptp_create();
    assert(ctx && !ap2_ptp_strict_peers(ctx));
    ap2_ptp_destroy(ctx);
    assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", "1", 1) == 0);
    expected_strict = true;
    ctx = ap2_ptp_create();
    struct in_addr bind_addr = {.s_addr = htonl(INADDR_LOOPBACK)};
    assert(ap2_ptp_engine_start(ctx, bind_addr, "127.0.0.1"));
    struct in_addr peer;
    assert(inet_pton(AF_INET, "127.0.0.1", &peer) == 1);
    assert(ptp_peer_is_registered(ctx, peer));
    ap2_ptp_destroy(ctx);
    test_ready_line(true);
    test_ready_line(false);
    assert(unsetenv("CLIAIRPLAY_PTP_STRICT_PEERS") == 0);
    printf("actual-dispatch policy cases=%d; refcount/env/initial-peer/ready-line tests passed\n",
           cases);
    return 0;
}
