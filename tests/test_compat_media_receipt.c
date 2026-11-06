/* The AirPlay 2 RAOP-compatible flow: the REAL patched libraop client nested in
 * the REAL ap2_client, observed by the REAL collector adapter through the
 * ap2cl bridge. Only select()/sendto() are routed through test seams; positive
 * writes really reach an owned loopback socket, no receiver is run. */
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "platform.h"

static int media_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
static ssize_t media_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
#define loglevel media_raop_loglevel
#define select media_select
#define sendto media_sendto
#include "../build/patched/raop-media/src/raop_client.c"
#undef select
#undef sendto
#undef loglevel

static unsigned cleanup_clears;
static void spy_set_outcome(struct raopcl_s *p, raop_media_outcome_cb cb, void *ctx);
#define raopcl_set_media_outcome_cb spy_set_outcome
#include "../src/ap2_client.c"
#undef raopcl_set_media_outcome_cb
#include "../src/media_receipt.h"

static void spy_set_outcome(struct raopcl_s *p, raop_media_outcome_cb cb, void *ctx)
{
    if (!cb) cleanup_clears++;
    raopcl_set_media_outcome_cb(p, cb, ctx);
}

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

log_level raop_loglevel = lSILENCE;
log_level util_loglevel = lSILENCE;
static log_level test_log_level = lSILENCE;
log_level *loglevel = &test_log_level;

enum fault { REAL_SEND, SELECT_ERROR };
static enum fault fault;
static size_t writes, last_length;

static int media_select(int nfds, fd_set *readfds, fd_set *writefds,
                        fd_set *exceptfds, struct timeval *timeout)
{
    if (fault == SELECT_ERROR) {
        errno = EBADF;
        return -1; /* leave the fd set: legacy still sends */
    }
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

static ssize_t media_sendto(int fd, const void *bytes, size_t length, int flags,
                            const struct sockaddr *destination, socklen_t addrlen)
{
    writes++;
    last_length = length;
    return sendto(fd, bytes, length, flags, destination, addrlen);
}

static int loopback_socket(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    socklen_t length = sizeof(addr);
    CHECK(getsockname(fd, (struct sockaddr *)&addr, &length) == 0);
    *port = ntohs(addr.sin_port);
    return fd;
}

/* A nested client in STREAMING over owned loopback sockets, whose SETUP
 * transport was parsed by the real analyse path. */
static struct raopcl_s *nested_client(uint16_t port)
{
    struct in_addr loopback = { htonl(INADDR_LOOPBACK) };
    struct raopcl_s *p = raopcl_create(loopback, 0, 0, NULL, NULL, RAOP_PCM,
        352, RAOP_LATENCY_MIN, RAOP_CLEAR, false, NULL, NULL, NULL, NULL,
        44100, 16, 2, -144);
    CHECK(p != NULL);
    char transport[128];
    snprintf(transport, sizeof(transport),
             "RTP/AVP/UDP;unicast;mode=record;server_port=%u;control_port=%u;timing_port=%u",
             port, port, port);
    key_data_t kd[2] = {{0}};
    CHECK(kd_add(kd, "Transport", transport));
    CHECK(raopcl_analyse_setup(p, kd));
    kd_free(kd);
    p->peer_addr = loopback;
    p->rtp_ports.audio.fd = loopback_socket(&p->rtp_ports.audio.lport);
    p->rtp_ports.ctrl.fd = loopback_socket(&p->rtp_ports.ctrl.lport);
    p->seq_number = 0;
    p->head_ts = 100;
    p->state = RAOP_STREAMING;
    return p;
}

static struct ap2cl_s *compat_client(struct raopcl_s *nested)
{
    ap2_device_info_t d = { .name = "compat fixture", .address = "127.0.0.1",
                           .port = 7000 };
    ap2_audio_format_t f = { .sample_rate = 44100, .bit_depth = 16,
                            .channels = 2 };
    struct ap2cl_s *p = ap2cl_create(&d, &f, NULL, NULL, NULL, NULL, 2000, -1);
    CHECK(p);
    CHECK(p->flow == FLOW_RAOP_COMPAT);
    p->raopcl = nested;
    p->state = AP2_STREAMING;
    return p;
}

static void content(struct ap2cl_s *p, uint64_t epoch)
{
    uint8_t pcm[4] = {0};
    CHECK(ap2cl_send_chunk_tagged(p, pcm, 1, AP2_MEDIA_FRESH, epoch) == AP2_SEND_SENT);
}

/* Exercise the actual public resume caller with one stored chunk. */
static void backlog(struct ap2cl_s *p, struct raopcl_s *nested)
{
    nested->pause_ts = nested->backlog[nested->seq_number % MAX_BACKLOG].timestamp;
    nested->latency_frames = 0;
    nested->chunk_len = RAOP_LATENCY_MIN;
    nested->flushing = true;
    nested->start_ts = 1;
    (void)ap2cl_accept_frames(p);
}

static void test_compat_path(uint16_t port)
{
    struct raopcl_s *nested = nested_client(port);
    struct ap2cl_s *p = compat_client(nested);
    CHECK(ap2cl_media_path(p) == AP2_MEDIA_PATH_RAOP_COMPAT);
    CHECK(ap2cl_media_setup_port(p) == port);
    CHECK(ap2cl_media_registration_generation(p) == 0);

    media_receipt_t mr;
    mr_init(&mr, true);
    CHECK(ap2cl_set_raop_media_outcome_cb(p, mr_raop_outcome_cb, &mr));
    uint32_t generation = ap2cl_media_registration_generation(p);
    CHECK(generation == 1);
    mr_configure(&mr, MR_ROUTE_COMPAT, ap2cl_media_setup_port(p), generation);
    CHECK(!mr.fault);
    content(p, 0); /* a legacy-shaped fresh send before START: unexpected */
    CHECK(mr.fault);

    mr_init(&mr, true);
    CHECK(ap2cl_set_raop_media_outcome_cb(p, mr_raop_outcome_cb, &mr));
    generation = ap2cl_media_registration_generation(p);
    mr_configure(&mr, MR_ROUTE_COMPAT, ap2cl_media_setup_port(p), generation);
    mr_applied(&mr, 1);

    size_t before = writes;
    content(p, 1);
    CHECK(writes == before + 1 && mr.fresh_units == 1);
    CHECK(mr.fresh_bytes == last_length && last_length == sizeof(rtp_audio_pkt_t) + 4);
    CHECK(mr.have_dest && mr.dest.sin_port == htons(port));
    CHECK(mr.dest.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && !mr.fault);

    /* The nested BACKLOG lane through ap2cl_accept_frames, never fresh. */
    before = writes;
    backlog(p, nested);
    CHECK(writes == before + 1);
    CHECK(mr.backlog_units == 1 && mr.fresh_units == 1 && !mr.fault);

    /* A select error with a still-successful legacy send: not a count. */
    uint32_t units = mr.fresh_units;
    fault = SELECT_ERROR;
    content(p, 1);
    fault = REAL_SEND;
    CHECK(mr.fault && mr.fresh_units == units);

    /* A clean collector: STOP freeze before the transport stop closes it. */
    mr_init(&mr, true);
    CHECK(ap2cl_set_raop_media_outcome_cb(p, mr_raop_outcome_cb, &mr));
    generation = ap2cl_media_registration_generation(p);
    mr_configure(&mr, MR_ROUTE_COMPAT, ap2cl_media_setup_port(p), generation);
    mr_applied(&mr, 1);
    content(p, 1);
    mr_freeze_for_stop(&mr, ap2cl_media_registration_generation(p));
    content(p, 1);
    CHECK(mr.fresh_units == 1 && !mr.fault);
    /* An external re-registration of the same hook is a detected change. */
    CHECK(ap2cl_set_raop_media_outcome_cb(p, mr_raop_outcome_cb, &mr));
    CHECK(ap2cl_media_registration_generation(p) == generation + 1);
    mr_begin_teardown(&mr, ap2cl_media_registration_generation(p));
    CHECK(atomic_load(&mr.terminal_invalid));

    /* Teardown order: owner clears under its lock, the nested cleanup clears
     * again before the destroy, no callback afterwards. */
    CHECK(ap2cl_set_raop_media_outcome_cb(p, NULL, NULL));
    CHECK(nested->media_outcome_cb == NULL && nested->media_outcome_ctx == NULL);
    unsigned clears = cleanup_clears;
    _raopcl_terminate_rtp(nested);
    nested->state = RAOP_DOWN;
    ap2_raop_session_cleanup(p);
    CHECK(p->raopcl == NULL && cleanup_clears == clears + 1);
    CHECK(ap2cl_media_path(p) == AP2_MEDIA_PATH_UNKNOWN);
    CHECK(!ap2cl_set_raop_media_outcome_cb(p, mr_raop_outcome_cb, &mr));
    CHECK(ap2cl_media_registration_generation(p) == 0);
    CHECK(ap2cl_destroy(p));
    puts("compat media: real nested fresh/backlog via ap2cl bridge, select error, freeze, re-registration, cleanup clear");
}

static void test_native_rejects_bridge(void)
{
    ap2_device_info_t d = { .name = "native fixture", .address = "127.0.0.1",
                           .port = 7000 };
    ap2_audio_format_t f = { .sample_rate = 44100, .bit_depth = 16,
                            .channels = 2 };
    struct ap2cl_s *p = ap2cl_create(&d, &f, NULL, NULL, NULL, NULL, 2000, -1);
    CHECK(p);
    p->flow = FLOW_NATIVE_AP2;
    CHECK(!ap2cl_set_raop_media_outcome_cb(p, mr_raop_outcome_cb, NULL));
    CHECK(!ap2cl_set_raop_media_outcome_cb(NULL, mr_raop_outcome_cb, NULL));
    CHECK(ap2cl_destroy(p));
    puts("compat media: the bridge refuses a native client");
}

int main(void)
{
    alarm(30);
    uint16_t port;
    int sink = loopback_socket(&port);
    test_compat_path(port);
    test_native_rejects_bridge();
    CHECK(close(sink) == 0);
    puts("Compat media receipt tests passed");
    return 0;
}
