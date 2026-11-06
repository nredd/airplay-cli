/* Include the actual build-patched production unit, not a sender replica.
 * Only socket syscalls are routed through test-only hooks. Positive cases use
 * real UDP sendto to an owned bound loopback socket; no receiver is run.
 */
#include "platform.h"
#include <stdatomic.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int media_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
static ssize_t media_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t media_recv(int, void *, size_t, int);
#define loglevel media_raop_loglevel
#define select media_select
#define sendto media_sendto
#define recv media_recv
#ifndef RAOP_MEDIA_SOURCE
#define RAOP_MEDIA_SOURCE "../build/patched/raop-media/src/raop_client.c"
#endif
#include RAOP_MEDIA_SOURCE
#undef select
#undef sendto
#undef recv
#undef loglevel

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

log_level raop_loglevel = lSILENCE;
log_level util_loglevel = lSILENCE;
static log_level test_log_level = lSILENCE;
log_level *loglevel = &test_log_level;

enum fault { REAL_SEND, NEGATIVE_SEND, SHORT_SEND, EINTR_SEND, NOT_READY,
             SELECT_ERROR, SELECT_EINTR };
static enum fault fault;
static struct raopcl_s *control_client;
static struct raopcl_s *sending_client;
static size_t writes, last_length;
static struct sockaddr_in last_destination;
static unsigned last_type;

struct capture {
    struct raopcl_s *client;
    atomic_uint calls;
    raop_media_origin_t origin;
    size_t bytes;
    struct sockaddr_in destination;
};

/* No I/O, blocking or library reentry: copy bounded values only. The trylock
 * assertion below is performed in the test syscall seam, NOT the callback. */
static void capture_write(void *ctx, raop_media_origin_t origin, size_t bytes,
                          const struct sockaddr_in *destination)
{
    struct capture *capture = ctx;
    capture->origin = origin;
    capture->bytes = bytes;
    capture->destination = *destination;
    atomic_fetch_add(&capture->calls, 1);
}

static int media_select(int nfds, fd_set *readfds, fd_set *writefds,
                        fd_set *exceptfds, struct timeval *timeout)
{
    if (readfds) return 1; /* One synthetic RTX request, no network input. */
    if (fault == NOT_READY) { FD_ZERO(writefds); return 0; }
    if (fault == SELECT_ERROR || fault == SELECT_EINTR) {
        errno = fault == SELECT_EINTR ? EINTR : EBADF;
        return -1; /* Deliberately leave fd set, matching legacy error path. */
    }
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

static ssize_t media_sendto(int fd, const void *bytes, size_t length, int flags,
                            const struct sockaddr *destination, socklen_t addrlen)
{
    /* Verify BOTH public audio callers actually own the mutex shared with
     * the setter. This nonblocking ownership probe is test-only, outside cb. */
    CHECK(sending_client != NULL);
    CHECK(pthread_mutex_trylock(&sending_client->mutex) == EBUSY);
    CHECK(addrlen == sizeof(struct sockaddr_in));
    const struct sockaddr_in *addr = (const struct sockaddr_in *)destination;
    CHECK(addr->sin_family == AF_INET);
    CHECK(addr->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    writes++;
    last_destination = *addr;
    last_length = length;
    last_type = ((const uint8_t *)bytes)[1];
    if (fault == NEGATIVE_SEND || fault == EINTR_SEND) {
        errno = fault == EINTR_SEND ? EINTR : EIO;
        return -1;
    }
    if (fault == SHORT_SEND) return (ssize_t)length - 1;
    return sendto(fd, bytes, length, flags, destination, addrlen);
}

static ssize_t media_recv(int fd, void *buffer, size_t length, int flags)
{
    (void)fd;
    (void)flags;
    CHECK(control_client != NULL && length == sizeof(rtp_lost_pkt_t));
    rtp_lost_pkt_t request = {0};
    request.seq_number = htons(control_client->seq_number);
    request.n = htons(1);
    memcpy(buffer, &request, sizeof(request));
    control_client->ctrl_running = false; /* Exit after the real RTX path. */
    return sizeof(request);
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

static struct raopcl_s *client_create(uint16_t port)
{
    struct in_addr loopback = { htonl(INADDR_LOOPBACK) };
    struct raopcl_s *p = raopcl_create(loopback, 0, 0, NULL, NULL, RAOP_PCM,
        352, RAOP_LATENCY_MIN, RAOP_CLEAR, false, NULL, NULL, NULL, NULL,
        44100, 16, 2, -144);
    CHECK(p != NULL);
    p->peer_addr = loopback;
    p->rtp_ports.audio.fd = loopback_socket(&p->rtp_ports.audio.lport);
    p->rtp_ports.audio.rport = port;
    p->rtp_ports.ctrl.fd = loopback_socket(&p->rtp_ports.ctrl.lport);
    p->rtp_ports.ctrl.rport = port;
    p->seq_number = 0;
    p->head_ts = 100;
    p->state = RAOP_STREAMING;
    sending_client = p;
    return p;
}

static void fresh(struct raopcl_s *p)
{
    uint8_t pcm[4] = {0};
    uint64_t playtime = 0;
    CHECK(raopcl_send_chunk(p, pcm, 1, &playtime)); /* Legacy bool unchanged. */
    CHECK(playtime != 0);
}

/* Exercise the actual public resume caller with one stored chunk. */
static void resume_one(struct raopcl_s *p)
{
    p->pause_ts = p->backlog[p->seq_number % MAX_BACKLOG].timestamp;
    p->latency_frames = 0;
    p->chunk_len = RAOP_LATENCY_MIN;
    p->flushing = true;
    p->start_ts = 1;
    (void)raopcl_accept_frames(p);
}

static void dispose(struct raopcl_s *p)
{
    raopcl_set_media_write_cb(p, NULL, NULL);
    /* No external RTSP endpoint: close only our own sockets, then destroy the
     * never-connected session in RAOP_DOWN (no RTSP flush/disconnect traffic). */
    _raopcl_terminate_rtp(p);
    p->state = RAOP_DOWN;
    CHECK(raopcl_destroy(p));
}

static void test_positive_and_exclusions(uint16_t port)
{
    struct raopcl_s *p = client_create(port);
    struct capture capture = { .client = p };
    CHECK(p->media_write_cb == NULL && p->media_write_ctx == NULL);
    fresh(p);
    CHECK(writes == 1 && last_length == sizeof(rtp_audio_pkt_t) + 4);
    raopcl_set_media_write_cb(p, capture_write, &capture);
    fresh(p);
    CHECK(atomic_load(&capture.calls) == 1);
    CHECK(capture.origin == RAOP_MEDIA_FRESH);
    CHECK(capture.bytes == last_length);
    CHECK(capture.destination.sin_family == AF_INET);
    CHECK(capture.destination.sin_addr.s_addr == last_destination.sin_addr.s_addr);
    CHECK(capture.destination.sin_port == htons(port));

    /* Resume a real stored frame through public accept_frames. Choose a
     * one-chunk latency internally so the backlog case is deterministic. */
    size_t before = writes;
    resume_one(p);
    CHECK(writes == before + 1);
    CHECK(atomic_load(&capture.calls) == 2);
    CHECK(capture.origin == RAOP_MEDIA_BACKLOG);
    CHECK(capture.bytes == last_length);
    CHECK(capture.destination.sin_family == last_destination.sin_family);
    CHECK(capture.destination.sin_addr.s_addr == last_destination.sin_addr.s_addr);
    CHECK(capture.destination.sin_port == last_destination.sin_port);

    _raopcl_send_sync(p, false);
    CHECK(last_type == 0xd4 && atomic_load(&capture.calls) == 2);
    control_client = p;
    p->ctrl_running = true;
    p->last_keepalive = raopcl_get_ntp(NULL);
    _rtp_control_thread(p);
    CHECK(last_type == 0xd6 && p->retransmit == 1);
    CHECK(atomic_load(&capture.calls) == 2);
    control_client = NULL;
    struct capture replacement = { .client = p };
    raopcl_set_media_write_cb(p, capture_write, &replacement);
    fresh(p);
    CHECK(atomic_load(&replacement.calls) == 1);
    CHECK(atomic_load(&capture.calls) == 2);
    raopcl_set_media_write_cb(p, NULL, &capture);
    CHECK(p->media_write_ctx == NULL);
    fresh(p);
    CHECK(atomic_load(&capture.calls) == 2);
    CHECK(atomic_load(&replacement.calls) == 1);
    dispose(p);
    puts("media positive: real fresh/backlog UDP, exact destination/length, NULL, sync/RTX exclusions");
}

static void test_failures(uint16_t port)
{
    for (enum fault f = NEGATIVE_SEND; f <= SELECT_EINTR; f++) {
        struct raopcl_s *p = client_create(port);
        struct capture capture = { .client = p };
        raopcl_set_media_write_cb(p, capture_write, &capture);
        fault = f;
        fresh(p);
        CHECK(atomic_load(&capture.calls) == 0);
        resume_one(p);
        CHECK(atomic_load(&capture.calls) == 0);
        fault = REAL_SEND;
        fresh(p);
        CHECK(atomic_load(&capture.calls) == 1);
        dispose(p);
    }
    struct raopcl_s *p = client_create(port);
    struct capture capture = { .client = p };
    raopcl_set_media_write_cb(p, capture_write, &capture);
    p->state = RAOP_DOWN;
    size_t before = writes;
    fresh(p);
    resume_one(p);
    CHECK(writes == before && atomic_load(&capture.calls) == 0);
    p->state = RAOP_STREAMING;
    CHECK(close(p->rtp_ports.audio.fd) == 0);
    p->rtp_ports.audio.fd = -1;
    fresh(p);
    resume_one(p);
    CHECK(writes == before && atomic_load(&capture.calls) == 0);
    dispose(p);
    raopcl_set_media_write_cb(NULL, NULL, NULL);
    puts("media failures: negative/short/EINTR/select error/select EINTR/nonready/down/closed, paired positives");
}


/* The separate OUTCOME hook: exactly one outcome per audio attempt. */
struct outcomes {
    atomic_uint calls;
    unsigned counts[5];
    raop_media_outcome_t last;
    raop_media_origin_t origin;
    size_t bytes;
    bool have_destination;
    struct sockaddr_in destination;
    uint16_t setup_port;
};

static void capture_outcome(void *ctx, raop_media_outcome_t outcome,
                            raop_media_origin_t origin, size_t bytes,
                            const struct sockaddr_in *destination,
                            uint16_t setup_port)
{
    struct outcomes *out = ctx;
    out->last = outcome;
    out->origin = origin;
    out->bytes = bytes;
    out->have_destination = destination != NULL;
    if (destination) out->destination = *destination;
    out->setup_port = setup_port;
    out->counts[outcome]++;
    atomic_fetch_add(&out->calls, 1);
}

static void test_outcomes(uint16_t port)
{
    struct raopcl_s *p = client_create(port);
    struct outcomes out = {0};
    struct capture capture = { .client = p };
    p->media_setup_port = port;
    CHECK(p->media_outcome_cb == NULL);
    CHECK(raopcl_media_registration_generation(p) == 0);
    fresh(p); /* default off: no outcome, legacy behavior */
    uint32_t generation = 0;
    raopcl_set_media_outcome_cb(p, capture_outcome, &out);
    CHECK((generation = raopcl_media_registration_generation(p)) == 1);
    CHECK(raopcl_media_setup_port(p) == port);
    CHECK(atomic_load(&out.calls) == 0);

    fresh(p);
    CHECK(atomic_load(&out.calls) == 1 && out.last == RAOP_MEDIA_OUTCOME_SENT);
    CHECK(out.origin == RAOP_MEDIA_FRESH && out.bytes == last_length);
    CHECK(out.have_destination && out.setup_port == port);
    CHECK(out.destination.sin_family == AF_INET);
    CHECK(out.destination.sin_port == htons(port));
    CHECK(out.destination.sin_addr.s_addr == last_destination.sin_addr.s_addr);

    resume_one(p); /* backlog */
    CHECK(atomic_load(&out.calls) == 2 && out.last == RAOP_MEDIA_OUTCOME_SENT);
    CHECK(out.origin == RAOP_MEDIA_BACKLOG && out.have_destination);

    /* Sync and RTX are never outcomes. */
    _raopcl_send_sync(p, false);
    CHECK(atomic_load(&out.calls) == 2);

    /* Both hooks coexist; the success hook semantics are unchanged. */
    raopcl_set_media_write_cb(p, capture_write, &capture);
    CHECK(raopcl_media_registration_generation(p) == generation + 1);
    fresh(p);
    CHECK(atomic_load(&capture.calls) == 1 && atomic_load(&out.calls) == 3);

    static const struct {
        enum fault fault;
        raop_media_outcome_t expected;
        bool sendto_reached;
    } matrix[] = {
        { NEGATIVE_SEND, RAOP_MEDIA_OUTCOME_SEND_ERROR, true },
        { SHORT_SEND, RAOP_MEDIA_OUTCOME_SEND_ERROR, true },
        { EINTR_SEND, RAOP_MEDIA_OUTCOME_SEND_ERROR, true },
        { NOT_READY, RAOP_MEDIA_OUTCOME_NOT_READY, false },
        /* A select error NEVER qualifies, even though legacy still sent. */
        { SELECT_ERROR, RAOP_MEDIA_OUTCOME_SELECT_ERROR, true },
        { SELECT_EINTR, RAOP_MEDIA_OUTCOME_SELECT_ERROR, true },
    };
    for (size_t i = 0; i < sizeof(matrix) / sizeof(matrix[0]); i++) {
        unsigned calls = atomic_load(&out.calls);
        unsigned success_calls = atomic_load(&capture.calls);
        size_t before = writes;
        fault = matrix[i].fault;
        fresh(p);
        CHECK(atomic_load(&out.calls) == calls + 1);
        CHECK(out.last == matrix[i].expected && out.origin == RAOP_MEDIA_FRESH);
        CHECK(!out.have_destination && out.bytes == 0);
        CHECK((writes == before + 1) == matrix[i].sendto_reached);
        CHECK(atomic_load(&capture.calls) == success_calls);
        resume_one(p);
        CHECK(atomic_load(&out.calls) == calls + 2);
        CHECK(out.last == matrix[i].expected && out.origin == RAOP_MEDIA_BACKLOG);
        fault = REAL_SEND;
    }
    CHECK(out.counts[RAOP_MEDIA_OUTCOME_SELECT_ERROR] == 4);

    /* The legacy return value stays false for failed attempts. */
    {
        uint8_t pcm[4] = {0};
        uint64_t playtime = 0;
        fault = NOT_READY;
        CHECK(raopcl_send_chunk(p, pcm, 1, &playtime)); /* caller ignores it */
        fault = REAL_SEND;
    }

    /* Unavailable preconditions: down and a closed audio socket. */
    unsigned calls = atomic_load(&out.calls);
    p->state = RAOP_DOWN;
    fresh(p);
    CHECK(out.last == RAOP_MEDIA_OUTCOME_UNAVAILABLE && !out.have_destination);
    p->state = RAOP_STREAMING;
    CHECK(close(p->rtp_ports.audio.fd) == 0);
    p->rtp_ports.audio.fd = -1;
    fresh(p);
    CHECK(out.last == RAOP_MEDIA_OUTCOME_UNAVAILABLE);
    CHECK(atomic_load(&out.calls) == calls + 2);

    raopcl_set_media_outcome_cb(p, NULL, &out);
    CHECK(p->media_outcome_cb == NULL && p->media_outcome_ctx == NULL);
    CHECK(raopcl_media_registration_generation(p) > generation + 1);
    raopcl_set_media_write_cb(p, NULL, NULL);
    dispose(p);
    raopcl_set_media_outcome_cb(NULL, NULL, NULL);
    CHECK(raopcl_media_registration_generation(NULL) == 0);
    CHECK(raopcl_media_setup_port(NULL) == 0);
    puts("media outcomes: one per attempt, fresh/backlog, select error never qualifies, unavailable, default off, generation");
}

static void test_setup_port_parse(void)
{
    static const struct { const char *transport; uint16_t port; } cases[] = {
        { "RTP/AVP/UDP;unicast;mode=record;server_port=6001;control_port=6002;timing_port=6003", 6001 },
        { "RTP/AVP/UDP;server_port=65535;control_port=6002", 65535 },
        { "RTP/AVP/UDP;server_port=65536;control_port=6002", 0 },
        { "RTP/AVP/UDP;server_port=70000;control_port=6002", 0 },
        { "RTP/AVP/UDP;server_port=60x1;control_port=6002", 0 },
        { "RTP/AVP/UDP;server_port=;control_port=6002", 0 },
        { "RTP/AVP/UDP;server_port=0;control_port=6002", 0 },
        { "RTP/AVP/UDP;control_port=6002", 0 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct raopcl_s *p = client_create(1);
        p->media_setup_port = 1234; /* a stale value must not survive */
        key_data_t kd[2] = {{0}};
        CHECK(kd_add(kd, "Transport", cases[i].transport));
        (void)raopcl_analyse_setup(p, kd); /* legacy result is not the subject */
        CHECK(raopcl_media_setup_port(p) == cases[i].port);
        kd_free(kd);
        dispose(p);
    }
    puts("media setup port: strict separately parsed server_port");
}

struct concurrent {
    struct raopcl_s *client;
    atomic_bool start, cleared;
    atomic_uint iterations;
};

static void *producer(void *ctx)
{
    struct concurrent *concurrent = ctx;
    while (!atomic_load(&concurrent->start)) sched_yield();
    for (unsigned n = 0; n < 1000; n++) {
        fresh(concurrent->client);
        atomic_fetch_add(&concurrent->iterations, 1);
    }
    while (!atomic_load(&concurrent->cleared)) sched_yield();
    for (unsigned n = 0; n < 100; n++) fresh(concurrent->client);
    return NULL;
}

static void test_unregister(uint16_t port)
{
    struct raopcl_s *p = client_create(port);
    struct capture *capture = calloc(1, sizeof(*capture));
    CHECK(capture != NULL);
    atomic_init(&capture->calls, 0);
    capture->client = p;
    struct concurrent concurrent = { .client = p };
    raopcl_set_media_write_cb(p, capture_write, capture);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, producer, &concurrent) == 0);
    atomic_store(&concurrent.start, true);
    while (atomic_load(&capture->calls) == 0) sched_yield();
    /* Both public paths hold this same mutex through notification; clearing
     * serializes with them and frees ctx before further producer sends. */
    raopcl_set_media_write_cb(p, NULL, NULL);
    CHECK(atomic_load(&capture->calls) > 0);
    free(capture);
    atomic_store(&concurrent.cleared, true);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(atomic_load(&concurrent.iterations) == 1000);
    CHECK(p->media_write_cb == NULL && p->media_write_ctx == NULL);
    dispose(p);
    puts("media lifetime: concurrent unregister, immediate context free, 100 later sends, caller joined before destroy");
}

int main(void)
{
    alarm(20); /* All concurrency and real socket paths are bounded. */
    uint16_t port;
    int sink = loopback_socket(&port);
    test_positive_and_exclusions(port);
    test_failures(port);
    test_outcomes(port);
    test_setup_port_parse();
    test_unregister(port);
    CHECK(close(sink) == 0);
    puts("RAOP media write tests passed");
    return 0;
}
