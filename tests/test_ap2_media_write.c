/* Exercise the full production native send/encode/encrypt/flush paths. All
 * sockets are owned loopback fixtures, never receivers. Only syscall failure
 * and short-write boundaries are injected; positive bytes really reach sockets.
 * Native API calls (including setters) share the caller-owned media mutex. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

ssize_t media_test_send(int, const void *, size_t, int);
#define send media_test_send
#include "../src/ap2_client.c"
#undef send

/* Assertions must remain active even though production objects use NDEBUG. */
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

static log_level level = lSILENCE;
log_level *loglevel = &level;
log_level util_loglevel = lSILENCE;
log_level raop_loglevel = lSILENCE;

/* Hooks are also linked into a separately compiled production ap2_io.c. */
static int hooked_fd = -1;
static int error_once;
static int persistent_error;
static size_t short_once;
static bool short_udp;
static bool poll_timeout;

ssize_t media_test_send(int fd, const void *buf, size_t len, int flags)
{
    if (fd == hooked_fd) {
        if (error_once) {
            errno = error_once;
            error_once = 0;
            return -1;
        }
        if (short_once) {
            size_t n = short_once;
            short_once = 0;
            CHECK(n < len);
            return send(fd, buf, n, flags); /* real partial acceptance */
        }
        if (persistent_error) {
            errno = persistent_error;
            return -1;
        }
    }
    return send(fd, buf, len, flags);
}

ssize_t media_test_sendto(int fd, const void *buf, size_t len, int flags,
                          const struct sockaddr *addr, socklen_t addrlen)
{
    if (fd == hooked_fd) {
        if (error_once) {
            errno = error_once;
            error_once = 0;
            return -1;
        }
        if (persistent_error) { errno = persistent_error; return -1; }
        if (short_udp) return (ssize_t)len - 1;
    }
    return sendto(fd, buf, len, flags, addr, addrlen);
}

int media_test_poll(struct pollfd *fds, nfds_t n, int timeout)
{
    if (poll_timeout) { errno = ETIMEDOUT; return 0; }
    return poll(fds, n, timeout);
}

typedef struct {
    unsigned count;
    ap2_media_write_t events[16];
} capture_t;

static void capture(void *ctx, const ap2_media_write_t *write)
{
    capture_t *c = ctx;
    CHECK(c->count < 16);
    c->events[c->count++] = *write;
}

static int loopback_socket(int type, struct sockaddr_in *addr)
{
    int fd = socket(AF_INET, type, 0);
    CHECK(fd >= 0);
    *addr = (struct sockaddr_in){ .sin_family = AF_INET,
                                 .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    struct timeval timeout = { .tv_sec = 1 };
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(bind(fd, (struct sockaddr *)addr, sizeof(*addr)) == 0);
    socklen_t len = sizeof(*addr);
    CHECK(getsockname(fd, (struct sockaddr *)addr, &len) == 0);
    return fd;
}

static int tcp_pair(int *other, struct sockaddr_in *peer)
{
    int listener = loopback_socket(SOCK_STREAM, peer);
    CHECK(listen(listener, 1) == 0);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    CHECK(connect(fd, (struct sockaddr *)peer, sizeof(*peer)) == 0);
    *other = accept(listener, NULL, NULL);
    CHECK(*other >= 0);
    struct timeval timeout = { .tv_sec = 1 };
    CHECK(setsockopt(*other, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(close(listener) == 0);
    CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    return fd;
}

static struct ap2cl_s *client(bool buffered, int fd,
                              struct sockaddr_in peer)
{
    ap2_device_info_t d = { .name = "media fixture", .address = "127.0.0.1",
                           .port = 7000 };
    ap2_audio_format_t f = { .sample_rate = 44100, .bit_depth = 16,
                            .channels = 2 };
    struct ap2cl_s *p = ap2cl_create(&d, &f, NULL, NULL, NULL, NULL, 2000, -1);
    CHECK(p);
    p->flow = FLOW_NATIVE_AP2;
    p->state = AP2_STREAMING;
    p->hap = ap2_hap_create(NULL); /* deterministic all-zero test secret */
    p->alac = alac_create_encoder(352, 44100, 16, 2);
    CHECK(p->hap && p->alac);
    p->first_packet = false;
    p->seq_number = 1; /* don't request periodic sync in most fixture sends */
    p->use_buffered = buffered;
    p->data_addr = peer;
    if (buffered) p->buffered_sock = fd;
    else p->data_sock = fd;
    return p;
}

static void reset_hooks(int fd)
{
    hooked_fd = fd;
    error_once = persistent_error = 0;
    short_once = 0;
    short_udp = poll_timeout = false;
}

static ap2_send_result_t push(struct ap2cl_s *p, ap2_media_origin_t origin,
                               uint64_t tag)
{
    uint8_t pcm[352 * 4] = {0};
    return ap2cl_send_chunk_tagged(p, pcm, 352, origin, tag);
}

static void check_event(const capture_t *c, unsigned index,
                         ap2_media_route_t route, ap2_media_origin_t origin,
                         uint64_t tag, struct sockaddr_in peer, size_t bytes)
{
    CHECK(c->count > index);
    const ap2_media_write_t *e = &c->events[index];
    CHECK(e->route == route && e->origin == origin && e->tag == tag);
    CHECK(e->bytes == bytes && e->destination_known);
    CHECK(e->destination.sin_family == peer.sin_family);
    CHECK(e->destination.sin_addr.s_addr == peer.sin_addr.s_addr);
    CHECK(e->destination.sin_port == peer.sin_port);
}

static size_t read_unit(int fd, bool tcp)
{
    uint8_t bytes[8192];
    if (!tcp) {
        ssize_t n = recv(fd, bytes, sizeof(bytes), 0);
        CHECK(n > 36);
        return (size_t)n;
    }
    CHECK(recv(fd, bytes, 2, MSG_WAITALL) == 2);
    size_t len = ((size_t)bytes[0] << 8) | bytes[1];
    CHECK(len > 38 && len <= sizeof(bytes));
    CHECK(recv(fd, bytes + 2, len - 2, MSG_WAITALL) == (ssize_t)len - 2);
    return len;
}

static void test_udp(void)
{
    struct sockaddr_in peer;
    int sink = loopback_socket(SOCK_DGRAM, &peer);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    struct ap2cl_s *p = client(false, fd, peer);
    reset_hooks(fd);
    capture_t c = {0};
    CHECK(!p->media_write_cb);
    CHECK(push(p, AP2_MEDIA_FRESH, 9) == AP2_SEND_SENT);
    read_unit(sink, false); /* default absent preserves send */
    ap2cl_set_media_write_cb(p, capture, &c);
    CHECK(push(p, AP2_MEDIA_FRESH, 10) == AP2_SEND_SENT);
    check_event(&c, 0, AP2_MEDIA_REALTIME_UDP, AP2_MEDIA_FRESH, 10,
                peer, read_unit(sink, false));
    uint8_t idle[352 * 4] = {0};
    CHECK(ap2cl_send_chunk(p, idle, 352) == AP2_SEND_SENT);
    check_event(&c, 1, AP2_MEDIA_REALTIME_UDP, AP2_MEDIA_UNKNOWN, 0,
                peer, read_unit(sink, false));
    error_once = EINTR;
    CHECK(push(p, AP2_MEDIA_IDLE, 11) == AP2_SEND_SENT);
    check_event(&c, 2, AP2_MEDIA_REALTIME_UDP, AP2_MEDIA_IDLE, 11,
                peer, read_unit(sink, false));
    error_once = EAGAIN;
    CHECK(push(p, AP2_MEDIA_BACKLOG, 12) == AP2_SEND_SENT);
    check_event(&c, 3, AP2_MEDIA_REALTIME_UDP, AP2_MEDIA_BACKLOG, 12,
                peer, read_unit(sink, false));
    persistent_error = EAGAIN;
    poll_timeout = true;
    CHECK(push(p, AP2_MEDIA_FRESH, 13) == AP2_SEND_DROPPED);
    CHECK(c.count == 4 && p->audio_packets_dropped == 1);
    reset_hooks(fd);
    short_udp = true;
    CHECK(push(p, AP2_MEDIA_FRESH, 14) == AP2_SEND_FATAL);
    CHECK(c.count == 4);
    reset_hooks(fd);
    persistent_error = EIO;
    CHECK(push(p, AP2_MEDIA_FRESH, 15) == AP2_SEND_FATAL);
    CHECK(c.count == 4);
    reset_hooks(fd);
    /* Initial sync goes to its own actual UDP socket, not the media hook. */
    p->ctrl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(p->ctrl_sock >= 0);
    p->ctrl_addr = peer;
    p->first_packet = true;
    CHECK(push(p, AP2_MEDIA_FRESH, 16) == AP2_SEND_SENT);
    uint8_t packet[8192];
    CHECK(recv(sink, packet, sizeof(packet), 0) == 20);
    check_event(&c, 4, AP2_MEDIA_REALTIME_UDP, AP2_MEDIA_FRESH, 16,
                peer, read_unit(sink, false));
    /* Exercise the real RTX responder send path, not a direct callback. */
    p->rtx_ring = calloc(AP2_RTX_RING_SLOTS, sizeof(*p->rtx_ring));
    CHECK(p->rtx_ring);
    ap2_rtx_store(p, 42, packet, 20);
    CHECK(ap2_rtx_resend(p, 42, 7, &peer));
    CHECK(recv(sink, packet, sizeof(packet), 0) == 24);
    CHECK(c.count == 5);
    ap2cl_set_media_write_cb(p, NULL, &c);
    CHECK(!p->media_write_ctx);
    CHECK(push(p, AP2_MEDIA_FRESH, 17) == AP2_SEND_SENT);
    read_unit(sink, false);
    CHECK(c.count == 5);
    CHECK(close(p->data_sock) == 0);
    p->data_sock = -1;
    CHECK(push(p, AP2_MEDIA_FRESH, 18) == AP2_SEND_FATAL);
    CHECK(c.count == 5);
    p->state = AP2_CONNECTED;
    CHECK(push(p, AP2_MEDIA_FRESH, 18) == AP2_SEND_FATAL);
    CHECK(c.count == 5);
    CHECK(ap2cl_destroy(p));
    CHECK(close(sink) == 0);
    puts("native media UDP production full-write and failure paths passed");
}

static void park_partial(struct ap2cl_s *p, uint64_t tag)
{
    short_once = 1;
    persistent_error = EAGAIN;
    CHECK(push(p, AP2_MEDIA_BACKLOG, tag) == AP2_SEND_SENT);
    CHECK(p->buffered_pending_len > 1 && p->buffered_pending_off == 1);
}

static void test_tcp(bool false_counter_claim)
{
    struct sockaddr_in peer;
    int sink;
    int fd = tcp_pair(&sink, &peer);
    struct ap2cl_s *p = client(true, fd, peer);
    reset_hooks(fd);
    capture_t c = {0}, replacement = {0};
    CHECK(push(p, AP2_MEDIA_FRESH, 99) == AP2_SEND_SENT);
    read_unit(sink, true); /* default absent callback preserves buffered API */
    ap2cl_set_media_write_cb(p, capture, &c);
    unsigned long long queued_before = p->audio_packets_sent;
    uint64_t next_tag = 100;
    park_partial(p, next_tag);
    next_tag = 101; /* caller advances generation while old frame is pending */
    /* Paired negative: the old queued-packet counter has advanced, but the
     * callback MUST still be zero while the final byte is unwritten. */
    CHECK(p->audio_packets_sent == queued_before + 1);
    if (false_counter_claim) CHECK(c.count == 1);
    CHECK(c.count == 0);
    CHECK(!ap2cl_accept_frames(p));
    CHECK(c.count == 0);
    size_t total = (size_t)p->buffered_pending_len;
    /* Drain all but final byte with the real syscall, then backpressure. */
    short_once = total - 2;
    CHECK(!ap2cl_accept_frames(p));
    CHECK(p->buffered_pending_off == (int)total - 1 && c.count == 0);
    reset_hooks(fd);
    ap2cl_accept_frames(p);
    check_event(&c, 0, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_BACKLOG, 100,
                peer, read_unit(sink, true));
    ap2cl_accept_frames(p);
    CHECK(c.count == 1); /* exactly once */
    error_once = EINTR;
    CHECK(push(p, AP2_MEDIA_FRESH, next_tag) == AP2_SEND_SENT);
    check_event(&c, 1, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_FRESH, 101,
                peer, read_unit(sink, true));
    /* Old partial frame finishes during production quiesce with its old tag. */
    park_partial(p, 102);
    ap2_buffered_quiesce_data(p); /* bounded undrained tail is NOT completion */
    CHECK(c.count == 2 && p->buffered_pending_off == 1);
    /* Warm splice FLUSH/resume keeps old pending attribution. */
    p->splice_timeline = true;
    p->rt_anchor_valid = true;
    p->head_ts = NTP2TS(raopcl_get_ntp(NULL) + MS2NTP(2000), 44100);
    CHECK(ap2cl_flush(p));
    CHECK(ap2cl_resume(p, 0, NULL) == AP2_COMMIT_OK);
    CHECK(c.count == 2);
    reset_hooks(fd);
    ap2_buffered_quiesce_data(p);
    check_event(&c, 2, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_BACKLOG, 102,
                peer, read_unit(sink, true));
    CHECK(push(p, AP2_MEDIA_FRESH, 103) == AP2_SEND_SENT);
    check_event(&c, 3, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_FRESH, 103,
                peer, read_unit(sink, true));
    /* Wholly unwritten pre-flush frame is discarded, never completed. */
    persistent_error = EAGAIN;
    CHECK(push(p, AP2_MEDIA_IDLE, 104) == AP2_SEND_SENT);
    CHECK(p->buffered_pending_off == 0);
    ap2_buffered_quiesce_data(p);
    CHECK(!p->buffered_pending_len && c.count == 4);
    reset_hooks(fd);
    /* Replacing even the same callback must not adopt an old partial frame. */
    park_partial(p, 105);
    ap2cl_set_media_write_cb(p, capture, &replacement);
    reset_hooks(fd);
    ap2cl_accept_frames(p);
    read_unit(sink, true);
    CHECK(c.count == 4 && replacement.count == 0);
    CHECK(push(p, AP2_MEDIA_IDLE, 106) == AP2_SEND_SENT);
    check_event(&replacement, 0, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_IDLE, 106,
                peer, read_unit(sink, true));
    park_partial(p, 107);
    ap2cl_set_media_write_cb(p, NULL, NULL);
    reset_hooks(fd);
    ap2cl_accept_frames(p);
    read_unit(sink, true);
    CHECK(replacement.count == 1);
    park_partial(p, 108); /* queued while absent cannot be adopted */
    ap2cl_set_media_write_cb(p, capture, &replacement);
    reset_hooks(fd);
    ap2cl_accept_frames(p);
    read_unit(sink, true);
    CHECK(replacement.count == 1);
    /* Hard failure after partial acceptance is not a completed frame. Even
     * if a caller later retries its old tail, a failed unit is not notified. */
    park_partial(p, 108);
    persistent_error = EIO;
    CHECK(!ap2cl_accept_frames(p));
    CHECK(replacement.count == 1);
    reset_hooks(fd);
    ap2cl_accept_frames(p);
    read_unit(sink, true);
    CHECK(replacement.count == 1);
    /* Reinstalling identical registration also invalidates old completion. */
    park_partial(p, 109);
    ap2cl_set_media_write_cb(p, capture, &replacement);
    reset_hooks(fd);
    ap2cl_accept_frames(p);
    read_unit(sink, true);
    CHECK(replacement.count == 1);
    persistent_error = EIO;
    CHECK(push(p, AP2_MEDIA_FRESH, 109) == AP2_SEND_FATAL);
    CHECK(replacement.count == 1 && p->buffered_sock == -1);
    CHECK(ap2cl_disconnect(p));
    CHECK(!p->buffered_pending_len);
    CHECK(close(sink) == 0);
    /* Reconnect socket replacement after disconnect cannot carry the old tag. */
    fd = tcp_pair(&sink, &peer);
    p->buffered_sock = fd;
    p->state = AP2_STREAMING;
    reset_hooks(fd);
    CHECK(push(p, AP2_MEDIA_FRESH, 110) == AP2_SEND_SENT);
    check_event(&replacement, 1, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_FRESH, 110,
                peer, read_unit(sink, true));
    uint8_t idle[352 * 4] = {0};
    CHECK(ap2cl_send_chunk(p, idle, 352) == AP2_SEND_SENT);
    check_event(&replacement, 2, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_UNKNOWN, 0,
                peer, read_unit(sink, true));
    park_partial(p, 111);
    CHECK(ap2cl_disconnect(p)); /* cancel drops partial tail, no completion */
    CHECK(replacement.count == 3 && !p->buffered_pending_len);
    ap2cl_set_media_write_cb(p, NULL, NULL);
    CHECK(ap2cl_destroy(p));
    CHECK(close(sink) == 0);
    puts("native media TCP production final-byte, attribution and discard paths passed");
}

/* Existing external serialization, not a new library lock: clear waits for an
 * in-flight callback because setter and sender take the same caller mutex. */
static pthread_mutex_t media_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    struct ap2cl_s *p;
    atomic_bool entered;
    atomic_bool release;
    atomic_bool cleared;
    capture_t *context;
} lifetime_t;

static void lifetime_callback(void *ctx, const ap2_media_write_t *write)
{
    lifetime_t *l = ctx;
    atomic_store(&l->entered, true);
    while (!atomic_load(&l->release)) sched_yield();
    capture(l->context, write);
}

static void *lifetime_sender(void *ctx)
{
    lifetime_t *l = ctx;
    CHECK(pthread_mutex_lock(&media_lock) == 0);
    CHECK(push(l->p, AP2_MEDIA_FRESH, 200) == AP2_SEND_SENT);
    CHECK(pthread_mutex_unlock(&media_lock) == 0);
    return NULL;
}

static void *lifetime_clear(void *ctx)
{
    lifetime_t *l = ctx;
    CHECK(pthread_mutex_lock(&media_lock) == 0);
    ap2cl_set_media_write_cb(l->p, NULL, NULL);
    free(l->context);
    l->context = NULL;
    atomic_store(&l->cleared, true);
    CHECK(pthread_mutex_unlock(&media_lock) == 0);
    return NULL;
}

/* Observe real kernel EAGAIN, then pin that boundary through encoding so an
 * asynchronous TCP ACK cannot make this test scheduler/sanitizer-dependent.
 * Fixture prefill is drained separately; final flush uses the real syscall. */
static void test_real_backpressure(void)
{
    struct sockaddr_in peer;
    int sink;
    int fd = tcp_pair(&sink, &peer);
    int capacity = 4096;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0);
    struct ap2cl_s *p = client(true, fd, peer);
    reset_hooks(fd);
    capture_t c = {0};
    ap2cl_set_media_write_cb(p, capture, &c);
    uint8_t filler[4096] = {0};
    size_t filled = 0;
    for (;;) {
        ssize_t n = send(fd, filler, sizeof(filler), 0);
        if (n < 0) {
            CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        CHECK(n > 0);
        filled += (size_t)n;
        CHECK(filled < 4 * 1024 * 1024);
    }
    CHECK(filled > 0);
    persistent_error = EAGAIN;
    CHECK(push(p, AP2_MEDIA_FRESH, 300) == AP2_SEND_SENT);
    CHECK(p->audio_packets_sent == 1 && c.count == 0);
    CHECK(p->buffered_pending_len > p->buffered_pending_off);
    while (filled) {
        size_t want = filled < sizeof(filler) ? filled : sizeof(filler);
        ssize_t n = recv(sink, filler, want, 0);
        CHECK(n > 0);
        filled -= (size_t)n;
    }
    reset_hooks(fd);
    CHECK(ap2_io_poll_fd(fd, POLLOUT, ap2_io_monotonic_ms() + 1000) == 1);
    ap2cl_accept_frames(p);
    check_event(&c, 0, AP2_MEDIA_BUFFERED_TCP, AP2_MEDIA_FRESH, 300,
                peer, read_unit(sink, true));
    CHECK(c.count == 1);
    ap2cl_set_media_write_cb(p, NULL, NULL);
    CHECK(ap2cl_destroy(p));
    CHECK(close(sink) == 0);
    puts("native media real TCP kernel backpressure and full flush passed");
}

static void test_lifetime(void)
{
    struct sockaddr_in peer;
    int sink = loopback_socket(SOCK_DGRAM, &peer);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    reset_hooks(fd);
    lifetime_t l = { .p = client(false, fd, peer),
                     .context = calloc(1, sizeof(capture_t)) };
    CHECK(l.context);
    ap2cl_set_media_write_cb(l.p, lifetime_callback, &l);
    pthread_t sender, clearer;
    CHECK(pthread_create(&sender, NULL, lifetime_sender, &l) == 0);
    while (!atomic_load(&l.entered)) sched_yield();
    CHECK(pthread_create(&clearer, NULL, lifetime_clear, &l) == 0);
    CHECK(!atomic_load(&l.cleared));
    atomic_store(&l.release, true);
    CHECK(pthread_join(sender, NULL) == 0);
    CHECK(pthread_join(clearer, NULL) == 0);
    CHECK(atomic_load(&l.cleared) && !l.context);
    read_unit(sink, false);
    CHECK(push(l.p, AP2_MEDIA_FRESH, 201) == AP2_SEND_SENT);
    read_unit(sink, false); /* no freed userdata access after clear */
    CHECK(ap2cl_destroy(l.p));
    CHECK(close(sink) == 0);
    puts("native media caller-serialized unregister lifetime passed");
}

int main(int argc, char **argv)
{
    bool false_counter_claim = argc == 2 &&
        strcmp(argv[1], "--counter-is-completion") == 0;
    test_udp();
    test_tcp(false_counter_claim);
    test_real_backpressure();
    test_lifetime();
    return 0;
}
