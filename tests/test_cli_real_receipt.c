/*
 * Real-binary integration test for --private-media-receipt.
 *
 * Spawns the actual cliairplay executable on the legacy RAOP, AirPlay 2 compat
 * and native AirPlay 2 routes with a real command FIFO, a real stdin PCM pipe
 * and a real stdout pipe/FIFO. The peer is an owned loopback fixture: a
 * scripted RTSP listener (RAOP-shaped, or the synthetic native receiver in
 * native_ap2_peer.c) whose SETUP names an owned UDP audio socket. Nothing leaves the loopback interface and no real
 * receiver, pairing or credential is involved. The code path under test is the
 * production main()/run_raop()/run_airplay2()/command thread/finish_run()/
 * mr_emit(), not a
 * compiled-in copy of it.
 *
 * Usage: test_cli_real_receipt <cliairplay-binary> [case|all] [route]
 *        (routes: raop, compat, native; no case/route runs everything)
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "native_ap2_peer.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
    return false; } } while (0)

extern char **environ;

/* ---- loopback peer: RTSP + owned UDP sockets ---- */

typedef struct {
    int rtsp_fd, audio_fd, ctrl_fd, time_fd;
    uint16_t rtsp_port, audio_port, ctrl_port, time_port;
    atomic_bool stop;
    bool stopped;       /* peer_stop() already ran */
    atomic_uint audio_units;
    atomic_ulong audio_bytes;
    atomic_uint teardowns;
    pthread_t rtsp_thread, audio_thread;
    bool native;        /* np serves instead of the legacy fields above */
    native_peer_t np;
} peer_t;

static peer_t *live_peer;
/* The wire route the next child and peer use; set by main() per route. */
typedef struct {
    const char *name, *protocol, *record_route, *route_line;
    bool native;    /* HAP transient pairing, served by native_ap2_peer.c */
} route_t;

static const route_t routes[] = {
    { "raop", "raop", "raop", "[STATUS] route protocol=raop flow=legacy", false },
    { "compat", "airplay2-compat", "compat",
      "[STATUS] route protocol=airplay2 flow=raop-compat", false },
    { "native", "airplay2", "udp", "[STATUS] route protocol=airplay2 flow=native",
      true },
};
static const route_t *g_route = &routes[0];

static unsigned peer_units(const peer_t *p)
{
    return atomic_load(p->native ? &p->np.audio_units : &p->audio_units);
}
static unsigned long peer_bytes(const peer_t *p)
{
    return atomic_load(p->native ? &p->np.audio_bytes : &p->audio_bytes);
}
static unsigned peer_teardowns(const peer_t *p)
{
    return atomic_load(p->native ? &p->np.teardowns : &p->teardowns);
}
static uint16_t peer_rtsp(const peer_t *p)
{
    return p->native ? p->np.rtsp_port : p->rtsp_port;
}
static uint16_t peer_audio_port(const peer_t *p)
{
    return p->native ? p->np.audio_port : p->audio_port;
}

static int bind_udp(uint16_t *port)
{
    struct sockaddr_in a = { .sin_family = AF_INET };
    socklen_t len = sizeof(a);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &len) != 0)
        return -1;
    if (port) *port = ntohs(a.sin_port);
    return fd;
}

static void sleep_ms(unsigned ms)
{
    struct timespec t = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

static uint64_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

static void *audio_main(void *opaque)
{
    peer_t *peer = opaque;
    uint8_t buf[2048];

    for (;;) {
        struct pollfd p = { .fd = peer->audio_fd, .events = POLLIN };
        if (poll(&p, 1, 50) > 0) {
            ssize_t n = recv(peer->audio_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                atomic_fetch_add(&peer->audio_units, 1);
                atomic_fetch_add(&peer->audio_bytes, (unsigned long)n);
            }
        } else if (atomic_load(&peer->stop)) {
            break;
        }
    }
    return NULL;
}

static void reply(peer_t *peer, int fd, int cseq)
{
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
                     "RTSP/1.0 200 OK\r\nCSeq: %d\r\nSession: loopback\r\n"
                     "Transport: RTP/AVP/UDP;server_port=%u;control_port=%u;"
                     "timing_port=%u\r\n\r\n", cseq, peer->audio_port,
                     peer->ctrl_port, peer->time_port);

    (void)!write(fd, buf, (size_t)n);
}

static void serve(peer_t *peer, int fd)
{
    char buf[4096];

    for (;;) {
        size_t used = 0;
        do {
            if (used + 1 >= sizeof(buf) || read(fd, buf + used, 1) != 1)
                return;
            buf[++used] = '\0';
        } while (!strstr(buf, "\r\n\r\n"));
        const char *length = strstr(buf, "Content-Length:");
        int body = length ? atoi(length + strlen("Content-Length:")) : 0;
        for (int i = 0; i < body; i++) {
            char byte;
            if (read(fd, &byte, 1) != 1)
                return;
        }
        const char *cseq = strstr(buf, "CSeq:");
        if (!strncmp(buf, "TEARDOWN", 8)) {
            atomic_fetch_add(&peer->teardowns, 1);
        }
        reply(peer, fd, cseq ? atoi(cseq + 5) : 0);
    }
}

static void *rtsp_main(void *opaque)
{
    peer_t *peer = opaque;

    while (!atomic_load(&peer->stop)) {
        struct pollfd p = { .fd = peer->rtsp_fd, .events = POLLIN };
        if (poll(&p, 1, 50) > 0) {
            int fd = accept(peer->rtsp_fd, NULL, NULL);
            if (fd >= 0) {
                serve(peer, fd);
                close(fd);
            }
        }
    }
    return NULL;
}

static bool peer_start(peer_t *peer)
{
    struct sockaddr_in a = { .sin_family = AF_INET };
    socklen_t len = sizeof(a);

    memset(peer, 0, sizeof(*peer));
    live_peer = peer;
    if (g_route->native) {
        peer->native = true;
        return native_peer_start(&peer->np);
    }
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer->rtsp_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(peer->rtsp_fd >= 0);
    CHECK(bind(peer->rtsp_fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    CHECK(listen(peer->rtsp_fd, 4) == 0);
    CHECK(getsockname(peer->rtsp_fd, (struct sockaddr *)&a, &len) == 0);
    peer->rtsp_port = ntohs(a.sin_port);
    peer->audio_fd = bind_udp(&peer->audio_port);
    peer->ctrl_fd = bind_udp(&peer->ctrl_port);
    peer->time_fd = bind_udp(&peer->time_port);
    CHECK(peer->audio_fd >= 0 && peer->ctrl_fd >= 0 && peer->time_fd >= 0);
    CHECK(pthread_create(&peer->rtsp_thread, NULL, rtsp_main, peer) == 0);
    CHECK(pthread_create(&peer->audio_thread, NULL, audio_main, peer) == 0);
    return true;
}

static void peer_stop(peer_t *peer)
{
    if (peer->stopped)
        return;
    peer->stopped = true;
    if (peer->native) {
        native_peer_stop(&peer->np);
        return;
    }
    atomic_store(&peer->stop, true);
    pthread_join(peer->rtsp_thread, NULL);
    pthread_join(peer->audio_thread, NULL);
    close(peer->rtsp_fd);
    close(peer->audio_fd);
    close(peer->ctrl_fd);
    close(peer->time_fd);
}

/* ---- child process ---- */

typedef struct {
    pid_t pid;
    char dir[64];
    char cmd_path[96], out_path[96], err_path[96];
    int stdin_w;    /* PCM */
    int stdout_r;   /* child stdout, read side */
    int fill_w;     /* second, independent open of a FIFO stdout (or -1) */
    int cmd_w;      /* command FIFO */
    atomic_bool feeder_run;
    pthread_t feeder;
    bool feeder_started;
    char out[262144];
    size_t out_len;
    bool waited, cleaned;   /* reaped / resources released */
} child_t;

/* The live fixtures of the running case, so main() can reap them even when a
 * CHECK returned early. Cases keep them in static storage for that reason. */
static child_t *live_child;

static bool set_flag(int fd, int flag)
{
    int f = fcntl(fd, F_GETFL);

    return f >= 0 && fcntl(fd, F_SETFL, f | flag) == 0;
}

static void *feed_main(void *opaque)
{
    child_t *c = opaque;
    static const uint8_t silence[4096];

    /* About 20 s of paced-by-pipe silence; ends on EPIPE or when stopped. */
    for (int i = 0; i < 4000 && atomic_load(&c->feeder_run); i++) {
        struct pollfd p = { .fd = c->stdin_w, .events = POLLOUT };
        if (poll(&p, 1, 100) <= 0)
            continue;
        if (write(c->stdin_w, silence, sizeof(silence)) < 0)
            break;
    }
    return NULL;
}

/* Completely full through the test's own (nonblocking) open file description:
 * 512-byte writes, then single bytes until the kernel says EAGAIN. */
static bool fill_pipe(int fd, size_t *total)
{
    char junk[512];

    memset(junk, 'x', sizeof(junk));
    *total = 0;
    for (;;) {
        ssize_t n = write(fd, junk, sizeof(junk));
        if (n < 0)
            break;
        *total += (size_t)n;
    }
    for (ssize_t n; (n = write(fd, junk, 1)) > 0;)
        *total += (size_t)n;
    return errno == EAGAIN;
}

/* stdout_fifo: the child's stdout is a named FIFO, so this test owns a second,
 * independent open file description on it (its own O_NONBLOCK, used to fill it
 * without touching the child's flags). Otherwise a plain anonymous pipe. */
static bool child_start(child_t *c, const char *binary, uint16_t port,
                        bool receipt, bool stdout_fifo, bool prefill)
{
    char port_text[16];
    int in_pipe[2], out_pipe[2] = { -1, -1 };
    posix_spawn_file_actions_t acts;

    memset(c, 0, sizeof(*c));
    live_child = c;
    c->fill_w = c->stdout_r = c->cmd_w = -1;
    snprintf(c->dir, sizeof(c->dir), "/tmp/cliairplay-real-XXXXXX");
    CHECK(mkdtemp(c->dir) != NULL);
    snprintf(c->cmd_path, sizeof(c->cmd_path), "%s/cmd", c->dir);
    snprintf(c->out_path, sizeof(c->out_path), "%s/out", c->dir);
    snprintf(c->err_path, sizeof(c->err_path), "%s/err", c->dir);
    CHECK(pipe(in_pipe) == 0);
    CHECK(posix_spawn_file_actions_init(&acts) == 0);
    CHECK(posix_spawn_file_actions_adddup2(&acts, in_pipe[0], 0) == 0);
    if (stdout_fifo) {
        CHECK(mkfifo(c->out_path, 0600) == 0);
        c->stdout_r = open(c->out_path, O_RDONLY | O_NONBLOCK);
        CHECK(c->stdout_r >= 0);
        c->fill_w = open(c->out_path, O_WRONLY | O_NONBLOCK);
        CHECK(c->fill_w >= 0);
        if (prefill) {
            size_t total;
            CHECK(fill_pipe(c->fill_w, &total));
        }
        CHECK(posix_spawn_file_actions_addopen(&acts, 1, c->out_path,
                                               O_WRONLY, 0) == 0);
    } else {
        CHECK(pipe(out_pipe) == 0);
        CHECK(posix_spawn_file_actions_adddup2(&acts, out_pipe[1], 1) == 0);
        c->stdout_r = out_pipe[0];
    }
    CHECK(posix_spawn_file_actions_addopen(&acts, 2, c->err_path,
                                           O_WRONLY | O_CREAT | O_TRUNC,
                                           0600) == 0);
    CHECK(posix_spawn_file_actions_addclose(&acts, in_pipe[1]) == 0);
    snprintf(port_text, sizeof(port_text), "%u", port);
    char *args[16];
    int n = 0;
    args[n++] = (char *)binary;
    args[n++] = "--protocol";
    args[n++] = (char *)g_route->protocol;
    args[n++] = "--port";
    args[n++] = port_text;
    args[n++] = "--cmdpipe";
    args[n++] = c->cmd_path;
    if (g_route->native) {
        args[n++] = "--ap2-native";
        args[n++] = "--timing";
        args[n++] = "ntp";
    }
    args[n++] = "--et";
    args[n++] = "0";
    if (receipt)
        args[n++] = "--private-media-receipt";
    args[n++] = "127.0.0.1";
    args[n] = NULL;
    CHECK(posix_spawn(&c->pid, binary, &acts, NULL, args, environ) == 0);
    posix_spawn_file_actions_destroy(&acts);
    close(in_pipe[0]);
    c->stdin_w = in_pipe[1];
    if (out_pipe[1] >= 0)
        close(out_pipe[1]);
    CHECK(set_flag(c->stdout_r, O_NONBLOCK));
    return true;
}

static size_t drain_stdout(child_t *c)
{
    for (;;) {
        if (c->out_len + 1 >= sizeof(c->out))
            return c->out_len;
        ssize_t n = read(c->stdout_r, c->out + c->out_len,
                         sizeof(c->out) - 1 - c->out_len);
        if (n <= 0)
            break;
        c->out_len += (size_t)n;
    }
    c->out[c->out_len] = '\0';
    return c->out_len;
}

static ssize_t read_err(const child_t *c, char *buf, size_t size)
{
    int fd = open(c->err_path, O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, buf, size - 1);

    if (fd >= 0)
        close(fd);
    if (n >= 0)
        buf[n] = '\0';
    return n;
}

static bool err_contains(const child_t *c, const char *needle)
{
    char buf[65536];

    return read_err(c, buf, sizeof(buf)) >= 0 && strstr(buf, needle) != NULL;
}

static size_t err_count(const child_t *c, const char *needle)
{
    char buf[65536];
    size_t count = 0;

    if (read_err(c, buf, sizeof(buf)) < 0)
        return 0;
    for (const char *p = buf; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        count++;
    return count;
}

static bool wait_err(const child_t *c, const char *needle, unsigned ms)
{
    uint64_t end = now_ms() + ms;

    while (now_ms() < end) {
        if (err_contains(c, needle))
            return true;
        sleep_ms(20);
    }
    fprintf(stderr, "timeout waiting for child log: %s\n", needle);
    return false;
}

static bool send_command(child_t *c, const char *text)
{
    if (c->cmd_w < 0) {
        uint64_t end = now_ms() + 10000;

        while (c->cmd_w < 0 && now_ms() < end) {
            c->cmd_w = open(c->cmd_path, O_WRONLY | O_NONBLOCK);
            if (c->cmd_w < 0)
                sleep_ms(20);
        }
        CHECK(c->cmd_w >= 0);
    }
    /* One write(): the whole text reaches the production reader in one read. */
    CHECK(write(c->cmd_w, text, strlen(text)) == (ssize_t)strlen(text));
    return true;
}

static void start_feeder(child_t *c)
{
    atomic_store(&c->feeder_run, true);
    c->feeder_started = pthread_create(&c->feeder, NULL, feed_main, c) == 0;
}

static void dump_err(const child_t *c)
{
    char buf[16384];

    if (read_err(c, buf, sizeof(buf)) > 0)
        fprintf(stderr, "---- child stderr ----\n%s\n----\n", buf);
}

/* Wait for the actual process; never leave it behind. `drain` keeps a reader
 * running, which a full-stdout case must not have. */
static bool child_wait(child_t *c, unsigned ms, int *status, bool drain)
{
    uint64_t end = now_ms() + ms;

    for (;;) {
        pid_t r = waitpid(c->pid, status, WNOHANG);
        if (r == c->pid) {
            c->waited = true;
            if (!WIFEXITED(*status) || WEXITSTATUS(*status) != 0) {
                fprintf(stderr, "child ended abnormally, status 0x%x\n", *status);
                dump_err(c);
            }
            return true;
        }
        if (r < 0 || now_ms() >= end)
            break;
        if (drain)
            drain_stdout(c);
        sleep_ms(10);
    }
    fprintf(stderr, "child did not exit within %u ms; killing\n", ms);
    kill(c->pid, SIGKILL);
    waitpid(c->pid, status, 0);
    c->waited = true;
    return false;
}

static void child_cleanup(child_t *c)
{
    if (c->cleaned)
        return;
    c->cleaned = true;
    atomic_store(&c->feeder_run, false);
    if (c->feeder_started)
        pthread_join(c->feeder, NULL);
    if (c->stdin_w >= 0) close(c->stdin_w);
    if (c->stdout_r >= 0) close(c->stdout_r);
    if (c->fill_w >= 0) close(c->fill_w);
    if (c->cmd_w >= 0) close(c->cmd_w);
    unlink(c->out_path);
    unlink(c->cmd_path);
    unlink(c->err_path);
    rmdir(c->dir);
}

/* The sender's count is final once the child exited; wait for the receiver
 * socket to have delivered exactly that many datagrams. */
static bool wait_receiver_settled(peer_t *peer, unsigned units)
{
    uint64_t end = now_ms() + 5000;

    while (now_ms() < end) {
        if (peer_units(peer) == units)
            return true;
        sleep_ms(10);
    }
    fprintf(stderr, "receiver saw %u datagrams, sender counted %u\n",
            peer_units(peer), units);
    return false;
}

/* Whatever the case left behind, even after a failed CHECK: no orphan child,
 * no thread, no temp directory. */
static void reap_live(void)
{
    int status;

    if (live_child && live_child->pid > 0 && !live_child->waited) {
        kill(live_child->pid, SIGKILL);
        waitpid(live_child->pid, &status, 0);
        live_child->waited = true;
    }
    if (live_child && live_child->dir[0] != '\0')
        child_cleanup(live_child);
    if (live_peer)
        peer_stop(live_peer);
    live_child = NULL;
    live_peer = NULL;
}

static bool wait_units(peer_t *peer, unsigned units, unsigned ms)
{
    uint64_t end = now_ms() + ms;

    while (now_ms() < end) {
        if (peer_units(peer) >= units)
            return true;
        sleep_ms(20);
    }
    fprintf(stderr, "timeout: loopback receiver saw %u of %u datagrams\n",
            peer_units(peer), units);
    return false;
}

/* ---- record inspection ---- */

typedef struct {
    unsigned records;   /* @MEDIA lines in stdout */
    bool last_is_final; /* final is the last line and LF terminated */
    bool stop, fault, overflow;
    unsigned epoch, fresh_units, fresh_bytes, idle_units, backlog_units;
    unsigned port, setup_port;
    char route[16], addr[32];
} record_t;

static bool parse_record(const char *out, record_t *r)
{
    const char *line = out;
    char terminal[16];

    memset(r, 0, sizeof(*r));
    while ((line = strstr(line, "@MEDIA")) != NULL) {
        r->records++;
        line += 6;
    }
    line = strstr(out, "@MEDIA1 ");
    if (!line)
        return true;
    char fault[8], overflow[8], addr[32];
    int got = sscanf(line,
        "@MEDIA1 {\"v\":1,\"terminal\":\"%15[a-z]\",\"route\":\"%15[a-z]\","
        "\"epoch\":%u,\"fresh_units\":%u,\"fresh_bytes\":%u,\"idle_units\":%u,"
        "\"backlog_units\":%u,\"fault\":%7[a-z],\"overflow\":%7[a-z],"
        "\"addr\":%31[^,],\"port\":%u,\"setup_port\":%u}",
        terminal, r->route, &r->epoch, &r->fresh_units, &r->fresh_bytes,
        &r->idle_units, &r->backlog_units, fault, overflow, addr, &r->port,
        &r->setup_port);
    if (got != 12)
        return false;
    r->stop = !strcmp(terminal, "stop");
    r->fault = !strcmp(fault, "true");
    r->overflow = !strcmp(overflow, "true");
    snprintf(r->addr, sizeof(r->addr), "%s", addr);
    const char *nl = strchr(line, '\n');
    r->last_is_final = nl && nl[1] == '\0';
    return true;
}

/* ---- scenarios ---- */

/* Common prologue: connect, START, feed, wait for real datagrams. */
static bool begin_playback(child_t *c, peer_t *peer, unsigned units)
{
    CHECK(wait_err(c, "[STATUS] connected", 15000));
    CHECK(send_command(c, "ACTION=START\n"));
    CHECK(wait_err(c, "[STATUS] started", 10000));
    start_feeder(c);
    CHECK(wait_units(peer, units, 15000));
    return true;
}

/* Normal production path: START, real PCM, real datagrams, one STOP. The
 * final must count exactly what the owned receiver saw, to the owned target. */
static bool case_positive(const char *binary)
{
    static peer_t peer;
    static child_t c;
    record_t r;
    int status;

    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), true, false, false));
    CHECK(begin_playback(&c, &peer, 20));
    CHECK(send_command(&c, "ACTION=STOP\n"));
    CHECK(child_wait(&c, 20000, &status, true));
    drain_stdout(&c);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(parse_record(c.out, &r));
    CHECK(wait_receiver_settled(&peer, r.fresh_units));
    CHECK(r.records == 1 && r.last_is_final);
    CHECK(r.stop && !r.fault && !r.overflow);
    CHECK(!strcmp(r.route, g_route->record_route) && r.epoch == 1);
    CHECK(!strcmp(r.addr, "\"127.0.0.1\""));
    CHECK(r.port == peer_audio_port(&peer) && r.setup_port == peer_audio_port(&peer));
    CHECK(r.fresh_units >= 20 && r.idle_units == 0 && r.backlog_units == 0);
    /* Sender count == what the owned receiver actually got, units and bytes. */
    fprintf(stderr, "sender %u units/%u bytes, receiver %u units/%lu bytes\n",
            r.fresh_units, r.fresh_bytes, peer_units(&peer),
            peer_bytes(&peer));
    CHECK(r.fresh_units == peer_units(&peer));
    CHECK(r.fresh_bytes == peer_bytes(&peer));
    CHECK(peer_teardowns(&peer) >= 1);
    /* Native: the HAP transient pair-setup really completed, exactly once. */
    CHECK(!g_route->native || atomic_load(&peer.np.pairings) == 1);
    CHECK(strstr(c.out, g_route->route_line) != NULL);
    fprintf(stderr, "ok: real CLI START/PCM/STOP -> one @MEDIA1 (%u units, %u bytes) "
            "== receiver\n", r.fresh_units, r.fresh_bytes);
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

/* Default off: identical run without the flag emits no record at all. */
static bool case_default_off(const char *binary)
{
    static peer_t peer;
    static child_t c;
    int status;

    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), false, false, false));
    CHECK(begin_playback(&c, &peer, 5));
    CHECK(send_command(&c, "ACTION=STOP\n"));
    CHECK(child_wait(&c, 20000, &status, true));
    drain_stdout(&c);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(strstr(c.out, "@MEDIA") == NULL);
    fprintf(stderr, "ok: real CLI without the flag emits no @MEDIA record\n");
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

/* Owner STOP with no START: no applied epoch, so never a qualifying record. */
static bool case_stop_without_start(const char *binary)
{
    static peer_t peer;
    static child_t c;
    record_t r;
    int status;

    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), true, false, false));
    CHECK(wait_err(&c, "[STATUS] connected", 15000));
    CHECK(send_command(&c, "ACTION=STOP\n"));
    CHECK(child_wait(&c, 20000, &status, true));
    drain_stdout(&c);
    CHECK(parse_record(c.out, &r));
    CHECK(r.records <= 1);
    /* Valid but empty: epoch 0, zero units and no target never qualifies. */
    CHECK(r.records == 0 || (r.epoch == 0 && r.fresh_units == 0 &&
                             r.fresh_bytes == 0 && !strcmp(r.addr, "null")));
    CHECK(peer_units(&peer) == 0);
    fprintf(stderr, "ok: real CLI STOP without START never qualifies\n");
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

/* A real SIGTERM mid-stream: the record, if any, is abnormal and faulted. */
static bool case_sigterm(const char *binary)
{
    static peer_t peer;
    static child_t c;
    record_t r;
    int status;

    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), true, false, false));
    CHECK(begin_playback(&c, &peer, 10));
    CHECK(kill(c.pid, SIGTERM) == 0);
    CHECK(child_wait(&c, 20000, &status, true));
    drain_stdout(&c);
    CHECK(parse_record(c.out, &r));
    CHECK(r.records == 1 && r.last_is_final);
    CHECK(!r.stop && r.fault);
    fprintf(stderr, "ok: real CLI SIGTERM mid-stream -> abnormal, fault=true\n");
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

/* `STOP\nSTART\n` in ONE FIFO read, ONE run. The production reader only checks
 * g_running between buffered lines, and the legacy STOP sends no RTSP the
 * fixture could hold, so which branch the real binary takes is OBSERVATIONAL:
 * either the START ran after the freeze (record must be invalid) or the owner
 * stop dropped it (record intact). Both orderings are forced deterministically
 * in test_cli_media_receipt (real reader + FIFO + transport barrier); this case
 * asserts the invariant for whichever branch happened and reports it. It does
 * not retry and is not the coverage proof of either branch. */
static bool case_buffered_stop_start(const char *binary)
{
    static peer_t peer;
    static child_t c;
    record_t r;
    int status;

    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), true, false, false));
    CHECK(begin_playback(&c, &peer, 10));
    size_t started = err_count(&c, "[STATUS] started");
    CHECK(send_command(&c, "ACTION=STOP\nACTION=START\n"));
    CHECK(child_wait(&c, 20000, &status, true));
    drain_stdout(&c);
    CHECK(parse_record(&c.out[0], &r));
    bool executed = err_count(&c, "[STATUS] started") > started ||
                    err_contains(&c, "START failed");
    CHECK(r.records == 1 && r.last_is_final);
    if (executed) {
        CHECK(r.fault);                     /* post-freeze START invalidates */
    } else {
        CHECK(!r.fault && r.epoch == 1);
        CHECK(wait_receiver_settled(&peer, r.fresh_units));
        CHECK(r.fresh_bytes == peer_bytes(&peer));
    }
    fprintf(stderr, "ok: real CLI buffered STOP\\nSTART observed branch: %s "
            "-> %s\n", executed ? "START executed after freeze" :
            "START dropped by owner stop",
            executed ? "record invalid (fault=true)" : "record intact");
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

/* Fill the child's stdout FIFO from this test's own file description so that
 * the route line already fit but the final record (~200 bytes) cannot: free
 * space is left at exactly `room` bytes inside one page-sized slot. */
static bool fill_stdout_leaving(child_t *c, size_t room)
{
    char junk[512];
    char slot[4096];
    size_t total;

    memset(junk, 'x', sizeof(junk));
    CHECK(fill_pipe(c->fill_w, &total));
    /* One 4096-byte slot back (the pipe buffer granule on Linux and macOS, both
     * verified), then re-fill it to all but `room` bytes. */
    CHECK(read(c->stdout_r, slot, sizeof(slot)) == (ssize_t)sizeof(slot));
    for (size_t left = sizeof(slot) - room; left > 0;) {
        ssize_t n = write(c->fill_w, junk, left < sizeof(junk) ? left : sizeof(junk));
        CHECK(n > 0);
        left -= (size_t)n;
    }
    fprintf(stderr, "filled %zu bytes, then freed and refilled to leave %zu\n",
            total, room);
    return true;
}

/* Real full stdout at the terminal phase: the child is running, has already
 * printed its route line, and the pipe has less room than the record. The
 * actual child must finish without waiting for the reader and omit the line. */
static bool case_full_stdout(const char *binary)
{
    static peer_t peer;
    static child_t c;
    int status;
    uint64_t start;

    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), true, true, false));
    CHECK(wait_err(&c, "[STATUS] connected", 15000));
    drain_stdout(&c);                           /* the route line is consumed */
    CHECK(strstr(c.out, "[STATUS] route") != NULL);
    CHECK(send_command(&c, "ACTION=START\n"));
    CHECK(wait_err(&c, "[STATUS] started", 10000));
    start_feeder(&c);
    CHECK(wait_units(&peer, 10, 15000));
    CHECK(fill_stdout_leaving(&c, 100));        /* no reader from here on */
    start = now_ms();
    CHECK(send_command(&c, "ACTION=STOP\n"));
    CHECK(child_wait(&c, 10000, &status, false)); /* no reader: a blocked write hangs */
    fprintf(stderr, "child exited %llu ms after STOP with a full stdout\n",
            (unsigned long long)(now_ms() - start));
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    drain_stdout(&c);                           /* everything left is junk */
    if (strstr(c.out, "@MEDIA"))
        fprintf(stderr, "pipe held %zu bytes; record: %.230s\n", c.out_len,
                strstr(c.out, "@MEDIA"));
    CHECK(strstr(c.out, "@MEDIA") == NULL);
    fprintf(stderr, "ok: real CLI omits the record on a full stdout without blocking\n");
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

/* EXPERIMENT, not in the default run: a stdout that is already full BEFORE
 * the child starts. The route line is an ordinary blocking printf+fflush that
 * runs before any receipt code, so the child stops there: nonblocking is only
 * established at the terminal emit. Shows why a terminal-only fix cannot
 * promise the child never blocks on stdout. */
static bool case_early_full_stdout_blocks(const char *binary)
{
    static peer_t peer;
    static child_t c;
    int status;

    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), true, true, true));
    sleep_ms(3000);
    CHECK(waitpid(c.pid, &status, WNOHANG) == 0);        /* still alive */
    CHECK(!err_contains(&c, "[STATUS] connected"));     /* never got past it */
    CHECK(!err_contains(&c, "Binding to"));
    fprintf(stderr, "observed: child blocked in the route-line write with a "
            "full stdout (alive after 3 s, no connect attempted)\n");
    kill(c.pid, SIGKILL);
    waitpid(c.pid, &status, 0);
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

static void stop_feeder(child_t *c)
{
    atomic_store(&c->feeder_run, false);
    if (c->feeder_started) {
        pthread_join(c->feeder, NULL);
        c->feeder_started = false;
    }
}

/* Native only: the PCM input runs dry (the test stops its own feeder) until the
 * client announces a splice-pad recovery (`[STATUS] REANCHOR`), then resumes.
 * The audio loop then owes the wire whole chunks of pad silence with no PCM in
 * them. Those must be counted as IDLE, never fresh, while the receiver still
 * sees every one: fresh + idle == all datagrams it received. */
static bool case_native_splice_pad(const char *binary)
{
    static peer_t peer;
    static child_t c;
    record_t r;
    int status;

    CHECK(g_route->native);
    CHECK(peer_start(&peer));
    CHECK(child_start(&c, binary, peer_rtsp(&peer), true, false, false));
    CHECK(begin_playback(&c, &peer, 20));
    stop_feeder(&c);
    CHECK(wait_err(&c, "[STATUS] REANCHOR", 20000));
    unsigned after_gap = peer_units(&peer);
    start_feeder(&c);
    CHECK(wait_units(&peer, after_gap + 40, 20000));
    CHECK(send_command(&c, "ACTION=STOP\n"));
    CHECK(child_wait(&c, 20000, &status, true));
    drain_stdout(&c);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(parse_record(c.out, &r));
    CHECK(wait_receiver_settled(&peer, r.fresh_units + r.idle_units));
    CHECK(r.records == 1 && r.last_is_final && r.stop && !r.fault && !r.overflow);
    CHECK(r.epoch == 1 && r.backlog_units == 0);
    CHECK(r.idle_units > 0 && r.fresh_units > 0);
    CHECK(r.fresh_bytes <= peer_bytes(&peer));
    fprintf(stderr, "ok: native splice pad -> %u idle (pad silence) + %u fresh "
            "== %u datagrams at the receiver\n", r.idle_units, r.fresh_units,
            peer_units(&peer));
    child_cleanup(&c);
    peer_stop(&peer);
    return true;
}

typedef bool (*case_fn)(const char *);

/* usage: driver <binary> [case] [route]; no case/route runs every one. */
int main(int argc, char **argv)
{
    static const struct { const char *name; case_fn fn; bool native_only; } cases[] = {
        { "positive", case_positive, false },
        { "default-off", case_default_off, false },
        { "stop-without-start", case_stop_without_start, false },
        { "sigterm", case_sigterm, false },
        { "buffered-stop-start", case_buffered_stop_start, false },
        { "full-stdout", case_full_stdout, false },
        { "native-splice-pad", case_native_splice_pad, true },
    };

    alarm(600);     /* a regression fails instead of hanging CI */
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2 || argc > 4)
        return 2;
    if (argc >= 3 && !strcmp(argv[2], "early-full-stdout-blocks")) {
        bool ok = case_early_full_stdout_blocks(argv[1]);

        reap_live();
        return ok ? 0 : 1;
    }
    for (size_t r = 0; r < sizeof(routes) / sizeof(routes[0]); r++) {
        if (argc == 4 && strcmp(argv[3], routes[r].name) != 0)
            continue;
        g_route = &routes[r];
        fprintf(stderr, "== route %s ==\n", routes[r].name);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (argc >= 3 && strcmp(argv[2], "all") != 0 &&
                strcmp(argv[2], cases[i].name) != 0)
                continue;
            if (cases[i].native_only && !g_route->native)
                continue;
            bool ok = cases[i].fn(argv[1]);

            reap_live();
            if (!ok) {
                fprintf(stderr, "FAILED case: %s (route %s)\n", cases[i].name,
                        routes[r].name);
                return 1;
            }
        }
    }
    return 0;
}
