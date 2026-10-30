/*
 * A failed raopcl_connect() must only join RTP threads that were created, and
 * must still reap the ones that were. Joining a never-created (zeroed)
 * pthread_t crashes glibc, so the join/create calls of the real raop_client.c
 * are hooked (see raop_thread_hooks.h) and every join is checked. The peer is
 * a loopback RTSP listener scripted per scenario: no real device, no pairing.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cross_log.h"
#include "raop_client.h"

static log_level test_log_level = lSILENCE;
log_level *loglevel = &test_log_level;
log_level util_loglevel = lSILENCE;
log_level raop_loglevel = lSILENCE;

#define CHECK(condition) do {                                                \
    if (!(condition)) {                                                      \
        fprintf(stderr, "%s:%d: check failed: %s\n",                         \
                __FILE__, __LINE__, #condition);                             \
        return false;                                                        \
    }                                                                        \
} while (0)

#define MAX_THREADS 16

static struct {
    pthread_t thread[MAX_THREADS];
    bool joined[MAX_THREADS];
    int created;
    int joins;
    int bad_joins;
    int attempts;
    int fail_at;
    bool exit_immediately;
} hook;

static void *exit_thread(void *arg)
{
    (void)arg;
    return NULL;
}

int raop_test_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                             void *(*start)(void *), void *arg)
{
    if (++hook.attempts == hook.fail_at)
        return EAGAIN;
    int rc = pthread_create(thread, attr,
                            hook.exit_immediately ? exit_thread : start, arg);

    if (rc == 0 && hook.created < MAX_THREADS) {
        hook.thread[hook.created] = *thread;
        hook.joined[hook.created++] = false;
    }
    return rc;
}

/* Only a thread this test saw created, and not yet joined, is really joined. */
int raop_test_pthread_join(pthread_t thread, void **retval)
{
    hook.joins++;
    for (int i = 0; i < hook.created; i++) {
        if (!hook.joined[i] && pthread_equal(hook.thread[i], thread)) {
            hook.joined[i] = true;
            return pthread_join(thread, retval);
        }
    }
    hook.bad_joins++;
    return ESRCH;
}

typedef enum {
    PEER_REFUSE,        /* nothing listens on the port */
    PEER_ANNOUNCE_401,  /* ANNOUNCE answered 401 */
    PEER_CLOSE,         /* socket closed on the first request */
    PEER_SETUP_500,     /* ANNOUNCE ok, SETUP answered 500 */
    PEER_OK,            /* SETUP and RECORD succeed */
} peer_mode_t;

typedef struct {
    int listen_fd;
    peer_mode_t mode;
    uint16_t port;
    atomic_bool stop;
    pthread_t thread;
    atomic_int target_requests;
} peer_t;

static void reply(int fd, const char *status, int cseq)
{
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
                     "RTSP/1.0 %s\r\nCSeq: %d\r\n"
                     "Session: loopback\r\n"
                     "Transport: RTP/AVP/UDP;server_port=6000;control_port=6001;"
                     "timing_port=6002\r\n\r\n", status, cseq);

    (void)!write(fd, buf, (size_t)n);
}

static int request_cseq(const char *request)
{
    const char *cseq = strstr(request, "CSeq:");

    return cseq ? atoi(cseq + 5) : 0;
}

static void serve_connection(peer_t *peer, int fd)
{
    char buf[4096];
    /* Read whole RTSP messages, not arbitrary TCP chunks. */
    for (;;) {
        size_t used = 0;
        do {
            if (used + 1 >= sizeof(buf) || read(fd, buf + used, 1) != 1)
                goto done;
            buf[++used] = '\0';
        } while (!strstr(buf, "\r\n\r\n"));
        const char *length = strstr(buf, "Content-Length:");
        int body = length ? atoi(length + strlen("Content-Length:")) : 0;
        for (int i = 0; i < body; i++) {
            char byte;
            if (read(fd, &byte, 1) != 1)
                goto done;
        }
        if (peer->mode == PEER_CLOSE) {
            atomic_fetch_add(&peer->target_requests, 1);
            break;
        }
        if (!strncmp(buf, "ANNOUNCE", 8)) {
            atomic_fetch_add(&peer->target_requests, 1);
            reply(fd, peer->mode == PEER_ANNOUNCE_401 ?
                  "401 Unauthorized" : "200 OK", request_cseq(buf));
        }
        else if (!strncmp(buf, "SETUP", 5))
            reply(fd, peer->mode == PEER_SETUP_500 ?
                  "500 Internal Server Error" : "200 OK", request_cseq(buf));
        else
            reply(fd, "200 OK", request_cseq(buf));
    }
done:
    close(fd);
}

/* Accept connections one at a time until peer_stop() pokes the listener. */
static void *peer_serve(void *arg)
{
    peer_t *peer = arg;

    while (!atomic_load(&peer->stop)) {
        int fd = accept(peer->listen_fd, NULL, NULL);

        if (fd < 0)
            break;
        if (atomic_load(&peer->stop)) {
            close(fd);
            break;
        }
        serve_connection(peer, fd);
    }
    return NULL;
}

static bool peer_start(peer_t *peer, peer_mode_t mode, uint16_t *port)
{
    struct sockaddr_in addr = { .sin_family = AF_INET };
    socklen_t len = sizeof(addr);

    peer->mode = mode;
    atomic_init(&peer->target_requests, 0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    peer->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(peer->listen_fd >= 0);
    CHECK(bind(peer->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CHECK(listen(peer->listen_fd, 1) == 0);
    CHECK(getsockname(peer->listen_fd, (struct sockaddr *)&addr, &len) == 0);
    *port = peer->port = ntohs(addr.sin_port);
    if (mode == PEER_REFUSE) {
        close(peer->listen_fd);
        peer->listen_fd = -1;
        return true;
    }
    return pthread_create(&peer->thread, NULL, peer_serve, peer) == 0;
}

static void peer_stop(peer_t *peer)
{
    if (peer->listen_fd < 0)
        return;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    int poke = socket(AF_INET, SOCK_STREAM, 0);

    /* wake the blocked accept() with a throwaway connection */
    atomic_store(&peer->stop, true);
    addr.sin_port = htons(peer->port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (poke >= 0) {
        (void)connect(poke, (struct sockaddr *)&addr, sizeof(addr));
        close(poke);
    }
    pthread_join(peer->thread, NULL);
    close(peer->listen_fd);
}

static bool run_scenario(peer_mode_t mode, const char *name, int fail_at,
                         bool exit_immediately)
{
    struct in_addr loopback = { .s_addr = htonl(INADDR_LOOPBACK) };
    peer_t peer = { .listen_fd = -1, .stop = false };
    uint16_t port = 0;
    struct raopcl_s *client;

    memset(&hook, 0, sizeof(hook));
    CHECK(peer_start(&peer, mode, &port));
    hook.fail_at = fail_at;
    hook.exit_immediately = exit_immediately;

    client = raopcl_create(loopback, 0, 0, NULL, NULL, RAOP_PCM, 352, 44100,
                           RAOP_CLEAR, false, NULL, NULL, "0,1", "0,1,2",
                           44100, 16, 2, -20.0f);
    CHECK(client != NULL);

    /* Repair forces cleanup again before reconnecting. */
    bool success = mode == PEER_OK && !fail_at;
    CHECK(raopcl_connect(client, loopback, port, false) == success);
    CHECK(hook.bad_joins == 0);
    hook.attempts = 0;
    CHECK(raopcl_repair(client, false) == success);
    CHECK(hook.bad_joins == 0);
    raopcl_disconnect(client);
    raopcl_disconnect(client);
    raopcl_destroy(client);

    for (int i = 0; i < hook.created; i++)
        CHECK(hook.joined[i]);
    /* The pinned TCP helper may defer refusal until ANNOUNCE. */
    int expected = fail_at == 1 ? 0 :
                   mode == PEER_OK && !fail_at ? 4 : 2;
    CHECK(hook.created == expected || (mode == PEER_REFUSE && hook.created == 0));
    CHECK(hook.joins == hook.created);
    CHECK(hook.bad_joins == 0);
    peer_stop(&peer);
    if (mode != PEER_REFUSE && !fail_at)
        CHECK(atomic_load(&peer.target_requests) == 2);
    fprintf(stderr, "ok: %s (rtp threads %d, joins %d)\n", name,
            hook.created, hook.joins);
    return true;
}

extern char **environ;

/* Spawn the actual CLI safely while the loopback peer thread is active. */
static bool run_cli(const char *binary, peer_mode_t mode, const char *protocol)
{
    peer_t peer = { .listen_fd = -1, .stop = false };
    uint16_t port;
    char directory[] = "/tmp/cliairplay-failure-XXXXXX";
    char pipe[128], port_text[16], output[8192];
    pid_t pid;
    int status;
    FILE *capture = tmpfile();
    posix_spawn_file_actions_t actions;

    CHECK(capture != NULL);
    CHECK(mkdtemp(directory) != NULL);
    snprintf(pipe, sizeof(pipe), "%s/pipe", directory);
    CHECK(peer_start(&peer, mode, &port));
    snprintf(port_text, sizeof(port_text), "%u", port);
    char *args[] = { (char *)binary, "--protocol", (char *)protocol,
                     "--port", port_text, "--cmdpipe", pipe, "--et", "0",
                     "127.0.0.1", NULL };
    CHECK(posix_spawn_file_actions_init(&actions) == 0);
    CHECK(posix_spawn_file_actions_adddup2(&actions, fileno(capture), 1) == 0);
    CHECK(posix_spawn_file_actions_adddup2(&actions, fileno(capture), 2) == 0);
    CHECK(posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", 0, 0) == 0);
    CHECK(posix_spawn(&pid, binary, &actions, NULL, args, environ) == 0);
    posix_spawn_file_actions_destroy(&actions);
    CHECK(waitpid(pid, &status, 0) == pid);
    rewind(capture);
    output[fread(output, 1, sizeof(output) - 1, capture)] = '\0';
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 1)
        fprintf(stderr, "CLI %s peer=%d wait status=%d\n%s", protocol, mode,
                status, output);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);
    CHECK(strstr(output, "[STATUS] error code=connect_failed") != NULL);
    CHECK(strstr(output, !strcmp(protocol, "raop") ?
                 "RAOP connect failed" : "RAOP-compatible connect failed") != NULL);
    CHECK(strstr(output, "Sanitizer") == NULL);
    CHECK(strstr(output, "runtime error:") == NULL);
    CHECK(access(pipe, F_OK) == -1 && errno == ENOENT);
    CHECK(rmdir(directory) == 0);
    fclose(capture);
    peer_stop(&peer);
    CHECK(mode == PEER_REFUSE || atomic_load(&peer.target_requests) == 1);
    fprintf(stderr, "ok: CLI %s peer=%d exits 1 and removes FIFO\n", protocol, mode);
    return true;
}

int main(int argc, char **argv)
{
    /* A regression must fail rather than leave CI blocked in accept/join. */
    alarm(90);
    signal(SIGPIPE, SIG_IGN);
    /* Focused subprocess runs let the external RED gate test every failure. */
    if (argc == 3 && !strcmp(argv[1], "--library-case")) {
        int mode = atoi(argv[2]);
        return mode >= PEER_REFUSE && mode <= PEER_CLOSE &&
               run_scenario((peer_mode_t)mode, argv[2], 0, false) ? 0 : 1;
    }
    if (argc == 5 && !strcmp(argv[1], "--cli-case")) {
        int mode = atoi(argv[4]);
        return mode >= PEER_REFUSE && mode <= PEER_CLOSE &&
               run_cli(argv[2], (peer_mode_t)mode, argv[3]) ? 0 : 1;
    }
    if (argc > 2)
        return 1;
    if (!run_scenario(PEER_REFUSE, "connection refused", 0, false) ||
        !run_scenario(PEER_ANNOUNCE_401, "ANNOUNCE 401", 0, false) ||
        !run_scenario(PEER_CLOSE, "peer closes early", 0, false) ||
        !run_scenario(PEER_SETUP_500, "SETUP 500", 0, false) ||
        !run_scenario(PEER_OK, "timing pthread_create fails", 1, false) ||
        !run_scenario(PEER_OK, "control pthread_create fails", 2, false) ||
        !run_scenario(PEER_OK, "successful connect/repair/disconnect", 0, false) ||
        !run_scenario(PEER_OK, "reap already-exited threads", 0, true))
        return 1;
    if (argc == 2) {
        for (peer_mode_t mode = PEER_REFUSE; mode <= PEER_CLOSE; mode++) {
            if (!run_cli(argv[1], mode, "raop") ||
                !run_cli(argv[1], mode, "airplay2-compat"))
                return 1;
        }
    }
    return 0;
}
