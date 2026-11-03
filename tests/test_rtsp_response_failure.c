/* Compile actual RTSP response code; deterministic bytes/time, AF_UNIX writes. */
#include "cross_net.h"
#include "cross_log.h"
#include "ap2_io.h"
#include "rtsp_response_fixture.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *wire;
static size_t offset;
static uint64_t now, step;
static unsigned reads;
static unsigned allocation_fail_at, allocations;
void *fixture_malloc(size_t size)
{
    if (++allocations == allocation_fail_at) return NULL;
    return malloc(size);
}
char *fixture_strdup(const char *text)
{
    if (++allocations == allocation_fail_at) return NULL;
    return strdup(text);
}
ssize_t scripted_read(int fd, uint8_t *buf, size_t len, uint64_t deadline)
{
    (void)fd;
    reads++;
    now += step;
    if (now >= deadline || !wire[offset]) { errno = ETIMEDOUT; return -1; }
    if (!len) return 0;
    *buf = (uint8_t)wire[offset++];
    return 1;
}
uint64_t scripted_time(void) { return now; }
int old_line(int fd, char *line, int maxlen, int timeout, bool polling)
{
    (void)polling;
    int used = 0;
    while (used < maxlen - 1) {
        uint8_t byte;
        if (scripted_read(fd, &byte, 1, now + (uint64_t)timeout) <= 0) return 0;
        if (byte == '\n') { line[used] = 0; return used; }
        if (byte != '\r') line[used++] = (char)byte;
    }
    line[used] = 0;
    return used;
}
ssize_t old_recv(int fd, void *buf, size_t len, int flags)
{
    (void)flags;
    return scripted_read(fd, buf, len, UINT64_MAX);
}

log_level raop_loglevel = lSILENCE;
log_level util_loglevel = lSILENCE;

static int check(const char *name, const char *response, uint64_t tick, bool expected)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 2;
    wire = response; offset = 0; now = 0; step = tick; reads = 0;
    allocations = 0;
    struct rtspcl_s *client = rtspcl_create("unit-test");
    fixture_attach(client, pair[0]);
    key_data_t headers[64] = {0};
    char *body = NULL;
    int length = 0;
    bool ok = fixture_request(client, headers, &body, &length);
    bool complete_error = !strcmp(name, "error status");
    bool clean_failure = ok || ((complete_error ? fixture_fd(client) >= 0 : fixture_fd(client) == -1)
                               && body == NULL && length == 0);
    const char *payload = strstr(response, "\r\n\r\n");
    bool correct_body = !ok || (payload && length == (int)strlen(payload + 4) &&
                        (!length || (body && !memcmp(body, payload + 4, (size_t)length))));
    /* Avoid another exchange; this fixture tests exactly one response. */
    fixture_close(client);
    rtspcl_destroy(client);
    close(pair[1]);
    kd_free(headers);
    free(body);
    if (ok != expected || !clean_failure || !correct_body) {
        fprintf(stderr, "FAIL %s: ok=%d clean_failure=%d bytes=%zu time=%llu\n",
                name, ok, clean_failure, offset, (unsigned long long)now);
        return 1;
    }
    printf("PASS %s\n", name);
    return 0;
}
static int optional_timeout(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 2;
    wire = ""; offset = 0; now = 0; step = 1;
    struct rtspcl_s *client = rtspcl_create("unit-test");
    fixture_attach(client, pair[0]);
    bool unchanged = fixture_optional(client) && fixture_fd(client) == pair[0];
    fixture_close(client);
    rtspcl_destroy(client);
    close(pair[1]);
    if (!unchanged) return 1;
    puts("PASS optional timeout policy unchanged");
    return 0;
}

static int reusable_error_response(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 2;
    wire = "RTSP/1.0 501 Not Implemented\r\nContent-Length: 3\r\n\r\nabc"
           "RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    offset = 0; now = 0; step = 1;
    struct rtspcl_s *client = rtspcl_create("unit-test");
    fixture_attach(client, pair[0]);
    bool rejected = !rtspcl_options(client, NULL);
    bool retained = fixture_fd(client) == pair[0];
    bool next_ok = rtspcl_options(client, NULL);
    bool drained = offset == strlen(wire);
    fixture_close(client);
    rtspcl_destroy(client);
    close(pair[1]);
    if (!rejected || !retained || !next_ok || !drained) {
        fprintf(stderr, "FAIL reusable501: rejected=%d retained=%d next=%d drained=%d\n",
                rejected, retained, next_ok, drained);
        return 1;
    }
    puts("PASS complete501 body drained and next response succeeds");
    return 0;
}

static int response_bounds(void)
{
    char headers[8192] = "RTSP/1.0 200 OK\r\n";
    for (int i = 0; i < 63; i++) strcat(headers, "X: value\r\n");
    strcat(headers, "\r\n");
    int errors = check("63 headers", headers, 0, true);
    strcpy(headers + strlen(headers) - 2, "X: extra\r\n\r\n");
    errors += check("64 headers rejected", headers, 0, false);

    strcpy(headers, "RTSP/1.0 200 OK\r\nX:");
    size_t prefix = strlen(headers);
    memset(headers + prefix, 'a', 2045);
    strcpy(headers + prefix + 2045, "\r\n\r\n");
    errors += check("2047-byte line", headers, 0, true);
    strcpy(headers + prefix + 2045, "a\r\n\r\n");
    errors += check("2048-byte line rejected", headers, 0, false);

    char *maximum = malloc(1048576 + 128);
    if (!maximum) return errors + 1;
    strcpy(maximum, "RTSP/1.0 200 OK\r\nContent-Length: 1048576\r\n\r\n");
    prefix = strlen(maximum);
    memset(maximum + prefix, 'a', 1048576);
    maximum[prefix + 1048576] = 0;
    errors += check("1MiB body", maximum, 0, true);
    free(maximum);
    return errors;
}

int main(void)
{
    (void)scripted_time; /* Used by the repaired implementation. */
    int errors = 0;
    errors += check("complete body", "RTSP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc", 1, true);
    errors += check("truncated body", "RTSP/1.0 200 OK\r\nContent-Length: 3\r\n\r\na", 1, false);
    errors += check("missing header terminator", "RTSP/1.0 200 OK\r\nCSeq: 1\r\n", 1, false);
    errors += check("trickle absolute deadline", "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n", 500, false);
    errors += check("oversized body", "RTSP/1.0 200 OK\r\nContent-Length: 1048577\r\n\r\n", 1, false);
    errors += check("negative body", "RTSP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n", 1, false);
    errors += check("duplicate length", "RTSP/1.0 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nx", 1, false);
    errors += check("empty body", "RTSP/1.0 200 OK\r\n\r\n", 1, true);
    errors += check("error status", "RTSP/1.0 401 Unauthorized\r\n\r\n", 1, false);
    errors += check("partial status", "RTSP/1.0 200", 1, false);
    errors += check("invalid length suffix", "RTSP/1.0 200 OK\r\nContent-Length: 1junk\r\n\r\nx", 1, false);
    errors += check("folded header", "RTSP/1.0 200 OK\r\nX: value\r\n continuation\r\n\r\n", 1, false);
    errors += optional_timeout();
    errors += check("wrong protocol", "X 200 OK\r\n\r\n", 1, false);
    errors += check("bare LF", "RTSP/1.0 200 OK\n\n", 1, false);
    errors += check("embedded CR", "RTSP/1.0 2\r00 OK\r\n\r\n", 1, false);
    errors += check("space before colon", "RTSP/1.0 200 OK\r\nContent-Length : 1\r\n\r\nx", 1, false);
    for (allocation_fail_at = 1; allocation_fail_at <= 3; allocation_fail_at++)
        errors += check("allocation failure", "RTSP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc", 1, false);
    allocation_fail_at = 0;
    errors += reusable_error_response();
    errors += response_bounds();
    return errors ? 1 : 0;
}
