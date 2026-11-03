/* Actual RTSP implementation with deterministic response failures.
 * AF_UNIX peers only; no network connection, credentials, or receiver. */
#include "cross_net.h"
#include "cross_log.h"
#include "rtsp_response_fixture.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int reads, mode;
int scripted_response(int fd, char *line, int maxlen, int timeout, bool polling)
{
    (void)fd; (void)timeout; (void)polling;
    reads++;
    line[0] = 0;
    if (mode < 0) { errno = EINTR; return -1; }
    if (mode == 0) return 0;
    if (reads % 2 == 0) return 0; /* end of headers */
    return snprintf(line, (size_t)maxlen, "RTSP/1.0 %s",
                    mode == 200 ? "200 OK" : "401 Unauthorized");
}

log_level raop_loglevel = lSILENCE;
log_level util_loglevel = lSILENCE;

static int check_case(int response)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 2;
    reads = 0;
    mode = response;
    struct rtspcl_s *client = rtspcl_create("unit-test");
    fixture_attach(client, pair[0]);
    bool announced = rtspcl_announce_sdp(client, "v=0\r\n", NULL);
    int fd_after_failure = fixture_fd(client);
    rtspcl_disconnect(client);
    rtspcl_destroy(client);
    char requests[4096];
    ssize_t received = recv(pair[1], requests, sizeof(requests) - 1, 0);
    close(pair[1]);
    if (received < 0) return 2;
    requests[received] = 0;
    bool failed_read = response <= 0;
    bool teardown = strstr(requests, "TEARDOWN") != NULL;
    if (announced != (response == 200) ||
        (failed_read && (reads != 1 || fd_after_failure != -1 || teardown)) ||
        (!failed_read && (fd_after_failure < 0 || !teardown))) {
        fprintf(stderr, "FAIL: mode=%d announced=%d reads=%d fd=%d teardown=%d\n",
                response, announced, reads, fd_after_failure, teardown);
        return 1;
    }
    printf("PASS: response mode %d\n", response);
    return 0;
}
static int check_optional_timeout(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 2;
    reads = 0; mode = 0;
    struct rtspcl_s *client = rtspcl_create("unit-test");
    fixture_attach(client, pair[0]);
    bool accepted = fixture_optional_request(client);
    bool unchanged = accepted && fixture_fd(client) == pair[0] && reads == 1;
    rtspcl_destroy(client);
    close(pair[1]);
    if (!unchanged) return 1;
    puts("PASS: optional response policy unchanged");
    return 0;
}

int main(void)
{
    int failures = check_case(0) + check_case(-1) + check_case(200) + check_case(401) + check_optional_timeout();
    return failures ? 1 : 0;
}
