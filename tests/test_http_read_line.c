/* Exercise the verbatim production function with deterministic syscall seams.
 * No sockets, signals, threads, or receiver processes are created. */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <poll.h>

static int poll_result, poll_error, poll_calls, recv_calls;
static const char *input;
static int recv_error;
int http_test_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    (void)fds; (void)count; (void)timeout;
    poll_calls++;
    errno = poll_error;
    return poll_result;
}
ssize_t http_test_recv(int fd, void *buffer, size_t size, int flags)
{
    (void)fd; (void)size; (void)flags;
    recv_calls++;
    if (recv_error) { errno = recv_error; return -1; }
    if (!*input) return 0;
    *(char *)buffer = *input++;
    return 1;
}
#include "cross_net.h"
#include "cross_log.h"
log_level util_loglevel = lSILENCE;

static int run_case(const char *name, int ready, int error, const char *bytes,
                    int read_error, bool polling, int expected, int reads)
{
    char line[64];
    poll_result = ready; poll_error = error; input = bytes;
    recv_error = read_error; poll_calls = recv_calls = 0;
    int result = http_read_line(7, line, sizeof(line), 10000, polling);
    if (result != expected || recv_calls != reads ||
        (!polling && poll_calls != 0)) {
        fprintf(stderr, "FAIL %s: result=%d recv=%d poll=%d\n",
                name, result, recv_calls, poll_calls);
        return 1;
    }
    printf("PASS %s\n", name);
    return 0;
}
int main(void)
{
    int failures = 0;
    failures += run_case("EINTR never receives", -1, EINTR, "", 0, true, -1, 0);
    failures += run_case("EIO never receives", -1, EIO, "", 0, true, -1, 0);
    failures += run_case("timeout never receives", 0, 0, "", 0, true, 0, 0);
    failures += run_case("ready CRLF", 1, 0, "OK\r\n", 0, true, 2, 4);
    failures += run_case("ready EOF", 1, 0, "", 0, true, 0, 1);
    failures += run_case("ready EAGAIN", 1, 0, "", EAGAIN, true, 0, 1);
    failures += run_case("nonpolling", -1, EINTR, "OK\n", 0, false, 2, 3);
    return failures ? 1 : 0;
}
