/* Collector state machine, closed record format and terminal emitter, against
 * real pipes. media_receipt.c is compiled with its fcntl/fflush/write seams
 * routed through the hooks below; every hook defaults to the real syscall and
 * the failure modes are injected only where a real kernel cannot be forced. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "media_receipt.h"

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

/* ---- syscall seams used by media_receipt.c ---- */
enum write_mode { WRITE_REAL, WRITE_EINTR, WRITE_PARTIAL, WRITE_EAGAIN };
static enum write_mode write_mode;
static unsigned write_calls, fflush_calls, fcntl_set_calls;
static bool fail_getfl, fail_setfl;
static bool nonblocking_at_flush, nonblocking_at_write;
static unsigned order_seq, setfl_seq, flush_seq, write_seq;

int mr_test_fcntl(int fd, int cmd, ...)
{
    if (cmd == F_GETFL) {
        if (fail_getfl) { errno = EBADF; return -1; }
        return fcntl(fd, F_GETFL);
    }
    CHECK(cmd == F_SETFL);
    va_list args;
    va_start(args, cmd);
    int flags = va_arg(args, int);
    va_end(args);
    fcntl_set_calls++;
    setfl_seq = ++order_seq;
    if (fail_setfl) { errno = EBADF; return -1; }
    return fcntl(fd, F_SETFL, flags);
}

int mr_test_fflush(FILE *f)
{
    fflush_calls++;
    flush_seq = ++order_seq;
    nonblocking_at_flush = (fcntl(fileno(f), F_GETFL) & O_NONBLOCK) != 0;
    return fflush(f);
}

ssize_t mr_test_write(int fd, const void *buf, size_t len)
{
    write_calls++;
    write_seq = ++order_seq;
    nonblocking_at_write = (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0;
    switch (write_mode) {
    case WRITE_EINTR: errno = EINTR; return -1;
    case WRITE_EAGAIN: errno = EAGAIN; return -1;
    case WRITE_PARTIAL: return write(fd, buf, len - 1);
    default: return write(fd, buf, len);
    }
}

static void reset_seams(void)
{
    write_mode = WRITE_REAL;
    write_calls = fflush_calls = fcntl_set_calls = 0;
    fail_getfl = fail_setfl = false;
    nonblocking_at_flush = nonblocking_at_write = false;
    order_seq = setfl_seq = flush_seq = write_seq = 0;
}

static const struct sockaddr_in *target(uint16_t port)
{
    static struct sockaddr_in addr;
    addr = (struct sockaddr_in){ .sin_family = AF_INET,
                                 .sin_port = htons(port) };
    inet_pton(AF_INET, "192.0.2.10", &addr.sin_addr);
    return &addr;
}

static media_receipt_t active(mr_route_t route)
{
    media_receipt_t mr;
    mr_init(&mr, true);
    mr_configure(&mr, route, 6001, 5);
    mr_applied(&mr, 1);
    return mr;
}

static void test_default_off(void)
{
    media_receipt_t mr;
    mr_init(&mr, false);
    mr_configure(&mr, MR_ROUTE_RAOP, 6001, 1);
    mr_applied(&mr, 1);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6001, 1);
    mr_failure(&mr);
    mr_freeze_for_stop(&mr, 9);
    mr_note_command(&mr);
    CHECK(!mr.configured && mr.fresh_units == 0 && !mr.fault);
    CHECK(atomic_load(&mr.state) == MR_WAIT);
    int fds[2];
    CHECK(pipe(fds) == 0);
    FILE *out = fdopen(fds[1], "w");
    reset_seams();
    CHECK(!mr_emit(&mr, true, out));
    CHECK(write_calls == 0 && fflush_calls == 0 && fcntl_set_calls == 0);
    CHECK((fcntl(fds[1], F_GETFL) & O_NONBLOCK) == 0); /* ordinary default */
    fclose(out);
    close(fds[0]);
    puts("receipt: disabled collector is inert, no emission, ordinary blocking mode");
}

static void test_counting(void)
{
    media_receipt_t mr = active(MR_ROUTE_RAOP);
    CHECK(atomic_load(&mr.state) == MR_ACTIVE && mr.applied_epoch == 1);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6001, 1);
    mr_sent(&mr, MR_ORIGIN_FRESH, 100, target(6001), 6001, 1);
    mr_sent(&mr, MR_ORIGIN_IDLE, 90, target(6001), 6001, 0);
    mr_sent(&mr, MR_ORIGIN_BACKLOG, 90, target(6001), 6001, 0);
    CHECK(mr.fresh_units == 2 && mr.fresh_bytes == 228);
    CHECK(mr.idle_units == 1 && mr.backlog_units == 1 && !mr.fault);
    mr_freeze_for_stop(&mr, 5);
    CHECK(atomic_load(&mr.state) == MR_FROZEN && mr.stop_frozen && !mr.fault);
    /* The interval is closed: late writes and failures never enter it. */
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6001, 1);
    mr_failure(&mr);
    CHECK(mr.fresh_units == 2 && !mr.fault);
    puts("receipt: fresh/idle/backlog accounting and freeze");
}

static void test_faults(void)
{
    media_receipt_t mr;

    /* Paired negative baseline: a select error followed by a successful send
     * is a fault, and the naive "count every sent" baseline would have
     * reported fresh_units == 1. */
    mr = active(MR_ROUTE_RAOP);
    mr_raop_outcome_cb(&mr, RAOP_MEDIA_OUTCOME_SELECT_ERROR, RAOP_MEDIA_FRESH,
                       0, NULL, 6001);
    mr_raop_outcome_cb(&mr, RAOP_MEDIA_OUTCOME_SENT, RAOP_MEDIA_FRESH, 128,
                       target(6001), 6001);
    CHECK(mr.fault && mr.fresh_units == 1); /* sticky fault, success counted */

    static const raop_media_outcome_t failures[] = {
        RAOP_MEDIA_OUTCOME_NOT_READY, RAOP_MEDIA_OUTCOME_SELECT_ERROR,
        RAOP_MEDIA_OUTCOME_SEND_ERROR, RAOP_MEDIA_OUTCOME_UNAVAILABLE,
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        mr = active(MR_ROUTE_RAOP);
        mr_raop_outcome_cb(&mr, failures[i], RAOP_MEDIA_FRESH, 0, NULL, 6001);
        CHECK(mr.fault && mr.fresh_units == 0);
        /* Before the applied transition a failure is not part of the epoch. */
        mr_init(&mr, true);
        mr_configure(&mr, MR_ROUTE_RAOP, 6001, 5);
        mr_raop_outcome_cb(&mr, failures[i], RAOP_MEDIA_FRESH, 0, NULL, 6001);
        CHECK(!mr.fault);
    }

    mr = active(MR_ROUTE_UDP);
    mr_sent(&mr, MR_ORIGIN_UNKNOWN, 128, target(6001), 6001, 1);
    CHECK(mr.fault && mr.fresh_units == 0);

    mr = active(MR_ROUTE_UDP);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6001, 2); /* stale epoch */
    CHECK(mr.fault && mr.fresh_units == 0);

    mr = active(MR_ROUTE_UDP);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6002), 6001, 1); /* port != setup */
    CHECK(mr.fault && mr.fresh_units == 0);
    mr = active(MR_ROUTE_UDP);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6002, 1); /* producer port */
    CHECK(mr.fault && mr.fresh_units == 0);

    mr = active(MR_ROUTE_UDP);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6001, 1);
    struct sockaddr_in other = *target(6001);
    other.sin_addr.s_addr = htonl(ntohl(other.sin_addr.s_addr) + 1);
    mr_sent(&mr, MR_ORIGIN_IDLE, 128, &other, 6001, 0); /* second destination */
    CHECK(mr.fault);

    mr = active(MR_ROUTE_UDP);
    struct sockaddr_in v6family = *target(6001);
    v6family.sin_family = AF_INET6;
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, &v6family, 6001, 1);
    CHECK(mr.fault && mr.fresh_units == 0);
    mr = active(MR_ROUTE_UDP);
    mr_sent(&mr, MR_ORIGIN_FRESH, 0, target(6001), 6001, 1);
    CHECK(mr.fault);
    mr = active(MR_ROUTE_UDP);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, NULL, 6001, 1);
    CHECK(mr.fault);

    /* Fresh before any applied epoch is unexpected; silence is ordinary. */
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_UDP, 6001, 5);
    mr_sent(&mr, MR_ORIGIN_IDLE, 128, target(6001), 6001, 0);
    CHECK(!mr.fault && mr.idle_units == 0);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6001, 0);
    CHECK(mr.fault);

    /* Second START (applied) and a wrong first epoch are incomplete. */
    mr = active(MR_ROUTE_UDP);
    mr_applied(&mr, 2);
    CHECK(mr.fault && mr.applied_epoch == 1 && mr.applied_count == 2);
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_UDP, 6001, 5);
    mr_applied(&mr, 2);
    CHECK(mr.fault && atomic_load(&mr.state) == MR_WAIT && mr.applied_epoch == 0);

    /* Unsupported/unknown route, absent port, no generation: no coverage. */
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_BUFFERED, 6001, 5);
    CHECK(mr.fault);
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_UNKNOWN, 6001, 5);
    CHECK(mr.fault);
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_RAOP, 0, 5);
    CHECK(mr.fault);
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_RAOP, 6001, 0);
    CHECK(mr.fault);

    /* Saturation never wraps. */
    mr = active(MR_ROUTE_UDP);
    mr.fresh_units = UINT32_MAX - 1;
    mr.fresh_bytes = UINT32_MAX - 100;
    mr_sent(&mr, MR_ORIGIN_FRESH, 90, target(6001), 6001, 1);
    CHECK(mr.fresh_units == UINT32_MAX - 0 && !mr.overflow);
    mr_sent(&mr, MR_ORIGIN_FRESH, 90, target(6001), 6001, 1);
    CHECK(mr.fresh_units == UINT32_MAX && mr.fresh_bytes == UINT32_MAX && mr.overflow);
    puts("receipt: select error/nonready/error/unknown/endpoint/epoch/route/overflow faults");
}

static void test_lifecycle_invalidation(void)
{
    media_receipt_t mr = active(MR_ROUTE_UDP);
    mr_note_command(&mr); /* before the freeze a command is ordinary */
    CHECK(!atomic_load(&mr.terminal_invalid));
    mr_freeze_for_stop(&mr, 5);
    CHECK(!atomic_load(&mr.terminal_invalid));
    mr_note_command(&mr); /* buffered post-freeze START/FLUSH/... */
    CHECK(atomic_load(&mr.terminal_invalid));

    mr = active(MR_ROUTE_UDP);
    mr_freeze_for_stop(&mr, 5);
    mr_applied(&mr, 2); /* a post-freeze START that succeeds */
    CHECK(atomic_load(&mr.terminal_invalid) && mr.applied_count == 1);

    mr = active(MR_ROUTE_UDP);
    mr_freeze_for_stop(&mr, 5);
    mr_freeze_for_stop(&mr, 5); /* unexpected second STOP */
    CHECK(atomic_load(&mr.terminal_invalid));

    /* Registration changed before the freeze: fault. After: invalid. */
    mr = active(MR_ROUTE_UDP);
    mr_freeze_for_stop(&mr, 6);
    CHECK(mr.fault);
    mr = active(MR_ROUTE_UDP);
    mr_freeze_for_stop(&mr, 5);
    mr_begin_teardown(&mr, 6); /* post-freeze re-registration */
    CHECK(atomic_load(&mr.terminal_invalid));

    /* The expected owner clear is normal only in the explicit phase. */
    mr = active(MR_ROUTE_UDP);
    mr_freeze_for_stop(&mr, 5);
    mr_begin_teardown(&mr, 5);
    CHECK(!atomic_load(&mr.terminal_invalid) && atomic_load(&mr.torn_down));
    mr_begin_teardown(&mr, 0); /* the clear itself, observed later */
    CHECK(!atomic_load(&mr.terminal_invalid) && !mr.fault);

    /* STOP before any applied START: frozen at epoch 0. */
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_UDP, 6001, 5);
    mr_freeze_for_stop(&mr, 5);
    CHECK(mr.stop_frozen && mr.applied_epoch == 0);

    mr = active(MR_ROUTE_UDP);
    mr_latch_invalid(&mr);
    CHECK(atomic_load(&mr.terminal_invalid));
    mr = active(MR_ROUTE_UDP);
    mr_signal(&mr);
    CHECK(mr.signaled == 1);
    puts("receipt: sticky post-freeze invalidation, registration change, explicit teardown phase");
}

static media_receipt_t example(void)
{
    media_receipt_t mr;
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_RAOP, 6001, 5);
    mr_applied(&mr, 1);
    mr_sent(&mr, MR_ORIGIN_FRESH, 128, target(6001), 6001, 1);
    mr_freeze_for_stop(&mr, 5);
    return mr;
}

static void test_format(void)
{
    char line[MEDIA_RECEIPT_MAX_LINE];
    media_receipt_t mr = example();
    size_t len = mr_format(&mr, true, line, sizeof(line));
    static const char expected[] =
        "@MEDIA1 {\"v\":1,\"terminal\":\"stop\",\"route\":\"raop\",\"epoch\":1,"
        "\"fresh_units\":1,\"fresh_bytes\":128,\"idle_units\":0,"
        "\"backlog_units\":0,\"fault\":false,\"overflow\":false,"
        "\"addr\":\"192.0.2.10\",\"port\":6001,\"setup_port\":6001}\n";
    CHECK(len == sizeof(expected) - 1 && memcmp(line, expected, len) == 0);
    CHECK(len <= MEDIA_RECEIPT_MAX_LINE && line[len - 1] == '\n');
    CHECK(memchr(line, '\n', len) == line + len - 1);

    /* Worst-case widths stay inside the 512-byte bound. */
    mr.fresh_units = mr.fresh_bytes = mr.idle_units = mr.backlog_units = UINT32_MAX;
    mr.overflow = true;
    mr.fault = true;
    mr.dest.sin_addr.s_addr = htonl(0xfefefefe);
    CHECK(mr_format(&mr, true, line, sizeof(line)) > 0);
    CHECK(mr_format(&mr, true, line, 100) == 0); /* overflow is rejected */

    /* No fresh unit: addr null, port zero; setup_port reported separately. */
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_UDP, 6001, 5);
    mr_applied(&mr, 1);
    mr_sent(&mr, MR_ORIGIN_IDLE, 90, target(6001), 6001, 0);
    mr_freeze_for_stop(&mr, 5);
    len = mr_format(&mr, true, line, sizeof(line));
    CHECK(len > 0 && strstr(line, "\"addr\":null,\"port\":0,\"setup_port\":6001}"));
    CHECK(strstr(line, "\"idle_units\":1"));

    /* Not a stop: abnormal with a fault, whatever the counters say. */
    mr = example();
    mr.signaled = 1;
    len = mr_format(&mr, true, line, sizeof(line));
    CHECK(strstr(line, "\"terminal\":\"abnormal\"") && strstr(line, "\"fault\":true"));
    mr = example();
    len = mr_format(&mr, false, line, sizeof(line));
    CHECK(strstr(line, "\"terminal\":\"abnormal\"") && strstr(line, "\"fault\":true"));
    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_RAOP, 6001, 5);
    mr_applied(&mr, 1); /* never stopped */
    len = mr_format(&mr, true, line, sizeof(line));
    CHECK(strstr(line, "\"terminal\":\"abnormal\"") && strstr(line, "\"fault\":true"));
    /* A post-freeze invalidation merges into the fault, STOP is still stop. */
    mr = example();
    mr_note_command(&mr);
    len = mr_format(&mr, true, line, sizeof(line));
    CHECK(strstr(line, "\"terminal\":\"stop\"") && strstr(line, "\"fault\":true"));
    CHECK(strstr(line, "\"fresh_units\":1"));
    puts("receipt: closed record format exact, bounded, abnormal/fault merge");
}

static int read_all(int fd, char *buf, size_t size)
{
    int flags = fcntl(fd, F_GETFL);
    CHECK(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    ssize_t n = read(fd, buf, size - 1);
    if (n < 0) { CHECK(errno == EAGAIN); n = 0; }
    buf[n] = '\0';
    return (int)n;
}

static void test_emit_success(void)
{
    media_receipt_t mr = example();
    int fds[2];
    CHECK(pipe(fds) == 0);
    FILE *out = fdopen(fds[1], "w");
    CHECK(out);
    CHECK(fputs("[STATUS] earlier line\n", out) >= 0); /* buffered earlier writer */
    reset_seams();
    CHECK(mr_emit(&mr, true, out));
    /* Nonblocking BEFORE the one flush, one flush, one write, no retry. */
    CHECK(fcntl_set_calls == 1 && fflush_calls == 1 && write_calls == 1);
    CHECK(nonblocking_at_flush && nonblocking_at_write);
    CHECK(setfl_seq < flush_seq && flush_seq < write_seq);
    CHECK((fcntl(fds[1], F_GETFL) & O_NONBLOCK) != 0); /* not restored */
    char got[1024];
    int n = read_all(fds[0], got, sizeof(got));
    static const char earlier[] = "[STATUS] earlier line\n";
    CHECK(n > (int)sizeof(earlier) - 1);
    CHECK(strncmp(got, earlier, sizeof(earlier) - 1) == 0);
    CHECK(strncmp(got + sizeof(earlier) - 1, "@MEDIA1 {", 9) == 0);
    CHECK(got[n - 1] == '\n' && strchr(got + sizeof(earlier) - 1, '\n') == got + n - 1);
    fclose(out);
    close(fds[0]);
    puts("receipt: one record after earlier output, O_NONBLOCK before flush, single write");
}

static void test_emit_failures(void)
{
    media_receipt_t mr = example();
    int fds[2];
    char got[1024];

    /* Not a pipe: refused before any syscall seam is touched. */
    FILE *file = tmpfile();
    CHECK(file);
    reset_seams();
    CHECK(!mr_emit(&mr, true, file));
    CHECK(write_calls == 0 && fflush_calls == 0 && fcntl_set_calls == 0);
    fclose(file);

    /* F_GETFL/F_SETFL failure omits the record and never flushes or writes. */
    for (int mode = 0; mode < 2; mode++) {
        CHECK(pipe(fds) == 0);
        FILE *out = fdopen(fds[1], "w");
        reset_seams();
        fail_getfl = mode == 0;
        fail_setfl = mode == 1;
        CHECK(!mr_emit(&mr, true, out));
        CHECK(fflush_calls == 0 && write_calls == 0);
        CHECK(read_all(fds[0], got, sizeof(got)) == 0);
        fclose(out);
        close(fds[0]);
    }

    /* write: EINTR, EAGAIN and a partial write are never retried or looped. */
    static const enum write_mode modes[] = { WRITE_EINTR, WRITE_EAGAIN, WRITE_PARTIAL };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        CHECK(pipe(fds) == 0);
        FILE *out = fdopen(fds[1], "w");
        reset_seams();
        write_mode = modes[i];
        CHECK(!mr_emit(&mr, true, out));
        CHECK(write_calls == 1 && fflush_calls == 1);
        int n = read_all(fds[0], got, sizeof(got));
        if (modes[i] == WRITE_PARTIAL) {
            /* The consumer sees a truncated line without LF: fail closed. */
            CHECK(n > 0 && got[n - 1] != '\n');
        } else {
            CHECK(n == 0);
        }
        fclose(out);
        close(fds[0]);
    }

    /* A REAL full pipe: earlier buffered stdout cannot be flushed. The flush
     * would block forever if O_NONBLOCK were not established first (alarm). */
    CHECK(pipe(fds) == 0);
    FILE *out = fdopen(fds[1], "w");
    static char big[1 << 20];
    CHECK(setvbuf(out, big, _IOFBF, sizeof(big)) == 0);
    static char filler[300 * 1024];
    memset(filler, 'x', sizeof(filler));
    CHECK(fwrite(filler, 1, sizeof(filler), out) == sizeof(filler));
    reset_seams();
    alarm(10);
    CHECK(!mr_emit(&mr, true, out));
    alarm(0);
    CHECK(fcntl_set_calls == 1 && fflush_calls == 1 && write_calls == 0);
    CHECK(nonblocking_at_flush);
    /* Drain: only filler bytes, never a media record. */
    char sink[65536];
    bool saw_record = false;
    ssize_t n;
    CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
    while ((n = read(fds[0], sink, sizeof(sink) - 1)) > 0) {
        sink[n] = '\0';
        if (strstr(sink, "@MEDIA")) saw_record = true;
    }
    CHECK(!saw_record);
    clearerr(out);
    fclose(out);
    close(fds[0]);

    /* A full pipe with nothing buffered: the single write fails EAGAIN. */
    CHECK(pipe(fds) == 0);
    CHECK(fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
    size_t stuffed = 0;
    for (;;) {
        ssize_t w = write(fds[1], filler, 512);
        if (w < 0) { CHECK(errno == EAGAIN); break; }
        stuffed += (size_t)w;
        CHECK(stuffed < (1u << 22));
    }
    out = fdopen(fds[1], "w");
    reset_seams();
    alarm(10);
    CHECK(!mr_emit(&mr, true, out));
    alarm(0);
    CHECK(write_calls == 1 && nonblocking_at_write);
    fclose(out);
    close(fds[0]);
    puts("receipt: refused non-pipe, fcntl/flush/write failures, EINTR/partial/EAGAIN, real full pipe, no waiting");
}

/* The route the CLI resolved up front must equal the hook path's route. */
static void test_expect_route(void)
{
    media_receipt_t mr;

    mr_init(&mr, true);
    mr_configure(&mr, MR_ROUTE_UDP, 6001, 5);
    mr_expect_route(&mr, MR_ROUTE_UNKNOWN);     /* unchecked */
    mr_expect_route(&mr, MR_ROUTE_UDP);
    CHECK(!mr.fault);
    mr_expect_route(&mr, MR_ROUTE_COMPAT);      /* resolved != actual path */
    CHECK(mr.fault);

    mr_init(&mr, false);                        /* disabled: no effect */
    mr_expect_route(&mr, MR_ROUTE_COMPAT);
    CHECK(!mr.fault);
    puts("media receipt: resolved route must match the hook path");
}

int main(void)
{
    alarm(60);
    test_expect_route();
    test_default_off();
    test_counting();
    test_faults();
    test_lifecycle_invalidation();
    test_format();
    test_emit_success();
    test_emit_failures();
    puts("Media receipt tests passed");
    return 0;
}
