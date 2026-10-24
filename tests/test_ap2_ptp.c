#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ap2_ptp.h"
#include "cross_log.h"

static log_level test_log_level = lSILENCE;
log_level *loglevel = &test_log_level;

#define MAX_SENDS 256
#define PTP_EVENT_PORT 319
#define PTP_GENERAL_PORT 320
#define PTP_HDR_LEN 34
#define PTP_MSG_SYNC 0x0
#define PTP_MSG_DELAY_REQ 0x1
#define PTP_MSG_PDELAY_REQ 0x2
#define PTP_MSG_PDELAY_RESP 0x3
#define PTP_MSG_PDELAY_RESP_FUP 0xA
#define PTP_MSG_DELAY_RESP 0x9
#define PTP_MSG_SIGNALING 0xC

struct sent_datagram {
    struct sockaddr_in dst;
    uint8_t msg_type;
    uint16_t seq;
};

static pthread_mutex_t sends_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sends_cond = PTHREAD_COND_INITIALIZER;
static struct sent_datagram sends[MAX_SENDS];
static int nsends;
static uint16_t bound_port[2];

/* ap2_ptp.c is compiled with -Dbind/-Dsendto: bind to ephemeral loopback
 * sockets and record every datagram instead of sending it. Incoming packets
 * below still traverse real UDP sockets and the engine's poll/recvfrom loop. */
int ap2_ptp_test_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    struct sockaddr_in a;
    memcpy(&a, addr, sizeof(a));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    int rc = bind(fd, (const struct sockaddr *)&a, len);
    if (rc != 0) return rc;

    socklen_t actual_len = sizeof(a);
    assert(getsockname(fd, (struct sockaddr *)&a, &actual_len) == 0);
    uint16_t requested = ntohs(((const struct sockaddr_in *)addr)->sin_port);
    assert(requested == PTP_EVENT_PORT || requested == PTP_GENERAL_PORT);
    bound_port[requested == PTP_GENERAL_PORT] = ntohs(a.sin_port);
    return 0;
}

ssize_t ap2_ptp_test_sendto(int fd, const void *buf, size_t len, int flags,
                            const struct sockaddr *dst, socklen_t dst_len)
{
    (void)fd;
    (void)flags;
    (void)dst_len;
    assert(len >= PTP_HDR_LEN);
    pthread_mutex_lock(&sends_lock);
    if (nsends < MAX_SENDS) {
        struct sent_datagram *sent = &sends[nsends++];
        memcpy(&sent->dst, dst, sizeof(sent->dst));
        sent->msg_type = ((const uint8_t *)buf)[0] & 0x0f;
        sent->seq = ((uint16_t)((const uint8_t *)buf)[30] << 8) | ((const uint8_t *)buf)[31];
    }
    pthread_cond_broadcast(&sends_cond);
    pthread_mutex_unlock(&sends_lock);
    return (ssize_t)len;
}

void get_mac(uint8_t mac[])
{
    static const uint8_t fixed[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    memcpy(mac, fixed, sizeof(fixed));
}

static int sends_count(void)
{
    pthread_mutex_lock(&sends_lock);
    int n = nsends;
    pthread_mutex_unlock(&sends_lock);
    return n;
}

static void sends_reset(void)
{
    pthread_mutex_lock(&sends_lock);
    nsends = 0;
    pthread_mutex_unlock(&sends_lock);
}

static bool wait_for_send(uint8_t msg_type, uint16_t seq, int needed, int timeout_ms)
{
    struct timespec deadline;
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&sends_lock);
    for (;;) {
        int found = 0;
        for (int i = 0; i < nsends; i++)
            found += (msg_type == UINT8_MAX || sends[i].msg_type == msg_type) &&
                     (seq == UINT16_MAX || sends[i].seq == seq);
        if (found >= needed) {
            pthread_mutex_unlock(&sends_lock);
            return true;
        }
        int rc = pthread_cond_timedwait(&sends_cond, &sends_lock, &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&sends_lock);
            return false;
        }
        assert(rc == 0);
    }
}

/* Every recorded datagram went to `ip` on a PTP port; none to multicast. */
static void assert_all_sends_to(const char *ip)
{
    struct in_addr want;
    assert(inet_pton(AF_INET, ip, &want) == 1);
    pthread_mutex_lock(&sends_lock);
    for (int i = 0; i < nsends; i++) {
        assert(sends[i].dst.sin_addr.s_addr == want.s_addr);
        uint16_t port = ntohs(sends[i].dst.sin_port);
        assert(port == PTP_EVENT_PORT || port == PTP_GENERAL_PORT);
    }
    pthread_mutex_unlock(&sends_lock);
}

static struct in_addr any_iface(void)
{
    struct in_addr a = {.s_addr = INADDR_ANY};
    return a;
}

static void send_ptp_from(const char *source_ip, uint16_t dst_port, uint8_t msg_type,
                          uint16_t seq)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in source = {.sin_family = AF_INET};
    assert(inet_pton(AF_INET, source_ip, &source.sin_addr) == 1);
    assert(bind(fd, (const struct sockaddr *)&source, sizeof(source)) == 0);

    uint8_t packet[PTP_HDR_LEN + 20] = {0};
    packet[0] = 0x10 | msg_type;
    packet[1] = 2;
    packet[2] = 0;
    packet[3] = sizeof(packet);
    packet[20] = 0x10; /* not the engine's clock identity */
    packet[30] = seq >> 8;
    packet[31] = seq;
    if (msg_type == PTP_MSG_SIGNALING) {
        packet[44] = 0;
        packet[45] = 4; /* REQUEST_UNICAST_TRANSMISSION */
        packet[46] = 0;
        packet[47] = 6;
        packet[48] = 0x10; /* request Announce */
        packet[49] = 0;
        packet[53] = 1;
    }

    struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = htons(dst_port)};
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(sendto(fd, packet, sizeof(packet), 0, (const struct sockaddr *)&dst, sizeof(dst)) ==
           (ssize_t)sizeof(packet));
    assert(close(fd) == 0);
}

static void test_engine_without_peers_stays_silent(void)
{
    sends_reset();
    struct ap2_ptp_ctx *ctx = ap2_ptp_create();
    assert(ctx);
    assert(ap2_ptp_engine_start(ctx, any_iface(), NULL));

    const struct timespec wait = {.tv_sec = 0, .tv_nsec = 400000000L};
    assert(nanosleep(&wait, NULL) == 0);
    assert(sends_count() == 0);

    const char *peers[1] = {"192.0.2.20"};
    ap2_ptp_set_peers(ctx, peers, 1);
    assert(wait_for_send(UINT8_MAX, UINT16_MAX, 1, 2000));
    assert_all_sends_to("192.0.2.20");

    ap2_ptp_destroy(ctx);
}

static void test_engine_start_serves_device_before_setpeers(void)
{
    sends_reset();
    struct ap2_ptp_ctx *ctx = ap2_ptp_create();
    assert(ctx);
    assert(ap2_ptp_engine_start(ctx, any_iface(), "192.0.2.10"));

    assert(wait_for_send(UINT8_MAX, UINT16_MAX, 1, 2000));
    assert_all_sends_to("192.0.2.10");

    ap2_ptp_destroy(ctx);
}

static void test_strict_peers_reject_unregistered_loopback(void)
{
    assert(setenv("CLIAIRPLAY_PTP_STRICT_PEERS", "1", 1) == 0);
    sends_reset();
    memset(bound_port, 0, sizeof(bound_port));
    struct ap2_ptp_ctx *ctx = ap2_ptp_create();
    assert(ctx);
    const char *peers[1] = {"127.0.0.1"};
    assert(ap2_ptp_engine_start(ctx, any_iface(), NULL));
    assert(bound_port[0] != 0 && bound_port[1] != 0);
    sends_reset();

    send_ptp_from("127.0.0.1", bound_port[0], PTP_MSG_DELAY_REQ, 101);
    send_ptp_from("127.0.0.1", bound_port[0], PTP_MSG_PDELAY_REQ, 102);
    send_ptp_from("127.0.0.1", bound_port[1], PTP_MSG_SIGNALING, 103);
    assert(!wait_for_send(PTP_MSG_DELAY_RESP, 101, 1, 250));
    assert(!wait_for_send(PTP_MSG_PDELAY_RESP, 102, 1, 250));
    assert(!wait_for_send(PTP_MSG_PDELAY_RESP_FUP, 102, 1, 250));
    assert(!wait_for_send(PTP_MSG_SIGNALING, 103, 1, 250));
    struct ap2_ptp_exchange exchange;
    assert(!ap2_ptp_peer_exchange(ctx, "127.0.0.1", &exchange));

    ap2_ptp_set_peers(ctx, peers, 1);
    sends_reset();
    send_ptp_from("127.0.0.1", bound_port[0], PTP_MSG_DELAY_REQ, 201);
    send_ptp_from("127.0.0.1", bound_port[0], PTP_MSG_PDELAY_REQ, 202);
    send_ptp_from("127.0.0.1", bound_port[1], PTP_MSG_SIGNALING, 203);
    assert(wait_for_send(PTP_MSG_DELAY_RESP, 201, 1, 2000));
    assert(wait_for_send(PTP_MSG_PDELAY_RESP, 202, 1, 2000));
    assert(wait_for_send(PTP_MSG_PDELAY_RESP_FUP, 202, 1, 2000));
    assert(wait_for_send(PTP_MSG_SIGNALING, 203, 1, 2000));
    assert(ap2_ptp_peer_exchange(ctx, "127.0.0.1", &exchange));
    assert(exchange.count >= 2);

    /* Retirement shares the membership lock with packet admission: a later
     * datagram from the drained address cannot produce a response. */
    ap2_ptp_set_peers(ctx, NULL, 0);
    sends_reset();
    send_ptp_from("127.0.0.1", bound_port[0], PTP_MSG_DELAY_REQ, 204);
    assert(!wait_for_send(PTP_MSG_DELAY_RESP, 204, 1, 250));

    ap2_ptp_destroy(ctx);
    assert(unsetenv("CLIAIRPLAY_PTP_STRICT_PEERS") == 0);
}

static void test_default_keeps_unregistered_responses(void)
{
    sends_reset();
    memset(bound_port, 0, sizeof(bound_port));
    struct ap2_ptp_ctx *ctx = ap2_ptp_create();
    assert(ctx);
    assert(ap2_ptp_engine_start(ctx, any_iface(), NULL));
    sends_reset();

    send_ptp_from("127.0.0.1", bound_port[0], PTP_MSG_DELAY_REQ, 301);
    send_ptp_from("127.0.0.1", bound_port[0], PTP_MSG_PDELAY_REQ, 302);
    send_ptp_from("127.0.0.1", bound_port[1], PTP_MSG_SIGNALING, 303);
    assert(wait_for_send(PTP_MSG_DELAY_RESP, 301, 1, 2000));
    assert(wait_for_send(PTP_MSG_PDELAY_RESP, 302, 1, 2000));
    assert(wait_for_send(PTP_MSG_PDELAY_RESP_FUP, 302, 1, 2000));
    assert(wait_for_send(PTP_MSG_SIGNALING, 303, 1, 2000));
    struct ap2_ptp_exchange exchange;
    assert(ap2_ptp_peer_exchange(ctx, "127.0.0.1", &exchange));

    ap2_ptp_destroy(ctx);
}

int main(void)
{
    test_engine_without_peers_stays_silent();
    test_engine_start_serves_device_before_setpeers();
    test_strict_peers_reject_unregistered_loopback();
    test_default_keeps_unregistered_responses();
    printf("test_ap2_ptp: all tests passed\n");
    return 0;
}
