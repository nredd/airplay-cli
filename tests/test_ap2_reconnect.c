/* Offline receiver for the public native connect/disconnect/connect lifecycle.
 * Reuse HAP's crypto/framing helpers, not a replacement client handshake. All
 * TCP peers are loopback; PTP transport is intercepted at bind/sendto only. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "../src/ap2_hap.c"
#include "ap2_client.h"
#include "ap2_plist.h"
#include "ap2_bplist.h"
#include "ap2_mrp.h"
#include "ap2_io.h"
#include "mrp_jpeg_fixture.h"

static log_level level = lSILENCE;
log_level *loglevel = &level;
log_level util_loglevel = lSILENCE;
log_level raop_loglevel = lSILENCE;

int ap2_ptp_test_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    struct sockaddr_in local;
    memcpy(&local, addr, sizeof(local));
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = 0;
    return bind(fd, (struct sockaddr *)&local, len);
}

ssize_t ap2_ptp_test_sendto(int fd, const void *buf, size_t len, int flags,
                          const struct sockaddr *dst, socklen_t dst_len)
{
    (void)fd; (void)buf; (void)flags; (void)dst; (void)dst_len;
    return (ssize_t)len; /* Never send timing traffic to a device or multicast. */
}

static void read_exact(int fd, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, (uint8_t *)buf + done, len - done);
        assert(n > 0);
        done += (size_t)n;
    }
}

static void write_exact(int fd, const void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, (const uint8_t *)buf + done, len - done);
        assert(n > 0);
        done += (size_t)n;
    }
}

/* Read one request including its body, without consuming the next request. */
static size_t request(int fd, struct ap2_hap_ctx *hap, uint8_t buf[16384],
                      size_t *body_offset)
{
    size_t len = 0, target = 0;
    *body_offset = 0;
    while (!target || len < target) {
        if (hap) {
            uint8_t frame[1042], *plain = NULL;
            read_exact(fd, frame, 2);
            size_t n = (size_t)frame[0] + ((size_t)frame[1] << 8) + 18;
            assert(n <= sizeof(frame));
            read_exact(fd, frame + 2, n - 2);
            int bytes = ap2_hap_decrypt(hap, frame, (int)n, &plain);
            assert(bytes > 0 && len + (size_t)bytes < 16384);
            memcpy(buf + len, plain, (size_t)bytes);
            len += (size_t)bytes;
            free(plain);
        } else {
            assert(len + 1 < 16384);
            read_exact(fd, buf + len++, 1);
        }
        buf[len] = 0;
        if (!*body_offset) {
            char *end = strstr((char *)buf, "\r\n\r\n");
            if (end) {
                *body_offset = (size_t)(end - (char *)buf) + 4;
                char *cl = strstr((char *)buf, "\r\nContent-Length: ");
                unsigned body_len = 0;
                if (cl) assert(sscanf(cl, "\r\nContent-Length: %u", &body_len) == 1);
                target = *body_offset + body_len;
                assert(target < 16384);
            }
        }
    }
    assert(len == target);
    return len;
}

static void reply(int fd, struct ap2_hap_ctx *hap, int cseq,
                  const uint8_t *body, size_t len)
{
    uint8_t buf[4096];
    int header = snprintf((char *)buf, sizeof(buf),
        "RTSP/1.0 200 OK\r\nCSeq: %d\r\nContent-Length: %zu\r\n\r\n", cseq, len);
    assert(header > 0 && (size_t)header + len < sizeof(buf));
    if (len) memcpy(buf + header, body, len);
    size_t total = (size_t)header + len;
    if (hap) {
        uint8_t *enc = NULL;
        int n = ap2_hap_encrypt(hap, buf, (int)total, &enc);
        assert(n > 0);
        write_exact(fd, enc, (size_t)n);
        free(enc);
    } else {
        write_exact(fd, buf, total);
    }
}

/* A real receiver-side pair-verify exchange, with fresh ephemeral session keys. */
static void pair_receiver(int fd, EVP_PKEY *identity, struct ap2_hap_ctx *hap)
{
    uint8_t buf[16384]; size_t offset;
    size_t len = request(fd, NULL, buf, &offset);
    assert(!strncmp((char *)buf, "POST /pair-verify ", 17));
    int n = 0;
    const uint8_t *pub = tlv_find(buf + offset, (int)(len - offset), TLV_PUBLIC_KEY, &n);
    assert(pub && n == 32);
    uint8_t client_pub[32]; memcpy(client_pub, pub, 32);
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *ephemeral = NULL;
    assert(gen && EVP_PKEY_keygen_init(gen) > 0 && EVP_PKEY_keygen(gen, &ephemeral) > 0);
    EVP_PKEY_CTX_free(gen);
    uint8_t server_pub[32]; size_t size = 32;
    assert(EVP_PKEY_get_raw_public_key(ephemeral, server_pub, &size) > 0);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, client_pub, 32);
    EVP_PKEY_CTX *derive = EVP_PKEY_CTX_new(ephemeral, NULL);
    uint8_t secret[32]; size = 32;
    assert(derive && peer && EVP_PKEY_derive_init(derive) > 0 &&
           EVP_PKEY_derive_set_peer(derive, peer) > 0 && EVP_PKEY_derive(derive, secret, &size) > 0);
    EVP_PKEY_CTX_free(derive); EVP_PKEY_free(peer); EVP_PKEY_free(ephemeral);
    uint8_t verify_key[32];
    assert(hkdf_sha512(secret, 32, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", verify_key, 32));
    const uint8_t id[] = "offline-receiver";
    uint8_t info[128]; size_t info_len = 0;
    memcpy(info, server_pub, 32); info_len += 32;
    memcpy(info + info_len, id, sizeof(id) - 1); info_len += sizeof(id) - 1;
    memcpy(info + info_len, client_pub, 32); info_len += 32;
    uint8_t signature[64]; size = 64;
    EVP_MD_CTX *sign = EVP_MD_CTX_new();
    assert(sign && EVP_DigestSignInit(sign, NULL, NULL, NULL, identity) > 0 &&
           EVP_DigestSign(sign, signature, &size, info, info_len) > 0);
    EVP_MD_CTX_free(sign);
    tlv_buf_t sub, msg; tlv_init(&sub); tlv_init(&msg);
    tlv_add(&sub, TLV_IDENTIFIER, id, sizeof(id) - 1);
    tlv_add(&sub, TLV_SIGNATURE, signature, 64);
    uint8_t nonce[12] = {0}, encrypted[256], tag[16];
    memcpy(nonce + 4, "PV-Msg02", 8);
    assert(chacha20_poly1305_encrypt(verify_key, nonce, NULL, 0, sub.data, sub.len, encrypted, tag) >= 0);
    memcpy(encrypted + sub.len, tag, 16);
    tlv_add_uint8(&msg, TLV_STATE, 2);
    tlv_add(&msg, TLV_PUBLIC_KEY, server_pub, 32);
    tlv_add(&msg, TLV_ENCRYPTED, encrypted, sub.len + 16);
    reply(fd, NULL, 1, msg.data, (size_t)msg.len);
    tlv_free(&sub); tlv_free(&msg);
    len = request(fd, NULL, buf, &offset);
    assert(!strncmp((char *)buf, "POST /pair-verify ", 17));
    uint8_t *enc = tlv_concat(buf + offset, (int)(len - offset), TLV_ENCRYPTED, &n);
    assert(enc && n > 16);
    memcpy(nonce + 4, "PV-Msg03", 8);
    uint8_t decoded[256];
    int decoded_len = chacha20_poly1305_decrypt(verify_key, nonce, NULL, 0, enc, n - 16, enc + n - 16, decoded);
    assert(decoded_len > 0);
    free(enc);
    static const uint8_t m4[] = {TLV_STATE, 1, 4};
    reply(fd, NULL, 2, m4, sizeof(m4));
    /* Reverse direction compared with the client's control channel keys. */
    assert(hkdf_sha512(secret, 32, "Control-Salt", "Control-Write-Encryption-Key", hap->read_key, 32));
    assert(hkdf_sha512(secret, 32, "Control-Salt", "Control-Read-Encryption-Key", hap->write_key, 32));
    hap->verified = true;
    memcpy(hap->shared_secret, secret, sizeof(secret));
}

/* Prove the reattached channel decrypts with this session's fresh keys and
 * counter zero, not just that the context reports an open descriptor. */
static void send_pause(int fd, const uint8_t secret[32], uint64_t counter)
{
    struct ap2_hap_ctx events = {0};
    assert(hkdf_sha512(secret, 32, "Events-Salt", "Events-Write-Encryption-Key", events.write_key, 32));
    events.verified = true;
    events.write_nonce_counter = counter;
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(root, "value", ap2_pl_string("paus"));
    uint8_t *body = NULL;
    int body_len = ap2_pl_serialize(root, &body);
    ap2_pl_free(root);
    uint8_t plain[2048];
    int hdr = snprintf((char *)plain, sizeof(plain),
        "POST /command RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: %d\r\n\r\n", body_len);
    assert(body_len > 0 && hdr > 0 && (size_t)(hdr + body_len) < sizeof(plain));
    memcpy(plain + hdr, body, (size_t)body_len); free(body);
    uint8_t *enc = NULL;
    int len = ap2_hap_encrypt(&events, plain, hdr + body_len, &enc);
    assert(len > 0); write_exact(fd, enc, (size_t)len); free(enc);
}

enum registration_flag {
    DEVICE_INFO = 1, NOW_PLAYING = 2, SUPPORTED_COMMANDS = 4,
    NOW_PLAYING_CLIENT = 8, PLAYBACK_STATE = 16, EXPECTED_TITLE = 32,
    ALL_REGISTRATIONS = 63,
};

typedef struct {
    int control_listener, event_listener, event_port;
    EVP_PKEY *identity;
    unsigned sessions;
    bool missing_first_event;
    bool send_commands;
    bool publication;
    bool retry_with_intent;
    bool reentrant;
    unsigned registrations[3];
    uint64_t playback_state[3];
    uint8_t *nowplaying[3];
    size_t nowplaying_len[3];
} receiver_t;

static int listener(int *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    assert(!bind(fd, (struct sockaddr *)&addr, sizeof(addr)) && !listen(fd, 4));
    socklen_t n = sizeof(addr);
    assert(!getsockname(fd, (struct sockaddr *)&addr, &n));
    *port = ntohs(addr.sin_port);
    return fd;
}

static void *receiver(void *arg)
{
    receiver_t *r = arg;
    for (unsigned session = 0; session < (r->retry_with_intent ? 3u : 2u); session++) {
        int fd = accept(r->control_listener, NULL, NULL); assert(fd >= 0);
        struct timeval tv = {.tv_sec = r->reentrant ? 10 : 5};
        assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));
        uint8_t buf[16384]; size_t offset;
        request(fd, NULL, buf, &offset);
        assert(!strncmp((char *)buf, "GET /info ", 10));
        int cseq;
        char *cs = strstr((char *)buf, "\r\nCSeq: "); assert(cs);
        assert(sscanf(cs, "\r\nCSeq: %d", &cseq) == 1);
        reply(fd, NULL, cseq, NULL, 0);
        struct ap2_hap_ctx hap = {0};
        pair_receiver(fd, r->identity, &hap);
        unsigned setups = 0; int event = -1;
        bool omit_event = (r->missing_first_event && session == 0) ||
                          (r->retry_with_intent && session == 1);
        for (;;) {
            size_t request_len = request(fd, &hap, buf, &offset);
            if (r->publication && !strncmp((char *)buf, "POST /command ", 14)) {
                const uint8_t *data = NULL; size_t data_len = 0;
                char type[64] = {0};
                if (ap2_bplist_get_params_data(buf + offset, request_len - offset, &data, &data_len))
                    r->registrations[session] |= DEVICE_INFO;
                if (ap2_bplist_get_root_string(buf + offset, request_len - offset, "type", type, sizeof(type))) {
                    if (!strcmp(type, "updateMRNowPlayingInfo")) {
                        r->registrations[session] |= NOW_PLAYING;
                        free(r->nowplaying[session]);
                        r->nowplaying_len[session] = request_len - offset;
                        r->nowplaying[session] = malloc(r->nowplaying_len[session]);
                        assert(r->nowplaying[session]);
                        memcpy(r->nowplaying[session], buf + offset, r->nowplaying_len[session]);
                        const char title[] = "fixture title";
                        for (size_t i = offset; i + sizeof(title) - 1 <= request_len; i++)
                            if (!memcmp(buf + i, title, sizeof(title) - 1))
                                r->registrations[session] |= EXPECTED_TITLE;
                    }
                    if (!strcmp(type, "updateMRSupportedCommands")) r->registrations[session] |= SUPPORTED_COMMANDS;
                    if (!strcmp(type, "updateMRNowPlayingClient")) r->registrations[session] |= NOW_PLAYING_CLIENT;
                    if (!strcmp(type, "updateMRPlaybackState")) {
                        uint64_t state = 0;
                        assert(ap2_bplist_find_uint(buf + offset, request_len - offset,
                                                   "mrPlaybackState", &state));
                        if (state != AP2_MRP_PLAYBACK_STOPPED)
                            r->playback_state[session] = state;
                        r->registrations[session] |= PLAYBACK_STATE;
                    }
                }
            }
            cs = strstr((char *)buf, "\r\nCSeq: "); assert(cs);
            assert(sscanf(cs, "\r\nCSeq: %d", &cseq) == 1);
            bool teardown = !strncmp((char *)buf, "TEARDOWN ", 9);
            uint8_t *body = NULL; int body_len = 0;
            if (!strncmp((char *)buf, "SETUP ", 6)) {
                struct ap2_plist *p = ap2_plist_create(); assert(p);
                if (setups++ == 0) {
                    if (!omit_event) ap2_plist_add_int(p, "eventPort", r->event_port);
                } else { ap2_plist_stream_begin(p); ap2_plist_stream_add_int(p, "dataPort", 65000);
                       ap2_plist_stream_add_int(p, "controlPort", 65001); ap2_plist_stream_end(p); }
                body_len = ap2_plist_serialize(p, &body); ap2_plist_free(p);
            }
            if (r->reentrant && session == 0 && !strncmp((char *)buf, "POST /feedback ", 15))
                send_pause(event, hap.shared_secret, 1);
            reply(fd, &hap, cseq, body, (size_t)body_len); free(body);
            if (r->send_commands && !omit_event && !strncmp((char *)buf, "SETPEERS ", 9)) {
                assert(event >= 0);
                send_pause(event, hap.shared_secret, 0);
            }
            if (!omit_event && setups == 1 && event < 0) {
                event = accept(r->event_listener, NULL, NULL); assert(event >= 0);
            }
            if (teardown) break;
        }
        assert(setups == 2 && (omit_event || event >= 0));
        if (event >= 0) close(event);
        close(fd); r->sessions++;
    }
    return NULL;
}

/* Ownership survives failed attachment and can be discarded without restore. */
static void intent_lifecycle(void)
{
    struct ap2_mrp_intent intent = {0};
    struct ap2_mrp_ctx *first = ap2_mrp_create("127.0.0.1", 1, NULL, NULL, NULL,
                                                NULL, NULL, NULL, 0);
    assert(first);
    assert(ap2_mrp_set_metadata(first, "a", "b", "c", 120000, "id"));
    assert(ap2_mrp_set_progress(first, 37000, 120000, false));
    ap2_mrp_artwork_info_t info;
    assert(ap2_mrp_set_artwork(first, "image/jpeg", k_baseline_jpeg,
                               sizeof(k_baseline_jpeg), &info));
    uint8_t *before = NULL, *after = NULL; int before_len = 0, after_len = 0;
    assert(ap2_mrp_build_nowplaying_command(first, &before, &before_len));
    ap2_mrp_intent_take(first, &intent);
    assert(intent.playback_state == AP2_MRP_PLAYBACK_PAUSED && intent.elapsed_ms == 37000);
    ap2_mrp_destroy(first);
    assert(!ap2_mrp_intent_restore(NULL, &intent) && intent.valid);
    struct ap2_mrp_ctx *second = ap2_mrp_create("127.0.0.1", 1, NULL, NULL, NULL,
                                                 NULL, NULL, NULL, 0);
    assert(second && ap2_mrp_intent_restore(second, &intent) && !intent.valid);
    assert(ap2_mrp_build_nowplaying_command(second, &after, &after_len));
    assert(before_len == after_len && !memcmp(before, after, (size_t)before_len));
    free(before); free(after);
    ap2_mrp_clear_artwork(second);
    ap2_mrp_intent_take(second, &intent);
    assert(!intent.artwork && !intent.artwork_mime);
    ap2_mrp_destroy(second);
    ap2_mrp_intent_clear(&intent);
    ap2_mrp_intent_clear(&intent);
    assert(!intent.valid);
}

/* Park the automatic reader at its next normal sleep after the first event.
 * The scheduling shim changes no client state or protocol path: the second
 * encrypted event must be consumed by the explicit public feedback call. */
static pthread_mutex_t callback_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t callback_cond = PTHREAD_COND_INITIALIZER;
static bool callback_entered, callback_release;
static bool retire_during_callback, callback_pending, callback_finish;
static struct ap2cl_s *callback_client;
static atomic_uint reentrant_commands;
static pthread_t callback_thread;
static bool callback_thread_known;
static bool delayed_callback;
static unsigned command_count, command_limit;

int ap2_reconnect_usleep(useconds_t delay)
{
    pthread_mutex_lock(&callback_lock);
    if (callback_thread_known && pthread_equal(pthread_self(), callback_thread)) {
        callback_entered = true;
        pthread_cond_broadcast(&callback_cond);
        while (!callback_release)
            pthread_cond_wait(&callback_cond, &callback_lock);
    }
    pthread_mutex_unlock(&callback_lock);
    return usleep(delay);
}

static void reentrant_remote(ap2_remote_command_t command, void *arg)
{
    (void)arg;
    assert(command == AP2_REMOTE_COMMAND_PAUSE);
    unsigned ordinal = atomic_fetch_add(&reentrant_commands, 1);
    if (ordinal == 0) {
        pthread_mutex_lock(&callback_lock);
        callback_thread = pthread_self();
        callback_thread_known = true;
        pthread_mutex_unlock(&callback_lock);
    } else {
        assert(ap2cl_mrp_push(callback_client) == 200);
        fprintf(stderr, "reentrant publication completed\n");
        if (retire_during_callback && ordinal == 1) {
            pthread_mutex_lock(&callback_lock);
            callback_pending = true;
            pthread_cond_broadcast(&callback_cond);
            while (!callback_finish)
                pthread_cond_wait(&callback_cond, &callback_lock);
            pthread_mutex_unlock(&callback_lock);
        }
    }
}

static void *public_feedback(void *arg)
{
    assert(ap2cl_feedback(arg));
    return NULL;
}

/* A failed lock regression must not strand a thread in the gate. Own the whole
 * child, kill it on deadline and reap it, including all its receiver/workers. */
static int bounded_reentrant(int argc, char **argv);

static void remote(ap2_remote_command_t command, void *arg)
{
    (void)arg;
    assert(command == AP2_REMOTE_COMMAND_PAUSE);
    pthread_mutex_lock(&callback_lock);
    if (delayed_callback) {
        callback_pending = true;
        pthread_cond_broadcast(&callback_cond);
        while (!callback_finish)
            pthread_cond_wait(&callback_cond, &callback_lock);
    }
    assert(command_count < command_limit && "duplicate or unexpected callback");
    command_count++;
    pthread_cond_broadcast(&callback_cond);
    pthread_mutex_unlock(&callback_lock);
}

/* Feedback is not a callback-completion fence: the background reader may own
 * input while the public tick skips it. Await the actual callback condition,
 * not elapsed time, and reject duplicate counts both here and at dispatch. */
static void await_commands(void)
{
    struct timespec deadline;
    assert(!clock_gettime(CLOCK_REALTIME, &deadline));
    deadline.tv_sec += 2;
    pthread_mutex_lock(&callback_lock);
    if (delayed_callback) {
        callback_finish = true;
        pthread_cond_broadcast(&callback_cond);
    }
    while (command_count < command_limit) {
        int err = pthread_cond_timedwait(&callback_cond, &callback_lock, &deadline);
        assert(!err || err == ETIMEDOUT);
        if (err == ETIMEDOUT) break;
    }
    fprintf(stderr, "callback count: actual=%u expected=%u\n", command_count, command_limit);
    assert(command_count == command_limit && "callback completion deadline");
    pthread_mutex_unlock(&callback_lock);
}

int main(int argc, char **argv)
{
    assert(argc == 1 || (argc == 2 && (!strcmp(argv[1], "--missing-first-event") ||
        !strcmp(argv[1], "--mrp-disabled") || !strcmp(argv[1], "--non-apple") ||
        !strcmp(argv[1], "--publication") || !strcmp(argv[1], "--retained-metadata") ||
        !strcmp(argv[1], "--retained-retry") || !strcmp(argv[1], "--reentrant-publication") ||
        !strcmp(argv[1], "--retired-feedback") || !strcmp(argv[1], "--retained-playing") ||
        !strcmp(argv[1], "--callback-barrier"))));
    delayed_callback = argc == 2 && !strcmp(argv[1], "--callback-barrier");
    retire_during_callback = argc == 2 && !strcmp(argv[1], "--retired-feedback");
    bool reentrant = retire_during_callback || (argc == 2 && !strcmp(argv[1], "--reentrant-publication"));
    if ((reentrant || delayed_callback) && !getenv("AP2_REENTRANT_CHILD")) return bounded_reentrant(argc, argv);
    bool missing_event = argc == 2 && !strcmp(argv[1], "--missing-first-event");
    bool mrp_disabled = argc == 2 && !strcmp(argv[1], "--mrp-disabled");
    bool retained_retry = argc == 2 && !strcmp(argv[1], "--retained-retry");
    bool retained_playing = argc == 2 && !strcmp(argv[1], "--retained-playing");
    bool retained_metadata = retained_playing || retained_retry || (argc == 2 && !strcmp(argv[1], "--retained-metadata"));
    bool publication = retained_metadata || (argc == 2 && !strcmp(argv[1], "--publication"));
    bool non_apple = (publication && !retained_retry) || (argc == 2 && !strcmp(argv[1], "--non-apple"));
    bool admitted = !mrp_disabled && !non_apple;
    alarm(20); /* Bound failures even if a protocol peer regresses. */
    if (retained_metadata) intent_lifecycle();
    signal(SIGPIPE, SIG_IGN);
    assert(!setenv("CLIAIRPLAY_EXPERIMENTAL_HOMEPOD_REMOTE", admitted ? "1" : "0", 1));
    assert(!setenv("CLIAIRPLAY_MRP_TYPE130", "0", 1));
    assert(!setenv("CLIAIRPLAY_MRP", mrp_disabled ? "0" : "1", 1));
    assert(!setenv("CLIAIRPLAY_SESSION_VOLUME", "0", 1));
    uint8_t seed[32] = {1}, client_seed[32] = {2}, pub[32]; size_t n = 32;
    EVP_PKEY *identity = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    assert(identity && EVP_PKEY_get_raw_public_key(identity, pub, &n) > 0);
    /* Fixture-only credentials, generated here and never read from the host. */
    uint8_t raw[96]; memcpy(raw, client_seed, 32);
    EVP_PKEY *client_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, client_seed, 32);
    n = 32; assert(client_key && EVP_PKEY_get_raw_public_key(client_key, raw + 32, &n) > 0);
    EVP_PKEY_free(client_key); memcpy(raw + 64, pub, 32);
    char credentials[193];
    for (size_t i = 0; i < sizeof(raw); i++) snprintf(credentials + 2 * i, 3, "%02x", raw[i]);
    int port;
    receiver_t r = {.identity = identity, .missing_first_event = missing_event,
                    .send_commands = admitted, .publication = publication,
                    .retry_with_intent = retained_retry, .reentrant = reentrant};
    r.control_listener = listener(&port); r.event_listener = listener(&r.event_port);
    pthread_t thread; assert(!pthread_create(&thread, NULL, receiver, &r));
    ap2_device_info_t device = {.name = "offline reconnect", .address = "127.0.0.1", .port = port,
        .txt_records = non_apple ? "model=OtherReceiver osvers=27.0" : "model=AudioAccessory5,1 osvers=27.0"};
    ap2_audio_format_t format = {.sample_rate = 44100, .bit_depth = 16, .channels = 2};
    struct ap2cl_s *p = ap2cl_create(&device, &format, credentials, NULL, "0011223344556677", "1", 600, 0);
    assert(p); ap2cl_force_native(p); ap2cl_set_ptp(p, true);
    callback_client = p;
    ap2cl_set_remote_command_callback(p, reentrant ? reentrant_remote : remote, NULL);
    for (unsigned cycle = 1; cycle <= (retained_retry ? 3u : 2u); cycle++) {
        pthread_mutex_lock(&callback_lock);
        if (admitted && !reentrant && !((missing_event && cycle == 1) || (retained_retry && cycle == 2)))
            command_limit++;
        callback_pending = callback_finish = false;
        pthread_mutex_unlock(&callback_lock);
        bool ok = ap2cl_connect(p);
        if ((missing_event && cycle == 1) || (retained_retry && cycle == 2)) {
            const char *detail = NULL;
            assert(!ok);
            ap2cl_connect_error(p, NULL, &detail);
            assert(detail && !strcmp(detail, "experimental HomePod reverse event attachment failed"));
            assert(ap2cl_state(p) == AP2_DOWN);
            continue;
        }
        if (!ok) {
            const char *detail = NULL;
            ap2cl_connect_error(p, NULL, &detail);
            fprintf(stderr, "connect cycle %u failed: %s\n", cycle, detail ? detail : "unknown");
        }
        assert(ok && "native reconnect must attach a fresh reverse event channel");
        assert(ap2cl_state(p) == AP2_CONNECTED);
        if (delayed_callback) {
            pthread_mutex_lock(&callback_lock);
            while (!callback_pending)
                pthread_cond_wait(&callback_cond, &callback_lock);
            pthread_mutex_unlock(&callback_lock);
        }
        if (reentrant && cycle == 1) {
            pthread_mutex_lock(&callback_lock);
            while (!callback_entered)
                pthread_cond_wait(&callback_cond, &callback_lock);
            pthread_mutex_unlock(&callback_lock);
        }
        if (retire_during_callback && cycle == 1) {
            pthread_t feedback;
            assert(!pthread_create(&feedback, NULL, public_feedback, p));
            pthread_mutex_lock(&callback_lock);
            while (!callback_pending)
                pthread_cond_wait(&callback_cond, &callback_lock);
            callback_release = true;
            pthread_cond_broadcast(&callback_cond);
            pthread_mutex_unlock(&callback_lock);
            assert(ap2cl_disconnect(p));
            assert(ap2cl_connect(p));
            assert(ap2cl_control_healthy(p));
            pthread_mutex_lock(&callback_lock);
            callback_finish = true;
            pthread_cond_broadcast(&callback_cond);
            pthread_mutex_unlock(&callback_lock);
            assert(!pthread_join(feedback, NULL));
            assert(ap2cl_control_healthy(p)); /* Old EOF cannot poison new health. */
            cycle++;
        } else {
            assert(ap2cl_feedback(p));
        }
        if (reentrant) {
            assert(atomic_load(&reentrant_commands) >= 2);
            pthread_mutex_lock(&callback_lock);
            callback_release = true;
            pthread_cond_broadcast(&callback_cond);
            pthread_mutex_unlock(&callback_lock);
        }
        if (!reentrant) await_commands();
        if (!ap2cl_control_healthy(p))
            fprintf(stderr, "control unhealthy on cycle %u\n", cycle);
        assert(ap2cl_control_healthy(p));
        if (publication) {
            if (retained_metadata && cycle > 1)
                assert(ap2cl_mrp_push(p) == 200);
            else if (retained_metadata) {
                if (retained_playing) {
                    uint64_t at;
                    ap2cl_start(p, 0, &at);
                    assert(ap2cl_is_playing(p));
                } else {
                    ap2cl_pause(p);
                }
                assert(ap2cl_set_metadata_ex(p, "fixture title", "fixture artist", "fixture album",
                    120, "fixture-id", "image/jpeg", k_baseline_jpeg, sizeof(k_baseline_jpeg),
                    NULL, NULL, NULL));
                assert(ap2cl_set_progress(p, 37, 120));
                ap2cl_mrp_publish_playback_state(p);
                assert(ap2cl_mrp_push(p) == 200);
            } else
                assert(ap2cl_set_metadata(p, "fixture title", "fixture artist", "fixture album", 120, "fixture-id"));
        }
        assert(ap2cl_disconnect(p));
        pthread_mutex_lock(&callback_lock);
        assert(command_count == command_limit); /* Joined worker: no late duplicates. */
        pthread_mutex_unlock(&callback_lock);
    }
    assert(ap2cl_destroy(p)); assert(!pthread_join(thread, NULL));
    assert(r.sessions == (retained_retry ? 3u : 2u));
    if (reentrant) assert(atomic_load(&reentrant_commands) == 3);
    if (publication) {
        unsigned last = retained_retry ? 2 : 1;
        fprintf(stderr, "registration masks: first=%u last=%u (expected 63 each)\n",
                r.registrations[0], r.registrations[last]);
        assert(r.registrations[0] == ALL_REGISTRATIONS && r.registrations[last] == ALL_REGISTRATIONS);
        if (retained_metadata) {
            uint64_t expected = retained_playing ? AP2_MRP_PLAYBACK_PLAYING : AP2_MRP_PLAYBACK_PAUSED;
            fprintf(stderr, "decrypted playback state: first=%llu last=%llu expected=%llu\n",
                    (unsigned long long)r.playback_state[0],
                    (unsigned long long)r.playback_state[last], (unsigned long long)expected);
            assert(r.playback_state[0] == expected && r.playback_state[last] == expected);
            assert(r.nowplaying_len[0] == r.nowplaying_len[last]);
            assert(!memcmp(r.nowplaying[0], r.nowplaying[last], r.nowplaying_len[0]));
        }
        for (unsigned i = 0; i < 3; i++) free(r.nowplaying[i]);
    }
    close(r.control_listener); close(r.event_listener);
    EVP_PKEY_free(identity);
    puts(retire_during_callback ? "test_ap2_reconnect: PASS (old feedback survives retirement; new health preserved)" :
         reentrant ? "test_ap2_reconnect: PASS (synchronous feedback callback publication)" :
         delayed_callback ? "test_ap2_reconnect: PASS (awaited delayed callback; exact counts)" :
         publication ? "test_ap2_reconnect: PASS (fresh publication registrations)" :
         missing_event ? "test_ap2_reconnect: PASS (failed event admission -> fresh successful session)" :
         mrp_disabled ? "test_ap2_reconnect: PASS (MRP disabled reconnect)" :
         non_apple ? "test_ap2_reconnect: PASS (non-Apple reconnect)" :
         "test_ap2_reconnect: PASS (two encrypted native sessions, fresh event keys, type130 off)");
    return 0;
}

static int bounded_reentrant(int argc, char **argv)
{
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!setenv("AP2_REENTRANT_CHILD", "1", 1));
        exit(main(argc, argv));
    }
    uint64_t deadline = ap2_io_monotonic_ms() + 4000;
    while (ap2_io_monotonic_ms() < deadline) {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        assert(result >= 0);
        if (result == child)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        usleep(10000);
    }
    assert(!kill(child, SIGKILL));
    assert(waitpid(child, NULL, 0) == child);
    fprintf(stderr, "FAIL: synchronous feedback callback publication deadlocked (child reaped)\n");
    return 1;
}
