/* Owned loopback native AirPlay 2 receiver, see native_ap2_peer.h. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* strcasestr, memmem */
#endif

#include "native_ap2_peer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/ap2_plist.h"

#define SRP_N_BYTES 384
#define HASH_LEN 64
#define TAG_LEN 16
#define FRAME_MAX 1024
#define BUF_MAX 65536

enum { TLV_METHOD = 0, TLV_SALT = 2, TLV_PUBLIC_KEY = 3, TLV_PROOF = 4,
       TLV_STATE = 6, TLV_ERROR = 7 };

/* RFC 5054 3072-bit group, g = 5. An independent copy of the constant the
 * client uses, so a typo on either side fails pairing instead of cancelling. */
static const char SRP_N_HEX[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

/* ---- hashing / SRP-6a server side ---- */

static void sha512(const void *a, size_t alen, const void *b, size_t blen,
                   const void *c, size_t clen, uint8_t out[HASH_LEN])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int n;

    EVP_DigestInit_ex(md, EVP_sha512(), NULL);
    if (a) EVP_DigestUpdate(md, a, alen);
    if (b) EVP_DigestUpdate(md, b, blen);
    if (c) EVP_DigestUpdate(md, c, clen);
    EVP_DigestFinal_ex(md, out, &n);
    EVP_MD_CTX_free(md);
}

static void hash_padded(const BIGNUM *x, const BIGNUM *y, uint8_t out[HASH_LEN])
{
    uint8_t buf[2 * SRP_N_BYTES];

    BN_bn2binpad(x, buf, SRP_N_BYTES);
    BN_bn2binpad(y, buf + SRP_N_BYTES, SRP_N_BYTES);
    sha512(buf, sizeof(buf), NULL, 0, NULL, 0, out);
}

static int bn_min(const BIGNUM *x, uint8_t buf[SRP_N_BYTES])
{
    return BN_bn2bin(x, buf);
}

typedef struct {
    BIGNUM *N, *g, *v, *b, *B;
    uint8_t salt[16];
    BN_CTX *ctx;
} srp_t;

static bool srp_init(srp_t *s, const char *pin)
{
    uint8_t d[HASH_LEN], xd[HASH_LEN];
    char userpass[64];
    BIGNUM *x = BN_new(), *k = BN_new(), *t = BN_new();
    uint8_t kd[HASH_LEN];
    bool ok = false;

    memset(s, 0, sizeof(*s));
    s->ctx = BN_CTX_new();
    s->g = BN_new();
    s->v = BN_new();
    s->b = BN_new();
    s->B = BN_new();
    if (!BN_hex2bn(&s->N, SRP_N_HEX) || !BN_set_word(s->g, 5) ||
        RAND_bytes(s->salt, sizeof(s->salt)) != 1)
        goto done;
    snprintf(userpass, sizeof(userpass), "Pair-Setup:%s", pin);
    sha512(userpass, strlen(userpass), NULL, 0, NULL, 0, d);
    sha512(s->salt, sizeof(s->salt), d, HASH_LEN, NULL, 0, xd);
    BN_bin2bn(xd, HASH_LEN, x);
    BN_mod_exp(s->v, s->g, x, s->N, s->ctx);
    hash_padded(s->N, s->g, kd);
    BN_bin2bn(kd, HASH_LEN, k);
    if (!BN_rand(s->b, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) goto done;
    BN_mod_mul(t, k, s->v, s->N, s->ctx);       /* k*v */
    BN_mod_exp(s->B, s->g, s->b, s->N, s->ctx); /* g^b */
    BN_mod_add(s->B, s->B, t, s->N, s->ctx);
    ok = true;
done:
    BN_clear_free(x);
    BN_free(k);
    BN_free(t);
    return ok;
}

static void srp_free(srp_t *s)
{
    BN_free(s->N); BN_free(s->g); BN_clear_free(s->v); BN_clear_free(s->b);
    BN_free(s->B); BN_CTX_free(s->ctx);
}

/* Verify the client proof M1 and produce the server proof and session key. */
static bool srp_verify(srp_t *s, const uint8_t *a_bytes, int a_len,
                       const uint8_t *m1, uint8_t hamk[HASH_LEN],
                       uint8_t key[HASH_LEN])
{
    BIGNUM *A = BN_bin2bn(a_bytes, a_len, NULL), *u = BN_new(), *S = BN_new();
    BIGNUM *t = BN_new();
    uint8_t ud[HASH_LEN], sb[SRP_N_BYTES], ab[SRP_N_BYTES], bb[SRP_N_BYTES];
    uint8_t hn[HASH_LEN], hg[HASH_LEN], hu[HASH_LEN], x[HASH_LEN];
    uint8_t expect[HASH_LEN];
    bool ok = false;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int n;

    BN_nnmod(t, A, s->N, s->ctx);
    if (BN_is_zero(t)) goto done;
    hash_padded(A, s->B, ud);
    BN_bin2bn(ud, HASH_LEN, u);
    BN_mod_exp(t, s->v, u, s->N, s->ctx);       /* v^u */
    BN_mod_mul(t, A, t, s->N, s->ctx);          /* A * v^u */
    BN_mod_exp(S, t, s->b, s->N, s->ctx);
    sha512(sb, (size_t)bn_min(S, sb), NULL, 0, NULL, 0, key);

    int alen = bn_min(A, ab), blen = bn_min(s->B, bb);
    int nlen = bn_min(s->N, sb);
    sha512(sb, (size_t)nlen, NULL, 0, NULL, 0, hn);
    nlen = bn_min(s->g, sb);
    sha512(sb, (size_t)nlen, NULL, 0, NULL, 0, hg);
    for (int i = 0; i < HASH_LEN; i++) x[i] = hn[i] ^ hg[i];
    sha512("Pair-Setup", strlen("Pair-Setup"), NULL, 0, NULL, 0, hu);
    EVP_DigestInit_ex(md, EVP_sha512(), NULL);
    EVP_DigestUpdate(md, x, HASH_LEN);
    EVP_DigestUpdate(md, hu, HASH_LEN);
    EVP_DigestUpdate(md, s->salt, sizeof(s->salt));
    EVP_DigestUpdate(md, ab, (size_t)alen);
    EVP_DigestUpdate(md, bb, (size_t)blen);
    EVP_DigestUpdate(md, key, HASH_LEN);
    EVP_DigestFinal_ex(md, expect, &n);
    if (CRYPTO_memcmp(expect, m1, HASH_LEN) != 0) goto done;
    EVP_DigestInit_ex(md, EVP_sha512(), NULL);
    EVP_DigestUpdate(md, ab, (size_t)alen);
    EVP_DigestUpdate(md, expect, HASH_LEN);
    EVP_DigestUpdate(md, key, HASH_LEN);
    EVP_DigestFinal_ex(md, hamk, &n);
    ok = true;
done:
    EVP_MD_CTX_free(md);
    BN_free(A); BN_free(u); BN_free(S); BN_free(t);
    return ok;
}

/* ---- TLV8 ---- */

typedef struct { uint8_t data[1024]; int len; } tlv_t;

static void tlv_add(tlv_t *t, uint8_t tag, const uint8_t *v, int len)
{
    while (len > 0) {
        int chunk = len > 255 ? 255 : len;
        t->data[t->len++] = tag;
        t->data[t->len++] = (uint8_t)chunk;
        memcpy(t->data + t->len, v, (size_t)chunk);
        t->len += chunk;
        v += chunk;
        len -= chunk;
    }
}

/* Concatenate every fragment of `tag`; returns the length (0 when absent). */
static int tlv_get(const uint8_t *d, int len, uint8_t tag, uint8_t *out, int cap)
{
    int total = 0;

    for (int pos = 0; pos + 2 <= len; ) {
        int l = d[pos + 1];
        if (pos + 2 + l > len) break;
        if (d[pos] == tag && total + l <= cap) {
            memcpy(out + total, d + pos + 2, (size_t)l);
            total += l;
        }
        pos += 2 + l;
    }
    return total;
}

/* ---- HAP framing ---- */

typedef struct {
    int fd;
    bool enc;
    uint8_t rkey[32], wkey[32];     /* receiver's read = client's write key */
    uint64_t rctr, wctr;
    uint8_t buf[BUF_MAX];
    size_t used;
} conn_t;

static bool hkdf(const uint8_t *secret, const char *salt, const char *info,
                 uint8_t out[32])
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t n = 32;
    bool ok = c && EVP_PKEY_derive_init(c) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha512()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(c, (const unsigned char *)salt, (int)strlen(salt)) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(c, secret, HASH_LEN) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(c, (const unsigned char *)info, (int)strlen(info)) > 0 &&
        EVP_PKEY_derive(c, out, &n) > 0;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static void nonce_of(uint64_t ctr, uint8_t nonce[12])
{
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(ctr >> (8 * i));
}

static bool aead(bool encrypt, const uint8_t *key, uint64_t ctr,
                 const uint8_t aad[2], const uint8_t *in, int len,
                 uint8_t *out, uint8_t tag[TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    uint8_t nonce[12];
    int n = 0, m = 0;
    bool ok;

    nonce_of(ctr, nonce);
    ok = c && EVP_CipherInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL, encrypt) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_CipherInit_ex(c, NULL, NULL, key, nonce, encrypt) == 1 &&
        EVP_CipherUpdate(c, NULL, &n, aad, 2) == 1;
    if (ok && !encrypt)
        ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag) == 1;
    ok = ok && EVP_CipherUpdate(c, out, &n, in, len) == 1 &&
         EVP_CipherFinal_ex(c, out + n, &m) == 1;
    if (ok && encrypt)
        ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

static bool read_full(int fd, uint8_t *p, size_t n)
{
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return false;
        p += r;
        n -= (size_t)r;
    }
    return true;
}

static bool write_full(int fd, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r <= 0) return false;
        p += r;
        n -= (size_t)r;
    }
    return true;
}

/* Append more request bytes (one decrypted frame when encrypted). */
static bool fill(conn_t *c)
{
    if (!c->enc) {
        if (c->used + 1 >= sizeof(c->buf)) return false;
        ssize_t r = read(c->fd, c->buf + c->used, sizeof(c->buf) - 1 - c->used);
        if (r <= 0) return false;
        c->used += (size_t)r;
        return true;
    }
    uint8_t head[2], body[FRAME_MAX + TAG_LEN];
    if (!read_full(c->fd, head, 2)) return false;
    int len = head[0] | (head[1] << 8);
    if (len > FRAME_MAX || c->used + (size_t)len >= sizeof(c->buf) ||
        !read_full(c->fd, body, (size_t)len + TAG_LEN))
        return false;
    if (!aead(false, c->rkey, c->rctr++, head, body, len, c->buf + c->used,
              body + len))
        return false;
    c->used += (size_t)len;
    return true;
}

static bool send_bytes(conn_t *c, const uint8_t *p, size_t n)
{
    if (!c->enc) return write_full(c->fd, p, n);
    while (n) {
        int len = n > FRAME_MAX ? FRAME_MAX : (int)n;
        uint8_t frame[2 + FRAME_MAX + TAG_LEN];
        frame[0] = (uint8_t)len;
        frame[1] = (uint8_t)(len >> 8);
        if (!aead(true, c->wkey, c->wctr++, frame, p, len, frame + 2,
                  frame + 2 + len) ||
            !write_full(c->fd, frame, (size_t)len + 2 + TAG_LEN))
            return false;
        p += len;
        n -= (size_t)len;
    }
    return true;
}

static bool respond(conn_t *c, int cseq, const uint8_t *body, int len)
{
    char head[192];
    int n = snprintf(head, sizeof(head),
                     "RTSP/1.0 200 OK\r\nServer: AirTunes/366.0\r\nCSeq: %d\r\n"
                     "Content-Length: %d\r\n\r\n", cseq, len);
    uint8_t *msg = malloc((size_t)n + (size_t)len);
    bool ok;

    if (!msg) return false;
    memcpy(msg, head, (size_t)n);
    if (len) memcpy(msg + n, body, (size_t)len);
    ok = send_bytes(c, msg, (size_t)n + (size_t)len);
    free(msg);
    return ok;
}

/* ---- request loop ---- */

typedef struct {
    char line[160];
    int cseq;
    uint8_t *body;
    int body_len;
    size_t total;
} request_t;

static bool next_request(conn_t *c, request_t *r)
{
    char *end;

    for (;;) {
        c->buf[c->used] = '\0';
        end = strstr((char *)c->buf, "\r\n\r\n");
        if (end) break;
        if (!fill(c)) return false;
    }
    size_t hlen = (size_t)(end - (char *)c->buf) + 4;
    const char *cl = strcasestr((char *)c->buf, "Content-Length:");
    const char *cs = strcasestr((char *)c->buf, "CSeq:");
    r->body_len = cl && cl < end ? atoi(cl + 15) : 0;
    r->cseq = cs && cs < end ? atoi(cs + 5) : 0;
    while (c->used < hlen + (size_t)r->body_len)
        if (!fill(c)) return false;
    size_t line = strcspn((char *)c->buf, "\r");
    snprintf(r->line, sizeof(r->line), "%.*s", (int)(line < 159 ? line : 159),
             (char *)c->buf);
    r->body = c->buf + hlen;
    r->total = hlen + (size_t)r->body_len;
    return true;
}

static void consume(conn_t *c, const request_t *r)
{
    memmove(c->buf, c->buf + r->total, c->used - r->total);
    c->used -= r->total;
}

static bool is(const request_t *r, const char *prefix)
{
    return !strncmp(r->line, prefix, strlen(prefix));
}

static bool pair_setup(conn_t *c, native_peer_t *peer, srp_t *srp,
                       uint8_t key[HASH_LEN], const request_t *r)
{
    uint8_t state = 0;
    tlv_t out = { .len = 0 };

    if (!tlv_get(r->body, r->body_len, TLV_STATE, &state, 1)) return false;
    if (state == 1) {
        uint8_t b[SRP_N_BYTES];
        uint8_t two = 2;
        int blen = bn_min(srp->B, b);

        tlv_add(&out, TLV_STATE, &two, 1);
        tlv_add(&out, TLV_SALT, srp->salt, sizeof(srp->salt));
        tlv_add(&out, TLV_PUBLIC_KEY, b, blen);
        return respond(c, r->cseq, out.data, out.len);
    }
    if (state == 3) {
        uint8_t a[SRP_N_BYTES], m1[HASH_LEN], hamk[HASH_LEN], four = 4;
        int alen = tlv_get(r->body, r->body_len, TLV_PUBLIC_KEY, a, sizeof(a));
        int mlen = tlv_get(r->body, r->body_len, TLV_PROOF, m1, sizeof(m1));

        if (alen <= 0 || mlen != HASH_LEN ||
            !srp_verify(srp, a, alen, m1, hamk, key)) {
            uint8_t s4 = 4, err = 2;
            tlv_add(&out, TLV_STATE, &s4, 1);
            tlv_add(&out, TLV_ERROR, &err, 1);
            respond(c, r->cseq, out.data, out.len);
            return false;
        }
        tlv_add(&out, TLV_STATE, &four, 1);
        tlv_add(&out, TLV_PROOF, hamk, HASH_LEN);
        if (!respond(c, r->cseq, out.data, out.len)) return false;
        /* Everything after M4 is framed. */
        if (!hkdf(key, "Control-Salt", "Control-Write-Encryption-Key", c->rkey) ||
            !hkdf(key, "Control-Salt", "Control-Read-Encryption-Key", c->wkey))
            return false;
        c->enc = true;
        c->rctr = c->wctr = 0;
        atomic_fetch_add(&peer->pairings, 1);
        return true;
    }
    return false;
}

static bool reply_session_setup(conn_t *c, const request_t *r,
                                const native_peer_t *peer)
{
    uint8_t *data = NULL;
    int len;
    struct ap2_plist *p = ap2_plist_create();

    if (memmem(r->body, (size_t)r->body_len, "streams", 7)) {
        ap2_plist_stream_begin(p);
        ap2_plist_stream_add_int(p, "type", 96);
        ap2_plist_stream_add_int(p, "dataPort", peer->audio_port);
        ap2_plist_stream_add_int(p, "controlPort", peer->ctrl_port);
        ap2_plist_stream_end(p);
    } else {
        ap2_plist_add_int(p, "timingPort", peer->ctrl_port);
    }
    len = ap2_plist_serialize(p, &data);
    ap2_plist_free(p);
    bool ok = len > 0 && respond(c, r->cseq, data, len);
    free(data);
    return ok;
}

static void serve(native_peer_t *peer, int fd)
{
    static conn_t c;    /* one connection at a time; big buffer off the stack */
    srp_t srp;
    uint8_t key[HASH_LEN];
    request_t r;

    memset(&c, 0, sizeof(c));
    c.fd = fd;
    if (!srp_init(&srp, "3939")) return;
    while (next_request(&c, &r)) {
        bool ok = true;

        if (is(&r, "POST /pair-setup"))
            ok = pair_setup(&c, peer, &srp, key, &r);
        else if (is(&r, "SETUP"))
            ok = reply_session_setup(&c, &r, peer);
        else {
            if (is(&r, "TEARDOWN"))
                atomic_fetch_add(&peer->teardowns, 1);
            /* /info, RECORD, SET_PARAMETER, FLUSH, /feedback, /command, ... */
            ok = respond(&c, r.cseq, NULL, 0);
        }
        consume(&c, &r);
        if (!ok) break;
    }
    srp_free(&srp);
}

static void *rtsp_main(void *opaque)
{
    native_peer_t *peer = opaque;

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

static void *audio_main(void *opaque)
{
    native_peer_t *peer = opaque;
    uint8_t buf[2048];

    for (;;) {
        struct pollfd p[2] = { { .fd = peer->audio_fd, .events = POLLIN },
                               { .fd = peer->ctrl_fd, .events = POLLIN } };
        if (poll(p, 2, 50) > 0) {
            if (p[0].revents & POLLIN) {
                ssize_t n = recv(peer->audio_fd, buf, sizeof(buf), 0);
                if (n > 0) {
                    atomic_fetch_add(&peer->audio_units, 1);
                    atomic_fetch_add(&peer->audio_bytes, (unsigned long)n);
                }
            }
            if (p[1].revents & POLLIN)
                (void)recv(peer->ctrl_fd, buf, sizeof(buf), 0);   /* sync etc. */
        } else if (atomic_load(&peer->stop)) {
            break;
        }
    }
    return NULL;
}

static int bind_socket(int type, uint16_t *port)
{
    struct sockaddr_in a = { .sin_family = AF_INET };
    socklen_t len = sizeof(a);
    int fd = socket(AF_INET, type, 0);

    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &len) != 0 ||
        (type == SOCK_STREAM && listen(fd, 4) != 0)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

bool native_peer_start(native_peer_t *peer)
{
    memset(peer, 0, sizeof(*peer));
    peer->rtsp_fd = peer->audio_fd = peer->ctrl_fd = -1;
    peer->rtsp_fd = bind_socket(SOCK_STREAM, &peer->rtsp_port);
    peer->audio_fd = bind_socket(SOCK_DGRAM, &peer->audio_port);
    peer->ctrl_fd = bind_socket(SOCK_DGRAM, &peer->ctrl_port);
    if (peer->rtsp_fd < 0 || peer->audio_fd < 0 || peer->ctrl_fd < 0) {
        native_peer_stop(peer);
        return false;
    }
    if (pthread_create(&peer->rtsp_thread, NULL, rtsp_main, peer) != 0 ||
        pthread_create(&peer->audio_thread, NULL, audio_main, peer) != 0) {
        atomic_store(&peer->stop, true);
        native_peer_stop(peer);
        return false;
    }
    peer->started = true;
    return true;
}

void native_peer_stop(native_peer_t *peer)
{
    atomic_store(&peer->stop, true);
    if (peer->started) {
        pthread_join(peer->rtsp_thread, NULL);
        pthread_join(peer->audio_thread, NULL);
        peer->started = false;
    }
    if (peer->rtsp_fd >= 0) close(peer->rtsp_fd);
    if (peer->audio_fd >= 0) close(peer->audio_fd);
    if (peer->ctrl_fd >= 0) close(peer->ctrl_fd);
    peer->rtsp_fd = peer->audio_fd = peer->ctrl_fd = -1;
}
