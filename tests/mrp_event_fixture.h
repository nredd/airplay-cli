/*
 * Shared encrypted /command event-channel fixture: an MRP context attached to
 * one end of a socketpair and the sender-side framing for the other end.
 * Included by tests that drive remote commands through the real ap2_mrp code.
 * Uses its own checks rather than assert(): the CLI build defines NDEBUG.
 */
#ifndef MRP_EVENT_FIXTURE_H
#define MRP_EVENT_FIXTURE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "ap2_mrp.h"
#include "ap2_plist.h"

#define KEY_SIZE 32
#define TAG_SIZE 16

#define must(c) do { if (!(c)) { \
    fprintf(stderr, "fixture check failed %s:%d: %s\n", __FILE__, __LINE__, #c); \
    abort(); } } while (0)

static void derive_key_from(const uint8_t *secret, size_t secret_len,
                            const char *info, uint8_t key[KEY_SIZE])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t len = KEY_SIZE;
    must(ctx);
    must(EVP_PKEY_derive_init(ctx) > 0);
    must(EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha512()) > 0);
    must(EVP_PKEY_CTX_set1_hkdf_salt(
               ctx, (const unsigned char *)"Events-Salt", 11) > 0);
    must(EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secret_len) > 0);
    must(EVP_PKEY_CTX_add1_hkdf_info(
               ctx, (const unsigned char *)info, strlen(info)) > 0);
    must(EVP_PKEY_derive(ctx, key, &len) > 0);
    EVP_PKEY_CTX_free(ctx);
}

static void derive_key(const uint8_t secret[KEY_SIZE], const char *info,
                       uint8_t key[KEY_SIZE])
{
    derive_key_from(secret, KEY_SIZE, info, key);
}

static void make_nonce(uint64_t counter, uint8_t nonce[12])
{
    memset(nonce, 0, 12);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)(counter >> (i * 8));
}

static int encrypt_frame(const uint8_t key[KEY_SIZE], uint64_t counter,
                         const uint8_t *plain, int plain_len, uint8_t *frame)
{
    uint8_t aad[2] = {plain_len & 0xff, (plain_len >> 8) & 0xff};
    uint8_t nonce[12];
    make_nonce(counter, nonce);
    memcpy(frame, aad, 2);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    must(ctx);
    must(EVP_EncryptInit_ex(
               ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) > 0);
    must(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0);
    must(EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) > 0);
    must(EVP_EncryptUpdate(ctx, NULL, &len, aad, 2) > 0);
    must(EVP_EncryptUpdate(
               ctx, frame + 2, &len, plain, plain_len) > 0);
    total = len;
    must(EVP_EncryptFinal_ex(ctx, frame + 2 + total, &len) > 0);
    total += len;
    must(EVP_CIPHER_CTX_ctrl(
               ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE,
               frame + 2 + total) > 0);
    EVP_CIPHER_CTX_free(ctx);
    return total + 2 + TAG_SIZE;
}

static int decrypt_frame(const uint8_t key[KEY_SIZE], uint64_t counter,
                         const uint8_t *frame, int frame_len, uint8_t *plain)
{
    must(frame_len >= 2 + TAG_SIZE);
    int cipher_len = frame[0] | (frame[1] << 8);
    must(frame_len == cipher_len + 2 + TAG_SIZE);
    uint8_t nonce[12];
    make_nonce(counter, nonce);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    must(ctx);
    must(EVP_DecryptInit_ex(
               ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) > 0);
    must(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) > 0);
    must(EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) > 0);
    must(EVP_DecryptUpdate(ctx, NULL, &len, frame, 2) > 0);
    must(EVP_DecryptUpdate(
               ctx, plain, &len, frame + 2, cipher_len) > 0);
    total = len;
    must(EVP_CIPHER_CTX_ctrl(
               ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE,
               (void *)(frame + 2 + cipher_len)) > 0);
    must(EVP_DecryptFinal_ex(ctx, plain + total, &len) > 0);
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
}

static struct ap2_mrp_ctx *create_mrp_with_callback(
    const uint8_t secret[KEY_SIZE], int event_sock,
    ap2_remote_command_cb_t callback, void *userdata)
{
    struct ap2_mrp_ctx *mrp = ap2_mrp_create(
        "127.0.0.1", 7000, NULL, "1A2B3D4EA1B2C3D4",
        "Music Assistant", "11111111-2222-4333-8444-555555555555",
        "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", secret, KEY_SIZE);
    must(mrp);
    ap2_mrp_set_remote_command_callback(mrp, callback, userdata);
    must(ap2_mrp_attach_events(mrp, event_sock));
    must(ap2_mrp_event_status(mrp) == 1);
    return mrp;
}

static struct ap2_mrp_ctx *create_mrp(const uint8_t secret[KEY_SIZE],
                                      int event_sock)
{
    return create_mrp_with_callback(secret, event_sock, NULL, NULL);
}

static int build_event_request(uint8_t *encrypted, size_t encrypted_size,
                               const uint8_t key[KEY_SIZE],
                               uint64_t counter, int cseq,
                               const uint8_t *body, int body_len)
{
    uint8_t request[1024];
    int header_len = snprintf(
        (char *)request, sizeof(request),
        "POST /command RTSP/1.0\r\n"
        "CSeq: %d\r\n"
        "Server: AirTunes/1.0\r\n"
        "Content-Type: application/x-apple-binary-plist\r\n"
        "Content-Length: %d\r\n\r\n",
        cseq, body_len);
    must(header_len > 0 && header_len + body_len < (int)sizeof(request));
    memcpy(request + header_len, body, (size_t)body_len);

    int request_len = header_len + body_len;
    must((size_t)(request_len + 2 + TAG_SIZE) <= encrypted_size);
    return encrypt_frame(
        key, counter, request, request_len, encrypted);
}

static int build_typed_command_request(
    uint8_t *encrypted, size_t encrypted_size,
    const uint8_t key[KEY_SIZE], uint64_t counter, int cseq,
    const char *type, const char *value)
{
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string(type));
    ap2_pl_dict_set(root, "value", ap2_pl_string(value));
    uint8_t *body = NULL;
    int body_len = ap2_pl_serialize(root, &body);
    ap2_pl_free(root);
    must(body_len > 0 && body);
    int encrypted_len = build_event_request(
        encrypted, encrypted_size, key, counter, cseq, body, body_len);
    free(body);
    return encrypted_len;
}

static int build_command_request(uint8_t *encrypted, size_t encrypted_size,
                                 const uint8_t key[KEY_SIZE],
                                 uint64_t counter, int cseq,
                                 const char *value)
{
    return build_typed_command_request(
        encrypted, encrypted_size, key, counter, cseq,
        "sendMediaRemoteCommand", value);
}

static void send_request(int fd, const uint8_t key[KEY_SIZE],
                         uint64_t counter, int cseq, const char *value)
{
    uint8_t encrypted[1200];
    int encrypted_len = build_command_request(
        encrypted, sizeof(encrypted), key, counter, cseq, value);
    must(write(fd, encrypted, (size_t)encrypted_len) == encrypted_len);
}

static void read_response(int fd, const uint8_t key[KEY_SIZE],
                          uint64_t counter, int cseq)
{
    uint8_t response_frame[2048], response[2048];
    must(recv(fd, response_frame, 2, MSG_WAITALL) == 2);
    int cipher_len = response_frame[0] | (response_frame[1] << 8);
    int remaining = cipher_len + TAG_SIZE;
    must(recv(fd, response_frame + 2, (size_t)remaining, MSG_WAITALL) ==
           remaining);
    int response_len = decrypt_frame(
        key, counter, response_frame, remaining + 2, response);
    response[response_len] = '\0';
    char expected_cseq[32];
    snprintf(expected_cseq, sizeof(expected_cseq), "CSeq: %d\r\n", cseq);
    must(strstr((char *)response, "RTSP/1.0 200 OK\r\n"));
    must(strstr((char *)response, "Content-Length: 0\r\n"));
    must(strstr((char *)response, "Audio-Latency: 0\r\n"));
    must(strstr((char *)response, "Server: AirTunes/1.0\r\n"));
    must(strstr((char *)response, expected_cseq));
}

#endif
