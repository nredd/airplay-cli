/* Private, point-in-time executable-image attestation. */
#include "attestation.h"

#include <string.h>

bool attestation_nonce_valid(const char *nonce)
{
    if (!nonce || strlen(nonce) != ATTESTATION_NONCE_HEX_LEN) return false;
    for (size_t i = 0; i < ATTESTATION_NONCE_HEX_LEN; i++) {
        if (!((nonce[i] >= '0' && nonce[i] <= '9') ||
              (nonce[i] >= 'a' && nonce[i] <= 'f')))
            return false;
    }
    return true;
}

#ifdef _WIN32

bool attestation_verify_fds(int asset_fd, int self_fd, const char *nonce)
{
    (void)asset_fd;
    (void)self_fd;
    (void)nonce;
    return false;
}

bool attestation_ack(int asset_fd, const char *nonce)
{
    (void)asset_fd;
    (void)nonce;
    return false;
}

#else

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#define ATTESTATION_MAX_FILE_SIZE (64U * 1024U * 1024U)
#define ATTESTATION_SHA256_HEX_LEN 64
#define ATTESTATION_LINE_MAX 512

static bool stable_regular_file(int fd, struct stat *st)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fstat(fd, st) != 0)
        return false;
    if (!S_ISREG(st->st_mode) || st->st_size <= 0 ||
        (uintmax_t)st->st_size > ATTESTATION_MAX_FILE_SIZE)
        return false;
    return true;
}

static bool same_file_stat(const struct stat *before, const struct stat *after)
{
    if (before->st_dev != after->st_dev || before->st_ino != after->st_ino ||
        before->st_size != after->st_size || before->st_mtime != after->st_mtime ||
        before->st_ctime != after->st_ctime)
        return false;
#ifdef __APPLE__
    return before->st_mtimespec.tv_nsec == after->st_mtimespec.tv_nsec &&
           before->st_ctimespec.tv_nsec == after->st_ctimespec.tv_nsec;
#else
    return before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
#endif
}

static bool hash_stable_file(int fd, unsigned char digest[EVP_MAX_MD_SIZE])
{
    struct stat before, after;
    if (!stable_regular_file(fd, &before)) return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    unsigned char buffer[16384];
    for (off_t offset = 0; ok && offset < before.st_size;) {
        size_t wanted = (size_t)(before.st_size - offset);
        if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
        ssize_t got = pread(fd, buffer, wanted, offset);
        if (got <= 0 || (size_t)got != wanted) {
            ok = false;
            break;
        }
        ok = EVP_DigestUpdate(ctx, buffer, (size_t)got) == 1;
        offset += got;
    }
    unsigned int digest_len = 0;
    if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1 && digest_len == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok || fstat(fd, &after) != 0 || !same_file_stat(&before, &after)) return false;
    return true;
}

static void hex_encode(const unsigned char digest[32], char output[ATTESTATION_SHA256_HEX_LEN + 1])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        output[i * 2] = digits[digest[i] >> 4];
        output[i * 2 + 1] = digits[digest[i] & 15];
    }
    output[ATTESTATION_SHA256_HEX_LEN] = '\0';
}

bool attestation_verify_fds(int asset_fd, int self_fd, const char *nonce)
{
    unsigned char asset_digest[32], self_digest[32];
    if (!attestation_nonce_valid(nonce) || asset_fd < 3 || self_fd < 0 ||
        !hash_stable_file(asset_fd, asset_digest) || !hash_stable_file(self_fd, self_digest) ||
        memcmp(asset_digest, self_digest, sizeof(asset_digest)) != 0)
        return false;

    char asset_hex[ATTESTATION_SHA256_HEX_LEN + 1];
    char self_hex[ATTESTATION_SHA256_HEX_LEN + 1];
    hex_encode(asset_digest, asset_hex);
    hex_encode(self_digest, self_hex);
    char line[ATTESTATION_LINE_MAX];
    int length = snprintf(line, sizeof(line),
        "[ATTEST] {\"version\":1,\"kind\":\"current-image-match-at-ack\",\"nonce\":\"%s\",\"exec_fd_sha256\":\"%s\",\"self_sha256\":\"%s\"}\n",
        nonce, asset_hex, self_hex);
    if (length <= 0 || (size_t)length >= sizeof(line)) return false;
    size_t written = 0;
    while (written < (size_t)length) {
        ssize_t result = write(STDOUT_FILENO, line + written, (size_t)length - written);
        if (result > 0) {
            written += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool attestation_ack(int asset_fd, const char *nonce)
{
#ifdef __linux__
    int self_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (self_fd < 0) return false;
    bool ok = attestation_verify_fds(asset_fd, self_fd, nonce);
    close(self_fd);
    return ok;
#else
    (void)asset_fd;
    (void)nonce;
    return false;
#endif
}

#endif