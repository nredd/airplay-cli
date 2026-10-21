#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "attestation.h"

static bool force_short_read;
static bool force_unstable_stat;
static int observed_stats;

static ssize_t fixture_pread(int fd, void *buffer, size_t count, off_t offset)
{
    return pread(fd, buffer, force_short_read && count > 1 ? count - 1 : count, offset);
}

static int fixture_fstat(int fd, struct stat *info)
{
    int result = fstat(fd, info);
    if (result == 0 && force_unstable_stat && ++observed_stats == 2)
        info->st_size++;
    return result;
}

#ifdef __linux__
static bool force_self_denied;
static int fixture_open(const char *path, int flags)
{
    if (force_self_denied && strcmp(path, "/proc/self/exe") == 0) {
        errno = EACCES;
        return -1;
    }
    return open(path, flags);
}
#define open fixture_open
#endif
#define pread fixture_pread
#define fstat fixture_fstat
#include "../src/attestation.c"
#undef pread
#undef fstat
#ifdef __linux__
#undef open
#endif

static const char nonce[] = "0123456789abcdef0123456789abcdef";

static int temp_file(char path[])
{
    strcpy(path, "/tmp/cliairplay-attestation.XXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(write(fd, "private executable image", 24) == 24);
    assert(fchmod(fd, 0500) == 0);
    return fd;
}

static void test_nonce_validation(void)
{
    assert(attestation_nonce_valid(nonce));
    assert(!attestation_nonce_valid("0123456789abcdef0123456789abcde"));
    assert(!attestation_nonce_valid("0123456789ABCDEF0123456789abcdef"));
    assert(!attestation_nonce_valid("0123456789abcdef0123456789abcdef0"));
}

static void test_ack_and_offset_independence(void)
{
    char path[64];
    int writable = temp_file(path);
    close(writable);
    int asset = open(path, O_RDONLY);
    int self = open(path, O_RDONLY);
    assert(asset >= 0 && self >= 0);
    assert(lseek(asset, 0, SEEK_END) == 24);

    int output[2];
    assert(pipe(output) == 0);
    int saved_stdout = dup(STDOUT_FILENO);
    assert(saved_stdout >= 0 && dup2(output[1], STDOUT_FILENO) >= 0);
    close(output[1]);
    assert(attestation_verify_fds(asset, self, nonce));
    assert(lseek(asset, 0, SEEK_CUR) == 24);
    assert(lseek(self, 0, SEEK_CUR) == 0);
    assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
    close(saved_stdout);

    char line[512] = {0};
    ssize_t length = read(output[0], line, sizeof(line) - 1);
    assert(length > 0);
    close(output[0]);
    assert((size_t)length < sizeof(line));
    assert(strncmp(line, "[ATTEST] {\"version\":1,\"kind\":\"current-image-match-at-ack\",", 56) == 0);
    assert(strstr(line, "\"nonce\":\"0123456789abcdef0123456789abcdef\"") != NULL);
    assert(strstr(line, "\"exec_fd_sha256\":\"f7a013d1d0c60fc89df9bd3d927905a2e4d8c443734e0c8494027dbe096f92f5\"") != NULL);
    assert(strstr(line, "\"self_sha256\":\"f7a013d1d0c60fc89df9bd3d927905a2e4d8c443734e0c8494027dbe096f92f5\"") != NULL);
    assert(line[length - 1] == '\n');

    close(self);
    close(asset);
    unlink(path);
}

static void test_rejects_bad_inputs(void)
{
    char first[64], second[64];
    int asset_writable = temp_file(first);
    int other_writable = temp_file(second);
    assert(pwrite(other_writable, "X", 1, 0) == 1);
    assert(!attestation_verify_fds(asset_writable, other_writable, nonce));
    close(asset_writable);
    close(other_writable);
    int asset = open(first, O_RDONLY);
    int other = open(second, O_RDONLY);
    assert(asset >= 0 && other >= 0);
    assert(!attestation_verify_fds(asset, other, nonce));
    assert(!attestation_verify_fds(asset, -1, nonce));
    assert(!attestation_verify_fds(2, other, nonce));

    char empty_path[64];
    strcpy(empty_path, "/tmp/cliairplay-attestation-empty.XXXXXX");
    int empty_writable = mkstemp(empty_path);
    assert(empty_writable >= 0);
    close(empty_writable);
    int empty = open(empty_path, O_RDONLY);
    assert(empty >= 0);
    assert(!attestation_verify_fds(empty, other, nonce));
    close(empty);
    unlink(empty_path);

    int pipefd[2];
    assert(pipe(pipefd) == 0);
    assert(!attestation_verify_fds(pipefd[0], other, nonce));
    close(pipefd[0]);
    close(pipefd[1]);

    char huge[64];
    int oversized_writable = temp_file(huge);
    assert(ftruncate(oversized_writable, 64L * 1024L * 1024L + 1L) == 0);
    close(oversized_writable);
    int oversized = open(huge, O_RDONLY);
    assert(oversized >= 0);
    assert(!attestation_verify_fds(oversized, other, nonce));

    close(oversized);
    close(other);
    close(asset);
    unlink(huge);
    unlink(second);
    unlink(first);
}

static void test_short_read_unstable_stat_and_self_denial(void)
{
    char path[64];
    int writable = temp_file(path);
    close(writable);
    int asset = open(path, O_RDONLY);
    int self = open(path, O_RDONLY);
    assert(asset >= 3 && self >= 0);
    force_short_read = true;
    assert(!attestation_verify_fds(asset, self, nonce));
    force_short_read = false;
    observed_stats = 0;
    force_unstable_stat = true;
    assert(!attestation_verify_fds(asset, self, nonce));
    force_unstable_stat = false;
#ifdef __linux__
    force_self_denied = true;
#endif
    assert(!attestation_ack(asset, nonce));
#ifdef __linux__
    force_self_denied = false;
#endif
    close(self);
    close(asset);
    unlink(path);
}

int main(void)
{
    test_nonce_validation();
    test_ack_and_offset_independence();
    test_rejects_bad_inputs();
    test_short_read_unstable_stat_and_self_denial();
    puts("attestation tests passed");
    return 0;
}
