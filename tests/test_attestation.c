#undef NDEBUG
#include <assert.h>
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

#define pread fixture_pread
#define fstat fixture_fstat
#include "../src/attestation.c"
#undef pread
#undef fstat

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
    assert(line[length - 1] == '\n');

    close(self);
    close(asset);
    unlink(path);
}

static void test_rejects_unsafe_or_unstable_files(void)
{
    char first[64], second[64];
    int first_writable = temp_file(first);
    int second_writable = temp_file(second);
    assert(pwrite(second_writable, "X", 1, 0) == 1);
    assert(!attestation_verify_fds(first_writable, second_writable, nonce));
    close(first_writable);
    close(second_writable);
    int asset = open(first, O_RDONLY);
    int other = open(second, O_RDONLY);
    assert(asset >= 3 && other >= 0);
    assert(!attestation_verify_fds(asset, other, nonce));
    assert(!attestation_verify_fds(asset, -1, nonce));
    assert(!attestation_verify_fds(2, other, nonce));

    force_short_read = true;
    assert(!attestation_verify_fds(asset, asset, nonce));
    force_short_read = false;
    observed_stats = 0;
    force_unstable_stat = true;
    assert(!attestation_verify_fds(asset, asset, nonce));
    force_unstable_stat = false;

    close(other);
    close(asset);
    unlink(second);
    unlink(first);
}

int main(void)
{
    test_nonce_validation();
    test_ack_and_offset_independence();
    test_rejects_unsafe_or_unstable_files();
    puts("attestation tests passed");
    return 0;
}
