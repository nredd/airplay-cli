/* Private, point-in-time executable-image attestation. */
#ifndef CLIAIRPLAY_ATTESTATION_H
#define CLIAIRPLAY_ATTESTATION_H

#include <stdbool.h>

#define ATTESTATION_NONCE_HEX_LEN 32

/* Validate the public challenge syntax. */
bool attestation_nonce_valid(const char *nonce);

/*
 * Hash two stable, read-only regular files through positional reads and emit the
 * single attestation acknowledgement on stdout.  Exposed for native fixtures;
 * production obtains self_fd from /proc/self/exe through attestation_ack().
 */
bool attestation_verify_fds(int asset_fd, int self_fd, const char *nonce);

/* Linux-only current-image acknowledgement.  Fails closed elsewhere. */
bool attestation_ack(int asset_fd, const char *nonce);

#endif
