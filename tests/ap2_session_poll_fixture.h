/* Test-only interception for the session reader translation unit.
 * Parse libc's declarations first: a command-line poll rename can also rename
 * an inline/asm-redirected libc declaration and silently bypass the observer.
 * The fixture still delegates to real poll in tests/test_ap2_session.c.
 */
#ifndef AP2_SESSION_POLL_FIXTURE_H
#define AP2_SESSION_POLL_FIXTURE_H

#include <poll.h>

int ap2_session_test_poll(struct pollfd *fds, nfds_t nfds, int timeout);

#define poll ap2_session_test_poll

#endif
