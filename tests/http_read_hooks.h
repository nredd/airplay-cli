/* Only the dedicated cross_net test object redirects syscalls. */
#include <poll.h>
#include <sys/socket.h>
int http_test_poll(struct pollfd *fds, nfds_t count, int timeout);
ssize_t http_test_recv(int fd, void *buffer, size_t size, int flags);
#define poll http_test_poll
#define recv http_test_recv
