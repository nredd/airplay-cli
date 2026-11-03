#ifndef RTSP_RESPONSE_FIXTURE_H
#define RTSP_RESPONSE_FIXTURE_H
#include <stdarg.h>
#include "cross_net.h"
#include "rtsp_client.h"
int old_line(int fd, char *line, int maxlen, int timeout, bool polling);
ssize_t old_recv(int fd, void *buf, size_t len, int flags);
ssize_t scripted_read(int fd, uint8_t *buf, size_t len, uint64_t deadline);
uint64_t scripted_time(void);
void *fixture_malloc(size_t size);
char *fixture_strdup(const char *text);
void fixture_attach(struct rtspcl_s *client, int fd);
int fixture_fd(struct rtspcl_s *client);
bool fixture_request(struct rtspcl_s *client, key_data_t *headers, char **body, int *length);
void fixture_close(struct rtspcl_s *client);
bool fixture_optional(struct rtspcl_s *client);
#endif
