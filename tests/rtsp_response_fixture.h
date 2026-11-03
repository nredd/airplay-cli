#ifndef RTSP_RESPONSE_FIXTURE_H
#define RTSP_RESPONSE_FIXTURE_H
#include <stdarg.h>
#include "cross_net.h"
#include "rtsp_client.h"

int scripted_response(int fd, char *line, int maxlen, int timeout, bool polling);
void fixture_attach(struct rtspcl_s *client, int fd);
int fixture_fd(struct rtspcl_s *client);
bool fixture_optional_request(struct rtspcl_s *client);
#endif
