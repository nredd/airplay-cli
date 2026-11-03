/* Keep the actual dependency under its normal production compiler flags;
 * assertions and scripted inputs are in the separately strict test unit. */
#include "rtsp_response_fixture.h"
#define http_read_line scripted_response
#include "../build/patched/rtsp_client.c"
#undef http_read_line

void fixture_attach(struct rtspcl_s *client, int fd)
{
    client->fd = fd;
    strcpy(client->url, "rtsp://synthetic/session");
}

int fixture_fd(struct rtspcl_s *client) { return client->fd; }

bool fixture_optional_request(struct rtspcl_s *client)
{
    return exec_request(client, "SET_PARAMETER", NULL, NULL, 0,
                        2, NULL, NULL, NULL, NULL, NULL);
}
