/* Actual dependency and strict reader under production compiler flags. */
#include "rtsp_response_fixture.h"
#include "ap2_io.h"
#include <stdlib.h>
#include <string.h>
#define http_read_line old_line
#define recv old_recv
#define ap2_io_read_deadline scripted_read
#define ap2_io_monotonic_ms scripted_time
#define malloc fixture_malloc
#define strdup fixture_strdup
#include "../src/raop_response.c"
#undef malloc
#undef strdup
#include "../build/patched/rtsp_client.c"
#undef recv
void fixture_attach(struct rtspcl_s *client, int fd)
{
    client->fd = fd;
    strcpy(client->url, "rtsp://synthetic/session");
}
int fixture_fd(struct rtspcl_s *client) { return client->fd; }
bool fixture_request(struct rtspcl_s *client, key_data_t *headers, char **body, int *length)
{
    return exec_request(client, "POST", NULL, NULL, 0, 1,
                        NULL, headers, body, length, NULL);
}
void fixture_close(struct rtspcl_s *client)
{
    if (client->fd >= 0) { close(client->fd); client->fd = -1; }
}
bool fixture_optional(struct rtspcl_s *client)
{
    return exec_request(client, "SET_PARAMETER", NULL, NULL, 0, 2,
                        NULL, NULL, NULL, NULL, NULL);
}
