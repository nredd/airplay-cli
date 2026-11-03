/* Compile the production CLI, including its STOP command handler and health
 * decision. Only transport effects are replaced; no receiver or sockets. */
#define main cli_main
#define ap2cl_is_connected test_connected
#define ap2cl_control_healthy test_healthy
#define ap2cl_stop test_stop
#define ap2cl_mrp_publish_playback_state test_publish
#include "../src/cliairplay.c"
#undef main

static bool connected = true;
static bool healthy = true;
static unsigned health_reads;

bool test_connected(struct ap2cl_s *p)
{
    (void)p;
    health_reads++;
    return connected;
}

bool test_healthy(struct ap2cl_s *p)
{
    (void)p;
    health_reads++;
    return healthy;
}

void test_stop(struct ap2cl_s *p)
{
    (void)p;
    connected = false;
}

void test_publish(struct ap2cl_s *p) { (void)p; }

static void *stop_command(void *opaque)
{
    handle_command("ACTION", "STOP", opaque);
    return NULL;
}

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    cli_config_t cfg = { .protocol = PROTO_AIRPLAY2 };
    /* Non-null identity; every transport function reached here is stubbed. */
    g_ap2cl = (struct ap2cl_s *)&cfg;
    g_status = STATUS_PLAYING;
    bool failed = false;
    CHECK(!airplay2_should_exit(&failed));
    CHECK(!failed);

    /* Main has entered its loop; command thread finishes STOP before health
     * inspection. Joining provides a deterministic happens-before relation. */
    pthread_t command;
    CHECK(pthread_create(&command, NULL, stop_command, &cfg) == 0);
    CHECK(pthread_join(command, NULL) == 0);
    CHECK(g_status == STATUS_STOPPED);
    health_reads = 0;
    CHECK(airplay2_should_exit(&failed));
    CHECK(!failed);
    CHECK(health_reads == 0);

    g_status = STATUS_PLAYING;
    CHECK(airplay2_should_exit(&failed));
    CHECK(failed);
    connected = true;
    healthy = false;
    failed = false;
    CHECK(airplay2_should_exit(&failed));
    CHECK(failed);
    puts("CLI STOP/health regression passed");
    return 0;
}
