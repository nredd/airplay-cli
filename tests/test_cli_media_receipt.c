/* Compile the production CLI (command handler, session wiring, collector glue,
 * install/teardown helpers and the real stdout writer `remote_command_event`).
 * Only transport effects are stubbed; no receiver or network is involved. The
 * production session engine runs for real, so START/applied-epoch wiring and
 * the STOP freeze are exercised through the actual command path, not by calling
 * collector entry points directly. stdout is a real pipe. */
#define main cli_main
#define ap2cl_is_connected test_connected
#define ap2cl_control_healthy test_healthy
#define ap2cl_stop test_stop
#define ap2cl_mrp_publish_playback_state test_publish
#define ap2cl_mrp_publish_playback_state_on_transition test_publish_transition
#define ap2cl_start test_start
#define ap2cl_resume test_resume
#define ap2cl_set_start_join test_set_start_join
#define ap2cl_start_ack_deferred test_ack_deferred
#define ap2cl_media_registration_generation test_generation
#define ap2cl_media_path test_media_path
#define ap2cl_media_setup_port test_setup_port
#define ap2cl_set_media_write_cb test_set_write_cb
#define ap2cl_set_media_outcome_cb test_set_outcome_cb
#define ap2cl_set_raop_media_outcome_cb test_set_raop_outcome_cb
#define ap2cl_clock_watch_restart test_clock_watch_restart
#define ap2cl_send_chunk_tagged test_send_tagged
#define ap2cl_head_audible_unix_ms test_head_audible
#define ap2cl_destroy test_destroy
#define raopcl_disconnect test_raopcl_disconnect
#define raopcl_destroy test_raopcl_destroy
#define ap2cl_flush test_flush
#define ap2cl_standby test_standby
#define ap2cl_play test_play
#define ap2cl_pause test_pause
#define raopcl_set_media_outcome_cb test_raopcl_set_outcome_cb
#define raopcl_media_registration_generation test_raopcl_generation
#define raopcl_media_setup_port test_raopcl_setup_port
#include "../src/cliairplay.c"
#undef main

#include <sched.h>
#define say(text) fprintf(stderr, "%s\n", text)
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); \
} } while (0)

/* ---- stubs ---- */
static bool connected = true;
static bool healthy = true;
static ap2_commit_result_t next_commit = AP2_COMMIT_OK;
static unsigned stop_calls, start_calls, resume_calls;
static bool stop_saw_frozen, stop_saw_send_lock;
static uint32_t generation = 5;
static ap2_media_path_t media_path = AP2_MEDIA_PATH_NATIVE_UDP;
static uint16_t setup_port = 6001;
static unsigned set_write_calls, set_outcome_calls, set_raop_calls, raopcl_set_calls;
static bool set_write_cleared, set_outcome_cleared, set_raop_cleared, raopcl_cleared;
static bool setters_under_lock = true;

void test_clock_watch_restart(struct ap2cl_s *p) { (void)p; }
bool test_flush(struct ap2cl_s *p) { (void)p; return true; }
void test_standby(struct ap2cl_s *p) { (void)p; }
void test_play(struct ap2cl_s *p) { (void)p; }
void test_pause(struct ap2cl_s *p) { (void)p; }

static ap2_media_origin_t last_origin;
static uint64_t last_tag;
static unsigned tagged_calls;
static bool destroy_result = true;
static void (*destroy_hook)(void);
static unsigned destroy_calls;

ap2_send_result_t test_send_tagged(struct ap2cl_s *p, uint8_t *sample, int frames,
                                   ap2_media_origin_t origin, uint64_t tag)
{
    (void)p; (void)sample; (void)frames;
    tagged_calls++;
    last_origin = origin;
    last_tag = tag;
    return AP2_SEND_SENT;
}

uint64_t test_head_audible(struct ap2cl_s *p) { (void)p; return 0; }

/* ap2cl_destroy joins the feedback worker first; the hook stands in for that. */
bool test_destroy(struct ap2cl_s *p)
{
    (void)p;
    destroy_calls++;
    if (destroy_hook) destroy_hook();
    return destroy_result;
}

bool test_raopcl_disconnect(struct raopcl_s *p) { (void)p; return true; }
bool test_raopcl_destroy(struct raopcl_s *p) { (void)p; return true; }
bool test_connected(struct ap2cl_s *p) { (void)p; return connected; }
bool test_healthy(struct ap2cl_s *p) { (void)p; return healthy; }
void test_publish(struct ap2cl_s *p) { (void)p; }
void test_publish_transition(struct ap2cl_s *p) { (void)p; }
void test_set_start_join(struct ap2cl_s *p, bool join) { (void)p; (void)join; }
bool test_ack_deferred(struct ap2cl_s *p) { (void)p; return false; }

void test_stop(struct ap2cl_s *p)
{
    (void)p;
    stop_calls++;
    /* The measured interval closed BEFORE the transport stop, under the lock. */
    stop_saw_frozen = atomic_load(&g_mr.state) == MR_FROZEN;
    stop_saw_send_lock = pthread_mutex_trylock(&g_audio_send_lock) == EBUSY;
    connected = false;
}

ap2_commit_result_t test_start(struct ap2cl_s *p, uint64_t start_unix_ms, uint64_t *at)
{
    (void)p;
    start_calls++;
    if (at) *at = start_unix_ms;
    return next_commit;
}

ap2_commit_result_t test_resume(struct ap2cl_s *p, uint64_t start_unix_ms, uint64_t *at)
{
    (void)p;
    resume_calls++;
    if (at) *at = start_unix_ms;
    return next_commit;
}

uint32_t test_generation(struct ap2cl_s *p) { (void)p; return generation; }
ap2_media_path_t test_media_path(struct ap2cl_s *p) { (void)p; return media_path; }
uint16_t test_setup_port(struct ap2cl_s *p) { (void)p; return setup_port; }
uint32_t test_raopcl_generation(struct raopcl_s *p) { (void)p; return generation; }
uint16_t test_raopcl_setup_port(struct raopcl_s *p) { (void)p; return setup_port; }

static void note_setter(void)
{
    if (pthread_mutex_trylock(&g_audio_send_lock) == 0) {
        pthread_mutex_unlock(&g_audio_send_lock);
        setters_under_lock = false;
    }
}

void test_set_write_cb(struct ap2cl_s *p, ap2_media_write_cb cb, void *ctx)
{
    (void)p; (void)ctx;
    note_setter();
    set_write_calls++;
    set_write_cleared = cb == NULL;
}

void test_set_outcome_cb(struct ap2cl_s *p, ap2_media_outcome_cb cb, void *ctx)
{
    (void)p; (void)ctx;
    note_setter();
    set_outcome_calls++;
    set_outcome_cleared = cb == NULL;
}

bool test_set_raop_outcome_cb(struct ap2cl_s *p, raop_media_outcome_cb cb, void *ctx)
{
    (void)p; (void)ctx;
    note_setter();
    set_raop_calls++;
    set_raop_cleared = cb == NULL;
    return true;
}

void test_raopcl_set_outcome_cb(struct raopcl_s *p, raop_media_outcome_cb cb, void *ctx)
{
    (void)p; (void)ctx;
    note_setter();
    raopcl_set_calls++;
    raopcl_cleared = cb == NULL;
}

/* ---- fixtures ---- */
static cli_config_t cfg = { .protocol = PROTO_AIRPLAY2, .sample_rate = 44100,
                            .bit_depth = 16, .channels = 2 };
/* Zeroed stand-in client identity: every transport call that matters is
 * stubbed, anything else reads zeros rather than a neighboring object. */
static struct ap2cl_s *fake_client;
static int stdout_read_fd = -1;
static int stdin_write_fd = -1;

static void reset_stubs(void)
{
    stop_calls = start_calls = resume_calls = 0;
    stop_saw_frozen = stop_saw_send_lock = false;
    next_commit = AP2_COMMIT_OK;
    connected = true;
    healthy = true;
    generation = 5;
    media_path = AP2_MEDIA_PATH_NATIVE_UDP;
    setup_port = 6001;
    set_write_calls = set_outcome_calls = set_raop_calls = raopcl_set_calls = 0;
    set_write_cleared = set_outcome_cleared = set_raop_cleared = raopcl_cleared = false;
    setters_under_lock = true;
}

/* A fresh engine, as run_airplay2 builds it through start_stream_session. */
static void begin_session(bool enabled)
{
    reset_stubs();
    mr_init(&g_mr, enabled);
    g_first_start_done = true;       /* resume path, no metadata push */
    g_real_metadata_sent = true;
    g_start_ack_withheld = false;
    g_ap2cl = fake_client; /* non-null identity, every use stubbed */
    g_status = STATUS_PAUSED;
    CHECK(start_stream_session(&cfg, 4, 352));
    if (enabled) mr_install_ap2(fake_client);
}

static void end_session(void)
{
    ap2_session_destroy(g_session);
    g_session = NULL;
    g_ap2cl = NULL;
}

/* What the audio loop does for one content chunk, under the send lock. */
static void sender_content(unsigned count, ap2_media_origin_t origin)
{
    pthread_mutex_lock(&g_audio_send_lock);
    for (unsigned i = 0; i < count; i++) {
        ap2_media_write_t write = { .route = AP2_MEDIA_REALTIME_UDP,
            .origin = origin, .tag = mr_current_epoch(&g_mr), .bytes = 1000,
            .destination_known = true };
        write.destination.sin_family = AF_INET;
        write.destination.sin_port = htons(6001);
        inet_pton(AF_INET, "192.0.2.10", &write.destination.sin_addr);
        mr_ap2_write_cb(&g_mr, &write);
    }
    pthread_mutex_unlock(&g_audio_send_lock);
}

static void test_default_off(void)
{
    begin_session(false);
    CHECK(g_session != NULL);
    handle_command("ACTION", "START", &cfg);
    CHECK(ap2_session_epoch(g_session) == 1);
    CHECK(!g_mr.enabled && !g_mr.configured && atomic_load(&g_mr.state) == MR_WAIT);
    handle_command("ACTION", "STOP", &cfg);
    handle_command("ACTION", "START", &cfg);
    CHECK(stop_calls == 1 && start_calls + resume_calls == 2);
    CHECK(atomic_load(&g_mr.state) == MR_WAIT && !atomic_load(&g_mr.terminal_invalid));
    CHECK(!g_mr.stop_frozen && g_mr.applied_epoch == 0);
    mr_teardown(fake_client, NULL);
    CHECK(set_write_calls == 0 && set_outcome_calls == 0 && set_raop_calls == 0);
    end_session();
    say("cli receipt: disabled by default, no collector effect on START/STOP/teardown");
}

static void test_install_routes(void)
{
    reset_stubs();
    mr_init(&g_mr, true);
    media_path = AP2_MEDIA_PATH_NATIVE_UDP;
    mr_install_ap2(fake_client);
    CHECK(set_write_calls == 1 && set_outcome_calls == 1 && set_raop_calls == 0);
    CHECK(g_mr.configured && g_mr.route == MR_ROUTE_UDP && !g_mr.fault);
    CHECK(g_mr.setup_port == 6001 && g_mr.reg_gen == 5 && setters_under_lock);

    reset_stubs();
    mr_init(&g_mr, true);
    media_path = AP2_MEDIA_PATH_RAOP_COMPAT;
    mr_install_ap2(fake_client);
    CHECK(set_write_calls == 0 && set_outcome_calls == 0 && set_raop_calls == 1);
    CHECK(g_mr.route == MR_ROUTE_COMPAT && !g_mr.fault && setters_under_lock);

    /* Buffered TCP: nothing registered, explicitly incomplete from the start. */
    reset_stubs();
    mr_init(&g_mr, true);
    media_path = AP2_MEDIA_PATH_NATIVE_BUFFERED;
    mr_install_ap2(fake_client);
    CHECK(set_write_calls == 0 && set_outcome_calls == 0 && set_raop_calls == 0);
    CHECK(g_mr.route == MR_ROUTE_BUFFERED && g_mr.fault);

    reset_stubs();
    mr_init(&g_mr, true);
    media_path = AP2_MEDIA_PATH_UNKNOWN;
    mr_install_ap2(fake_client);
    CHECK(g_mr.route == MR_ROUTE_UNKNOWN && g_mr.fault);

    /* Missing SETUP port: bound to nothing, incomplete. */
    reset_stubs();
    mr_init(&g_mr, true);
    setup_port = 0;
    mr_install_ap2(fake_client);
    CHECK(g_mr.fault);

    reset_stubs();
    mr_init(&g_mr, true);
    mr_install_raop((struct raopcl_s *)fake_client);
    CHECK(raopcl_set_calls == 1 && g_mr.route == MR_ROUTE_RAOP && !g_mr.fault);
    CHECK(g_mr.reg_gen == 5 && g_mr.setup_port == 6001 && setters_under_lock);
    mr_teardown(NULL, (struct raopcl_s *)fake_client);
    CHECK(raopcl_set_calls == 2 && raopcl_cleared && setters_under_lock);

    reset_stubs();
    mr_init(&g_mr, false);
    mr_install_raop((struct raopcl_s *)fake_client);
    mr_install_ap2(fake_client);
    CHECK(raopcl_set_calls == 0 && set_write_calls == 0 && !g_mr.configured);
    say("cli receipt: install registers the actual route (udp/compat/raop), buffered/unknown incomplete");
}

static void test_stop_freezes_before_transport(void)
{
    begin_session(true);
    CHECK(g_mr.configured && g_session != NULL);
    sender_content(1, AP2_MEDIA_FRESH); /* before START: fresh is unexpected */
    CHECK(g_mr.fault);
    end_session();

    begin_session(true);
    sender_content(2, AP2_MEDIA_IDLE);
    CHECK(g_mr.idle_units == 0 && !g_mr.fault);
    handle_command("ACTION", "START", &cfg);
    CHECK(atomic_load(&g_mr.state) == MR_ACTIVE && g_mr.applied_epoch == 1);
    CHECK(g_status == STATUS_PLAYING);
    sender_content(3, AP2_MEDIA_FRESH);
    sender_content(1, AP2_MEDIA_IDLE);
    CHECK(g_mr.fresh_units == 3 && g_mr.fresh_bytes == 3000 && g_mr.idle_units == 1);
    CHECK(!g_mr.fault && !atomic_load(&g_mr.terminal_invalid));

    handle_command("ACTION", "STOP", &cfg);
    CHECK(stop_calls == 1 && stop_saw_frozen && stop_saw_send_lock);
    CHECK(g_mr.stop_frozen && !atomic_load(&g_mr.terminal_invalid) && !g_mr.fault);
    /* An in-flight post-freeze write cannot enter the count. */
    sender_content(2, AP2_MEDIA_FRESH);
    CHECK(g_mr.fresh_units == 3);

    /* Buffered `STOP\nSTART\n`: the START that SUCCEEDS after the freeze. */
    handle_command("ACTION", "START", &cfg);
    CHECK(atomic_load(&g_mr.terminal_invalid));
    CHECK(g_mr.applied_count == 1 && g_mr.fresh_units == 3);
    end_session();

    /* ... and the START that FAILS after the freeze still latches. */
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    sender_content(1, AP2_MEDIA_FRESH);
    handle_command("ACTION", "STOP", &cfg);
    CHECK(!atomic_load(&g_mr.terminal_invalid));
    next_commit = AP2_COMMIT_FAILED;
    handle_command("ACTION", "START", &cfg);
    CHECK(atomic_load(&g_mr.terminal_invalid) && g_mr.applied_count == 1);
    end_session();

    /* Each other post-freeze transport command latches too; metadata does not. */
    static const char *const verbs[] = { "FLUSH", "STANDBY", "PAUSE", "PLAY",
                                         "DISCONNECT", "STOP" };
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
        begin_session(true);
        handle_command("ACTION", "START", &cfg);
        handle_command("ACTION", "STOP", &cfg);
        handle_command("TITLE", "ignored", &cfg);
        handle_command("VOLUME", "10", &cfg);
        CHECK(!atomic_load(&g_mr.terminal_invalid));
        handle_command("ACTION", verbs[i], &cfg);
        CHECK(atomic_load(&g_mr.terminal_invalid));
        end_session();
    }

    /* A STOP with no client to stop is an observed failure before the ordinary
     * stopped status. */
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    g_ap2cl = NULL;
    handle_command("ACTION", "STOP", &cfg);
    CHECK(atomic_load(&g_mr.terminal_invalid) && g_mr.stop_frozen);
    end_session();
    say("cli receipt: START applied epoch, STOP freeze before transport stop, post-freeze START ok/fail, commands, no client");
}

static void test_commit_failure_never_activates(void)
{
    begin_session(true);
    next_commit = AP2_COMMIT_FAILED;
    handle_command("ACTION", "START", &cfg);
    CHECK(atomic_load(&g_mr.state) == MR_WAIT && g_mr.applied_count == 0);
    CHECK(ap2_session_epoch(g_session) == 0);
    next_commit = AP2_COMMIT_OK;
    handle_command("ACTION", "START", &cfg);
    CHECK(atomic_load(&g_mr.state) == MR_ACTIVE && g_mr.applied_epoch == 1);
    /* A second START before STOP: the one-start profile is incomplete. */
    handle_command("ACTION", "START", &cfg);
    CHECK(g_mr.fault && g_mr.applied_count == 2);
    end_session();
    say("cli receipt: failed START never activates, second START latches incomplete");
}

static void test_registration_changes(void)
{
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    generation = 6; /* an external set before the freeze */
    handle_command("ACTION", "STOP", &cfg);
    CHECK(g_mr.fault);
    end_session();

    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    handle_command("ACTION", "STOP", &cfg);
    generation = 7; /* post-freeze re-registration */
    mr_teardown(fake_client, NULL);
    CHECK(atomic_load(&g_mr.terminal_invalid));
    end_session();

    /* Control: the owner's own clear is expected, only in the explicit phase. */
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    handle_command("ACTION", "STOP", &cfg);
    set_write_calls = set_outcome_calls = set_raop_calls = 0;
    mr_teardown(fake_client, NULL);
    CHECK(!atomic_load(&g_mr.terminal_invalid) && !g_mr.fault);
    CHECK(set_write_calls == 1 && set_write_cleared);
    CHECK(set_outcome_calls == 1 && set_outcome_cleared);
    CHECK(set_raop_calls == 1 && set_raop_cleared && setters_under_lock);
    generation = 0; /* the cleared registration observed afterwards is normal */
    mr_teardown(fake_client, NULL); /* idempotent */
    CHECK(!atomic_load(&g_mr.terminal_invalid));
    end_session();
    say("cli receipt: registration change before/after freeze latches, owner clear is explicit and normal");
}

/* ---- terminal emission with a REAL stdout writer thread ---- */
typedef struct {
    atomic_bool run;
    atomic_uint events;
    atomic_bool holding;
    atomic_bool release;
    bool hold_lock;
} writer_t;

static void *feedback_standin(void *opaque)
{
    writer_t *w = opaque;
    if (w->hold_lock) {
        /* A writer inside libc's FILE lock, as a blocked printf would be. */
        flockfile(stdout);
        atomic_store(&w->holding, true);
        while (!atomic_load(&w->release)) sched_yield();
        funlockfile(stdout);
    }
    while (atomic_load(&w->run)) {
        remote_command_event(AP2_REMOTE_COMMAND_PLAY, NULL);
        atomic_fetch_add(&w->events, 1);
        sched_yield();
    }
    return NULL;
}

static unsigned drain_stdout(char *out, size_t size)
{
    int flags = fcntl(stdout_read_fd, F_GETFL);
    CHECK(fcntl(stdout_read_fd, F_SETFL, flags | O_NONBLOCK) == 0);
    size_t used = 0;
    for (;;) {
        ssize_t n = read(stdout_read_fd, out + used, size - 1 - used);
        if (n <= 0) break;
        used += (size_t)n;
    }
    out[used] = '\0';
    return (unsigned)used;
}

static writer_t *destroy_writer;
static pthread_t destroy_feedback;
static bool destroy_saw_cleared, destroy_lock_free, destroy_saw_record;
static char destroy_pre[16384];
static unsigned destroy_pre_len;

/* What ap2cl_destroy does first: stop and join the feedback worker. By then the
 * owner has cleared every hook, holds no media lock, and nothing was emitted. */
static void destroy_join_feedback(void)
{
    destroy_saw_cleared = set_write_cleared && set_outcome_cleared && set_raop_cleared;
    destroy_lock_free = pthread_mutex_trylock(&g_audio_send_lock) == 0;
    if (destroy_lock_free) pthread_mutex_unlock(&g_audio_send_lock);
    atomic_store(&destroy_writer->run, false);
    CHECK(pthread_join(destroy_feedback, NULL) == 0);
    destroy_pre_len = drain_stdout(destroy_pre, sizeof(destroy_pre));
    destroy_saw_record = strstr(destroy_pre, "@MEDIA1") != NULL;
}

static unsigned split_lines(char *out, char **last, unsigned *records)
{
    unsigned lines = 0;
    char *saveptr = NULL;
    *records = 0;
    for (char *line = strtok_r(out, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
        lines++;
        *last = line;
        if (strncmp(line, "@MEDIA1 {", 9) == 0) (*records)++;
        else CHECK(strncmp(line, "[EVENT] remote command=", 23) == 0);
    }
    return lines;
}

/* The production end-of-run sequence (finish_run, as main calls it) after a
 * real STOP, with a remote-command writer still running until the client
 * destroy joins it. */
static void run_finish_scenario(bool destroy_ok, char *out, size_t size)
{
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    sender_content(4, AP2_MEDIA_FRESH);

    writer_t writer = { .hold_lock = false };
    atomic_store(&writer.run, true);
    CHECK(pthread_create(&destroy_feedback, NULL, feedback_standin, &writer) == 0);
    destroy_writer = &writer;
    while (atomic_load(&writer.events) < 5) sched_yield();
    handle_command("ACTION", "STOP", &cfg); /* STOP while it writes */
    destroy_result = destroy_ok;
    destroy_hook = destroy_join_feedback;
    destroy_calls = 0;
    destroy_saw_cleared = destroy_lock_free = destroy_saw_record = false;
    cfg.cmdpipe = NULL;
    CHECK(finish_run(&cfg, 0));
    destroy_hook = NULL;
    destroy_result = true;
    CHECK(destroy_calls == 1 && g_ap2cl == NULL);
    /* Ordering inside the production sequence. */
    CHECK(destroy_saw_cleared && destroy_lock_free && !destroy_saw_record);
    end_session();
    /* Everything the stand-in writer printed before the join, then the rest. */
    CHECK(destroy_pre_len + 1 < size);
    memcpy(out, destroy_pre, destroy_pre_len);
    CHECK(drain_stdout(out + destroy_pre_len, size - destroy_pre_len) > 0);
}

static void test_final_after_writers_joined(void)
{
    char out[16384];
    char *last = NULL;
    unsigned records = 0;
    char discard[16384];
    (void)drain_stdout(discard, sizeof(discard));
    run_finish_scenario(true, out, sizeof(out));
    unsigned lines = split_lines(out, &last, &records);
    CHECK(records == 1 && lines >= 2);
    CHECK(strncmp(last, "@MEDIA1 {", 9) == 0); /* single line, after the writer */
    CHECK(strstr(last, "\"terminal\":\"stop\"") && strstr(last, "\"fault\":false"));
    CHECK(strstr(last, "\"fresh_units\":4,\"fresh_bytes\":4000"));
    CHECK(strstr(last, "\"addr\":\"192.0.2.10\",\"port\":6001,\"setup_port\":6001"));

    /* A failed client destroy is an observed cleanup failure: merged fault. */
    run_finish_scenario(false, out, sizeof(out));
    (void)split_lines(out, &last, &records);
    CHECK(records == 1 && strncmp(last, "@MEDIA1 {", 9) == 0);
    CHECK(strstr(last, "\"terminal\":\"stop\"") && strstr(last, "\"fault\":true"));

    /* A failed process result is a playback failure: abnormal. */
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    sender_content(1, AP2_MEDIA_FRESH);
    handle_command("ACTION", "STOP", &cfg);
    CHECK(finish_run(&cfg, 1));
    end_session();
    CHECK(drain_stdout(out, sizeof(out)) > 0);
    (void)split_lines(out, &last, &records);
    CHECK(strstr(last, "\"terminal\":\"abnormal\"") && strstr(last, "\"fault\":true"));
    say("cli receipt: finish_run emits one final line after STOP, hooks cleared, feedback writer joined by destroy, failed destroy/result merged");
}

/* Idle silence keeps its explicit IDLE label on the native lane; the nested
 * RAOP lane cannot label it, so an ACTIVE collector goes incomplete. */
static void test_silence_origin(void)
{
    uint8_t buf[352 * 4];
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    tagged_calls = 0;
    pthread_mutex_lock(&g_audio_send_lock);
    CHECK(ap2_send_silence_chunk(&cfg, buf, NULL, 4));
    pthread_mutex_unlock(&g_audio_send_lock);
    CHECK(tagged_calls == 1 && last_origin == AP2_MEDIA_IDLE && last_tag == 0);
    CHECK(!g_mr.fault);
    end_session();

    begin_session(true);
    media_path = AP2_MEDIA_PATH_RAOP_COMPAT;
    mr_install_ap2(fake_client);
    pthread_mutex_lock(&g_audio_send_lock);
    CHECK(ap2_send_silence_chunk(&cfg, buf, NULL, 4)); /* WAIT: not part of it */
    pthread_mutex_unlock(&g_audio_send_lock);
    CHECK(!g_mr.fault);
    handle_command("ACTION", "START", &cfg);
    pthread_mutex_lock(&g_audio_send_lock);
    CHECK(ap2_send_silence_chunk(&cfg, buf, NULL, 4));
    pthread_mutex_unlock(&g_audio_send_lock);
    CHECK(g_mr.fault);
    end_session();
    say("cli receipt: idle silence keeps its IDLE label; unlabelled compat lane goes incomplete");
}

typedef struct {
    atomic_bool started, done;
    bool ok;
} emit_t;

static void *emit_thread(void *opaque)
{
    emit_t *e = opaque;
    atomic_store(&e->started, true);
    e->ok = mr_emit(&g_mr, true, stdout);
    atomic_store(&e->done, true);
    return NULL;
}

/* Negative control: with the join skipped the emitter cannot get past a live
 * writer's FILE lock, which is exactly why the join precedes it. */
static void test_unjoined_writer_control(void)
{
    char out[16384];
    (void)drain_stdout(out, sizeof(out));
    begin_session(true);
    handle_command("ACTION", "START", &cfg);
    sender_content(1, AP2_MEDIA_FRESH);
    handle_command("ACTION", "STOP", &cfg);
    mr_teardown(fake_client, NULL);
    end_session();

    writer_t writer = { .hold_lock = true };
    atomic_store(&writer.run, true);
    pthread_t feedback;
    CHECK(pthread_create(&feedback, NULL, feedback_standin, &writer) == 0);
    while (!atomic_load(&writer.holding)) sched_yield();
    emit_t emit = {0};
    pthread_t emitter;
    CHECK(pthread_create(&emitter, NULL, emit_thread, &emit) == 0);
    while (!atomic_load(&emit.started)) sched_yield();
    usleep(200 * 1000);
    CHECK(!atomic_load(&emit.done)); /* blocked behind the unjoined writer */
    atomic_store(&writer.release, true);
    atomic_store(&writer.run, false);
    CHECK(pthread_join(feedback, NULL) == 0);
    CHECK(pthread_join(emitter, NULL) == 0);
    CHECK(emit.ok);
    (void)drain_stdout(out, sizeof(out));
    say("cli receipt: control, emission waits behind an unjoined stdout writer (join required)");
}

int main(void)
{
    alarm(60);
    fake_client = calloc(1, 1 << 20);
    CHECK(fake_client != NULL);
    int out_pipe[2], in_pipe[2];
    CHECK(pipe(out_pipe) == 0 && pipe(in_pipe) == 0);
    CHECK(dup2(out_pipe[1], STDOUT_FILENO) == STDOUT_FILENO);
    CHECK(dup2(in_pipe[0], STDIN_FILENO) == STDIN_FILENO);
    stdout_read_fd = out_pipe[0];
    stdin_write_fd = in_pipe[1];
    CHECK(setvbuf(stdout, NULL, _IOFBF, 8192) == 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    /* Quiet the production status lines on stderr. */
    util_loglevel = lSILENCE;
    raop_loglevel = lSILENCE;
    main_log = lSILENCE;

    test_default_off();
    test_install_routes();
    test_stop_freezes_before_transport();
    test_commit_failure_never_activates();
    test_registration_changes();
    test_silence_origin();
    test_final_after_writers_joined();
    test_unjoined_writer_control();
    free(fake_client);
    say("CLI media receipt tests passed");
    return 0;
}
