/* Test-only C stdout -> external backend -> real FIFO parser -> decrypted
 * feedback seam. No speaker sockets, keys, discovery or settings are used. */
static int session_volume_harness(const char *fifo)
{
    int pair[2]; assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL, "1", "offline", NULL, NULL, NULL, 0);
    assert(m); m->sock = pair[0]; m->connected = true;
    ap2_mrp_set_volume_mode(m, true); m->verified_volume_identity = true;
    ap2_device_info_t device = {.name = "offline", .address = "127.0.0.1", .port = 7000};
    ap2_audio_format_t format = {.sample_rate = 44100, .bit_depth = 16, .channels = 2};
    g_ap2cl = ap2cl_create(&device, &format, NULL, NULL, "0011223344556677", "1", 600, 0);
    assert(g_ap2cl); ap2cl_test_set_mrp(g_ap2cl, m);
    cli_config_t cfg = {.protocol = PROTO_AIRPLAY2, .cmdpipe = (char *)fifo};
    assert(start_command_thread(&cfg));
    printf("[STATUS] session_volume_transport ready=1 publication=0\n"); fflush(stdout);
    uint64_t in = 0, out = 0, until = ap2_io_monotonic_ms() + 8000;
    bool sent = false, done = false;
    uint8_t plain[8192];
    while (g_running && ap2_io_monotonic_ms() < until) {
        struct pollfd pfd = {.fd = pair[1], .events = POLLIN};
        (void)poll(&pfd, 1, 10);
        pthread_mutex_lock(&m->volume.lock);
        bool known = m->volume.known, executing = m->volume.executing;
        unsigned milli = m->volume.milli;
        uint64_t ordinal = m->volume.ordinal;
        bool bound = m->volume.generation == 7 && m->volume.output_len == 3 &&
            !memcmp(m->volume.output, "P\0R", 3);
        pthread_mutex_unlock(&m->volume.lock);
        if (!sent && bound && known) {
            /* Real encrypted request; runtime callback emits frozen IPC. */
            m->volume_replay_generation = 7;
            m->volume_published_revision = 1;
            contract_send(m, pair[1], &in, &out, 51, .63f, false, "comm", plain);
            sent = true;
        }
        if (sent && ordinal == 1 && !executing && known && milli != 0) {
            ap2_mrp_tick(m);
            int bytes = contract_read(m, pair[1], &out, plain);
            const uint8_t *p; size_t len;
            assert(bytes > MRP_DATA_HDR_LEN && ap2_bplist_get_params_data(
                plain + MRP_DATA_HDR_LEN, (size_t)bytes - MRP_DATA_HDR_LEN, &p, &len));
            const uint8_t *end = p + len; uint64_t n;
            assert(mrp_diag_varint(&p, end, &n));
            struct mrp_diag_reader r = {.p = p, .end = end};
            bool type52 = false, actual = false;
            while (r.p < r.end) {
                struct mrp_diag_field f; assert(mrp_diag_field(&r, &f));
                if (f.number == 1) type52 = f.integer == 52;
                if (f.number == 56) {
                    struct mrp_diag_volume v = {0};
                    assert(mrp_diag_volume_body(52, f.data, f.len, &v));
                    actual = v.value_milli == (int)milli;
                }
            }
            assert(type52 && actual);
            printf("[STATUS] session_volume_harness committed=1 milli=%u\n", milli); fflush(stdout);
            done = true; break;
        }
    }
    g_running = false;
    assert(join_command_thread());
    close(g_cmdpipe_fd); g_cmdpipe_fd = -1;
    ap2cl_destroy(g_ap2cl); g_ap2cl = NULL; close(pair[1]);
    return done ? 0 : 2;
}
