/* Offline contract tests include the production parsers/driver, not a model. */
static unsigned volume_calls, volume_last;
static uint64_t volume_generation, volume_ordinal;
static void contract_callback(void *unused, uint64_t generation, uint64_t ordinal, unsigned milli)
{
    (void)unused;
    ++volume_calls; volume_last = milli; volume_generation = generation; volume_ordinal = ordinal;
}
static void test_volume_driver(void)
{
    struct ap2_volume v;
    ap2_volume_init(&v);
    v.callback = contract_callback;
    static const uint8_t uid[] = {'P',0,'R'};
    unsigned milli = 999;
    assert(ap2_volume_bind(&v, 7, uid, sizeof(uid), NULL, 0));
    assert(!ap2_volume_get(&v, uid, sizeof(uid), &milli) && milli == 999);
    assert(!ap2_volume_state(&v, 6, 1, true, 0));
    assert(ap2_volume_state(&v, 7, 1, true, 0));
    assert(ap2_volume_get(&v, uid, sizeof(uid), &milli) && milli == 0);
    assert(!ap2_volume_set(&v, uid, 1, 630, 100));
    assert(ap2_volume_set(&v, uid, sizeof(uid), 630, 100));
    assert(volume_calls == 1 && volume_generation == 7 && volume_ordinal == 1);
    assert(ap2_volume_get(&v, uid, sizeof(uid), &milli) && milli == 0);
    for (unsigned i = 0; i < 10000; ++i) assert(ap2_volume_set(&v, uid, sizeof(uid), i % 1001, 101));
    assert(volume_calls == 1 && v.have_trailing);
    assert(!ap2_volume_complete(&v, 6, 1, "committed", 2, true, 610, 200));
    assert(ap2_volume_complete(&v, 7, 1, "committed", 2, true, 610, 200));
    assert(volume_calls == 2 && volume_ordinal == 2 && volume_last == 9999 % 1001);
    assert(ap2_volume_get(&v, uid, sizeof(uid), &milli) && milli == 610);
    assert(!ap2_volume_complete(&v, 7, 1, "committed", 3, true, 630, 210));
    assert(ap2_volume_complete(&v, 7, 2, "failed", 3, false, 0, 210));
    assert(!ap2_volume_get(&v, uid, sizeof(uid), &milli));
    assert(ap2_volume_set(&v, uid, sizeof(uid), 100, 220));
    ap2_volume_tick(&v, 3220);
    assert(!ap2_volume_complete(&v, 7, 3, "committed", 4, true, 100, 3221));
    assert(!ap2_volume_set(&v, uid, sizeof(uid), 200, 3221));
    assert(ap2_volume_state(&v, 7, 4, true, 150));
    assert(ap2_volume_set(&v, uid, sizeof(uid), 200, 3230));
    assert(ap2_volume_bind(&v, 8, uid, sizeof(uid), NULL, 0));
    assert(!ap2_volume_complete(&v, 7, 4, "committed", 5, true, 200, 3240));
    assert(!ap2_volume_bind(&v, 8, uid, sizeof(uid), NULL, 0));
    ap2_volume_unbind(&v, 7); assert(v.output_len);
    ap2_volume_unbind(&v, 8); assert(!v.output_len);
    ap2_volume_destroy(&v);
}
static void stage_line(cli_config_t *cfg, const char *key, const char *value)
{
    handle_command(key, value, cfg);
}
static void contract_bind(cli_config_t *cfg)
{
    stage_line(cfg, "SESSION_VOLUME_GENERATION", "7");
    stage_line(cfg, "SESSION_VOLUME_OUTPUT_UID_HEX", "500052");
    stage_line(cfg, "SESSION_VOLUME_ENDPOINT_UID_HEX", "");
    stage_line(cfg, "ACTION", "SESSION_VOLUME_BIND");
}
static void contract_state(cli_config_t *cfg, const char *revision, const char *milli)
{
    stage_line(cfg, "SESSION_VOLUME_GENERATION", "7");
    stage_line(cfg, "SESSION_VOLUME_REVISION", revision);
    stage_line(cfg, "SESSION_VOLUME_KNOWN", "1");
    stage_line(cfg, "SESSION_VOLUME_MILLI", milli);
    stage_line(cfg, "ACTION", "SESSION_VOLUME_STATE");
}
/* Build public schemas including an embedded-NUL identifier to prove exact
 * field-2 correlation, independent of field85's unrelated identity. */
static uint8_t *contract_payload(unsigned type, float level, bool bad_uid, int *len)
{
    mbuf inner = {0}, pb = {0}, blob = {0};
    static const uint8_t uid[] = {'P',0,'R'}, id[] = {'c',0,'r'};
    if (type != 49) assert(pb_put_float_field(&inner, 1, level));
    if (type == 49 || type == 51)
        assert(pb_put_bytes_field(&inner, type == 49 ? 1 : 2, uid, bad_uid ? 1 : sizeof(uid)));
    assert(pb_put_varint_field(&pb, 1, type));
    assert(pb_put_bytes_field(&pb, 2, id, sizeof(id)));
    assert(pb_put_string_field(&pb, 85, "PRIVATE_NOT_CORRELATION"));
    assert(pb_put_msg_field(&pb, type == 49 ? 53 : type == 51 ? 55 : type == 50 ? 54 : 56, &inner));
    assert(pb_put_varint(&blob, pb.len) && mbuf_put(&blob, pb.p, pb.len));
    uint8_t *out = diag_payload(blob.p, blob.len, len);
    mbuf_free(&inner); mbuf_free(&pb); mbuf_free(&blob);
    return out;
}
static int contract_read(struct ap2_mrp_ctx *m, int fd, uint64_t *counter, uint8_t *plain)
{
    uint8_t encrypted[8192]; int received = 0, plain_len = 0;
    ssize_t got;
    while ((got = recv(fd, encrypted + received, sizeof(encrypted) - (size_t)received, MSG_DONTWAIT)) > 0)
        received += (int)got;
    assert(received && mrp_drain_channel_frames(encrypted, &received, plain, &plain_len,
        8192, m->out_key, counter, "test"));
    assert(!received);
    return plain_len;
}
static int contract_send(struct ap2_mrp_ctx *m, int fd, uint64_t *in, uint64_t *out,
    unsigned type, float level, bool bad_uid, const char *command, uint8_t *plain)
{
    int len; uint8_t *b = contract_payload(type, level, bad_uid, &len);
    uint8_t frame[4096];
    mrp_write_data_header(frame, "sync", command, 0x12345678, len);
    memcpy(frame + MRP_DATA_HDR_LEN, b, (size_t)len); free(b);
    uint8_t *encrypted;
    int n = mrp_channel_encrypt_with(m->in_key, in, frame, MRP_DATA_HDR_LEN + len, &encrypted);
    assert(n > 0 && write(fd, encrypted, 1) == 1);
    ap2_mrp_tick(m);
    assert(recv(fd, plain, 8192, MSG_DONTWAIT) < 0);
    assert(write(fd, encrypted + 1, (size_t)n - 1) == n - 1); free(encrypted);
    ap2_mrp_tick(m);
    int size = contract_read(m, fd, out, plain);
    uint8_t ack[MRP_DATA_HDR_LEN]; static const char zero[4] = {0};
    mrp_write_data_header(ack, "rply", zero, 0x12345678, 0);
    assert(size >= MRP_DATA_HDR_LEN && !memcmp(plain, ack, sizeof(ack)));
    return size;
}
static void test_volume_optional_transport(void)
{
    int data[2], event[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, data));
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, event));
    uint8_t secret[32] = {4};
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL, "1", "offline", NULL, NULL, secret, sizeof(secret));
    assert(m && ap2_mrp_attach_events(m, event[0]));
    m->sock = data[0]; m->connected = true;
    ap2_mrp_set_volume_mode(m, true);
    assert(mrp_data_handshake(m));
    uint8_t plain[8192]; uint64_t counter = 0;
    int n = contract_read(m, data[1], &counter, plain);
    static const unsigned expected[] = {15, 38, 16};
    size_t off = 0;
    for (unsigned i = 0; i < 3; ++i) {
        uint32_t size = (uint32_t)test_be(plain + off, 4);
        assert(size >= MRP_DATA_HDR_LEN && off + size <= (size_t)n);
        int type;
        assert(!strcmp(mrp_diag_protobuf(plain + off + MRP_DATA_HDR_LEN,
            size - MRP_DATA_HDR_LEN, &type), "protobuf"));
        assert((unsigned)type == expected[i]);
        off += size;
    }
    assert(off == (size_t)n); /* no now-playing metadata moved onto this channel */
    uint8_t *state = NULL; int state_len = 0; uint64_t generation;
    assert(!ap2_mrp_prepare_state_push(m, &state, &state_len, &generation));
    close(data[1]);
    void (*old_signal)(int) = signal(SIGPIPE, SIG_IGN);
    assert(!mrp_data_handshake(m));
    signal(SIGPIPE, old_signal);
    assert(!m->connected && ap2_mrp_event_status(m) == 1);
    unsigned callbacks = 0;
    ap2_mrp_set_remote_command_callback(m, diag_callback, &callbacks);
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(root, "value", ap2_pl_string("play"));
    uint8_t *body; int len = ap2_pl_serialize(root, &body); ap2_pl_free(root);
    uint64_t in = 0, out = 0;
    volume_send(m, event[1], true, &in, &out, body, len);
    assert(callbacks == 2); free(body);
    ap2_mrp_destroy(m); close(event[1]);
}
/* Private capture attaches the datastream receive-only: the handshake registers the
 * sender (DEVICE_INFO, connection state, updates config) and nothing else, and no
 * now-playing push is ever prepared; a plain type-130 attach still publishes. */
static void test_capture_datastream_receive_only(void)
{
    for (int capture = 0; capture < 2; ++capture) {
        int data[2], event[2];
        assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, data));
        assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, event));
        uint8_t secret[32] = {5};
        struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL, "1", "offline", NULL, NULL, secret, sizeof(secret));
        assert(m && ap2_mrp_attach_events(m, event[0]));
        m->sock = data[0]; m->connected = true;
        ap2_mrp_set_experimental_homepod_remote(m, true);
        ap2_mrp_set_private_native_volume_capture(m, capture != 0);
        ap2_mrp_set_track(m, "title", "artist", "album", 0, NULL, NULL, NULL, 0, NULL, NULL);
        assert(mrp_data_handshake(m));
        uint8_t plain[8192]; uint64_t counter = 0;
        int n = contract_read(m, data[1], &counter, plain);
        unsigned types[8]; unsigned count = 0; size_t off = 0;
        while (off < (size_t)n && count < 8) {
            uint32_t size = (uint32_t)test_be(plain + off, 4);
            assert(size >= MRP_DATA_HDR_LEN && off + size <= (size_t)n);
            int type;
            assert(!strcmp(mrp_diag_protobuf(plain + off + MRP_DATA_HDR_LEN,
                size - MRP_DATA_HDR_LEN, &type), "protobuf"));
            types[count++] = (unsigned)type;
            off += size;
        }
        assert(off == (size_t)n);
        if (capture) {
            assert(count == 3 && types[0] == 15 && types[1] == 38 && types[2] == 16);
            uint8_t *state = NULL; int state_len = 0; uint64_t generation;
            m->state_dirty = true;
            assert(!ap2_mrp_prepare_state_push(m, &state, &state_len, &generation));
        } else {
            assert(count > 3); /* plain attach still carries now-playing */
        }
        ap2_mrp_destroy(m); close(data[1]); close(event[1]);
    }
}
static void test_session_volume_contract(void)
{
    test_volume_optional_transport();
    test_capture_datastream_receive_only();
    test_volume_driver();
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL, "1", "test", NULL, NULL, NULL, 0);
    assert(m);
    int pair[2]; assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    m->sock = pair[0]; m->connected = true;
    ap2_mrp_set_volume_mode(m, true);
    ap2_mrp_set_volume_callback(m, contract_callback, NULL);
    volume_calls = 0;
    cli_config_t cfg = {.protocol = PROTO_AIRPLAY2};
    ap2_device_info_t device = {.name = "volume test", .address = "127.0.0.1", .port = 7000};
    ap2_audio_format_t format = {.sample_rate = 44100, .bit_depth = 16, .channels = 2};
    g_ap2cl = ap2cl_create(&device, &format, NULL, NULL, "0011223344556677", "1", 600, 50);
    assert(g_ap2cl);
    ap2cl_test_set_mrp(g_ap2cl, m);
    contract_bind(&cfg);
    assert(m->volume.output_len == 3 && m->volume.generation == 7);
    uint64_t in = 0, out = 0; uint8_t plain[8192];
    assert(contract_send(m, pair[1], &in, &out, 49, 0, false, "comm", plain) == MRP_DATA_HDR_LEN);
    contract_state(&cfg, "1", "0");
    assert(m->volume.known && m->volume.milli == 0);
    assert(contract_send(m, pair[1], &in, &out, 49, 0, false, "comm", plain) == MRP_DATA_HDR_LEN);
    /* Root telemetry with an otherwise VALID public Set decoy never dispatches.
     * The original observer envelope reader deliberately remains unchanged. */
    int telemetry_len; uint8_t *candidate = contract_payload(51, .63f, false, &telemetry_len);
    const uint8_t *blob; size_t blob_len;
    assert(ap2_bplist_get_params_data(candidate, (size_t)telemetry_len, &blob, &blob_len));
    ap2_pl_node *telemetry = ap2_pl_dict(), *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "data", ap2_pl_data(blob, blob_len));
    ap2_pl_dict_set(telemetry, "params", params);
    ap2_pl_dict_set(telemetry, "type", ap2_pl_string("receiverVolumeDidChange"));
    uint8_t *body; int body_len = ap2_pl_serialize(telemetry, &body); ap2_pl_free(telemetry);
    assert(ap2_bplist_get_params_data(body, (size_t)body_len, &blob, &blob_len));
    volume_send(m, pair[1], false, &in, &out, body, body_len);
    assert(volume_calls == 0); free(body); free(candidate);
    /* Known backend is insufficient to open native publication. */
    assert(!mrp_volume_publication_allowed(m));
    m->verified_volume_identity = true;
    m->volume_published_revision = 1;
    int n = contract_send(m, pair[1], &in, &out, 49, 0, false, "comm", plain);
    assert(n > 2 * MRP_DATA_HDR_LEN);
    const uint8_t *p; size_t bytes;
    assert(ap2_bplist_get_params_data(plain + 2 * MRP_DATA_HDR_LEN,
        (size_t)n - 2 * MRP_DATA_HDR_LEN, &p, &bytes));
    const uint8_t *end = p + bytes; uint64_t pb_len;
    assert(mrp_diag_varint(&p, end, &pb_len));
    struct mrp_diag_reader r = {.p = p, .end = end}; bool correlation = false, result = false;
    while (r.p < r.end) {
        struct mrp_diag_field f; assert(mrp_diag_field(&r, &f));
        if (f.number == 2) { assert(f.len == 3 && !memcmp(f.data, "c\0r", 3)); correlation = true; }
        assert(f.number != 85);
        if (f.number == 54) { assert(f.len == 5 && f.data[0] == 13 && !memcmp(f.data + 1, "\0\0\0\0", 4)); result = true; }
    }
    assert(correlation && result);
    assert(contract_send(m, pair[1], &in, &out, 51, .63f, true, "comm", plain) == MRP_DATA_HDR_LEN);
    assert(volume_calls == 0);
    assert(contract_send(m, pair[1], &in, &out, 51, .63f, false, "dvlc", plain) == MRP_DATA_HDR_LEN);
    assert(contract_send(m, pair[1], &in, &out, 50, .63f, false, "comm", plain) == MRP_DATA_HDR_LEN);
    assert(contract_send(m, pair[1], &in, &out, 52, .63f, false, "comm", plain) == MRP_DATA_HDR_LEN);
    assert(volume_calls == 0);
    assert(contract_send(m, pair[1], &in, &out, 51, NAN, false, "comm", plain) == MRP_DATA_HDR_LEN);
    assert(volume_calls == 0);
    assert(contract_send(m, pair[1], &in, &out, 51, .63f, false, "comm", plain) == MRP_DATA_HDR_LEN);
    assert(volume_calls == 1 && volume_last == 630 && m->volume.milli == 0);
    assert(contract_send(m, pair[1], &in, &out, 51, .63f, false, "comm", plain) == MRP_DATA_HDR_LEN);
    assert(volume_calls == 1); /* replay */
    stage_line(&cfg, "SESSION_VOLUME_GENERATION", "7");
    stage_line(&cfg, "SESSION_VOLUME_ORDINAL", "1");
    stage_line(&cfg, "SESSION_VOLUME_RESULT", "committed");
    stage_line(&cfg, "SESSION_VOLUME_REVISION", "2");
    stage_line(&cfg, "SESSION_VOLUME_KNOWN", "1");
    stage_line(&cfg, "SESSION_VOLUME_MILLI", "610");
    stage_line(&cfg, "ACTION", "SESSION_VOLUME_COMPLETE");
    assert(m->volume.known && m->volume.milli == 610);
    ap2_mrp_tick(m);
    n = contract_read(m, pair[1], &out, plain);
    assert(n > MRP_DATA_HDR_LEN);
    /* Strict parser: missing, duplicate, overflow, mixed namespace and leftovers. */
    contract_state(&cfg, "3", "1001"); assert(m->volume.revision == 2);
    stage_line(&cfg, "SESSION_VOLUME_GENERATION", "7");
    stage_line(&cfg, "SESSION_VOLUME_GENERATION", "7");
    contract_state(&cfg, "3", "1"); assert(m->volume.revision == 2);
    contract_state(&cfg, "18446744073709551616", "1"); assert(m->volume.revision == 2);
    stage_line(&cfg, "STREAM_VOLUME_GENERATION", "7");
    contract_state(&cfg, "3", "1"); assert(m->volume.revision == 2);
    stage_line(&cfg, "ACTION", "SESSION_VOLUME_STATE"); assert(m->volume.revision == 2);
    contract_state(&cfg, "3", "1"); assert(m->volume.revision == 3);
    stage_line(&cfg, "SESSION_VOLUME_GENERATION", "7");
    stage_line(&cfg, "SESSION_VOLUME_REVISION", "4");
    stage_line(&cfg, "SESSION_VOLUME_KNOWN", "0");
    stage_line(&cfg, "SESSION_VOLUME_MILLI", "0");
    stage_line(&cfg, "ACTION", "SESSION_VOLUME_STATE");
    assert(m->volume.revision == 3); /* unknown MUST omit milli */
    stage_line(&cfg, "SESSION_VOLUME_GENERATION", "7");
    stage_line(&cfg, "SESSION_VOLUME_REVISION", "4");
    stage_line(&cfg, "SESSION_VOLUME_KNOWN", "0");
    stage_line(&cfg, "ACTION", "SESSION_VOLUME_STATE");
    assert(m->volume.revision == 4 && !m->volume.known);
    /* Leave no pending test publication before teardown. */
    m->verified_volume_identity = false;
    ap2cl_test_set_mrp(g_ap2cl, NULL);
    ap2cl_destroy(g_ap2cl); g_ap2cl = NULL;
    ap2_mrp_destroy(m); close(pair[1]);
}
