/* Observe-only public-schema fixtures through real encrypted input channels.
 * These are synthetic fixtures, NOT measured HomePod volume wire messages. */
static uint8_t *volume_payload(unsigned type, unsigned extension,
                               const uint8_t *payload, size_t bytes, int *len)
{
    mbuf pb = {0}, blob = {0};
    assert(pb_put_varint(&pb, 8) && pb_put_varint(&pb, type));
    assert(pb_put_varint(&pb, ((uint64_t)extension << 3) | 2));
    assert(pb_put_varint(&pb, bytes) && mbuf_put(&pb, payload, bytes));
    assert(pb_put_varint(&blob, pb.len) && mbuf_put(&blob, pb.p, pb.len));
    uint8_t *result = diag_payload(blob.p, blob.len, len);
    mbuf_free(&blob);
    mbuf_free(&pb);
    return result;
}

/* Coalesce two plaintext requests into one encrypted write, then fragment its
 * first length byte. Decrypt the actual replies and verify the unchanged ACK. */
static void volume_send(struct ap2_mrp_ctx *m, int fd, bool event,
                         uint64_t *counter, uint64_t *ack_counter,
                         const uint8_t *b, int len)
{
    uint8_t request[4096];
    int header = event ? snprintf((char *)request, sizeof(request),
        "POST /command HTTP/1.1\r\nContent-Type: SECRET_CONTENT_TYPE\r\n"
        "Content-Length: %d\r\n\r\n", len) : MRP_DATA_HDR_LEN;
    if (!event) mrp_write_data_header(request, "sync", "comm", 77, len);
    memcpy(request + header, b, (size_t)len);
    int size = header + len;
    assert(size * 2 < (int)sizeof(request));
    memcpy(request + size, request, (size_t)size);
    uint8_t *encrypted = NULL;
    int n = mrp_channel_encrypt_with(event ? m->event_in_key : m->in_key,
        counter, request, size * 2, &encrypted);
    assert(n > 0 && write(fd, encrypted, 1) == 1);
    ap2_mrp_tick(m);
    assert(write(fd, encrypted + 1, (size_t)n - 1) == n - 1);
    free(encrypted);
    ap2_mrp_tick(m);
    uint8_t ack[4096], plain[4096];
    int received = 0;
    ssize_t got;
    while ((got = recv(fd, ack + received, sizeof(ack) - (size_t)received,
                       MSG_DONTWAIT)) > 0) received += (int)got;
    assert(received > 0);
    int plain_len = 0;
    assert(mrp_drain_channel_frames(ack, &received, plain, &plain_len,
        sizeof(plain), event ? m->event_out_key : m->out_key, ack_counter, "test"));
    assert(received == 0);
    if (event) {
        static const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
            "Audio-Latency: 0\r\n\r\n";
        assert(plain_len == 2 * (int)(sizeof(response) - 1));
        assert(!memcmp(plain, response, sizeof(response) - 1));
        assert(!memcmp(plain + sizeof(response) - 1, response, sizeof(response) - 1));
    } else {
        uint8_t expected[MRP_DATA_HDR_LEN];
        static const char zero[4] = {0};
        mrp_write_data_header(expected, "rply", zero, 77, 0);
        assert(plain_len == 2 * MRP_DATA_HDR_LEN);
        assert(!memcmp(plain, expected, sizeof(expected)));
        assert(!memcmp(plain + sizeof(expected), expected, sizeof(expected)));
    }
}

static void test_observe_only_volume(void)
{
    /* Bound field-count work even when all unknown fields fit the byte bound. */
    mbuf many = {0};
    for (unsigned i = 0; i < 257; i++) {
        assert(pb_put_varint(&many, (uint64_t)(100 + i) << 3));
        assert(pb_put_varint(&many, 0));
    }
    struct mrp_diag_reader bounded = {.p = many.p, .end = many.p + many.len};
    struct mrp_diag_field field;
    for (unsigned i = 0; i < 256; i++) assert(mrp_diag_field(&bounded, &field));
    assert(!mrp_diag_field(&bounded, &field));
    mbuf_free(&many);
    static const struct {
        unsigned type, extension;
        uint8_t data[32];
        size_t bytes;
        const char *message, *value_state, *target;
        int milli, available, capabilities;
    } cases[] = {
        {51,55,{13,0,0,0,63,18,6,'S','E','C','R','E','T'},13,
            "volume_set_candidate","valid","unresolved",500,-1,-1},
        {52,56,{13,0,0,128,63,26,0},7,"volume_feedback","valid","unresolved",1000,-1,-1},
        {50,54,{13,0,0,0,0},5,"volume_result","valid","missing",0,-1,-1},
        {49,53,{10,6,'S','E','C','R','E','T'},8,"volume_get","missing","unresolved",-1,-1,-1},
        {17,22,{8,1,16,3},4,"volume_capability","missing","missing",-1,1,3},
        {64,68,{10,4,8,0,16,2,26,0},8,"volume_capability","missing","unresolved",-1,0,2},
        {51,55,{0},0,"invalid","missing","missing",-1,-1,-1},
        {51,56,{13,0,0,0,63},5,"invalid","missing","missing",-1,-1,-1},
        {51,55,{13,0,0,192,127},5,"invalid","invalid","missing",-1,-1,-1}, /* NaN */
        {51,55,{13,0,0,128,127},5,"invalid","invalid","missing",-1,-1,-1}, /* inf */
        {51,55,{13,0,0,0,191},5,"invalid","invalid","missing",-1,-1,-1}, /* -.5 */
        {51,55,{13,0,0,0,64},5,"invalid","invalid","missing",-1,-1,-1}, /* 2 */
        {51,55,{8,1},2,"invalid","invalid","missing",-1,-1,-1},
        {51,55,{13,0,0,0,63,13,0,0,0,63},10,"invalid","invalid","missing",-1,-1,-1},
        {52,56,{18,8,'S'},3,"invalid","missing","missing",-1,-1,-1},
        {17,22,{8,2},2,"invalid","missing","missing",-1,-1,-1},
        {17,22,{16,4},2,"invalid","missing","missing",-1,-1,-1},
        {64,68,{10,2,8,128},4,"invalid","missing","missing",-1,-1,-1},
        {52,56,{34,5,13,0,0,0,63},7,"volume_feedback","missing","missing",-1,-1,-1}, /* nested decoy */
        {139,55,{13,0,0,0,63},5,"unknown","missing","missing",-1,-1,-1},
        {51,55,{13,0,0,0,63,33,0,0,0,0,0,0,0,0,40,1,50,2,'S','E',61,0,0,0,0},25,
            "volume_set_candidate","valid","missing",500,-1,-1}, /* skip wire 1/0/2/5 */
        {51,55,{160,1,1,160,1,2},6,"invalid","missing","missing",-1,-1,-1}, /* duplicate unknown */
        {51,55,{18,1,'X',10,0},5,"invalid","invalid","missing",-1,-1,-1},
        {51,55,{18,1,'X'},3,"invalid","missing","missing",-1,-1,-1}, /* target but no level */
        {50,54,{0},0,"volume_result","missing","missing",-1,-1,-1},
        {52,56,{18,1,'X'},3,"volume_feedback","missing","unresolved",-1,-1,-1},
        {17,22,{16,2},2,"volume_capability","missing","missing",-1,-1,2}, /* optional available absent */
    };
    int events[2], data[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, events));
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, data));
    uint8_t secret[32] = {2};
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL, "1",
        "SECRET_METADATA", NULL, NULL, secret, sizeof(secret));
    assert(m && ap2_mrp_attach_events(m, events[0]));
    m->sock = data[0];
    m->connected = true;
    ap2_mrp_set_experimental_homepod_remote(m, true);
    unsigned callbacks = 0;
    ap2_mrp_set_remote_command_callback(m, diag_callback, &callbacks);
    uint64_t event_counter = 0, data_counter = 0, event_ack = 0, data_ack = 0;
    int saved = dup(STDERR_FILENO);
    FILE *capture = tmpfile();
    assert(saved >= 0 && capture && dup2(fileno(capture), STDERR_FILENO) >= 0);
    log_level previous_level = *loglevel;
    *loglevel = lDEBUG;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int len;
        uint8_t *b = volume_payload(cases[i].type, cases[i].extension,
            cases[i].data, cases[i].bytes, &len);
        int type;
        const char *classification = mrp_diag_protobuf(b, (size_t)len, &type);
        struct mrp_diag_volume v = mrp_diag_volume(b, (size_t)len, -1, classification);
        assert(!strcmp(v.message, cases[i].message));
        assert(!strcmp(v.value_state, cases[i].value_state));
        assert(!strcmp(v.target, cases[i].target));
        assert(v.value_milli == cases[i].milli && v.available == cases[i].available &&
               v.capabilities == cases[i].capabilities);
        volume_send(m, events[1], true, &event_counter, &event_ack, b, len);
        volume_send(m, data[1], false, &data_counter, &data_ack, b, len);
        free(b);
    }
    /* Known root telemetry stays telemetry for arbitrary values. Nested data is
     * not a root params.data binding and must not reveal a semantic decoy. */
    for (unsigned i = 0; i < 2; i++) {
        ap2_pl_node *root = ap2_pl_dict();
        ap2_pl_dict_set(root, "type", ap2_pl_string(i ? "SECRET_TYPE" : "receiverVolumeDidChange"));
        ap2_pl_dict_set(root, "value", ap2_pl_string("SECRET_VALUE"));
        ap2_pl_node *nested = ap2_pl_dict();
        static const uint8_t decoy[] = {9,8,51,186,3,5,13,0,0,0,63};
        ap2_pl_dict_set(nested, "data", ap2_pl_data(decoy, sizeof(decoy)));
        ap2_pl_dict_set(root, "SECRET_FIELD", nested);
        uint8_t *b = NULL;
        int len = ap2_pl_serialize(root, &b);
        ap2_pl_free(root);
        struct mrp_diag_volume v = mrp_diag_volume(b, (size_t)len, -1, "unknown");
        assert(!strcmp(v.message, i ? "unknown" : "receiver_telemetry"));
        volume_send(m, events[1], true, &event_counter, &event_ack, b, len);
        free(b);
    }
    static const struct { uint8_t data[16]; size_t bytes; } malformed[] = {
        {{2,8,51},3}, /* missing matching extension */
        {{8,8,51,186,3,0,186,3,0},9}, /* duplicate extension */
        {{5,8,51,184,3,0},6}, /* wrong extension wire */
        {{4,8,51,8,51},5}, /* duplicate type */
        {{6,8,51,186,3,2,13},7}, /* truncated extension */
        {{7,8,51,16,0,186,3,0},8}, /* identifier wrong wire */
        {{13,8,51,186,3,5,13,0,0,0,63,194,3,0},14}, /* extra distinct extension */
    };
    for (size_t i = 0; i < sizeof(malformed)/sizeof(malformed[0]); i++) {
        int len, type;
        uint8_t *b = diag_payload(malformed[i].data, malformed[i].bytes, &len);
        const char *classification = mrp_diag_protobuf(b, (size_t)len, &type);
        struct mrp_diag_volume v = mrp_diag_volume(b, (size_t)len, -1, classification);
        assert(!strcmp(v.message, "invalid") && v.value_milli == -1 &&
               !strcmp(v.target, "missing"));
        volume_send(m, events[1], true, &event_counter, &event_ack, b, len);
        volume_send(m, data[1], false, &data_counter, &data_ack, b, len);
        free(b);
    }
    for (unsigned duplicate_params = 0; duplicate_params < 2; duplicate_params++) {
        ap2_pl_node *root = ap2_pl_dict();
        ap2_pl_node *params = ap2_pl_dict();
        static const uint8_t candidate[] = {10,8,51,186,3,5,13,0,0,0,63};
        ap2_pl_dict_set(params, "data", ap2_pl_data(candidate, sizeof(candidate)));
        if (!duplicate_params)
            ap2_pl_dict_set(params, "data", ap2_pl_data(candidate, sizeof(candidate)));
        ap2_pl_dict_set(root, "params", params);
        if (duplicate_params) ap2_pl_dict_set(root, "params", ap2_pl_dict());
        uint8_t *b = NULL;
        int len = ap2_pl_serialize(root, &b);
        ap2_pl_free(root);
        struct mrp_diag_volume v = mrp_diag_volume(b, (size_t)len, -1, "unknown");
        assert(!strcmp(v.message, "unknown")); /* ambiguous container rejected */
        volume_send(m, events[1], true, &event_counter, &event_ack, b, len);
        free(b);
    }
    assert(callbacks == 0);
    /* Saturate the shared event/DataStream budget with telemetry, then prove
     * the existing transport callback and both ACK paths still work. */
    int len;
    uint8_t *b = volume_payload(51, 55, cases[0].data, cases[0].bytes, &len);
    for (unsigned i = 0; i < 70; i++)
        volume_send(m, data[1], false, &data_counter, &data_ack, b, len);
    free(b);
    assert(m->diagnostic_count == 128 && callbacks == 0);
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(root, "value", ap2_pl_string("play"));
    len = ap2_pl_serialize(root, &b);
    ap2_pl_free(root);
    volume_send(m, events[1], true, &event_counter, &event_ack, b, len);
    free(b);
    assert(callbacks == 2 && m->diagnostic_count == 128);
    fflush(stderr);
    *loglevel = previous_level;
    assert(dup2(saved, STDERR_FILENO) >= 0);
    close(saved);
    rewind(capture);
    char line[2048];
    unsigned records = 0, golden_records = 0;
    /* Captured from this encrypted test. Only elapsed_ms varies between runs. */
    FILE *golden = fopen("tests/fixtures/homepod_volume_diagnostics.txt", "r");
    assert(golden);
    bool saw_telemetry = false, saw_candidate = false;
    while (fgets(line, sizeof(line), capture)) {
        assert(!strstr(line, "SECRET") && !strstr(line, "534543524554") &&
               !strstr(line, "5345435245545f") && !strstr(line, "hex="));
        if (!strstr(line, "[STATUS] homepod_remote ")) continue;
        if (strstr(line, "ordinal=1 ") || strstr(line, "ordinal=17 ")) {
            char expected[2048];
            assert(fgets(expected, sizeof(expected), golden));
            const char *actual_fields = strstr(line, " channel=");
            const char *expected_fields = strstr(expected, " channel=");
            assert(actual_fields && expected_fields && !strcmp(actual_fields, expected_fields));
            golden_records++;
        }
        assert(strstr(line, "dispatched=0"));
        assert(!strstr(line, "session_group"));
        if (strstr(line, "value_state=missing") || strstr(line, "value_state=invalid"))
            assert(!strstr(line, "value_milli="));
        if (strstr(line, "message=invalid"))
            assert(!strstr(line, "available=") && !strstr(line, "capabilities="));
        if (strstr(line, "message=receiver_telemetry")) saw_telemetry = true;
        if (strstr(line, "message=volume_set_candidate")) saw_candidate = true;
        records++;
    }
    assert(records == 128 && saw_telemetry && saw_candidate && golden_records == 2);
    fclose(golden);
    fclose(capture);
    ap2_mrp_destroy(m);
    close(events[1]);
    close(data[1]);
}

/* Private capture is aggregate-only: real encrypted fixture traffic reaches
 * both pre-whitelist event ingress and post-decrypt DataStream ingress without
 * retaining the fixture's injected strings or identifiers. */
static void test_private_native_volume_capture(void)
{
    struct ap2_mrp_ctx *off = ap2_mrp_create("127.0.0.1", 7000, NULL, "1",
        "SECRET_METADATA", "SECRET_SESSION", "SECRET_GROUP", NULL, 0);
    assert(off);
    int saved = dup(STDERR_FILENO);
    FILE *capture = tmpfile();
    assert(saved >= 0 && capture && dup2(fileno(capture), STDERR_FILENO) >= 0);
    ap2_mrp_stop(off);
    fflush(stderr);
    rewind(capture);
    char line[2048];
    assert(!fgets(line, sizeof(line), capture)); /* default off */
    assert(dup2(saved, STDERR_FILENO) >= 0);
    close(saved);
    fclose(capture);
    ap2_mrp_destroy(off);

    int events[2], data[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, events));
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, data));
    uint8_t secret[32] = {3};
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL, "1",
        "SECRET_METADATA", "SECRET_SESSION", "SECRET_GROUP", secret, sizeof(secret));
    assert(m && ap2_mrp_attach_events(m, events[0]));
    m->sock = data[0];
    m->connected = true;
    m->data_attached = true;
    ap2_mrp_set_experimental_homepod_remote(m, true);
    ap2_mrp_set_private_native_volume_capture(m, true);
    saved = dup(STDERR_FILENO);
    capture = tmpfile();
    assert(saved >= 0 && capture && dup2(fileno(capture), STDERR_FILENO) >= 0);
    uint64_t event_in = 0, data_in = 0, event_out = 0, data_out = 0;
    int len;
    static const uint8_t malformed_change[] = {13,0,0,0,63,18,14,
        'S','E','C','R','E','T','_','S','E','S','S','I','O','N',24,1};
    uint8_t *malformed = volume_payload(52, 56, malformed_change,
        sizeof(malformed_change), &len);
    volume_send(m, data[1], false, &data_in, &data_out, malformed, len);
    free(malformed);
    assert(!m->capture_endpoint_session_match);
    assert(!m->capture_output_session_match);
    static const uint8_t candidate[] = {13,0,0,0,63,18,13,
        'S','E','C','R','E','T','_','T','A','R','G','E','T'};
    uint8_t *body = volume_payload(51, 55, candidate, sizeof(candidate), &len);
    volume_send(m, events[1], true, &event_in, &event_out, body, len);
    for (unsigned i = 0; i < 64; ++i)
        volume_send(m, data[1], false, &data_in, &data_out, body, len);
    free(body);
    static const uint8_t get[] = {10,5,'O','T','H','E','R'};
    static const uint8_t result[] = {13,0,0,0,63};
    static const uint8_t change[] = {13,0,0,0,63,18,14,
        'S','E','C','R','E','T','_','S','E','S','S','I','O','N',26,5,'O','T','H','E','R'};
    static const uint8_t availability[] = {8,1,16,3};
    static const uint8_t capabilities[] = {10,4,8,1,16,2,26,5,'O','T','H','E','R'};
    const unsigned types[] = {49,50,52,17,64};
    const unsigned extensions[] = {53,54,56,22,68};
    const uint8_t *payloads[] = {get,result,change,availability,capabilities};
    const size_t sizes[] = {sizeof(get),sizeof(result),sizeof(change),sizeof(availability),sizeof(capabilities)};
    for (unsigned i = 0; i < 5; ++i) {
        body = volume_payload(types[i], extensions[i], payloads[i], sizes[i], &len);
        volume_send(m, data[1], false, &data_in, &data_out, body, len);
        free(body);
    }
    ap2_pl_node *transport_root = ap2_pl_dict();
    ap2_pl_dict_set(transport_root, "type", ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(transport_root, "value", ap2_pl_string("play"));
    len = ap2_pl_serialize(transport_root, &body);
    ap2_pl_free(transport_root);
    volume_send(m, events[1], true, &event_in, &event_out, body, len);
    free(body);
    m->volume.generation = UINT64_C(4294967297);
    m->capture_records = UINT64_MAX;
    mrp_capture_egress(m, true); /* Force saturation without unbounded traffic. */
    ap2_mrp_stop(m);
    fflush(stderr);
    assert(dup2(saved, STDERR_FILENO) >= 0);
    close(saved);
    rewind(capture);
    assert(fgets(line, sizeof(line), capture));
    assert(strstr(line, "[STATUS] native_volume_capture version=1") &&
        strstr(line, "overflow=1") && strstr(line, "volume_get=2") &&
        strstr(line, "volume_result=2") && strstr(line, "volume_set_candidate=130") &&
        strstr(line, "volume_feedback=2") && strstr(line, "volume_availability=2") &&
        strstr(line, "volume_capabilities=2") && strstr(line, "transport=2") &&
        strstr(line, "parser_valid=140") && strstr(line, "parser_invalid=2") &&
        strstr(line, "parser_unknown=2") && strstr(line, "generation_at_cutoff=4294967297") && strstr(line, "event_at_cutoff=connected") &&
        strstr(line, "datastream_at_cutoff=connected") && strstr(line, "endpoint_session_match=1") &&
        strstr(line, "output_session_match=0") && strstr(line, "dacp=outside_cli") &&
        strstr(line, "publication=0") &&
        !strstr(line, "SECRET") && !strstr(line, "TARGET") && !strstr(line, "534543"));
    assert(!fgets(line, sizeof(line), capture));
    fclose(capture);
    ap2_mrp_destroy(m);
    close(events[1]);
    close(data[1]);
}

static void *capture_summary_thread(void *context)
{
    mrp_capture_summary(context);
    return NULL;
}

/* A stalled stderr consumer must not hold the receive-path capture mutex. */
static void test_private_capture_summary_releases_receive_lock(void)
{
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL,
        "1", "capture", NULL, NULL, NULL, 0);
    assert(m);
    ap2_mrp_set_experimental_homepod_remote(m, true);
    ap2_mrp_set_private_native_volume_capture(m, true);
    mrp_capture_freeze(m);
    int saved = dup(STDERR_FILENO);
    FILE *output = tmpfile();
    assert(saved >= 0 && output && dup2(fileno(output), STDERR_FILENO) >= 0);
    flockfile(stderr);
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, capture_summary_thread, m));
    bool available = false;
    uint64_t deadline = ap2_io_monotonic_ms() + 2000;
    while (ap2_io_monotonic_ms() < deadline) {
        if (!pthread_mutex_trylock(&m->capture_lock)) {
            available = m->capture_emitted;
            pthread_mutex_unlock(&m->capture_lock);
            if (available) break;
        }
        usleep(1000);
    }
    if (available) mrp_capture_egress(m, true);
    funlockfile(stderr);
    assert(!pthread_join(thread, NULL));
    fflush(stderr);
    assert(dup2(saved, STDERR_FILENO) >= 0);
    close(saved);
    fclose(output);
    ap2_mrp_destroy(m);
    assert(available);
}
