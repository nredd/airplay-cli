/* Exercise the real cmdpipe handler and both MRP serializers without hardware.
 * Include the implementations to inspect private state, not a parallel model. */
#undef NDEBUG
#include <assert.h>
#define main cliairplay_program_main
#include "../src/cliairplay.c"
#undef main
#include "../src/ap2_mrp.c"
#include "mrp_jpeg_fixture.h"

void ap2cl_test_set_mrp(struct ap2cl_s *p, struct ap2_mrp_ctx *m);

/* Read only serializer-owned, well-formed plists. Find a dictionary value's
 * object offset; this also lets assertions distinguish plist bools from ints. */
static uint64_t test_be(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    while (n--) v = (v << 8) | *p++;
    return v;
}

static size_t test_object(const uint8_t *b, size_t len, uint64_t ref)
{
    const uint8_t *t = b + len - 32;
    return (size_t)test_be(b + test_be(t + 24, 8) + ref * t[6], t[6]);
}

static size_t test_count(const uint8_t *b, size_t *pos)
{
    size_t count = b[(*pos)++] & 15;
    if (count == 15) {
        size_t n = (size_t)1 << (b[(*pos)++] & 15);
        count = (size_t)test_be(b + *pos, n);
        *pos += n;
    }
    return count;
}

static size_t test_value(const uint8_t *b, size_t len, const char *key)
{
    const uint8_t *t = b + len - 32;
    for (uint64_t ref = 0; ref < test_be(t + 8, 8); ref++) {
        size_t pos = test_object(b, len, ref);
        if ((b[pos] & 0xf0) != 0xd0) continue;
        size_t count = test_count(b, &pos);
        for (size_t i = 0; i < count; i++) {
            size_t kp = test_object(b, len, test_be(b + pos + i * t[7], t[7]));
            if ((b[kp] & 0xf0) != 0x50) continue;
            size_t chars = test_count(b, &kp);
            if (strlen(key) == chars && !memcmp(b + kp, key, chars))
                return test_object(b, len,
                    test_be(b + pos + (count + i) * t[7], t[7]));
        }
    }
    return 0;
}

static void check_commands(struct ap2_mrp_ctx *m, bool live)
{
    uint8_t *b = NULL;
    int len = 0;
    assert(ap2_mrp_build_supportedcommands_command(m, &b, &len));
    size_t pos = test_value(b, (size_t)len, "mrSupportedCommandsFromSender");
    assert(pos && (b[pos] & 0xf0) == 0xa0);
    size_t count = test_count(b, &pos);
    static const int baseline[] = {26,25,24,18,17,10,11,8,9,5,4,3,2,1,0};
    static const int radio[] = {0,1,2,4,5};
    bool restricted = live || m->experimental_homepod_remote;
    const int *expected = restricted ? radio : baseline;
    assert(count == (restricted ? 5 : 15));
    for (size_t i = 0; i < count; i++) {
        size_t blob = test_object(b, (size_t)len,
            test_be(b + pos + i * b[len - 25], b[len - 25]));
        assert((b[blob] & 0xf0) == 0x40);
        size_t bytes = test_count(b, &blob);
        uint64_t cmd = 999;
        assert(ap2_bplist_find_uint(b + blob, bytes, "kCommandInfoCommandKey", &cmd));
        assert(cmd == (uint64_t)expected[i]);
        if (restricted) {
            size_t enabled = test_value(b + blob, bytes, "kCommandInfoEnabledKey");
            assert(enabled && b[blob + enabled] == 0x09);
            assert(!test_value(b + blob, bytes, "kCommandInfoOptionsKey"));
        }
    }
    free(b);
}

/* Minimal proto2 reader for the owned SET_STATE payload. Skip fields by wire
 * type, so a value in artwork or a title cannot masquerade as a live flag. */
static uint64_t test_varint(mbuf *b)
{
    uint64_t v = 0;
    for (unsigned shift = 0; shift < 64; shift += 7) {
        assert(b->len);
        uint8_t c = *b->p++;
        b->len--;
        v |= (uint64_t)(c & 127) << shift;
        if (!(c & 128)) return v;
    }
    abort();
}

static bool test_pb_field(mbuf b, unsigned field, mbuf *payload, uint64_t *value)
{
    while (b.len) {
        uint64_t tag = test_varint(&b);
        unsigned wire = tag & 7;
        uint64_t v = 0;
        size_t size = 0;
        if (wire == 0) v = test_varint(&b);
        else if (wire == 1) size = 8;
        else if (wire == 2) size = (size_t)test_varint(&b);
        else if (wire == 5) size = 4;
        else abort();
        assert(size <= b.len);
        if ((tag >> 3) == field) {
            if (payload) *payload = (mbuf){.p = b.p, .len = size};
            if (value) *value = v;
            return true;
        }
        b.p += size;
        b.len -= size;
    }
    return false;
}

static void check_state(struct ap2_mrp_ctx *m, bool live, bool duration)
{
    uint8_t *b = NULL;
    int len = 0;
    assert(ap2_mrp_build_nowplaying_command(m, &b, &len));
    size_t flag = test_value(b, (size_t)len, "kMRMediaRemoteNowPlayingInfoIsAlwaysLive");
    assert(live ? flag && b[flag] == 0x09 : !flag);
    assert((test_value(b, (size_t)len, "kMRMediaRemoteNowPlayingInfoDuration") != 0) == duration);
    uint64_t uid = 0;
    assert(ap2_bplist_find_uint(b, (size_t)len,
        "kMRMediaRemoteNowPlayingInfoUniqueIdentifier", &uid));
    assert(uid == m->np_uid);
    if (m->artwork_len > 0) {
        size_t art = test_value(b, (size_t)len,
            "kMRMediaRemoteNowPlayingInfoArtworkIdentifier");
        assert(art && (b[art] & 0xf0) == 0x50);
        size_t chars = test_count(b, &art);
        assert(chars == strlen(m->artwork_id));
        assert(!memcmp(b + art, m->artwork_id, chars));
    }
    free(b);
    /* Decode both optional type-130 metadata messages and command list. */
    mbuf state = {0}, inner, npi, queue, item, meta, commands;
    uint64_t value = 0;
    assert(build_set_state(m, true, &state));
    assert(test_pb_field(state, MRP_EXT_SET_STATE, &inner, NULL));
    assert(test_pb_field(inner, 1, &npi, NULL));
    assert(test_pb_field(npi, 3, NULL, NULL) == duration);
    assert(test_pb_field(npi, 17, NULL, &value) == live);
    if (live) assert(value == 1);
    assert(test_pb_field(inner, 3, &queue, NULL));
    assert(test_pb_field(queue, 2, &item, NULL));
    assert(test_pb_field(item, 2, &meta, NULL));
    assert(test_pb_field(meta, 14, NULL, NULL) == duration);
    assert(test_pb_field(meta, 37, NULL, &value) == live);
    if (live) assert(value == 1);
    assert(test_pb_field(inner, 2, &commands, NULL));
    static const unsigned expected[] = {1, 2, 3, 5, 6};
    for (size_t i = 0; i < 5; i++) {
        mbuf ci;
        assert(test_pb_field(commands, 1, &ci, NULL));
        assert(test_pb_field(ci, 1, NULL, &value) && value == expected[i]);
        assert(test_pb_field(ci, 2, NULL, &value) && value == 1);
        size_t consumed = (size_t)(ci.p + ci.len - commands.p);
        commands.p += consumed;
        commands.len -= consumed;
    }
    assert(commands.len == 0);
    mbuf_free(&state);
    check_commands(m, live);
}

static void test_live_bundle(bool experimental)
{
    cli_config_t cfg = {.protocol = PROTO_AIRPLAY2};
    ap2_device_info_t device = {.name = "live test", .address = "127.0.0.1", .port = 7000};
    ap2_audio_format_t format = {.sample_rate = 44100, .bit_depth = 16, .channels = 2};
    g_ap2cl = ap2cl_create(&device, &format, NULL, NULL,
        "0011223344556677", "1", 600, 50);
    assert(g_ap2cl);
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL,
        "0011223344556677", "Live test", NULL, NULL, NULL, 0);
    assert(m);
    ap2_mrp_set_experimental_homepod_remote(m, experimental);
    ap2cl_test_set_mrp(g_ap2cl, m);
    handle_command("TITLE", "Finite track", &cfg);
    handle_command("ITEMID", "station-id", &cfg);
    handle_command("DURATION", "180", &cfg);
    handle_command("ACTION", "SENDMETA", &cfg);
    assert(m->duration_ms == 180000);
    check_state(m, false, true);
    uint64_t uid = m->np_uid;
    ap2_mrp_artwork_info_t info;
    assert(ap2_mrp_set_artwork(m, "image/jpeg", k_baseline_jpeg,
        sizeof(k_baseline_jpeg), &info));
    char art_id[17];
    memcpy(art_id, m->artwork_id, sizeof(art_id));

    handle_command("IS_LIVE", "1", &cfg);
    /* Staging cannot alter a published item, even on an intervening progress. */
    handle_command("PROGRESS", "12", &cfg);
    check_state(m, false, true);
    handle_command("TITLE", "KCRW programme", &cfg);
    handle_command("ACTION", "SENDMETA", &cfg);
    assert(m->duration_ms == 0);
    assert(m->np_uid == uid && !strcmp(art_id, m->artwork_id));
    check_state(m, true, false);
    static const char *invalid[] = {"", "true", "false", "2", "-1", "01", "1 ", "0x0"};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        handle_command("IS_LIVE", invalid[i], &cfg);
        handle_command("ACTION", "SENDMETA", &cfg);
        check_state(m, true, false);
    }
    handle_command("DURATION", "900", &cfg);
    handle_command("PROGRESS", "20", &cfg);
    check_state(m, true, false);
    /* The protocol-neutral MRP API also rejects a finite total while live. */
    assert(ap2_mrp_set_progress(m, 20000, 900000, true));
    check_state(m, true, false);
    handle_command("TITLE", "Next programme", &cfg);
    handle_command("ACTION", "SENDMETA", &cfg);
    assert(m->duration_ms == 0);
    assert(m->np_uid == uid && !strcmp(art_id, m->artwork_id));
    check_state(m, true, false);
    handle_command("IS_LIVE", "0", &cfg);
    handle_command("DURATION", "240", &cfg);
    check_state(m, true, false);
    handle_command("ACTION", "SENDMETA", &cfg);
    assert(m->duration_ms == 240000);
    check_state(m, false, true);
    handle_command("IS_LIVE", "broken", &cfg);
    handle_command("DURATION", "0", &cfg);
    handle_command("ACTION", "SENDMETA", &cfg);
    assert(m->duration_ms == 240000); /* unchanged non-live refinement rule */
    check_state(m, false, true);

    /* Legacy API calls remain non-live, including unknown duration. */
    assert(ap2_mrp_set_metadata(m, "Unknown finite item", "", "", 0, "new-id"));
    check_state(m, false, false);
    ap2cl_destroy(g_ap2cl);
    g_ap2cl = NULL;
    free(g_metadata.title);
    free(g_metadata.item_id);
    memset(&g_metadata, 0, sizeof(g_metadata));
}

static void test_live_remote_mapping(void)
{
    static const char *values[] = {"play", "paus", "plps", "nitm", "pitm"};
    for (size_t i = 0; i < 5; i++) {
        ap2_pl_node *bp = ap2_pl_dict();
        ap2_pl_dict_set(bp, "type", ap2_pl_string("sendMediaRemoteCommand"));
        ap2_pl_dict_set(bp, "value", ap2_pl_string(values[i]));
        uint8_t *b = NULL;
        int len = ap2_pl_serialize(bp, &b);
        ap2_remote_command_t cmd;
        assert(mrp_parse_remote_command(b, len, &cmd));
        assert(cmd == (ap2_remote_command_t)i);
        free(b);
        ap2_pl_free(bp);
    }
}

static uint8_t *diag_payload(const uint8_t *pb, size_t bytes, int *len)
{
    ap2_pl_node *root = ap2_pl_dict(), *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "data", ap2_pl_data(pb, bytes));
    ap2_pl_dict_set(root, "params", params);
    uint8_t *out = NULL;
    *len = ap2_pl_serialize(root, &out);
    ap2_pl_free(root);
    return out;
}

int ap2cl_test_session_setup(bool ptp, bool enabled, uint8_t **out);

static void test_paired_setup_booleans(void)
{
    uint8_t *b = NULL;
    int len = ap2cl_test_session_setup(true, true, &b);
    size_t relay = test_value(b, (size_t)len, "senderSupportsRelay");
    size_t multi = test_value(b, (size_t)len, "isMultiSelectAirPlay");
    assert(relay && multi && b[relay] == 0x09 && b[multi] == 0x09);
    free(b);
    for (unsigned ptp = 0; ptp < 2; ptp++) {
        len = ap2cl_test_session_setup(ptp, false, &b);
        assert(!test_value(b, (size_t)len, "senderSupportsRelay"));
        assert(!test_value(b, (size_t)len, "isMultiSelectAirPlay"));
        free(b);
    }
}

static void test_diagnostic_classifier(void)
{
    /* One envelope, field 1 only. Opaque extension strings never become types. */
    static const uint8_t valid[] = {10, 8, 139, 1, 18, 5, 'S','E','C','R','T'};
    int len, type;
    uint8_t *b = diag_payload(valid, sizeof(valid), &len);
    assert(!strcmp(mrp_diag_protobuf(b, (size_t)len, &type), "protobuf") && type == 139);
    assert(!strcmp(mrp_diag_protobuf(b, 65537, &type), "invalid") && type == -1);
    for (int n = 0; n < len; n++) {
        const char *result = mrp_diag_protobuf(b, (size_t)n, &type);
        assert(!strcmp(result, "unknown") || !strcmp(result, "invalid"));
    }
    free(b);
    static const uint8_t malformed[][12] = {
        {2, 8}, {2, 8, 128}, {2, 0, 1}, {2, 15, 1},
        {4, 8, 1, 8, 2}, {2, 10, 0}, {3, 18, 8, 0},
        {11, 8, 255,255,255,255,255,255,255,255,255,2}
    };
    static const size_t sizes[] = {2,3,3,3,5,3,4,12};
    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        b = diag_payload(malformed[i], sizes[i], &len);
        assert(!strcmp(mrp_diag_protobuf(b, (size_t)len, &type), "invalid") && type == -1);
        free(b);
    }
    static const uint8_t unknown[] = {4, 8, 128,128,4}; /* type 65536 */
    b = diag_payload(unknown, sizeof(unknown), &len);
    assert(!strcmp(mrp_diag_protobuf(b, (size_t)len, &type), "unknown") && type == -1);
    free(b);
}

static void diag_callback(ap2_remote_command_t command, void *userdata)
{
    assert(command == AP2_REMOTE_COMMAND_PLAY);
    (*(unsigned *)userdata)++;
}

/* Encrypt into the actual input sockets, exercising authentication, framing,
 * classification, acknowledgement and dispatch rather than calling a model. */
static void diag_send(struct ap2_mrp_ctx *m, int fd, bool event,
                      uint64_t *counter, const uint8_t *body, int bytes)
{
    uint8_t *encrypted = NULL;
    int n = mrp_channel_encrypt_with(event ? m->event_in_key : m->in_key,
        counter, body, bytes, &encrypted);
    assert(n > 0 && write(fd, encrypted, (size_t)n) == n);
    free(encrypted);
    ap2_mrp_tick(m);
    assert(event ? ap2_mrp_event_status(m) == 1 : m->connected);
    uint8_t ack[2048];
    /* Only sync DataStream frames receive an ACK; unknown kinds do not. */
    ssize_t ack_len = recv(fd, ack, sizeof(ack), MSG_DONTWAIT);
    if (event || !memcmp(body + 4, "sync", 4)) assert(ack_len > 0);
}

static void test_encrypted_diagnostics_and_cap(void)
{
    int events[2], data[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, events));
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, data));
    uint8_t secret[32] = {1};
    struct ap2_mrp_ctx *m = ap2_mrp_create("127.0.0.1", 7000, NULL, "1",
        "SECRET_METADATA", NULL, NULL, secret, sizeof(secret));
    assert(m && ap2_mrp_attach_events(m, events[0]));
    m->sock = data[0];
    m->connected = true;
    unsigned callbacks = 0;
    ap2_mrp_set_remote_command_callback(m, diag_callback, &callbacks);
    uint64_t event_counter = 0, data_counter = 0;
    int saved = dup(STDERR_FILENO);
    FILE *capture = tmpfile();
    assert(saved >= 0 && capture && dup2(fileno(capture), STDERR_FILENO) >= 0);

    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("sendMediaRemoteCommand"));
    ap2_pl_dict_set(root, "value", ap2_pl_string("play"));
    ap2_pl_dict_set(root, "secret", ap2_pl_string("SECRET_TOKEN_AND_ID"));
    uint8_t *b = NULL;
    int n = ap2_pl_serialize(root, &b);
    ap2_pl_free(root);
    uint8_t event[2048];
    int header = snprintf((char *)event, sizeof(event),
        "POST /command HTTP/1.1\r\nContent-Length: %d\r\n\r\n", n);
    memcpy(event + header, b, (size_t)n);
    free(b);
    int event_len = header + n;
    diag_send(m, events[1], true, &event_counter, event, event_len);
    assert(callbacks == 1 && m->diagnostic_count == 0); /* default off */
    ap2_mrp_set_experimental_homepod_remote(m, true);
    diag_send(m, events[1], true, &event_counter, event, header + n);

    root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("SECRET_TYPE"));
    ap2_pl_dict_set(root, "value", ap2_pl_string("SECRET_VALUE"));
    n = ap2_pl_serialize(root, &b);
    ap2_pl_free(root);
    uint8_t unknown_event[2048];
    int unknown_header = snprintf((char *)unknown_event, sizeof(unknown_event),
        "POST /command HTTP/1.1\r\nContent-Length: %d\r\n\r\n", n);
    memcpy(unknown_event + unknown_header, b, (size_t)n);
    free(b);
    diag_send(m, events[1], true, &event_counter, unknown_event, unknown_header + n);
    assert(callbacks == 2);

    static const uint8_t protobuf[] = {3, 8, 139, 1};
    b = diag_payload(protobuf, sizeof(protobuf), &n);
    uint8_t frame[2048];
    mrp_write_data_header(frame, "sync", "comm", 42, n);
    memcpy(frame + MRP_DATA_HDR_LEN, b, (size_t)n);
    free(b);
    diag_send(m, data[1], false, &data_counter, frame, MRP_DATA_HDR_LEN + n);
    assert(m->diagnostic_count == 3);
    static const uint8_t invalid_pb[] = {2, 8, 128};
    b = diag_payload(invalid_pb, sizeof(invalid_pb), &n);
    mrp_write_data_header(frame, "SECR", "comm", 43, n);
    memcpy(frame + MRP_DATA_HDR_LEN, b, (size_t)n);
    free(b);
    diag_send(m, data[1], false, &data_counter, frame, MRP_DATA_HDR_LEN + n);
    for (unsigned i = 0; i < 140; i++)
        diag_send(m, events[1], true, &event_counter, event, event_len);
    /* Every record after the cap is still acknowledged and dispatched. */
    assert(m->diagnostic_count == 128 && callbacks == 142);
    fflush(stderr);
    assert(dup2(saved, STDERR_FILENO) >= 0);
    close(saved);
    rewind(capture);
    char line[1024];
    unsigned records = 0;
    bool saw_data = false;
    while (fgets(line, sizeof(line), capture)) {
        assert(strstr(line, "[STATUS] homepod_remote ordinal="));
        assert(!strstr(line, "SECRET") && !strstr(line, "token=") && !strstr(line, "metadata="));
        if (strstr(line, "channel=datastream")) {
            assert((strstr(line, "frame_kind=sync classification=protobuf") && strstr(line, "protobuf_type=139")) ||
                   (strstr(line, "frame_kind=unknown classification=invalid") && strstr(line, "protobuf_type=-1")));
            assert(strstr(line, "dispatched=0")); /* sync ACK is not dispatch */
            saw_data = true;
        } else if (strstr(line, "classification=unknown"))
            assert(strstr(line, "command=unknown") && strstr(line, "dispatched=0"));
        else assert(strstr(line, "command=play") && strstr(line, "dispatched=1"));
        records++;
    }
    assert(records == 128 && saw_data);
    fclose(capture);
    ap2_mrp_destroy(m);
    close(events[1]);
    close(data[1]);
}

int main(void)
{
    test_paired_setup_booleans();
    test_diagnostic_classifier();
    test_encrypted_diagnostics_and_cap();
    test_live_bundle(false);
    test_live_bundle(true);
    test_live_remote_mapping();
    puts("Live metadata cmdpipe, serializer and remote mapping tests passed");
    return 0;
}
