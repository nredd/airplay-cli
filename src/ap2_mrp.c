/*
 * AirPlay 2 MediaRemote (MRP) SENDER
 *
 * Pushes now-playing state to an Apple receiver over the AirPlay 2
 * remote-control data channel (stream type 130): hand-rolled protobuf
 * ProtocolMessage encoding, 32-byte data-frame header, binary-plist payload
 * wrapper, and ChaCha20-Poly1305 channel encryption with HKDF-derived
 * DataStream keys. Protocol references live in DESIGN.md §8.
 *
 * The `/command` path carries sender now-playing state. The optional type-130
 * channel provides remote-control transport and is kept for future inbound
 * command handling.
 *
 * Copyright (C) 2024-2026 Music Assistant Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "cross_log.h"
#include "ap2_bplist.h"
#include "ap2_io.h"
#include "ap2_plist.h"
#include "ap2_mrp.h"

extern log_level *loglevel;

/* ---- Wire constants (sources cited in DESIGN.md §8) ---- */

/* HKDF-SHA512 salt/info strings for the AirPlay 2 logical channels
 * (pyatv pyatv/protocols/airplay/ap2_session.py). The DataStream salt is the
 * literal string with the SETUP "seed" appended in decimal. */
#define MRP_DATASTREAM_SALT_PREFIX  "DataStream-Salt"
#define MRP_DATASTREAM_OUTPUT_INFO  "DataStream-Output-Encryption-Key"
#define MRP_DATASTREAM_INPUT_INFO   "DataStream-Input-Encryption-Key"
/* Event channel strings kept here for the sidecar bootstrap (write/read are
 * swapped relative to our perspective; the receiver drives that channel). */
#define MRP_EVENTS_SALT             "Events-Salt"
#define MRP_EVENTS_WRITE_INFO       "Events-Write-Encryption-Key"
#define MRP_EVENTS_READ_INFO        "Events-Read-Encryption-Key"

/* Data channel SETUP constants (AP2_MRP_STREAM_TYPE_REMOTE_CONTROL etc.) live
 * in ap2_mrp.h so the SETUP request in ap2_client.c shares one definition. */

/* HAP channel framing (identical shape to ap2_hap.c: [2-byte LE length]
 * [ciphertext + 16-byte tag], AAD = the length field, nonce = 4 zero bytes +
 * 8-byte LE counter, max 1024 plaintext bytes per frame). */
#define MRP_FRAME_MAX    1024
#define MRP_TAG_SIZE     16
#define MRP_NONCE_SIZE   12
#define MRP_KEY_SIZE     32
#define MRP_KDF_SECRET_MAX 64   /* full SRP session key (transient pairing) */

/* Data-frame header: 32 bytes big-endian — size:u32 (includes the header),
 * message_type:12 raw bytes ("sync"+NULs from us, "rply"+NULs in replies),
 * command:4 bytes ("comm"), seqno:u64, padding:u32
 * (pyatv pyatv/protocols/airplay/channels.py DataHeader, struct ">I12s4sQI"). */
#define MRP_DATA_HDR_LEN 32

/* ProtocolMessage.Type values we use (pyatv protobuf/ProtocolMessage.proto). */
enum mrp_msg_type {
    MRP_MSG_SEND_COMMAND            = 1,
    MRP_MSG_SEND_COMMAND_RESULT     = 2,
    MRP_MSG_GET_STATE               = 3,
    MRP_MSG_SET_STATE               = 4,
    MRP_MSG_SET_ARTWORK             = 5,
    MRP_MSG_NOTIFICATION            = 11,
    MRP_MSG_DEVICE_INFO             = 15,
    MRP_MSG_CLIENT_UPDATES_CONFIG   = 16,
    MRP_MSG_PLAYBACK_QUEUE_REQUEST  = 32,
    MRP_MSG_TRANSACTION             = 33,
    MRP_MSG_CRYPTO_PAIRING          = 34,
    MRP_MSG_DEVICE_INFO_UPDATE      = 37,
    MRP_MSG_SET_CONNECTION_STATE    = 38,
    MRP_MSG_WAKE_DEVICE             = 41,
    MRP_MSG_GENERIC                 = 42,
    MRP_MSG_SET_NOW_PLAYING_CLIENT  = 46,
    MRP_MSG_SET_NOW_PLAYING_PLAYER  = 47,
    MRP_MSG_UPDATE_CLIENT           = 55,
    MRP_MSG_UPDATE_CONTENT_ITEM     = 56,
    MRP_MSG_REMOVE_CLIENT           = 53,
    MRP_MSG_REMOVE_PLAYER           = 54,
    MRP_MSG_UPDATE_OUTPUT_DEVICE    = 65,
    MRP_MSG_CONFIGURE_CONNECTION    = 120,
};

/* ProtocolMessage extension field numbers of the inner messages we emit
 * (pyatv protobuf sources, the "extend ProtocolMessage" blocks). */
enum mrp_ext_field {
    MRP_EXT_SET_STATE               = 9,
    MRP_EXT_SET_ARTWORK             = 10,
    MRP_EXT_DEVICE_INFO             = 20,
    MRP_EXT_CLIENT_UPDATES_CONFIG   = 21,
    MRP_EXT_TRANSACTION             = 38,
    MRP_EXT_SET_CONNECTION_STATE    = 42,
    MRP_EXT_SET_NOW_PLAYING_CLIENT  = 50,
    MRP_EXT_CONFIGURE_CONNECTION    = 94,
};

/* Enum values used inside the payload messages (pyatv protobuf sources). */
#define MRP_CONNECTION_STATE_CONNECTED     2   /* SetConnectionStateMessage */
#define MRP_CONNECTION_STATE_DISCONNECTED  3
#define MRP_DEVICE_CLASS_IPHONE            1   /* Common.proto DeviceClass */
#define MRP_MEDIA_TYPE_AUDIO               1   /* ContentItemMetadata */
#define MRP_MEDIA_SUBTYPE_MUSIC            1

/* Command enum values (pyatv protobuf/CommandInfo.proto: Play=1, Pause=2,
 * TogglePlayPause=3, Stop=4, NextTrack=5, PreviousTrack=6). Advertised in
 * SetStateMessage.supportedCommands so the receiver knows we are a controllable
 * now-playing origin — a candidate precondition for tvOS rendering the UI
 * (DESIGN.md §8). */
#define MRP_CMD_PLAY               1
#define MRP_CMD_PAUSE              2
#define MRP_CMD_TOGGLE_PLAY_PAUSE  3
#define MRP_CMD_NEXT_TRACK         5
#define MRP_CMD_PREVIOUS_TRACK     6

/* Apple epoch (CFAbsoluteTime): seconds between 1970-01-01 and 2001-01-01.
 * MRP timestamps are doubles on this timebase. */
#define MRP_APPLE_EPOCH_OFFSET 978307200.0

/* Cadence of the defensive state re-push that ap2_mrp_prepare_state_push()
 * arms for the /feedback keepalive worker (seconds, type-130 channel only). */
#define MRP_STATE_REPUSH_S 15
#define MRP_WRITE_TIMEOUT_MS 1000

struct ap2_mrp_ctx {
    struct ap2_volume volume;
    bool volume_mode;
#ifdef AP2_VOLUME_TESTING
    bool verified_volume_identity; /* synthetic offline target only */
#endif
    uint8_t volume_replay[16][128];
    size_t volume_replay_len[16];
    unsigned volume_replay_next;
    uint64_t volume_replay_generation;
    struct { uint8_t id[128]; size_t len; uint64_t generation; } volume_gets[8];
    unsigned volume_get_count;
    uint64_t volume_published_revision;
    /* Target + identity */
    char *host;
    int port;
    char *auth_credentials;   /* 192-hex HAP creds (sidecar pair-verify) */
    char *dacp_id;            /* stable sender identifier */
    char *name;               /* advertised display name */
    char *session_uuid;       /* active AirPlay session */
    char *group_uuid;         /* active AirPlay group */
    char device_uuid[37];     /* stable UUID derived from dacp_id */
    ap2_remote_command_cb_t remote_command_cb;
    void *remote_command_userdata;

    /* Channel crypto. The event and DataStream keys derive from the pairing
     * secret of the RTSP session they belong to: 32 bytes after pair-verify,
     * the full 64-byte SRP session key after transient pair-setup. */
    uint8_t shared_secret[MRP_KDF_SECRET_MAX];
    size_t shared_secret_len;
    bool have_secret;
    uint8_t out_key[MRP_KEY_SIZE];    /* DataStream-Output-Encryption-Key */
    uint8_t in_key[MRP_KEY_SIZE];     /* DataStream-Input-Encryption-Key */
    uint64_t out_counter;             /* per-direction nonce counters */
    uint64_t in_counter;

    /* Data channel connection */
    int sock;
    bool connected;
    uint64_t send_seqno;      /* constant per channel, random 33-bit (pyatv) */
    /* Sends come from the caller's cmdpipe thread and from tick (replies);
     * the lock keeps frames and the nonce sequence intact (same reasoning as
     * rtsp_lock in ap2_client.c). */
    pthread_mutex_t send_lock;

    /* Decrypted inbound stream, reassembled across TCP reads */
    uint8_t rx_enc[8192];     /* undecrypted channel bytes */
    int rx_enc_len;
    uint8_t rx_msg[16384];    /* decrypted data-frame bytes */
    int rx_msg_len;

    /* Encrypted reverse event channel. It has independent HKDF keys/counters
     * from both RTSP control and the optional type-130 data channel. */
    int event_sock;
    _Atomic bool event_connected;
    bool event_attached;
    uint8_t event_out_key[MRP_KEY_SIZE]; /* Events-Read-Encryption-Key */
    uint8_t event_in_key[MRP_KEY_SIZE];  /* Events-Write-Encryption-Key */
    uint64_t event_out_counter;
    uint64_t event_in_counter;
    uint8_t event_rx_enc[8192];
    int event_rx_enc_len;
    uint8_t event_plain[16384];
    int event_plain_len;

    /* Now-playing state (owned copies) */
    char *title;
    char *artist;
    char *album;
    int duration_ms;
    bool is_live;            /* explicit sender intent, never inferred from duration */
    bool experimental_homepod_remote; /* set before publication, immutable */
    /* Private capture is aggregate-only. It never changes channel setup,
     * command dispatch, ACKs, publication, or backend bindings. */
    bool private_native_volume_capture;
    bool capture_emitted, capture_frozen, data_attached;
    pthread_mutex_t capture_lock;
    uint64_t capture_records;
    bool capture_overflow;
    uint64_t capture_plane[2][2]; /* [event|datastream][in|out] */
    uint64_t capture_volume[6]; /* get|result|set|feedback|availability|capabilities */
    uint64_t capture_kind[2]; /* transport|other inbound only */
    uint64_t capture_parser[3]; /* valid|invalid|unknown inbound only */
    bool capture_sender_candidate, capture_session_candidate, capture_group_candidate;
    bool capture_endpoint_sender_match, capture_endpoint_session_match, capture_endpoint_group_match;
    bool capture_output_sender_match, capture_output_session_match, capture_output_group_match;
    int capture_event_cutoff, capture_data_cutoff; /* -1 unattached, 0 closed, 1 connected */
    uint64_t capture_generation;
    bool capture_binding;
    unsigned diagnostic_count; /* tick thread only, capped at 128 */
    uint64_t diagnostic_start_ms;
    int elapsed_ms;
    ap2_mrp_playback_state_t playback_state;
    double elapsed_set_at;    /* CFAbsoluteTime when elapsed_ms was captured */
    char *artwork_mime;
    uint8_t *artwork;
    int artwork_len;
    char artwork_id[17];      /* 16-hex ArtworkIdentifier for the current art */
    char *item_id;            /* sender's stable per-track identity ("" = none) */
    uint64_t np_uid;          /* per-track now-playing UniqueIdentifier */

    time_t last_state_push;
    uint64_t state_generation;
    bool state_dirty;
    bool state_include_artwork;
};

static void mrp_capture_egress(struct ap2_mrp_ctx *m, bool event);

static void mrp_artwork_info_init(ap2_mrp_artwork_info_t *info, size_t bytes)
{
    if (!info) return;
    memset(info, 0, sizeof(*info));
    info->result = AP2_MRP_ARTWORK_INVALID_ARGUMENT;
    info->bytes = bytes;
}

static ap2_mrp_artwork_result_t
mrp_artwork_result(ap2_mrp_artwork_info_t *info,
                   ap2_mrp_artwork_result_t result)
{
    if (info) info->result = result;
    return result;
}

const char *ap2_mrp_artwork_result_name(ap2_mrp_artwork_result_t result)
{
    switch (result) {
    case AP2_MRP_ARTWORK_NOT_APPLICABLE:    return "not_applicable";
    case AP2_MRP_ARTWORK_ACCEPTED:          return "accepted";
    case AP2_MRP_ARTWORK_UNCHANGED:         return "unchanged";
    case AP2_MRP_ARTWORK_INVALID_ARGUMENT:  return "invalid_argument";
    case AP2_MRP_ARTWORK_UNSUPPORTED_TYPE:  return "unsupported_type";
    case AP2_MRP_ARTWORK_STAGING_LIMIT:     return "staging_limit";
    case AP2_MRP_ARTWORK_INVALID_JPEG_ENVELOPE:
        return "invalid_jpeg_envelope";
    case AP2_MRP_ARTWORK_NO_MEMORY:         return "no_memory";
    }
    return "unknown";
}

static bool mrp_jpeg_is_sof(uint8_t marker)
{
    switch (marker) {
    case 0xC0: case 0xC1: case 0xC2: case 0xC3:
    case 0xC5: case 0xC6: case 0xC7:
    case 0xC9: case 0xCA: case 0xCB:
    case 0xCD: case 0xCE: case 0xCF:
        return true;
    default:
        return false;
    }
}

static bool mrp_jpeg_is_progressive_sof(uint8_t marker)
{
    return marker == 0xC2 || marker == 0xC6 ||
           marker == 0xCA || marker == 0xCE;
}

static void mrp_jpeg_probe_metadata(const uint8_t *data, size_t len,
                                    ap2_mrp_artwork_info_t *info)
{
    size_t pos = 2;
    while (pos + 3 < len - 2) {
        if (data[pos++] != 0xFF) return;
        while (pos < len - 2 && data[pos] == 0xFF) pos++;
        if (pos >= len - 2) return;
        uint8_t marker = data[pos++];
        if (marker == 0xD9 || marker == 0xDA) return;
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7))
            continue;
        if (marker == 0x00 || marker == 0xD8 || pos + 2 > len) return;

        size_t segment_len = ((size_t)data[pos] << 8) | data[pos + 1];
        if (segment_len < 2 || segment_len > len - pos) return;
        if (mrp_jpeg_is_sof(marker) && segment_len >= 8) {
            const uint8_t *sof = data + pos + 2;
            uint8_t components = sof[5];
            if (segment_len < (size_t)(8 + 3 * components)) return;
            info->precision = sof[0];
            info->height = ((uint16_t)sof[1] << 8) | sof[2];
            info->width = ((uint16_t)sof[3] << 8) | sof[4];
            info->components = components;
            info->sof_marker = marker;
            info->progressive = mrp_jpeg_is_progressive_sof(marker);
            return;
        }
        pos += segment_len;
    }
}

ap2_mrp_artwork_result_t
ap2_mrp_probe_artwork(const char *mime, const uint8_t *data, size_t len,
                      ap2_mrp_artwork_info_t *info)
{
    ap2_mrp_artwork_info_t local_info;
    if (!info) info = &local_info;
    mrp_artwork_info_init(info, len);
    if (!mime || !data || len == 0)
        return AP2_MRP_ARTWORK_INVALID_ARGUMENT;
    if (strcmp(mime, "image/jpeg") != 0)
        return mrp_artwork_result(info, AP2_MRP_ARTWORK_UNSUPPORTED_TYPE);
    if (len > AP2_MRP_ARTWORK_STAGING_MAX_BYTES)
        return mrp_artwork_result(info, AP2_MRP_ARTWORK_STAGING_LIMIT);
    if (len < 4 || data[0] != 0xFF || data[1] != 0xD8 ||
        data[len - 2] != 0xFF || data[len - 1] != 0xD9)
        return mrp_artwork_result(
            info, AP2_MRP_ARTWORK_INVALID_JPEG_ENVELOPE);

    mrp_jpeg_probe_metadata(data, len, info);
    return mrp_artwork_result(info, AP2_MRP_ARTWORK_ACCEPTED);
}

static void mrp_reset_artwork(struct ap2_mrp_ctx *m)
{
    if (!m) return;
    free(m->artwork);
    m->artwork = NULL;
    m->artwork_len = 0;
    free(m->artwork_mime);
    m->artwork_mime = NULL;
    m->artwork_id[0] = '\0';
}

/* ---- Small helpers ---- */

static double mrp_cf_now(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6 - MRP_APPLE_EPOCH_OFFSET;
}

static void mrp_gen_uuid(char out[37])
{
    uint8_t b[16];
    RAND_bytes(b, sizeof(b));
    snprintf(out, 37,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

static void mrp_identity_uuid(const char *identity, char out[37])
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!identity ||
        EVP_Digest(identity, strlen(identity), digest, &digest_len,
                   EVP_sha256(), NULL) != 1 || digest_len < 16) {
        mrp_gen_uuid(out);
        return;
    }
    digest[6] = (digest[6] & 0x0F) | 0x50; /* deterministic UUID v5 shape */
    digest[8] = (digest[8] & 0x3F) | 0x80;
    snprintf(out, 37,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             digest[0], digest[1], digest[2], digest[3],
             digest[4], digest[5], digest[6], digest[7],
             digest[8], digest[9], digest[10], digest[11],
             digest[12], digest[13], digest[14], digest[15]);
}

static char *mrp_strdup(const char *s)
{
    if (!s) s = "";
    size_t n = strlen(s) + 1;
    char *d = malloc(n);
    if (d) memcpy(d, s, n);
    return d;
}

static void mrp_replace_str(char **dst, const char *src)
{
    free(*dst);
    *dst = mrp_strdup(src);
}

/* NULL-safe equality; NULL compares equal to the empty string, matching how
 * the now-playing fields are serialized. */
static bool mrp_str_eq(const char *a, const char *b)
{
    return strcmp(a ? a : "", b ? b : "") == 0;
}

/* ---- Growable byte buffer ---- */

typedef struct {
    uint8_t *p;
    size_t len;
    size_t cap;
} mbuf;

static bool mbuf_reserve(mbuf *b, size_t extra)
{
    if (b->len + extra <= b->cap) return true;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra) cap *= 2;
    uint8_t *np = realloc(b->p, cap);
    if (!np) return false;
    b->p = np;
    b->cap = cap;
    return true;
}

static bool mbuf_put(mbuf *b, const void *data, size_t n)
{
    if (!mbuf_reserve(b, n)) return false;
    memcpy(b->p + b->len, data, n);
    b->len += n;
    return true;
}

static bool mbuf_put_u8(mbuf *b, uint8_t v) { return mbuf_put(b, &v, 1); }

static void mbuf_free(mbuf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

/* ---- Protobuf primitives (proto2 wire format) ---- */

static bool pb_put_varint(mbuf *b, uint64_t v)
{
    do {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if (v) byte |= 0x80;
        if (!mbuf_put_u8(b, byte)) return false;
    } while (v);
    return true;
}

/* Field key: (field_number << 3) | wire_type. Wire types: 0 varint,
 * 1 64-bit LE, 2 length-delimited, 5 32-bit LE. */
static bool pb_put_key(mbuf *b, uint32_t field, uint32_t wire_type)
{
    return pb_put_varint(b, ((uint64_t)field << 3) | wire_type);
}

static bool pb_put_varint_field(mbuf *b, uint32_t field, uint64_t v)
{
    return pb_put_key(b, field, 0) && pb_put_varint(b, v);
}

static bool pb_put_bool_field(mbuf *b, uint32_t field, bool v)
{
    return pb_put_varint_field(b, field, v ? 1 : 0);
}

static bool pb_put_bytes_field(mbuf *b, uint32_t field,
                               const void *data, size_t n)
{
    return pb_put_key(b, field, 2) && pb_put_varint(b, n) &&
           (n == 0 || mbuf_put(b, data, n));
}

static bool pb_put_string_field(mbuf *b, uint32_t field, const char *s)
{
    return pb_put_bytes_field(b, field, s, strlen(s));
}

static bool pb_put_double_field(mbuf *b, uint32_t field, double v)
{
    uint64_t bits;
    memcpy(&bits, &v, sizeof(bits));
    uint8_t le[8];
    for (int i = 0; i < 8; i++) le[i] = (bits >> (i * 8)) & 0xFF;
    return pb_put_key(b, field, 1) && mbuf_put(b, le, 8);
}

static bool pb_put_float_field(mbuf *b, uint32_t field, float v)
{
    uint32_t bits;
    memcpy(&bits, &v, sizeof(bits));
    uint8_t le[4];
    for (int i = 0; i < 4; i++) le[i] = (bits >> (i * 8)) & 0xFF;
    return pb_put_key(b, field, 5) && mbuf_put(b, le, 4);
}

/* Embed a fully built submessage as a length-delimited field. */
static bool pb_put_msg_field(mbuf *b, uint32_t field, const mbuf *sub)
{
    return pb_put_bytes_field(b, field, sub->p, sub->len);
}

/* ---- ProtocolMessage envelope ----
 *
 * ProtocolMessage: type = field 1 (varint, MUST be emitted first — receivers
 * and pyatv both rely on the leading 0x08 byte), extension field = the inner
 * message (length-delimited), uniqueIdentifier = field 85 (string UUID). */
static bool mrp_envelope(mbuf *out, enum mrp_msg_type type,
                         enum mrp_ext_field ext_field, const mbuf *inner)
{
    char uuid[37];
    mrp_gen_uuid(uuid);
    if (!pb_put_varint_field(out, 1, (uint64_t)type)) return false;
    if (inner && !pb_put_msg_field(out, (uint32_t)ext_field, inner)) return false;
    return pb_put_string_field(out, 85, uuid);
}

/* ---- Message builders (field numbers from pyatv protobuf sources) ---- */

/* DEVICE_INFO_MESSAGE (ext 20). Must be the FIRST message on the channel or
 * the receiver will not respond (pyatv protocol.py). Values mirror what a
 * real sender advertises; com.apple.Music vs com.apple.TVRemote is a live
 * validation item (DESIGN.md §8). */
static bool build_device_info(struct ap2_mrp_ctx *m, mbuf *out)
{
    bool ok = true;
    mbuf inner = {0};
    ok &= pb_put_string_field(&inner, 1, m->device_uuid);       /* uniqueIdentifier */
    ok &= pb_put_string_field(&inner, 2, m->name);              /* name (required) */
    ok &= pb_put_string_field(&inner, 3, "iPhone");             /* localizedModelName */
    ok &= pb_put_string_field(&inner, 4, "21F90");              /* systemBuildVersion */
    ok &= pb_put_string_field(&inner, 5, "com.apple.Music");    /* applicationBundleIdentifier */
    ok &= pb_put_varint_field(&inner, 7, 1);                    /* protocolVersion */
    ok &= pb_put_varint_field(&inner, 8, 139);                  /* lastSupportedMessageType (captured from a real iPhone) */
    ok &= pb_put_bool_field(&inner, 9, true);                   /* supportsSystemPairing */
    ok &= pb_put_bool_field(&inner, 10, true);                  /* allowsPairing */
    ok &= pb_put_string_field(&inner, 12, "com.apple.Music");   /* systemMediaApplication */
    ok &= pb_put_bool_field(&inner, 13, true);                  /* supportsACL */
    ok &= pb_put_bool_field(&inner, 14, true);                  /* supportsSharedQueue */
    ok &= pb_put_bool_field(&inner, 15, true);                  /* supportsExtendedMotion */
    ok &= pb_put_varint_field(&inner, 17, 2);                   /* sharedQueueVersion */
    ok &= pb_put_string_field(&inner, 19, m->dacp_id);          /* deviceUID */
    ok &= pb_put_varint_field(&inner, 21, MRP_DEVICE_CLASS_IPHONE); /* deviceClass */
    ok &= pb_put_varint_field(&inner, 22, 1);                   /* logicalDeviceCount */
    ok &= pb_put_string_field(&inner, 31, "com.apple.podcasts"); /* systemPodcastApplication */
    ok &= pb_put_string_field(&inner, 39, "iPhone17,1");        /* modelID */
    if (m->session_uuid && *m->session_uuid)
        ok &= pb_put_string_field(&inner, 41, m->session_uuid); /* routingContextID */
    if (m->group_uuid && *m->group_uuid)
        ok &= pb_put_string_field(&inner, 42, m->group_uuid);   /* airPlayGroupID */
    ok &= pb_put_string_field(&inner, 43, "com.apple.iBooks");  /* systemBooksApplication */
    ok = ok && mrp_envelope(out, MRP_MSG_DEVICE_INFO, MRP_EXT_DEVICE_INFO, &inner);
    mbuf_free(&inner);
    return ok;
}

/* SET_CONNECTION_STATE_MESSAGE (ext 42): state = field 1. */
static bool build_set_connection_state(mbuf *out, int state)
{
    bool ok;
    mbuf inner = {0};
    ok = pb_put_varint_field(&inner, 1, (uint64_t)state);
    ok = ok && mrp_envelope(out, MRP_MSG_SET_CONNECTION_STATE,
                            MRP_EXT_SET_CONNECTION_STATE, &inner);
    mbuf_free(&inner);
    return ok;
}

/* CLIENT_UPDATES_CONFIG_MESSAGE (ext 21): we are a sender pushing state, not a
 * controller subscribing, so everything is off — the message merely completes
 * the handshake shape controllers use. */
static bool build_client_updates_config(mbuf *out)
{
    bool ok = true;
    mbuf inner = {0};
    ok &= pb_put_bool_field(&inner, 1, false);   /* artworkUpdates */
    ok &= pb_put_bool_field(&inner, 2, false);   /* nowPlayingUpdates */
    ok &= pb_put_bool_field(&inner, 3, false);   /* volumeUpdates */
    ok &= pb_put_bool_field(&inner, 4, false);   /* keyboardUpdates */
    ok &= pb_put_bool_field(&inner, 5, false);   /* outputDeviceUpdates */
    ok = ok && mrp_envelope(out, MRP_MSG_CLIENT_UPDATES_CONFIG,
                            MRP_EXT_CLIENT_UPDATES_CONFIG, &inner);
    mbuf_free(&inner);
    return ok;
}

/* MRNowPlayingClientCreateExternalRepresentation serializes this protobuf
 * directly. The same submessage is nested in SET_NOW_PLAYING_CLIENT on the
 * optional type-130 channel. */
static bool build_now_playing_client(struct ap2_mrp_ctx *m, mbuf *client)
{
    bool ok = true;
    ok &= pb_put_varint_field(client, 1, (uint64_t)getpid());
    ok &= pb_put_string_field(client, 2, "com.apple.Music");
    ok &= pb_put_string_field(client, 7, m->name);
    return ok;
}

/* SET_NOW_PLAYING_CLIENT_MESSAGE (ext 50): client = field 1. */
static bool build_set_now_playing_client(struct ap2_mrp_ctx *m, mbuf *out)
{
    bool ok = true;
    mbuf client = {0}, inner = {0};
    ok = build_now_playing_client(m, &client);
    ok = ok && pb_put_msg_field(&inner, 1, &client);
    ok = ok && mrp_envelope(out, MRP_MSG_SET_NOW_PLAYING_CLIENT,
                            MRP_EXT_SET_NOW_PLAYING_CLIENT, &inner);
    mbuf_free(&client);
    mbuf_free(&inner);
    return ok;
}

/* ContentItemMetadata for the current track (field numbers from
 * ContentItemMetadata.proto). */
static bool build_content_item_metadata(struct ap2_mrp_ctx *m, mbuf *meta)
{
    bool ok = true;
    double dur_s = m->duration_ms / 1000.0;
    double elapsed_s = m->elapsed_ms / 1000.0;
    ok &= pb_put_string_field(meta, 1, m->title ? m->title : "");     /* title */
    ok &= pb_put_string_field(meta, 6, m->album ? m->album : "");     /* albumName */
    ok &= pb_put_string_field(meta, 7, m->artist ? m->artist : "");   /* trackArtistName */
    if (m->duration_ms > 0)
        ok &= pb_put_double_field(meta, 14, dur_s);                   /* duration */
    ok &= pb_put_bool_field(meta, 19, m->artwork_len > 0);            /* artworkAvailable */
    ok &= pb_put_bool_field(meta, 27,
                            m->playback_state != AP2_MRP_PLAYBACK_STOPPED);
    if (m->artwork_mime && m->artwork_len > 0)
        ok &= pb_put_string_field(meta, 31, m->artwork_mime);         /* artworkMIMEType */
    ok &= pb_put_double_field(meta, 35, elapsed_s);                   /* elapsedTime */
    if (m->is_live)
        ok &= pb_put_bool_field(meta, 37, true);                     /* isAlwaysLive */
    ok &= pb_put_float_field(meta, 39,
                             m->playback_state == AP2_MRP_PLAYBACK_PLAYING
                                 ? 1.0f : 0.0f);                      /* playbackRate */
    ok &= pb_put_varint_field(meta, 64, MRP_MEDIA_TYPE_AUDIO);        /* mediaType */
    ok &= pb_put_varint_field(meta, 65, MRP_MEDIA_SUBTYPE_MUSIC);     /* mediaSubType */
    ok &= pb_put_double_field(meta, 74, m->elapsed_set_at);           /* elapsedTimeTimestamp */
    return ok;
}

/* SupportedCommands submessage (pyatv SupportedCommands.proto: field 1 is a
 * repeated CommandInfo; CommandInfo.proto: command = field 1, enabled = field
 * 2). Advertises the transport controls we accept, so the receiver treats us as
 * a controllable now-playing client. */
static bool build_supported_commands(mbuf *sc)
{
    static const uint32_t cmds[] = {
        MRP_CMD_PLAY, MRP_CMD_PAUSE, MRP_CMD_TOGGLE_PLAY_PAUSE,
        MRP_CMD_NEXT_TRACK, MRP_CMD_PREVIOUS_TRACK,
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        mbuf ci = {0};
        ok &= pb_put_varint_field(&ci, 1, cmds[i]);   /* command (enum) */
        ok &= pb_put_bool_field(&ci, 2, true);        /* enabled */
        ok = ok && pb_put_msg_field(sc, 1, &ci);      /* repeated supportedCommands */
        mbuf_free(&ci);
    }
    return ok;
}

/* SET_STATE_MESSAGE (ext 9) carrying the full now-playing picture:
 * SetStateMessage { nowPlayingInfo=1, playbackQueue=3, displayName=5,
 * playbackState=6, playbackStateTimestamp=11 }; the queue holds one
 * ContentItem { identifier=1, metadata=2, artworkData=3 }. */
static bool build_set_state(struct ap2_mrp_ctx *m, bool include_artwork,
                            mbuf *out)
{
    bool ok = true;
    mbuf npi = {0}, meta = {0}, item = {0}, queue = {0}, sc = {0}, inner = {0};
    double now_cf = mrp_cf_now();

    /* NowPlayingInfo (field numbers from NowPlayingInfo.proto) */
    ok &= pb_put_string_field(&npi, 1, m->album ? m->album : "");     /* album */
    ok &= pb_put_string_field(&npi, 2, m->artist ? m->artist : "");   /* artist */
    if (m->duration_ms > 0)
        ok &= pb_put_double_field(&npi, 3, m->duration_ms / 1000.0);  /* duration */
    ok &= pb_put_double_field(&npi, 4, m->elapsed_ms / 1000.0);       /* elapsedTime */
    ok &= pb_put_float_field(&npi, 5,
                             m->playback_state == AP2_MRP_PLAYBACK_PLAYING
                                 ? 1.0f : 0.0f);                       /* playbackRate */
    ok &= pb_put_double_field(&npi, 8, now_cf);                       /* timestamp */
    ok &= pb_put_string_field(&npi, 9, m->title ? m->title : "");     /* title */
    ok &= pb_put_bool_field(&npi, 12, true);                          /* isMusicApp */
    if (m->is_live)
        ok &= pb_put_bool_field(&npi, 17, true);                      /* isAlwaysLive */

    /* PlaybackQueue { location=1, contentItems=2 } with one ContentItem */
    ok = ok && build_content_item_metadata(m, &meta);
    ok &= pb_put_string_field(&item, 1, m->dacp_id);                  /* identifier */
    ok = ok && pb_put_msg_field(&item, 2, &meta);                     /* metadata */
    if (include_artwork && m->artwork && m->artwork_len > 0)
        ok &= pb_put_bytes_field(&item, 3, m->artwork,
                                 (size_t)m->artwork_len);             /* artworkData */
    ok &= pb_put_varint_field(&queue, 1, 0);                          /* location */
    ok = ok && pb_put_msg_field(&queue, 2, &item);                    /* contentItems */

    /* SetStateMessage { nowPlayingInfo=1, supportedCommands=2, playbackQueue=3,
     * displayName=5, playbackState=6, playbackStateTimestamp=11 } */
    ok = ok && build_supported_commands(&sc);
    ok = ok && pb_put_msg_field(&inner, 1, &npi);
    ok = ok && pb_put_msg_field(&inner, 2, &sc);                      /* supportedCommands */
    ok = ok && pb_put_msg_field(&inner, 3, &queue);
    ok &= pb_put_string_field(&inner, 5, m->name);                    /* displayName */
    ok &= pb_put_varint_field(&inner, 6, m->playback_state);          /* playbackState */
    ok &= pb_put_double_field(&inner, 11, now_cf);                    /* playbackStateTimestamp */

    ok = ok && mrp_envelope(out, MRP_MSG_SET_STATE, MRP_EXT_SET_STATE, &inner);

    mbuf_free(&npi);
    mbuf_free(&meta);
    mbuf_free(&item);
    mbuf_free(&queue);
    mbuf_free(&sc);
    mbuf_free(&inner);
    return ok;
}

/* ---- Channel crypto (mirrors ap2_hap.c hkdf_sha512 / chacha helpers; those
 * are static there, and the MRP channel has its own keys and counters) ---- */

static bool mrp_hkdf_sha512(const uint8_t *secret, int secret_len,
                            const char *salt_str, const char *info_str,
                            uint8_t *out, int out_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return false;
    bool ok = false;
    size_t dklen = out_len;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha512()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const unsigned char *)salt_str,
                                    strlen(salt_str)) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) <= 0) goto done;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char *)info_str,
                                    strlen(info_str)) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, out, &dklen) <= 0) goto done;
    ok = true;
done:
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static void mrp_make_nonce(uint64_t counter, uint8_t nonce[MRP_NONCE_SIZE])
{
    memset(nonce, 0, MRP_NONCE_SIZE);
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = (counter >> (i * 8)) & 0xFF;
}

static int mrp_chacha_encrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *aad, int aad_len,
                              const uint8_t *pt, int pt_len,
                              uint8_t *ct, uint8_t tag[MRP_TAG_SIZE])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, ct_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, MRP_NONCE_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    if (aad && aad_len > 0)
        EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ct + ct_len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, MRP_TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

static int mrp_chacha_decrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *aad, int aad_len,
                              const uint8_t *ct, int ct_len,
                              const uint8_t *tag, uint8_t *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, pt_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, MRP_NONCE_SIZE, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    if (aad && aad_len > 0)
        EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
    EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, MRP_TAG_SIZE, (void *)tag);
    int ok = EVP_DecryptFinal_ex(ctx, pt + pt_len, &len);
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1 ? pt_len : -1;
}

/* Encrypt a plaintext blob into HAP channel frames. Caller frees *out. */
static int mrp_channel_encrypt_with(const uint8_t key[MRP_KEY_SIZE],
                                    uint64_t *counter,
                                    const uint8_t *in, int in_len,
                                    uint8_t **out)
{
    int num_frames = (in_len + MRP_FRAME_MAX - 1) / MRP_FRAME_MAX;
    int total = num_frames * (2 + MRP_TAG_SIZE) + in_len;
    *out = malloc(total);
    if (!*out) return -1;

    int out_off = 0, in_off = 0;
    while (in_off < in_len) {
        int chunk = in_len - in_off;
        if (chunk > MRP_FRAME_MAX) chunk = MRP_FRAME_MAX;

        uint8_t len_bytes[2] = { chunk & 0xFF, (chunk >> 8) & 0xFF };
        memcpy(*out + out_off, len_bytes, 2);
        out_off += 2;

        /* Encryption consumes the nonce even if the eventual write fails.
         * Callers close the channel on failure rather than retrying ciphertext. */
        uint8_t nonce[MRP_NONCE_SIZE];
        mrp_make_nonce((*counter)++, nonce);

        uint8_t tag[MRP_TAG_SIZE];
        if (mrp_chacha_encrypt(key, nonce, len_bytes, 2,
                               in + in_off, chunk,
                               *out + out_off, tag) < 0) {
            free(*out);
            *out = NULL;
            return -1;
        }
        out_off += chunk;
        memcpy(*out + out_off, tag, MRP_TAG_SIZE);
        out_off += MRP_TAG_SIZE;
        in_off += chunk;
    }
    return out_off;
}

static int mrp_channel_encrypt(struct ap2_mrp_ctx *m, const uint8_t *in,
                               int in_len, uint8_t **out)
{
    return mrp_channel_encrypt_with(m->out_key, &m->out_counter,
                                    in, in_len, out);
}

/* ---- Data-frame construction and send ---- */

static bool mrp_write_all(int fd, const uint8_t *data, int len)
{
    return ap2_io_write_all_deadline(
        fd, data, (size_t)len,
        ap2_io_monotonic_ms() + MRP_WRITE_TIMEOUT_MS);
}

static void mrp_close_data_channel(struct ap2_mrp_ctx *m)
{
    bool was_connected = m->connected;
    m->connected = false;
    if (m->volume_mode) {
        pthread_mutex_lock(&m->volume.lock);
        uint64_t generation = m->volume.generation;
        pthread_mutex_unlock(&m->volume.lock);
        ap2_volume_unbind(&m->volume, generation);
        if (was_connected) {
            printf("[STATUS] session_volume_transport ready=0 publication=0\n");
            fflush(stdout);
        }
    }
    if (m->sock >= 0) {
        shutdown(m->sock, SHUT_RDWR);
        close(m->sock);
        m->sock = -1;
    }
}

static void mrp_close_event_channel(struct ap2_mrp_ctx *m)
{
    atomic_store(&m->event_connected, false);
    if (m->event_sock >= 0) {
        shutdown(m->event_sock, SHUT_RDWR);
        close(m->event_sock);
        m->event_sock = -1;
    }
}

/* Write the 32-byte big-endian data-frame header. */
static void mrp_write_data_header(uint8_t hdr[MRP_DATA_HDR_LEN],
                                  const char msg_type4[4], const char cmd4[4],
                                  uint64_t seqno, uint32_t payload_len)
{
    uint32_t size = MRP_DATA_HDR_LEN + payload_len;
    memset(hdr, 0, MRP_DATA_HDR_LEN);
    hdr[0] = (size >> 24) & 0xFF;
    hdr[1] = (size >> 16) & 0xFF;
    hdr[2] = (size >> 8) & 0xFF;
    hdr[3] = size & 0xFF;
    memcpy(hdr + 4, msg_type4, 4);       /* 12-byte field, rest stays zero */
    memcpy(hdr + 16, cmd4, 4);
    for (int i = 0; i < 8; i++)
        hdr[16 + 4 + i] = (seqno >> ((7 - i) * 8)) & 0xFF;
    /* padding u32 at offset 28 stays zero */
}

/* Send raw bytes through the encrypted channel (holds send_lock). */
static bool mrp_send_raw(struct ap2_mrp_ctx *m, const uint8_t *data, int len)
{
    pthread_mutex_lock(&m->send_lock);
    if (m->sock < 0) {
        pthread_mutex_unlock(&m->send_lock);
        return false;
    }
    uint8_t *enc = NULL;
    int enc_len = mrp_channel_encrypt(m, data, len, &enc);
    bool ok = false;
    if (enc_len > 0 && enc)
        ok = mrp_write_all(m->sock, enc, enc_len);
    free(enc);
    if (!ok) {
        LOG_ERROR("[MRP] data channel write failed: %s", strerror(errno));
        mrp_close_data_channel(m);
    }
    pthread_mutex_unlock(&m->send_lock);
    return ok;
}

/* Wrap one serialized ProtocolMessage into a "sync"/"comm" data frame:
 * payload = bplist {"params": {"data": <varint length + protobuf>}}
 * (pyatv channels.py send_protobuf / encode_protobufs). */
static bool mrp_send_protobuf(struct ap2_mrp_ctx *m, const mbuf *msg)
{
    if (!m->connected) return false;

    /* varint length prefix + message bytes */
    mbuf blob = {0};
    bool ok = pb_put_varint(&blob, msg->len) && mbuf_put(&blob, msg->p, msg->len);
    if (!ok) {
        mbuf_free(&blob);
        return false;
    }

    /* {"params": {"data": blob}} */
    ap2_pl_node *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "data", ap2_pl_data(blob.p, blob.len));
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "params", params);
    uint8_t *plist = NULL;
    int plist_len = ap2_pl_serialize(root, &plist);
    ap2_pl_free(root);
    mbuf_free(&blob);
    if (plist_len <= 0 || !plist) {
        free(plist);
        return false;
    }

    uint8_t *frame = malloc(MRP_DATA_HDR_LEN + (size_t)plist_len);
    if (!frame) {
        free(plist);
        return false;
    }
    mrp_write_data_header(frame, "sync", "comm", m->send_seqno,
                          (uint32_t)plist_len);
    memcpy(frame + MRP_DATA_HDR_LEN, plist, plist_len);
    free(plist);

    ok = mrp_send_raw(m, frame, MRP_DATA_HDR_LEN + plist_len);
    free(frame);
    return ok;
}

/* Reply frame ("rply", zero command) acknowledging a receiver "sync" frame. */
static bool mrp_send_reply(struct ap2_mrp_ctx *m, uint64_t seqno)
{
    uint8_t hdr[MRP_DATA_HDR_LEN];
    static const char zero4[4] = {0, 0, 0, 0};
    mrp_write_data_header(hdr, "rply", zero4, seqno, 0);
    bool ok = mrp_send_raw(m, hdr, sizeof(hdr));
    if (ok) mrp_capture_egress(m, false);
    return ok;
}

/* Build + push the full current state (metadata, progress, artwork). */
static bool mrp_push_state(struct ap2_mrp_ctx *m, bool include_artwork)
{
    mbuf msg = {0};
    bool ok = build_set_state(m, include_artwork, &msg);
    ok = ok && mrp_send_protobuf(m, &msg);
    mbuf_free(&msg);
    if (ok) m->last_state_push = time(NULL);
    LOG_DEBUG("[MRP] SET_STATE push (%s artwork) -> %s",
              include_artwork ? "with" : "without", ok ? "sent" : "failed");
    return ok;
}

/* ---- Inbound handling ---- */

static bool mrp_drain_channel_frames(uint8_t *enc, int *enc_len,
                                     uint8_t *plain, int *plain_len,
                                     int plain_cap,
                                     const uint8_t key[MRP_KEY_SIZE],
                                     uint64_t *counter,
                                     const char *label)
{
    int off = 0;
    while (off + 2 <= *enc_len) {
        int chunk = enc[off] | (enc[off + 1] << 8);
        if (chunk <= 0 || chunk > MRP_FRAME_MAX) {
            LOG_ERROR("[MRP] invalid %s frame size %d", label, chunk);
            return false;
        }
        if (off + 2 + chunk + MRP_TAG_SIZE > *enc_len) break;

        if (*plain_len + chunk > plain_cap) {
            LOG_ERROR("[MRP] %s plaintext buffer full", label);
            return false;
        }

        uint8_t len_bytes[2] = { enc[off], enc[off + 1] };
        uint8_t nonce[MRP_NONCE_SIZE];
        mrp_make_nonce((*counter)++, nonce);

        int n = mrp_chacha_decrypt(key, nonce, len_bytes, 2,
                                   enc + off + 2, chunk,
                                   enc + off + 2 + chunk,
                                   plain + *plain_len);
        if (n < 0) {
            LOG_ERROR("[MRP] %s frame decryption failed", label);
            return false;
        }
        *plain_len += n;
        off += 2 + chunk + MRP_TAG_SIZE;
    }
    if (off > 0) {
        memmove(enc, enc + off, *enc_len - off);
        *enc_len -= off;
    }
    return true;
}

/* Decrypt whatever data-channel frames are complete into rx_msg. */
static void mrp_drain_encrypted(struct ap2_mrp_ctx *m)
{
    if (!mrp_drain_channel_frames(m->rx_enc, &m->rx_enc_len,
                                  m->rx_msg, &m->rx_msg_len,
                                  (int)sizeof(m->rx_msg),
                                  m->in_key, &m->in_counter, "data channel"))
        mrp_close_data_channel(m);
}

/* Bounded diagnostic parsing only. These observations never dispatch commands. */
static bool mrp_diag_varint(const uint8_t **p, const uint8_t *end, uint64_t *v)
{
    *v = 0;
    for (unsigned i = 0; i < 10 && *p < end; i++) {
        uint8_t b = *(*p)++;
        if (i == 9 && b > 1) return false;
        *v |= (uint64_t)(b & 127) << (i * 7);
        if (!(b & 128)) return true;
    }
    return false;
}

/* Returns a fixed classification and a bounded numeric type, never strings
 * from the receiver. Unknown/malformed containers are not semantic messages. */
static const char *mrp_diag_protobuf(const uint8_t *body, size_t len, int *type)
{
    *type = -1;
    if (!body || len > 65536) return "invalid";
    const uint8_t *p;
    size_t bytes;
    if (!ap2_bplist_get_params_data(body, len, &p, &bytes)) return "unknown";
    const uint8_t *end = p + bytes;
    uint64_t n;
    if (!mrp_diag_varint(&p, end, &n) || n != (uint64_t)(end - p))
        return "invalid";
    bool found = false;
    int candidate = -1;
    while (p < end) {
        uint64_t tag, value;
        if (!mrp_diag_varint(&p, end, &tag) || !(tag >> 3) ||
            (tag >> 3) > 0x1fffffff) return "invalid";
        if ((tag & 7) == 0) {
            if (!mrp_diag_varint(&p, end, &value)) return "invalid";
            if ((tag >> 3) == 1) {
                if (found) return "invalid";
                found = true;
                if (value <= 65535) candidate = (int)value;
            }
        } else {
            if ((tag >> 3) == 1) return "invalid";
            if ((tag & 7) == 1) n = 8;
            else if ((tag & 7) == 5) n = 4;
            else if ((tag & 7) != 2 || !mrp_diag_varint(&p, end, &n))
                return "invalid";
            if (n > (uint64_t)(end - p)) return "invalid";
            p += (size_t)n;
        }
    }
    *type = candidate;
    return candidate >= 0 ? "protobuf" : "unknown";
}

/* Public pyatv proto2 schemas, not a claim about measured HomePod wire traffic.
 * Reject duplicate fields (including unknown ones) and bound work independently
 * of the payload byte bound. Unknown bytes are skipped, never retained/logged. */
struct mrp_diag_reader {
    const uint8_t *p, *end;
    uint32_t seen[256];
    unsigned count;
};

struct mrp_diag_field {
    unsigned number, wire;
    uint64_t integer;
    const uint8_t *data;
    size_t len;
};

static bool mrp_diag_field(struct mrp_diag_reader *r, struct mrp_diag_field *f)
{
    uint64_t tag, n = 0;
    memset(f, 0, sizeof(*f));
    if (r->count >= 256 || !mrp_diag_varint(&r->p, r->end, &tag) ||
        !(tag >> 3) || (tag >> 3) > 0x1fffffff) return false;
    f->number = (unsigned)(tag >> 3);
    f->wire = tag & 7;
    for (unsigned i = 0; i < r->count; i++)
        if (r->seen[i] == f->number) return false;
    r->seen[r->count++] = f->number;
    if (f->wire == 0) return mrp_diag_varint(&r->p, r->end, &f->integer);
    if (f->wire == 1) n = 8;
    else if (f->wire == 5) n = 4;
    else if (f->wire != 2 || !mrp_diag_varint(&r->p, r->end, &n)) return false;
    if (n > (uint64_t)(r->end - r->p)) return false;
    f->data = r->p;
    f->len = (size_t)n;
    r->p += f->len;
    return true;
}

struct mrp_diag_volume {
    const char *message, *target, *value_state;
    int value_milli, available, capabilities;
    const uint8_t *endpoint_bytes, *output_bytes;
    size_t endpoint_len, output_len;
    int type;
};

/* Availability is also nested in capabilities-did-change field 1. */
static bool mrp_diag_availability(const uint8_t *p, size_t len,
                                  struct mrp_diag_volume *v)
{
    struct mrp_diag_reader r = {.p = p, .end = p + len};
    while (r.p < r.end) {
        struct mrp_diag_field f;
        if (!mrp_diag_field(&r, &f)) return false;
        if (f.number == 1 || f.number == 2) {
            if (f.wire != 0 || f.integer > (f.number == 1 ? 1 : 3)) return false;
            if (f.number == 1) v->available = (int)f.integer;
            else v->capabilities = (int)f.integer;
        }
    }
    return true;
}

static bool mrp_diag_volume_body(int type, const uint8_t *p, size_t len,
                                 struct mrp_diag_volume *v)
{
    if (type == 17) return mrp_diag_availability(p, len, v);
    struct mrp_diag_reader r = {.p = p, .end = p + len};
    while (r.p < r.end) {
        struct mrp_diag_field f;
        if (!mrp_diag_field(&r, &f)) return false;
        if (type == 64 && f.number == 1) {
            if (f.wire != 2 || !mrp_diag_availability(f.data, f.len, v)) return false;
        } else if (type != 49 && type != 64 && f.number == 1) {
            if (f.wire != 5) { v->value_state = "invalid"; return false; }
            uint32_t bits = (uint32_t)f.data[0] | (uint32_t)f.data[1] << 8 |
                (uint32_t)f.data[2] << 16 | (uint32_t)f.data[3] << 24;
            float value;
            memcpy(&value, &bits, sizeof(value));
            if (!isfinite(value) || value < 0 || value > 1) {
                v->value_state = "invalid";
                return false;
            }
            v->value_state = "valid";
            v->value_milli = (int)(value * 1000.0f + 0.5f);
        } else if ((type == 49 && f.number == 1) ||
                   (type == 51 && f.number == 2) ||
                   (type == 52 && (f.number == 2 || f.number == 3)) ||
                   (type == 64 && (f.number == 3 || f.number == 4))) {
            if (f.wire != 2) return false;
            v->target = "unresolved"; /* Presence is NOT a session/group binding. */
            if ((type == 52 && f.number == 2) || (type == 64 && f.number == 3)) {
                v->endpoint_bytes = f.data;
                v->endpoint_len = f.len;
            } else {
                v->output_bytes = f.data;
                v->output_len = f.len;
            }
        }
    }
    return true;
}

static struct mrp_diag_volume mrp_diag_volume(const uint8_t *body, size_t len,
                                             int command, const char *classification)
{
    struct mrp_diag_volume v = {command >= 0 ? "transport" : "unknown",
        "missing", "missing", -1, -1, -1};
    if (command >= 0) return v;
    char root_type[64];
    if (body && len <= 65536 && ap2_bplist_get_root_string(
            body, len, "type", root_type, sizeof(root_type)) &&
        !strcmp(root_type, "receiverVolumeDidChange")) {
        v.message = "receiver_telemetry";
        return v; /* Arbitrary root value is never interpreted as a command/value. */
    }
    if (!strcmp(classification, "invalid")) { v.message = "invalid"; return v; }
    const uint8_t *p;
    size_t bytes;
    if (!body || len > 65536 || !ap2_bplist_get_params_data(body, len, &p, &bytes))
        return v;
    const uint8_t *end = p + bytes;
    uint64_t n;
    if (!mrp_diag_varint(&p, end, &n) || n != (uint64_t)(end - p)) {
        v.message = "invalid"; return v;
    }
    struct mrp_diag_reader r = {.p = p, .end = end};
    struct mrp_diag_field extension = {0};
    int type = -1;
    while (r.p < r.end) {
        struct mrp_diag_field f;
        if (!mrp_diag_field(&r, &f)) goto invalid;
        if (f.number == 1) {
            if (f.wire != 0) goto invalid;
            if (f.integer <= 65535) type = (int)f.integer;
        } else if (f.number > 5 && f.number != 78 && f.number != 85) {
            if (extension.number) goto invalid;
            extension = f;
        } else {
            unsigned wire = (f.number == 2 || f.number == 3 ||
                             f.number == 78 || f.number == 85) ? 2 : 0;
            if (f.wire != wire) goto invalid;
        }
    }
    unsigned expected;
    v.type = type;
    switch (type) {
        case 17: expected = 22; v.message = "volume_capability"; break;
        case 49: expected = 53; v.message = "volume_get"; break;
        case 50: expected = 54; v.message = "volume_result"; break;
        case 51: expected = 55; v.message = "volume_set_candidate"; break;
        case 52: expected = 56; v.message = "volume_feedback"; break;
        case 64: expected = 68; v.message = "volume_capability"; break;
        default: return v;
    }
    if (extension.number != expected || extension.wire != 2 ||
        !mrp_diag_volume_body(type, extension.data, extension.len, &v)) goto invalid;
    /* The public field is optional, but a set candidate needs an actual level.
     * Missing feedback/result levels remain observations, never implicit zero. */
    if (type == 51 && strcmp(v.value_state, "valid")) goto invalid;
    return v;
invalid:
    v.message = "invalid";
    v.target = "missing";
    if (!strcmp(v.value_state, "valid")) v.value_state = "invalid";
    v.value_milli = v.available = v.capabilities = -1;
    v.endpoint_bytes = v.output_bytes = NULL;
    v.endpoint_len = v.output_len = 0;
    return v;
}

/* Capture no receiver bytes or strings. Candidate role comparisons are exact
 * process-memory byte comparisons only; no UID normalization or registration
 * follows from a match. */
static void mrp_capture_increment(uint64_t *value, bool *overflow)
{
    if (*value == UINT64_MAX) { *overflow = true; return; }
    ++*value;
}

static void mrp_capture_ingress(struct ap2_mrp_ctx *m, bool event, bool transport,
    const char *classification, const struct mrp_diag_volume *v)
{
    if (!m->private_native_volume_capture) return;
    pthread_mutex_lock(&m->capture_lock);
    if (m->capture_frozen) { pthread_mutex_unlock(&m->capture_lock); return; }
    mrp_capture_increment(&m->capture_records, &m->capture_overflow);
    mrp_capture_increment(&m->capture_plane[event ? 0 : 1][0], &m->capture_overflow);
    if (!strcmp(v->message, "volume_get")) mrp_capture_increment(&m->capture_volume[0], &m->capture_overflow);
    else if (!strcmp(v->message, "volume_result")) mrp_capture_increment(&m->capture_volume[1], &m->capture_overflow);
    else if (!strcmp(v->message, "volume_set_candidate")) mrp_capture_increment(&m->capture_volume[2], &m->capture_overflow);
    else if (!strcmp(v->message, "volume_feedback")) mrp_capture_increment(&m->capture_volume[3], &m->capture_overflow);
    else if (!strcmp(v->message, "volume_capability"))
        mrp_capture_increment(&m->capture_volume[v->type == 17 ? 4 : 5], &m->capture_overflow);
    else mrp_capture_increment(&m->capture_kind[transport ? 0 : 1], &m->capture_overflow);
    if (!strcmp(classification, "invalid") || !strcmp(v->message, "invalid"))
        mrp_capture_increment(&m->capture_parser[1], &m->capture_overflow);
    else if (!strcmp(classification, "protobuf"))
        mrp_capture_increment(&m->capture_parser[0], &m->capture_overflow);
    else mrp_capture_increment(&m->capture_parser[2], &m->capture_overflow);
    const char *roles[] = {m->device_uuid, m->session_uuid, m->group_uuid};
    bool *candidates[] = {&m->capture_sender_candidate, &m->capture_session_candidate,
        &m->capture_group_candidate};
    bool *endpoint_matches[] = {&m->capture_endpoint_sender_match,
        &m->capture_endpoint_session_match, &m->capture_endpoint_group_match};
    bool *output_matches[] = {&m->capture_output_sender_match,
        &m->capture_output_session_match, &m->capture_output_group_match};
    for (unsigned i = 0; i < 3; ++i) if (roles[i] && roles[i][0]) {
        *candidates[i] = true;
        if (v->endpoint_bytes && v->endpoint_len == strlen(roles[i]) &&
            !memcmp(v->endpoint_bytes, roles[i], v->endpoint_len)) *endpoint_matches[i] = true;
        if (v->output_bytes && v->output_len == strlen(roles[i]) &&
            !memcmp(v->output_bytes, roles[i], v->output_len)) *output_matches[i] = true;
    }
    pthread_mutex_unlock(&m->capture_lock);
}

static void mrp_capture_egress(struct ap2_mrp_ctx *m, bool event)
{
    if (!m->private_native_volume_capture) return;
    pthread_mutex_lock(&m->capture_lock);
    if (!m->capture_frozen) {
        mrp_capture_increment(&m->capture_records, &m->capture_overflow);
        mrp_capture_increment(&m->capture_plane[event ? 0 : 1][1], &m->capture_overflow);
    }
    pthread_mutex_unlock(&m->capture_lock);
}

static void mrp_capture_freeze(struct ap2_mrp_ctx *m)
{
    if (!m->private_native_volume_capture) return;
    pthread_mutex_lock(&m->capture_lock);
    if (m->capture_frozen) { pthread_mutex_unlock(&m->capture_lock); return; }
    m->capture_frozen = true; /* Stop entry is the observation cutoff. */
    m->capture_event_cutoff = !m->event_attached ? -1 : atomic_load(&m->event_connected) ? 1 : 0;
    m->capture_data_cutoff = !m->data_attached ? -1 : m->connected ? 1 : 0;
    pthread_mutex_lock(&m->volume.lock);
    m->capture_generation = m->volume.generation;
    m->capture_binding = m->volume.output_len != 0;
    pthread_mutex_unlock(&m->volume.lock);
    pthread_mutex_unlock(&m->capture_lock);
}

static void mrp_capture_summary(struct ap2_mrp_ctx *m)
{
    if (!m->private_native_volume_capture) return;
    pthread_mutex_lock(&m->capture_lock);
    if (!m->capture_frozen || m->capture_emitted) {
        pthread_mutex_unlock(&m->capture_lock);
        return;
    }
    m->capture_emitted = true;
    uint64_t generation = m->capture_generation;
    bool bound = m->capture_binding;
    /* Freeze makes every summary field immutable. Never hold the receive-path
     * mutex while waiting on stderr, which may have a stalled consumer. */
    pthread_mutex_unlock(&m->capture_lock);
    flockfile(stderr);
    fprintf(stderr, "[STATUS] native_volume_capture version=1 records=%llu overflow=%d "
        "event_in=%llu event_out=%llu datastream_in=%llu datastream_out=%llu "
        "volume_get=%llu volume_result=%llu volume_set_candidate=%llu volume_feedback=%llu "
        "volume_availability=%llu volume_capabilities=%llu transport=%llu other=%llu "
        "parser_valid=%llu parser_invalid=%llu parser_unknown=%llu "
        "event_at_cutoff=%s datastream_at_cutoff=%s dacp=outside_cli subscription=0 publication=0 capability=0 "
        "generation_at_cutoff=%llu binding_at_cutoff=%d sender_candidate=%d endpoint_sender_match=%d output_sender_match=%d "
        "session_candidate=%d endpoint_session_match=%d output_session_match=%d "
        "group_candidate=%d endpoint_group_match=%d output_group_match=%d\n",
        (unsigned long long)m->capture_records, m->capture_overflow ? 1 : 0,
        (unsigned long long)m->capture_plane[0][0], (unsigned long long)m->capture_plane[0][1],
        (unsigned long long)m->capture_plane[1][0], (unsigned long long)m->capture_plane[1][1],
        (unsigned long long)m->capture_volume[0], (unsigned long long)m->capture_volume[1],
        (unsigned long long)m->capture_volume[2], (unsigned long long)m->capture_volume[3],
        (unsigned long long)m->capture_volume[4], (unsigned long long)m->capture_volume[5],
        (unsigned long long)m->capture_kind[0], (unsigned long long)m->capture_kind[1],
        (unsigned long long)m->capture_parser[0], (unsigned long long)m->capture_parser[1],
        (unsigned long long)m->capture_parser[2],
        m->capture_event_cutoff > 0 ? "connected" : m->capture_event_cutoff == 0 ? "closed" : "unattached",
        m->capture_data_cutoff > 0 ? "connected" : m->capture_data_cutoff == 0 ? "closed" : "unattached",
        (unsigned long long)generation, bound ? 1 : 0,
        m->capture_sender_candidate ? 1 : 0, m->capture_endpoint_sender_match ? 1 : 0,
        m->capture_output_sender_match ? 1 : 0, m->capture_session_candidate ? 1 : 0,
        m->capture_endpoint_session_match ? 1 : 0, m->capture_output_session_match ? 1 : 0,
        m->capture_group_candidate ? 1 : 0, m->capture_endpoint_group_match ? 1 : 0,
        m->capture_output_group_match ? 1 : 0);
    funlockfile(stderr);
}

static void mrp_diagnostic(struct ap2_mrp_ctx *m, bool event,
    const char *kind, const uint8_t *body, size_t len, int command, bool handled)
{
    if (!m->experimental_homepod_remote || m->private_native_volume_capture ||
        m->diagnostic_count >= 128) return;
    uint64_t now = ap2_io_monotonic_ms();
    if (!m->diagnostic_count) m->diagnostic_start_ms = now;
    int type = -1;
    const char *classification = command >= 0 ? "command" :
        mrp_diag_protobuf(body, len, &type);
    static const char *commands[] = {"play", "pause", "toggle", "next", "previous"};
    const char *name = command >= 0 && command < 5 ? commands[command] : "unknown";
    struct mrp_diag_volume v = mrp_diag_volume(body, len, command, classification);
    flockfile(stderr);
    fprintf(stderr, "[STATUS] homepod_remote ordinal=%u elapsed_ms=%llu "
        "channel=%s frame_kind=%s classification=%s command=%s protobuf_type=%d "
        "bytes=%zu dispatched=%d message=%s target=%s value_state=%s", ++m->diagnostic_count,
        (unsigned long long)(now - m->diagnostic_start_ms),
        event ? "event" : "datastream", kind, classification, name, type, len,
        handled ? 1 : 0, v.message, v.target, v.value_state);
    if (v.value_milli >= 0) fprintf(stderr, " value_milli=%d", v.value_milli);
    if (v.available >= 0) fprintf(stderr, " available=%d", v.available);
    if (v.capabilities >= 0) fprintf(stderr, " capabilities=%d", v.capabilities);
    fputc('\n', stderr);
    funlockfile(stderr);
}

/* PUBLICATION CLOSED in production. Test inclusion can verify encrypted wire
 * behavior against an explicitly synthetic identity; no runtime bypass exists. */
static bool mrp_volume_publication_allowed(struct ap2_mrp_ctx *m)
{
#ifdef AP2_VOLUME_TESTING
    return m->verified_volume_identity;
#else
    (void)m;
    return false;
#endif
}
static bool mrp_volume_reply(struct ap2_mrp_ctx *m, unsigned milli,
    const uint8_t *identifier, size_t identifier_len, bool change)
{
    if (!mrp_volume_publication_allowed(m)) return false;
    mbuf msg = {0}, inner = {0};
    bool ok = pb_put_float_field(&inner, 1, milli / 1000.0f);
    if (change) {
        pthread_mutex_lock(&m->volume.lock);
        ok &= pb_put_bytes_field(&inner, 2, m->volume.endpoint, m->volume.endpoint_len);
        ok &= pb_put_bytes_field(&inner, 3, m->volume.output, m->volume.output_len);
        pthread_mutex_unlock(&m->volume.lock);
    }
    ok &= pb_put_varint_field(&msg, 1, change ? 52 : 50);
    if (!change) ok &= pb_put_bytes_field(&msg, 2, identifier, identifier_len);
    ok &= pb_put_msg_field(&msg, change ? 56 : 54, &inner);
    if (ok) ok = mrp_send_protobuf(m, &msg);
    mbuf_free(&msg); mbuf_free(&inner);
    return ok;
}
static void mrp_volume_request(void *userdata, uint64_t generation,
    uint64_t ordinal, unsigned milli)
{
    (void)userdata;
    printf("[EVENT] session_volume_set generation=%llu ordinal=%llu milli=%u\n",
        (unsigned long long)generation, (unsigned long long)ordinal, milli);
    fflush(stdout);
}
void ap2_mrp_set_volume_mode(struct ap2_mrp_ctx *m, bool enabled)
{
    if (!m) return;
    m->volume_mode = enabled;
    m->volume.callback = enabled ? mrp_volume_request : NULL;
}
void ap2_mrp_set_volume_callback(struct ap2_mrp_ctx *m,
    ap2_volume_request_cb callback, void *userdata)
{
    if (!m) return;
    m->volume.callback = callback; m->volume.userdata = userdata;
}
bool ap2_mrp_volume_action(struct ap2_mrp_ctx *m, const char *action,
    const struct ap2_volume_transaction *t)
{
    if (!m || !m->volume_mode) return false;
    if (!strcmp(action, "SESSION_VOLUME_BIND"))
        return ap2_volume_bind(&m->volume, t->generation, t->output, t->output_len,
            t->endpoint, t->endpoint_len);
    if (!strcmp(action, "SESSION_VOLUME_UNBIND")) {
        ap2_volume_unbind(&m->volume, t->generation); return true;
    }
    if (!strcmp(action, "SESSION_VOLUME_STATE"))
        return ap2_volume_state(&m->volume, t->generation, t->revision, t->known, t->milli);
    if (!strcmp(action, "SESSION_VOLUME_COMPLETE"))
        return ap2_volume_complete(&m->volume, t->generation, t->ordinal, t->result,
            t->revision, t->known, t->milli, ap2_io_monotonic_ms());
    return false;
}
static void mrp_volume_receive(struct ap2_mrp_ctx *m, const uint8_t *body, size_t len)
{
    if (!m->volume_mode) return;
    pthread_mutex_lock(&m->volume.lock);
    uint64_t generation = m->volume.generation;
    pthread_mutex_unlock(&m->volume.lock);
    if (generation != m->volume_replay_generation) {
        memset(m->volume_replay_len, 0, sizeof(m->volume_replay_len));
        m->volume_replay_next = 0;
        m->volume_replay_generation = generation;
        m->volume_published_revision = 0;
    }
    const uint8_t *p; size_t bytes;
    if (!ap2_bplist_get_volume_data(body, len, &p, &bytes)) return;
    const uint8_t *end = p + bytes; uint64_t n;
    if (!mrp_diag_varint(&p, end, &n) || n != (uint64_t)(end - p)) return;
    struct mrp_diag_reader r = {.p = p, .end = end};
    struct mrp_diag_field ext = {0}, id = {0};
    unsigned type = 0;
    while (r.p < r.end) {
        struct mrp_diag_field f;
        if (!mrp_diag_field(&r, &f)) return;
        if (f.number == 1) { if (f.wire != 0 || f.integer > 65535) return; type = f.integer; }
        else if (f.number == 2) { if (f.wire != 2 || !f.len || f.len > 128) return; id = f; }
        else if (f.number > 5 && f.number != 78 && f.number != 85) {
            if (ext.number || f.wire != 2) return;
            ext = f;
        } else if (f.wire != ((f.number == 3 || f.number == 78 || f.number == 85) ? 2u : 0u)) return;
    }
    /* Results/feedback/capabilities are observations, NEVER requests. No
     * outgoing Gets exist, so there is no pending response registry. */
    if ((type != 49 && type != 51) || ext.number != (type == 49 ? 53u : 55u)) return;
    struct mrp_diag_volume v = {0}; v.value_milli = -1;
    if (!mrp_diag_volume_body(type, ext.data, ext.len, &v)) return;
    struct mrp_diag_reader inner = {.p = ext.data, .end = ext.data + ext.len};
    const uint8_t *uid = NULL; size_t uid_len = 0;
    while (inner.p < inner.end) {
        struct mrp_diag_field f;
        if (!mrp_diag_field(&inner, &f)) return;
        if (f.number == (type == 49 ? 1u : 2u)) { uid = f.data; uid_len = f.len; }
    }
    if (!uid_len || uid_len > 128) return;
    unsigned milli;
    if (type == 49) {
        if (id.len && m->volume_get_count < 8 &&
            ap2_volume_get(&m->volume, uid, uid_len, &milli) && mrp_volume_publication_allowed(m)) {
            unsigned slot = m->volume_get_count++;
            memcpy(m->volume_gets[slot].id, id.data, id.len);
            m->volume_gets[slot].len = id.len;
            m->volume_gets[slot].generation = generation;
        }
    } else if (v.value_milli >= 0) {
        if (id.len) for (unsigned i = 0; i < 16; ++i)
            if (m->volume_replay_len[i] == id.len && !memcmp(m->volume_replay[i], id.data, id.len)) return;
        if (ap2_volume_set(&m->volume, uid, uid_len, v.value_milli, ap2_io_monotonic_ms()) && id.len) {
            unsigned slot = m->volume_replay_next++ % 16;
            memcpy(m->volume_replay[slot], id.data, id.len); m->volume_replay_len[slot] = id.len;
        }
    }
}
static void mrp_volume_flush(struct ap2_mrp_ctx *m)
{
    if (!m->volume_mode) return;
    pthread_mutex_lock(&m->volume.lock);
    bool known = m->volume.known && !m->volume.uncertain && m->volume.output_len;
    unsigned milli = m->volume.milli;
    uint64_t revision = m->volume.revision, generation = m->volume.generation;
    pthread_mutex_unlock(&m->volume.lock);
    if (known && mrp_volume_publication_allowed(m)) {
        for (unsigned i = 0; i < m->volume_get_count; ++i)
            if (m->volume_gets[i].generation == generation)
                mrp_volume_reply(m, milli, m->volume_gets[i].id, m->volume_gets[i].len, false);
        if (revision > m->volume_published_revision && mrp_volume_reply(m, milli, NULL, 0, true))
            m->volume_published_revision = revision;
    }
    m->volume_get_count = 0;
}
/* ACK before semantic processing; backend calls never hold send/state locks. */
static void mrp_process_frames(struct ap2_mrp_ctx *m)
{
    int off = 0;
    while (m->rx_msg_len - off >= MRP_DATA_HDR_LEN) {
        const uint8_t *h = m->rx_msg + off;
        uint32_t size = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
                        ((uint32_t)h[2] << 8) | h[3];
        if (size < MRP_DATA_HDR_LEN || size > sizeof(m->rx_msg)) {
            LOG_ERROR("[MRP] bad data frame size %u, resetting buffer", size);
            m->rx_msg_len = 0;
            return;
        }
        if ((int)size > m->rx_msg_len - off) break;   /* incomplete */

        uint64_t seqno = 0;
        for (int i = 0; i < 8; i++) seqno = (seqno << 8) | h[20 + i];

        bool sync = !memcmp(h + 4, "sync\0\0\0\0\0\0\0\0", 12);
        bool reply = !memcmp(h + 4, "rply\0\0\0\0\0\0\0\0", 12);
        if (m->private_native_volume_capture) {
            int type = -1;
            const uint8_t *body = h + MRP_DATA_HDR_LEN;
            size_t body_len = size - MRP_DATA_HDR_LEN;
            const char *classification = mrp_diag_protobuf(body, body_len, &type);
            struct mrp_diag_volume volume = mrp_diag_volume(body, body_len, -1, classification);
            mrp_capture_ingress(m, false, false, classification, &volume);
        }
        mrp_diagnostic(m, false, sync ? "sync" : reply ? "reply" : "unknown",
            h + MRP_DATA_HDR_LEN, size - MRP_DATA_HDR_LEN, -1, false);
        if (memcmp(h + 4, "sync", 4) == 0) {
            LOG_DEBUG("[MRP] inbound frame kind=sync bytes=%u", size);
            mrp_send_reply(m, seqno);
            if (sync && !memcmp(h + 16, "comm", 4))
                mrp_volume_receive(m, h + MRP_DATA_HDR_LEN, size - MRP_DATA_HDR_LEN);
        } else {
            LOG_DEBUG("[MRP] inbound frame kind=%s bytes=%u", reply ? "reply" : "unknown", size);
        }
        off += (int)size;
    }
    if (off > 0) {
        memmove(m->rx_msg, m->rx_msg + off, m->rx_msg_len - off);
        m->rx_msg_len -= off;
    }
}

/* ---- Reverse event-channel handling ---- */

static int mrp_http_header_end(const uint8_t *data, int len)
{
    for (int i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n')
            return i + 4;
    }
    return 0;
}

static bool mrp_http_header_value(const char *header, const char *name,
                                  char *out, size_t out_size)
{
    size_t name_len = strlen(name);
    const char *line = strstr(header, "\r\n");
    if (!line) return false;
    line += 2;

    while (*line) {
        const char *end = strstr(line, "\r\n");
        if (!end || end == line) break;
        size_t line_len = (size_t)(end - line);
        if (line_len > name_len && line[name_len] == ':' &&
            strncasecmp(line, name, name_len) == 0) {
            const char *value = line + name_len + 1;
            while (value < end && (*value == ' ' || *value == '\t')) value++;
            while (end > value && (end[-1] == ' ' || end[-1] == '\t')) end--;
            size_t value_len = (size_t)(end - value);
            if (value_len >= out_size) value_len = out_size - 1;
            memcpy(out, value, value_len);
            out[value_len] = '\0';
            return true;
        }
        line = end + 2;
    }
    return false;
}

void ap2_mrp_set_remote_command_callback(
    struct ap2_mrp_ctx *m, ap2_remote_command_cb_t callback, void *userdata)
{
    if (!m) return;
    m->remote_command_cb = callback;
    m->remote_command_userdata = userdata;
}

static void mrp_emit_remote_command(
    struct ap2_mrp_ctx *m, ap2_remote_command_t command)
{
    if (m->remote_command_cb)
        m->remote_command_cb(command, m->remote_command_userdata);
}

static bool mrp_parse_remote_command(const uint8_t *body, int body_len,
                                     ap2_remote_command_t *command)
{
    if (!body || body_len < 8 || !command ||
        memcmp(body, "bplist00", 8) != 0)
        return false;

    char type[64];
    char value[64];
    if (!ap2_bplist_get_root_string(
            body, (size_t)body_len, "type", type, sizeof(type)) ||
        strcmp(type, "sendMediaRemoteCommand") != 0 ||
        !ap2_bplist_get_root_string(
            body, (size_t)body_len, "value", value, sizeof(value)))
        return false;

    if (strcmp(value, "play") == 0)
        *command = AP2_REMOTE_COMMAND_PLAY;
    else if (strcmp(value, "paus") == 0)
        *command = AP2_REMOTE_COMMAND_PAUSE;
    else if (strcmp(value, "plps") == 0)
        *command = AP2_REMOTE_COMMAND_PLAY_PAUSE;
    else if (strcmp(value, "nitm") == 0)
        *command = AP2_REMOTE_COMMAND_NEXT;
    else if (strcmp(value, "pitm") == 0)
        *command = AP2_REMOTE_COMMAND_PREVIOUS;
    else
        return false;
    return true;
}

static bool mrp_event_send_response(struct ap2_mrp_ctx *m,
                                    const uint8_t *response, int response_len)
{
    pthread_mutex_lock(&m->send_lock);
    if (!atomic_load(&m->event_connected) || m->event_sock < 0) {
        pthread_mutex_unlock(&m->send_lock);
        return false;
    }
    uint8_t *enc = NULL;
    int enc_len = mrp_channel_encrypt_with(
        m->event_out_key, &m->event_out_counter,
        response, response_len, &enc);
    bool ok = enc_len > 0 && enc &&
              mrp_write_all(m->event_sock, enc, enc_len);
    free(enc);
    if (ok) mrp_capture_egress(m, true);
    if (!ok) {
        LOG_ERROR("[MRP] event channel write failed: %s", strerror(errno));
        mrp_close_event_channel(m);
    }
    pthread_mutex_unlock(&m->send_lock);
    return ok;
}

static bool mrp_process_event_requests(struct ap2_mrp_ctx *m)
{
    int off = 0;
    while (off < m->event_plain_len) {
        int available = m->event_plain_len - off;
        int header_len = mrp_http_header_end(m->event_plain + off, available);
        if (!header_len) break;
        if (header_len >= 8192) {
            LOG_ERROR("[MRP] event HTTP header too large");
            return false;
        }

        char header[8192];
        memcpy(header, m->event_plain + off, (size_t)header_len);
        header[header_len] = '\0';

        int content_len = 0;
        char value[256];
        if (mrp_http_header_value(header, "Content-Length",
                                  value, sizeof(value))) {
            char *end = NULL;
            long parsed = strtol(value, &end, 10);
            if (!end || end == value || *end != '\0' || parsed < 0 ||
                parsed > (long)sizeof(m->event_plain)) {
                LOG_ERROR("[MRP] invalid event Content-Length");
                return false;
            }
            content_len = (int)parsed;
        }
        if (header_len + content_len > available) break;

        char method[16] = "";
        char path[256] = "";
        char version[16] = "RTSP/1.0";
        if (sscanf(header, "%15s %255s %15s", method, path, version) < 3) {
            LOG_ERROR("[MRP] malformed event request line");
            return false;
        }
        bool is_command = content_len > 0 &&
                          strcasecmp(method, "POST") == 0 &&
                          strcmp(path, "/command") == 0;
        ap2_remote_command_t remote_command;
        bool have_remote_command = false;
        const uint8_t *body = m->event_plain + off + header_len;
        if (m->private_native_volume_capture) {
            int capture_type = -1;
            const char *capture_classification = mrp_diag_protobuf(body, (size_t)content_len,
                &capture_type);
            struct mrp_diag_volume capture_volume = mrp_diag_volume(body,
                (size_t)content_len, -1, capture_classification);
            ap2_remote_command_t capture_command;
            /* Classification is before dispatch; unknown requests remain `other`. */
            bool transport = is_command && mrp_parse_remote_command(body, content_len,
                &capture_command);
            mrp_capture_ingress(m, true, transport, capture_classification, &capture_volume);
        }
        if (is_command) {
            have_remote_command =
                mrp_parse_remote_command(body, content_len, &remote_command);
            LOG_DEBUG("[MRP] event command classification=%s bytes=%d",
                      have_remote_command ? "transport" : "unknown", content_len);
        }

        char cseq[64] = "";
        char server[256] = "";
        bool have_cseq = mrp_http_header_value(header, "CSeq",
                                               cseq, sizeof(cseq));
        bool have_server = mrp_http_header_value(header, "Server",
                                                 server, sizeof(server));
        char response[768];
        int response_len = snprintf(
            response, sizeof(response),
            "%s 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Audio-Latency: 0\r\n"
            "%s%s%s"
            "%s%s%s"
            "\r\n",
            version,
            have_server ? "Server: " : "", have_server ? server : "",
            have_server ? "\r\n" : "",
            have_cseq ? "CSeq: " : "", have_cseq ? cseq : "",
            have_cseq ? "\r\n" : "");
        bool response_ok =
            response_len > 0 && response_len < (int)sizeof(response) &&
            mrp_event_send_response(
                m, (const uint8_t *)response, response_len);
        bool dispatched = have_remote_command && m->remote_command_cb != NULL;
        if (have_remote_command)
            mrp_emit_remote_command(m, remote_command);
        mrp_diagnostic(m, true, is_command ? "command" : "unknown",
            m->event_plain + off + header_len, (size_t)content_len,
            have_remote_command ? (int)remote_command : -1,
            dispatched);
        if (!response_ok) {
            LOG_ERROR("[MRP] event response send failed");
            return false;
        }
        LOG_DEBUG("[MRP] event kind=%s bytes=%d -> 200",
                  is_command ? "command" : "unknown", content_len);
        off += header_len + content_len;
    }

    if (off > 0) {
        memmove(m->event_plain, m->event_plain + off,
                (size_t)(m->event_plain_len - off));
        m->event_plain_len -= off;
    }
    return true;
}

static void mrp_tick_events(struct ap2_mrp_ctx *m)
{
    if (!atomic_load(&m->event_connected) || m->event_sock < 0) return;

    struct pollfd pfd = {
        .fd = m->event_sock,
        .events = POLLIN,
    };
    while (poll(&pfd, 1, 0) > 0) {
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            LOG_WARN("[MRP] event channel socket error");
            mrp_close_event_channel(m);
            return;
        }
        if (!(pfd.revents & POLLIN)) {
            if (pfd.revents & POLLHUP) {
                LOG_WARN("[MRP] event channel closed by receiver");
                mrp_close_event_channel(m);
            }
            return;
        }

        int space = (int)sizeof(m->event_rx_enc) - m->event_rx_enc_len;
        if (space <= 0) {
            LOG_ERROR("[MRP] event encrypted buffer full");
            mrp_close_event_channel(m);
            return;
        }
        ssize_t n = read(m->event_sock,
                         m->event_rx_enc + m->event_rx_enc_len,
                         (size_t)space);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) {
            LOG_WARN("[MRP] event channel closed by receiver");
            mrp_close_event_channel(m);
            return;
        }
        m->event_rx_enc_len += (int)n;
        if (!mrp_drain_channel_frames(
                m->event_rx_enc, &m->event_rx_enc_len,
                m->event_plain, &m->event_plain_len,
                (int)sizeof(m->event_plain),
                m->event_in_key, &m->event_in_counter, "event channel") ||
            !mrp_process_event_requests(m)) {
            mrp_close_event_channel(m);
            return;
        }
        pfd.revents = 0;
    }
}

/* ---- Public API ---- */

struct ap2_mrp_ctx *ap2_mrp_create(const char *host, int port,
                                    const char *auth_credentials,
                                    const char *dacp_id,
                                    const char *device_name,
                                    const char *session_uuid,
                                    const char *group_uuid,
                                    const uint8_t *secret, size_t secret_len)
{
    if (!host) return NULL;
    if (secret && (secret_len == 0 || secret_len > MRP_KDF_SECRET_MAX))
        return NULL;
    struct ap2_mrp_ctx *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    if (!ap2_volume_init(&m->volume)) { free(m); return NULL; }

    m->host = mrp_strdup(host);
    m->port = port;
    m->auth_credentials = auth_credentials ? mrp_strdup(auth_credentials) : NULL;
    m->dacp_id = mrp_strdup(dacp_id && *dacp_id ? dacp_id : "cliairplay");
    m->name = mrp_strdup(device_name && *device_name ? device_name : "Music Assistant");
    m->session_uuid = mrp_strdup(session_uuid);
    m->group_uuid = mrp_strdup(group_uuid);
    mrp_identity_uuid(m->dacp_id, m->device_uuid);
    m->playback_state = AP2_MRP_PLAYBACK_PAUSED;
    m->elapsed_set_at = mrp_cf_now();
    m->state_generation = 1;
    m->state_dirty = true;
    m->sock = -1;
    m->event_sock = -1;
    pthread_mutex_init(&m->send_lock, NULL);
    pthread_mutex_init(&m->capture_lock, NULL);
    atomic_init(&m->event_connected, false);

    if (secret) {
        memcpy(m->shared_secret, secret, secret_len);
        m->shared_secret_len = secret_len;
        m->have_secret = true;
    }

    /* pyatv picks a random 33-bit seqno (randrange(0x100000000, 0x1FFFFFFFF))
     * and keeps it constant for every frame on the channel. */
    uint32_t r = 0;
    RAND_bytes((uint8_t *)&r, sizeof(r));
    m->send_seqno = 0x100000000ULL | r;

    return m;
}

void ap2_mrp_destroy(struct ap2_mrp_ctx *m)
{
    if (!m) return;
    ap2_mrp_stop(m);
    pthread_mutex_destroy(&m->send_lock);
    pthread_mutex_destroy(&m->capture_lock);
    ap2_volume_destroy(&m->volume);
    OPENSSL_cleanse(m->shared_secret, sizeof(m->shared_secret));
    OPENSSL_cleanse(m->out_key, sizeof(m->out_key));
    OPENSSL_cleanse(m->in_key, sizeof(m->in_key));
    OPENSSL_cleanse(m->event_out_key, sizeof(m->event_out_key));
    OPENSSL_cleanse(m->event_in_key, sizeof(m->event_in_key));
    free(m->host);
    free(m->auth_credentials);
    free(m->dacp_id);
    free(m->name);
    free(m->session_uuid);
    free(m->group_uuid);
    free(m->title);
    free(m->artist);
    free(m->album);
    free(m->item_id);
    free(m->artwork_mime);
    free(m->artwork);
    free(m);
}

void ap2_mrp_set_experimental_homepod_remote(struct ap2_mrp_ctx *m, bool enabled)
{
    if (!m) return;
    m->experimental_homepod_remote = enabled;
}

void ap2_mrp_set_private_native_volume_capture(struct ap2_mrp_ctx *m, bool enabled)
{
    if (!m || !m->experimental_homepod_remote) return;
    m->private_native_volume_capture = enabled;
}

bool ap2_mrp_attach_events(struct ap2_mrp_ctx *m, int event_sock)
{
    if (!m || event_sock < 0) return false;
    if (!m->have_secret) {
        LOG_ERROR("[MRP] event channel requires the pairing shared secret");
        return false;
    }
    /* The receiver is the logical writer on this reverse channel, so the key
     * labels are swapped from our perspective (pyatv EventChannel). */
    int secret_len = (int)m->shared_secret_len;
    if (!mrp_hkdf_sha512(m->shared_secret, secret_len, MRP_EVENTS_SALT,
                         MRP_EVENTS_READ_INFO,
                         m->event_out_key, MRP_KEY_SIZE) ||
        !mrp_hkdf_sha512(m->shared_secret, secret_len, MRP_EVENTS_SALT,
                         MRP_EVENTS_WRITE_INFO,
                         m->event_in_key, MRP_KEY_SIZE)) {
        LOG_ERROR("[MRP] event channel key derivation failed");
        return false;
    }
    m->event_sock = event_sock;
    atomic_store(&m->event_connected, true);
    m->event_attached = true;
    m->event_out_counter = 0;
    m->event_in_counter = 0;
    m->event_rx_enc_len = 0;
    m->event_plain_len = 0;
    LOG_INFO("[MRP] encrypted event channel attached");
    return true;
}

/* Now-playing rides the datastream only on a plain type-130 attach. Volume mode keeps
 * it on POST /command, and private capture attaches the datastream receive-only: the
 * session under observation must not gain a second now-playing publisher. */
static bool mrp_now_playing_on_datastream(const struct ap2_mrp_ctx *m)
{
    return !m->volume_mode && !m->private_native_volume_capture;
}

/* Separated only to exercise actual opening/failure behavior with socketpairs. */
static bool mrp_data_handshake(struct ap2_mrp_ctx *m)
{
    mbuf msg = {0};
    bool ok = build_device_info(m, &msg) && mrp_send_protobuf(m, &msg);
    mbuf_free(&msg);
    ok = ok && build_set_connection_state(&msg, MRP_CONNECTION_STATE_CONNECTED) && mrp_send_protobuf(m, &msg);
    mbuf_free(&msg);
    ok = ok && build_client_updates_config(&msg) && mrp_send_protobuf(m, &msg);
    mbuf_free(&msg);
    if (mrp_now_playing_on_datastream(m)) {
        ok = ok && build_set_now_playing_client(m, &msg) && mrp_send_protobuf(m, &msg);
        mbuf_free(&msg);
        ok = ok && mrp_push_state(m, m->artwork_len > 0);
        if (ok) { m->state_dirty = false; m->state_include_artwork = false; }
    }
    if (!ok) {
        LOG_ERROR("[MRP] handshake push failed");
        mrp_close_data_channel(m); /* NEVER close the independent event channel. */
    }
    return ok;
}

bool ap2_mrp_attach(struct ap2_mrp_ctx *m, int data_port, uint64_t seed)
{
    if (!m || data_port <= 0) return false;
    if (!m->have_secret) {
        LOG_ERROR("[MRP] attach requires the session's pairing shared secret");
        return false;
    }

    /* Derive the DataStream channel keys: HKDF-SHA512, salt =
     * "DataStream-Salt" + decimal seed, info = the Output/Input strings. */
    char salt[64];
    snprintf(salt, sizeof(salt), MRP_DATASTREAM_SALT_PREFIX "%llu",
             (unsigned long long)seed);
    int secret_len = (int)m->shared_secret_len;
    if (!mrp_hkdf_sha512(m->shared_secret, secret_len, salt,
                         MRP_DATASTREAM_OUTPUT_INFO, m->out_key, MRP_KEY_SIZE) ||
        !mrp_hkdf_sha512(m->shared_secret, secret_len, salt,
                         MRP_DATASTREAM_INPUT_INFO, m->in_key, MRP_KEY_SIZE)) {
        LOG_ERROR("[MRP] DataStream key derivation failed");
        return false;
    }
    m->out_counter = 0;
    m->in_counter = 0;

    /* TCP connect to the receiver's dataPort */
    m->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (m->sock < 0) return false;
    struct timeval tv = { .tv_sec = 5 };
    setsockopt(m->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(m->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)data_port),
    };
    inet_pton(AF_INET, m->host, &addr.sin_addr);
    if (connect(m->sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LOG_ERROR("[MRP] data channel connect to %s:%d failed: %s",
                  m->host, data_port, strerror(errno));
        close(m->sock);
        m->sock = -1;
        return false;
    }
    int one = 1;
    setsockopt(m->sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    m->connected = true;
    m->data_attached = true;
    LOG_INFO("[MRP] data channel connected to %s:%d", m->host, data_port);

    /* DEVICE_INFO first, then connection/update configuration. Volume mode
     * deliberately leaves all now-playing publication on POST /command. */
    return mrp_data_handshake(m);
}

bool ap2_mrp_start(struct ap2_mrp_ctx *m)
{
    if (!m) return false;
    /* Sidecar bootstrap for the metadata-only display mode: own TCP
     * connection to host:port, HAP pair-verify with auth_credentials (client
     * identity from dacp_id), session SETUP with isRemoteControlOnly=true and
     * timingProtocol="None", event channel attach, RECORD, then the type-130
     * data channel SETUP and ap2_mrp_attach() on its result. Needs the RTSP +
     * HAP plumbing from ap2_client.c/ap2_hap.c. */
    LOG_WARN("[MRP] standalone remote-control session not implemented yet "
             "(metadata-only mode); use ap2_mrp_attach from an audio session");
    return false;
}

void ap2_mrp_stop(struct ap2_mrp_ctx *m)
{
    if (!m) return;
    mrp_capture_freeze(m);
    if (m->connected) {
        mbuf msg = {0};
        if (build_set_connection_state(&msg, MRP_CONNECTION_STATE_DISCONNECTED))
            mrp_send_protobuf(m, &msg);
        mbuf_free(&msg);
    }
    mrp_close_data_channel(m);
    mrp_close_event_channel(m);
    m->rx_enc_len = 0;
    m->rx_msg_len = 0;
    m->event_rx_enc_len = 0;
    m->event_plain_len = 0;
    mrp_capture_summary(m);
}

bool ap2_mrp_set_track_live(struct ap2_mrp_ctx *m, const char *title,
                       const char *artist, const char *album,
                       int duration_ms, bool is_live, const char *item_id,
                       const char *mime, const uint8_t *art, int art_len,
                       bool *track_changed_out, ap2_mrp_artwork_info_t *info)
{
    ap2_mrp_artwork_info_t local_info;
    if (!info) info = &local_info;
    if (track_changed_out) *track_changed_out = false;
    if (!m) {
        mrp_artwork_info_init(info, art_len > 0 ? (size_t)art_len : 0);
        return false;
    }
    /* The UniqueIdentifier must stay stable across a track's pushes: the
     * receiver keys its now-playing item on it, so a fresh uid on a redundant
     * re-send (registration burst, warm seek, progress correction) reads as a
     * brand-new item and resets the receiver's Now Playing UI. Mint one only
     * when the track actually changes — keyed on the sender's item id when
     * both sides have one, because the text tuple is NOT stable for one
     * track: the server may refine tags mid-track (library enrichment
     * settling after playback start), and such a refinement must update the
     * existing item, not present as a new track. Random 63-bit, matching the
     * large uint64 a real sender emits. */
    bool have_ids = m->item_id && *m->item_id && item_id && *item_id;
    bool track_changed = have_ids
        ? strcmp(m->item_id, item_id) != 0
        : (!mrp_str_eq(m->title, title) ||
           !mrp_str_eq(m->artist, artist) ||
           !mrp_str_eq(m->album, album));
    if (track_changed && m->np_uid != 0) {
        LOG_INFO("[MRP] now-playing item changed: \"%s\" (id %s) -> "
                 "\"%s\" (id %s)",
                 m->title ? m->title : "", m->item_id ? m->item_id : "-",
                 title ? title : "", item_id ? item_id : "-");
    }
    mrp_replace_str(&m->title, title);
    mrp_replace_str(&m->artist, artist);
    mrp_replace_str(&m->album, album);
    mrp_replace_str(&m->item_id, item_id);
    /* A duration-less update of the same item keeps the known total: the
     * timeline "update" push never re-supplies Duration, so zeroing it here
     * would strip the total from every later replace push. A new item with
     * unknown duration must not inherit the previous track's length. */
    m->is_live = is_live;
    if (is_live)
        m->duration_ms = 0;
    else if (duration_ms > 0)
        m->duration_ms = duration_ms;
    else if (track_changed)
        m->duration_ms = 0;
    if (track_changed || m->np_uid == 0) {
        uint64_t uid = 0;
        RAND_bytes((uint8_t *)&uid, sizeof(uid));
        m->np_uid = uid & 0x7FFFFFFFFFFFFFFFULL;
        if (track_changed) {
            /* A new item starts at zero. Keeping the previous track's elapsed
             * would push the new title at the old position; the sender's
             * settled correction follows only when it starts elsewhere. */
            m->elapsed_ms = 0;
            m->elapsed_set_at = mrp_cf_now();
        }
    }
    if (art && art_len > 0) {
        /* The staged artwork survives the identity change long enough for
         * set_artwork's identical-bytes comparison: the same cover riding a
         * new track (one album) keeps its ArtworkIdentifier, because an
         * identifier flip alone makes the receiver invalidate and re-render
         * the art it is already showing. A rejected image clears staging the
         * way set_artwork always does. */
        ap2_mrp_set_artwork(m, mime, art, art_len, info);
    } else {
        mrp_artwork_info_init(info, 0);
        info->result = AP2_MRP_ARTWORK_NOT_APPLICABLE;
        /* The old track's staged artwork must not ride the new item; the same
         * item without a new image keeps what it has (tag refinement). */
        if (track_changed) mrp_reset_artwork(m);
    }
    m->state_generation++;
    m->state_dirty = true;
    if (track_changed_out) *track_changed_out = track_changed;
    return true;
}

bool ap2_mrp_set_track(struct ap2_mrp_ctx *m, const char *title,
                       const char *artist, const char *album,
                       int duration_ms, const char *item_id,
                       const char *mime, const uint8_t *art, int art_len,
                       bool *track_changed_out, ap2_mrp_artwork_info_t *info)
{
    return ap2_mrp_set_track_live(m, title, artist, album, duration_ms, false,
                                  item_id, mime, art, art_len,
                                  track_changed_out, info);
}

bool ap2_mrp_set_metadata(struct ap2_mrp_ctx *m, const char *title,
                          const char *artist, const char *album,
                          int duration_ms, const char *item_id)
{
    return ap2_mrp_set_track(m, title, artist, album, duration_ms, item_id,
                             NULL, NULL, 0, NULL, NULL);
}

bool ap2_mrp_set_artwork(struct ap2_mrp_ctx *m, const char *mime,
                         const uint8_t *data, int len,
                         ap2_mrp_artwork_info_t *info)
{
    ap2_mrp_artwork_info_t local_info;
    if (!info) info = &local_info;
    if (!m) {
        mrp_artwork_info_init(info, len > 0 ? (size_t)len : 0);
        return false;
    }
    ap2_mrp_artwork_result_t result =
        ap2_mrp_probe_artwork(mime, data, len > 0 ? (size_t)len : 0, info);
    if (result != AP2_MRP_ARTWORK_ACCEPTED) {
        mrp_reset_artwork(m);
        LOG_WARN("[MRP] artwork rejected: reason=%s bytes=%d width=%u height=%u "
                 "sof=0x%02x components=%u progressive=%d staging_max_bytes=%d",
                 ap2_mrp_artwork_result_name(result), len,
                 info->width, info->height, info->sof_marker, info->components,
                 info->progressive, AP2_MRP_ARTWORK_STAGING_MAX_BYTES);
        return false;
    }

    /* A redundant re-send of the retained image is a no-op: keeping the
     * ArtworkIdentifier means the receiver never invalidates and re-resolves
     * the art it is already showing (an identifier flip re-renders the
     * receiver's Now Playing UI even when the pixels are identical). */
    if (m->artwork && m->artwork_len == len &&
        memcmp(m->artwork, data, (size_t)len) == 0 &&
        mrp_str_eq(m->artwork_mime, mime)) {
        LOG_INFO("[MRP] artwork unchanged (%d bytes); keeping identifier %s",
                 len, m->artwork_id);
        info->result = AP2_MRP_ARTWORK_UNCHANGED;
        return true;
    }

    uint8_t *copy = malloc((size_t)len);
    char *mime_copy = mrp_strdup(mime);
    if (!copy || !mime_copy) {
        free(copy);
        free(mime_copy);
        mrp_reset_artwork(m);
        info->result = AP2_MRP_ARTWORK_NO_MEMORY;
        LOG_ERROR("[MRP] cannot retain artwork: out of memory");
        return false;
    }
    memcpy(copy, data, (size_t)len);
    free(m->artwork);
    m->artwork = copy;
    m->artwork_len = len;
    free(m->artwork_mime);
    m->artwork_mime = mime_copy;
    /* Fresh artwork: new ArtworkIdentifier for the new pixels. The bytes ride
     * every now-playing push while retained (ap2_mrp_build_nowplaying_command). */
    uint8_t idb[8];
    RAND_bytes(idb, sizeof(idb));
    snprintf(m->artwork_id, sizeof(m->artwork_id),
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             idb[0], idb[1], idb[2], idb[3], idb[4], idb[5], idb[6], idb[7]);
    m->state_generation++;
    m->state_dirty = true;
    m->state_include_artwork = true;
    return true;
}

void ap2_mrp_clear_artwork(struct ap2_mrp_ctx *m)
{
    if (!m) return;
    mrp_reset_artwork(m);
    if (m->connected && mrp_now_playing_on_datastream(m)) mrp_push_state(m, false);
}

bool ap2_mrp_set_progress(struct ap2_mrp_ctx *m, int elapsed_ms,
                          int duration_ms, bool playing)
{
    if (!m) return false;
    m->elapsed_ms = elapsed_ms > 0 ? elapsed_ms : 0;
    if (!m->is_live && duration_ms > 0) m->duration_ms = duration_ms;
    m->playback_state = playing ? AP2_MRP_PLAYBACK_PLAYING
                                : AP2_MRP_PLAYBACK_PAUSED;
    m->elapsed_set_at = mrp_cf_now();
    m->state_generation++;
    m->state_dirty = true;
    return true;
}

bool ap2_mrp_set_playing(struct ap2_mrp_ctx *m, bool playing)
{
    if (!m) return false;
    /* Advance the stored elapsed to now before flipping so the frozen (pause)
     * or resumed (play) position matches what the receiver extrapolated up to
     * this instant, then re-anchor the timestamp at now. */
    double now = mrp_cf_now();
    if (m->playback_state == AP2_MRP_PLAYBACK_PLAYING &&
        m->elapsed_set_at > 0.0) {
        double advanced_ms = (now - m->elapsed_set_at) * 1000.0;
        if (advanced_ms > 0.0) m->elapsed_ms += (int)advanced_ms;
    }
    m->playback_state = playing ? AP2_MRP_PLAYBACK_PLAYING
                                : AP2_MRP_PLAYBACK_PAUSED;
    m->elapsed_set_at = now;
    m->state_generation++;
    m->state_dirty = true;
    return true;
}

bool ap2_mrp_set_stopped(struct ap2_mrp_ctx *m)
{
    if (!m) return false;
    m->playback_state = AP2_MRP_PLAYBACK_STOPPED;
    m->elapsed_set_at = mrp_cf_now();
    m->state_generation++;
    m->state_dirty = true;
    return true;
}

void ap2_mrp_tick(struct ap2_mrp_ctx *m)
{
    if (m) ap2_volume_tick(&m->volume, ap2_io_monotonic_ms());
    if (!m) return;
    mrp_tick_events(m);
    if (!m->connected || m->sock < 0) return;

    /* Drain inbound bytes without blocking */
    struct pollfd pfd = { .fd = m->sock, .events = POLLIN };
    while (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
        int space = (int)sizeof(m->rx_enc) - m->rx_enc_len;
        if (space <= 0) break;
        ssize_t n = read(m->sock, m->rx_enc + m->rx_enc_len, (size_t)space);
        if (n <= 0) {
            LOG_WARN("[MRP] data channel closed by receiver");
            mrp_close_data_channel(m);
            return;
        }
        m->rx_enc_len += (int)n;
        mrp_drain_encrypted(m);
        mrp_process_frames(m);
        if (!m->connected) return;
    }
    mrp_volume_flush(m);
}

bool ap2_mrp_prepare_state_push(struct ap2_mrp_ctx *m, uint8_t **out,
                                int *out_len, uint64_t *generation)
{
    if (!m || !out || !out_len || !generation || !m->connected ||
        !mrp_now_playing_on_datastream(m))
        return false;
    bool periodic =
        m->playback_state == AP2_MRP_PLAYBACK_PLAYING &&
        time(NULL) - m->last_state_push >= MRP_STATE_REPUSH_S;
    if (!m->state_dirty && !periodic) return false;

    mbuf msg = {0};
    if (!build_set_state(m, m->state_include_artwork, &msg)) {
        mbuf_free(&msg);
        return false;
    }
    *out = msg.p;
    *out_len = (int)msg.len;
    *generation = m->state_generation;
    return true;
}

bool ap2_mrp_send_state_push(struct ap2_mrp_ctx *m,
                             const uint8_t *data, int len)
{
    if (!m || !data || len <= 0 || !m->connected) return false;
    mbuf msg = { .p = (uint8_t *)data, .len = (size_t)len, .cap = (size_t)len };
    bool ok = mrp_send_protobuf(m, &msg);
    LOG_DEBUG("[MRP] queued SET_STATE push -> %s", ok ? "sent" : "failed");
    return ok;
}

void ap2_mrp_complete_state_push(struct ap2_mrp_ctx *m,
                                 uint64_t generation, bool success)
{
    if (!m || !success) return;
    m->last_state_push = time(NULL);
    if (m->state_generation == generation) {
        m->state_dirty = false;
        m->state_include_artwork = false;
    }
}

bool ap2_mrp_is_connected(struct ap2_mrp_ctx *m)
{
    return m && m->connected;
}

int ap2_mrp_event_status(struct ap2_mrp_ctx *m)
{
    if (!m || !m->event_attached) return -1;
    return atomic_load(&m->event_connected) ? 1 : 0;
}

bool ap2_mrp_build_nowplaying_command(struct ap2_mrp_ctx *m,
                                      uint8_t **out, int *out_len)
{
    if (!m || !out || !out_len) return false;

    /* Push path A: POST /command carrying MediaRemote now-playing info. Shape
     * captured VERBATIM from a real iPhone -> AirPlay 2 receiver session
     * (2026-07-20, DESIGN.md §8): a triple-nested bplist
     *   { "type": "updateMRNowPlayingInfo",
     *     "params": { "type": "npi-text", "mergePolicy": "replace",
     *                 "params": { kMRMediaRemoteNowPlayingInfo* ... } } }
     * Our earlier "updateNowPlayingInfo" (missing the "npi-text"/"mergePolicy"
     * wrapper and using a fabricated type string) was HTTP-400'd by the Apple
     * TV; this is the attested envelope. Durations/elapsed/rate are plist
     * reals; Timestamp is a CFDate (the reference time for ElapsedTime). */
    ap2_pl_node *info = ap2_pl_dict();
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoTitle",
                    ap2_pl_string(m->title ? m->title : ""));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoArtist",
                    ap2_pl_string(m->artist ? m->artist : ""));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoAlbum",
                    ap2_pl_string(m->album ? m->album : ""));
    if (m->is_live)
        ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoIsAlwaysLive",
                        ap2_pl_bool(true));
    if (m->duration_ms > 0)
        ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoDuration",
                        ap2_pl_real((double)m->duration_ms / 1000.0));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoElapsedTime",
                    ap2_pl_real((double)m->elapsed_ms / 1000.0));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoPlaybackRate",
                    ap2_pl_real(m->playback_state == AP2_MRP_PLAYBACK_PLAYING
                                    ? 1.0 : 0.0));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoDefaultPlaybackRate",
                    ap2_pl_real(1.0));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoTimestamp",
                    ap2_pl_date(m->elapsed_set_at > 0.0 ? m->elapsed_set_at
                                                        : mrp_cf_now()));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoMediaType",
                    ap2_pl_string("MRMediaRemoteMediaTypeMusic"));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoUniqueIdentifier",
                    ap2_pl_int((int64_t)m->np_uid));
    if (m->artwork && m->artwork_len > 0) {
        ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoArtworkIdentifier",
                        ap2_pl_string(m->artwork_id));
        ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoArtworkMIMEType",
                        ap2_pl_string(m->artwork_mime ? m->artwork_mime
                                                      : "image/jpeg"));
        /* The npi-text bridge REPLACES the receiver's whole now-playing info
         * on every push: a push carrying only the ArtworkIdentifier drops the
         * artwork on tvOS (hardware-verified on tvOS 26/27 — artworkAvailable
         * flips false on an elapsed-only push with stable identifiers). The
         * bytes therefore ride EVERY push while artwork is retained. Pushes
         * are rare by design (seek, track change, play/pause; the receiver
         * extrapolates steady-state progress), so the cost stays a few tens
         * of KB on the control channel, and a receiver that dropped its art
         * self-heals on the next push. */
        ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoArtworkData",
                        ap2_pl_data(m->artwork, (size_t)m->artwork_len));
    }

    ap2_pl_node *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "type", ap2_pl_string("npi-text"));
    ap2_pl_dict_set(params, "mergePolicy", ap2_pl_string("replace"));
    ap2_pl_dict_set(params, "params", info);
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("updateMRNowPlayingInfo"));
    ap2_pl_dict_set(root, "params", params);

    int len = ap2_pl_serialize(root, out);
    ap2_pl_free(root);
    if (len <= 0) return false;
    *out_len = len;
    return true;
}

bool ap2_mrp_build_nowplaying_progress_command(struct ap2_mrp_ctx *m,
                                               uint8_t **out, int *out_len)
{
    if (!m || !out || !out_len) return false;
    /* Pure timeline correction (seek): mergePolicy "update" carrying only the
     * timeline fields. A "replace" push would need the artwork bytes riding
     * along (any replace without ArtworkData drops the receiver's art — with
     * or without the identifier keys, both hardware-verified), and a
     * bytes-carrying push makes tvOS visibly re-decode and re-set the cover.
     * The "update" shape measured on tvOS 26/27: HTTP 200, elapsed lands as
     * an in-place content-item update, artworkAvailable stays true, no state
     * re-render. The dict stays minimal on purpose — no Duration (a total
     * that changes re-lays-out the receiver's Now Playing screen) and no
     * UniqueIdentifier (re-asserting the item identity invites a refresh);
     * the update applies to the current now-playing item. A receiver that
     * rejects the policy gets the full replace push instead
     * (ap2cl_mrp_push_progress falls back per session). */
    ap2_pl_node *info = ap2_pl_dict();
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoElapsedTime",
                    ap2_pl_real((double)m->elapsed_ms / 1000.0));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoPlaybackRate",
                    ap2_pl_real(m->playback_state == AP2_MRP_PLAYBACK_PLAYING
                                    ? 1.0 : 0.0));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoDefaultPlaybackRate",
                    ap2_pl_real(1.0));
    ap2_pl_dict_set(info, "kMRMediaRemoteNowPlayingInfoTimestamp",
                    ap2_pl_date(m->elapsed_set_at > 0.0 ? m->elapsed_set_at
                                                        : mrp_cf_now()));

    ap2_pl_node *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "type", ap2_pl_string("npi-text"));
    ap2_pl_dict_set(params, "mergePolicy", ap2_pl_string("update"));
    ap2_pl_dict_set(params, "params", info);
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("updateMRNowPlayingInfo"));
    ap2_pl_dict_set(root, "params", params);

    int len = ap2_pl_serialize(root, out);
    ap2_pl_free(root);
    if (len <= 0) return false;
    *out_len = len;
    return true;
}

/* Wrap a serialized protobuf as the bplist {"params": {"data": <varint length +
 * protobuf>}} that carries MRP messages — over the type-130 channel normally,
 * or over POST /command when that channel is unavailable (a real iPhone falls
 * back to /command when its type-130 SETUP does not complete). Caller frees
 * *out. */
static bool mrp_wrap_params_data(const mbuf *msg, uint8_t **out, int *out_len)
{
    mbuf blob = {0};
    bool ok = pb_put_varint(&blob, msg->len) && mbuf_put(&blob, msg->p, msg->len);
    if (!ok) { mbuf_free(&blob); return false; }
    ap2_pl_node *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "data", ap2_pl_data(blob.p, blob.len));
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "params", params);
    int len = ap2_pl_serialize(root, out);
    ap2_pl_free(root);
    mbuf_free(&blob);
    if (len <= 0) return false;
    *out_len = len;
    return true;
}

bool ap2_mrp_build_deviceinfo_command(struct ap2_mrp_ctx *m,
                                      uint8_t **out, int *out_len)
{
    if (!m || !out || !out_len) return false;
    /* Register as a now-playing origin: the DeviceInfoMessage protobuf (same as
     * the channel handshake) wrapped as {params:{data:...}} and POSTed to
     * /command. A real iPhone sends exactly this (describing itself, deviceClass
     * iPhone, com.apple.Music) before pushing now-playing (DESIGN.md §8). */
    mbuf msg = {0};
    bool ok = build_device_info(m, &msg);
    ok = ok && mrp_wrap_params_data(&msg, out, out_len);
    mbuf_free(&msg);
    return ok;
}

/* One serialized MRSupportedCommand: a standalone bplist of
 * {kCommandInfoCommandKey, kCommandInfoEnabledKey, [kCommandInfoOptionsKey]}
 * returned as a data node for the mrSupportedCommandsFromSender array (each
 * element is itself an archived plist, exactly as captured). `options` is owned
 * (freed with the temp dict). Returns NULL on failure. */
static ap2_pl_node *mrp_cmd_info_blob(int cmd, bool enabled, ap2_pl_node *options)
{
    ap2_pl_node *d = ap2_pl_dict();
    ap2_pl_dict_set(d, "kCommandInfoCommandKey", ap2_pl_int(cmd));
    ap2_pl_dict_set(d, "kCommandInfoEnabledKey", ap2_pl_bool(enabled));
    if (options) ap2_pl_dict_set(d, "kCommandInfoOptionsKey", options);
    uint8_t *b = NULL;
    int bl = ap2_pl_serialize(d, &b);
    ap2_pl_free(d);
    ap2_pl_node *data = (bl > 0 && b) ? ap2_pl_data(b, (size_t)bl) : NULL;
    free(b);
    return data;
}

bool ap2_mrp_build_supportedcommands_command(struct ap2_mrp_ctx *m,
                                             uint8_t **out, int *out_len)
{
    if (!out || !out_len) return false;
    /* Command list, options and MRMediaRemoteCommand numbering captured VERBATIM
     * from a real iPhone sender (DESIGN.md §8). Order preserved. Note this
     * is MRMediaRemoteCommand numbering (Play=0, Pause=1, ...), distinct from
     * the pyatv protobuf Command enum used in the type-130 SET_STATE path. */
    ap2_pl_node *arr = ap2_pl_array();

    if (m && (m->is_live || m->experimental_homepod_remote)) {
        /* Only commands accepted by mrp_parse_remote_command: Apple command
         * numbering Play=0, Pause=1, Toggle=2, Next=4, Previous=5. */
        static const int live[] = {0, 1, 2, 4, 5};
        for (size_t i = 0; i < sizeof(live) / sizeof(live[0]); i++)
            ap2_pl_array_append(arr, mrp_cmd_info_blob(live[i], true, NULL));
    } else {
        ap2_pl_node *o26 = ap2_pl_dict();
        ap2_pl_dict_set(o26, "kMRMediaRemoteCommandInfoShuffleMode", ap2_pl_int(1));
        ap2_pl_array_append(arr, mrp_cmd_info_blob(26, true, o26));

        ap2_pl_node *o25 = ap2_pl_dict();
        ap2_pl_dict_set(o25, "kMRMediaRemoteCommandInfoRepeatMode", ap2_pl_int(1));
        ap2_pl_array_append(arr, mrp_cmd_info_blob(25, true, o25));

        ap2_pl_node *o24 = ap2_pl_dict();
        ap2_pl_dict_set(o24, "kMRMediaRemoteCommandInfoCanBeControlledByScrubbingKey",
                        ap2_pl_bool(false));
        ap2_pl_dict_set(o24, "kMRMediaRemoteCommandInfoSupportsReferencePosition",
                        ap2_pl_bool(false));
        ap2_pl_array_append(arr, mrp_cmd_info_blob(24, true, o24));

        ap2_pl_node *o18 = ap2_pl_dict();
        ap2_pl_dict_set(o18, "kMRMediaRemoteCommandInfoPreferredIntervalsKey", ap2_pl_array());
        ap2_pl_array_append(arr, mrp_cmd_info_blob(18, false, o18));

        ap2_pl_node *o17 = ap2_pl_dict();
        ap2_pl_dict_set(o17, "kMRMediaRemoteCommandInfoPreferredIntervalsKey", ap2_pl_array());
        ap2_pl_array_append(arr, mrp_cmd_info_blob(17, false, o17));

        static const int simple[] = { 10, 11, 8, 9, 5, 4, 3, 2, 1, 0 };
        for (size_t i = 0; i < sizeof(simple) / sizeof(simple[0]); i++)
            ap2_pl_array_append(arr, mrp_cmd_info_blob(simple[i], true, NULL));
    }

    ap2_pl_node *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "mrSupportedCommandsFromSender", arr);
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type", ap2_pl_string("updateMRSupportedCommands"));
    ap2_pl_dict_set(root, "params", params);
    int len = ap2_pl_serialize(root, out);
    ap2_pl_free(root);
    if (len <= 0) return false;
    *out_len = len;
    return true;
}

bool ap2_mrp_build_playbackstate_command(struct ap2_mrp_ctx *m,
                                         uint8_t **out, int *out_len)
{
    if (!m || !out || !out_len) return false;

    ap2_pl_node *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "mrPlaybackState",
                    ap2_pl_int(m->playback_state));
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type",
                    ap2_pl_string("updateMRPlaybackState"));
    ap2_pl_dict_set(root, "params", params);

    int len = ap2_pl_serialize(root, out);
    ap2_pl_free(root);
    if (len <= 0) return false;
    *out_len = len;
    return true;
}

bool ap2_mrp_build_nowplayingclient_command(struct ap2_mrp_ctx *m,
                                            uint8_t **out, int *out_len)
{
    if (!m || !out || !out_len) return false;

    /* MRNowPlayingClientCreateExternalRepresentation returns the serialized
     * NowPlayingClient protobuf itself — unlike params.data DEVICE_INFO, there
     * is no ProtocolMessage envelope or varint length prefix. */
    mbuf client = {0};
    if (!build_now_playing_client(m, &client)) {
        mbuf_free(&client);
        return false;
    }

    ap2_pl_node *params = ap2_pl_dict();
    ap2_pl_dict_set(params, "mrNowPlayingClient",
                    ap2_pl_data(client.p, client.len));
    ap2_pl_node *root = ap2_pl_dict();
    ap2_pl_dict_set(root, "type",
                    ap2_pl_string("updateMRNowPlayingClient"));
    ap2_pl_dict_set(root, "params", params);

    int len = ap2_pl_serialize(root, out);
    ap2_pl_free(root);
    mbuf_free(&client);
    if (len <= 0) return false;
    *out_len = len;
    return true;
}
