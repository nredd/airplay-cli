/* Logical session volume, independent of receiver gain and native UI identity.
 * SPDX-License-Identifier: Apache-2.0 */
#include "ap2_volume.h"
#include <string.h>
#include <limits.h>

bool ap2_volume_init(struct ap2_volume *v)
{
    if (!v) return false;
    memset(v, 0, sizeof(*v));
    return pthread_mutex_init(&v->lock, NULL) == 0;
}
void ap2_volume_destroy(struct ap2_volume *v) { pthread_mutex_destroy(&v->lock); }

bool ap2_volume_bind(struct ap2_volume *v, uint64_t generation,
    const uint8_t *output, size_t output_len, const uint8_t *endpoint, size_t endpoint_len)
{
    if (!generation || !output || !output_len || output_len > 128 ||
        endpoint_len > 128 || (endpoint_len && !endpoint)) return false;
    pthread_mutex_lock(&v->lock);
    bool ok = generation > v->generation;
    if (ok) {
        v->generation = generation; v->revision = 0;
        v->known = v->executing = v->have_trailing = v->uncertain = false;
        memset(v->output, 0, sizeof(v->output));
        memset(v->endpoint, 0, sizeof(v->endpoint));
        memcpy(v->output, output, output_len); v->output_len = output_len;
        if (endpoint_len) memcpy(v->endpoint, endpoint, endpoint_len);
        v->endpoint_len = endpoint_len;
    }
    pthread_mutex_unlock(&v->lock);
    return ok;
}
bool ap2_volume_state(struct ap2_volume *v, uint64_t generation, uint64_t revision,
    bool known, unsigned milli)
{
    if (milli > 1000) return false;
    pthread_mutex_lock(&v->lock);
    bool ok = v->output_len && generation == v->generation && revision > v->revision;
    if (ok) {
        v->revision = revision; v->known = known; v->milli = milli;
        v->uncertain = false;
    }
    pthread_mutex_unlock(&v->lock);
    return ok;
}
void ap2_volume_unbind(struct ap2_volume *v, uint64_t generation)
{
    pthread_mutex_lock(&v->lock);
    if (generation == v->generation) {
        memset(v->output, 0, sizeof(v->output)); memset(v->endpoint, 0, sizeof(v->endpoint));
        v->output_len = v->endpoint_len = 0;
        v->known = v->executing = v->have_trailing = false;
    }
    pthread_mutex_unlock(&v->lock);
}
static bool matches(struct ap2_volume *v, const uint8_t *uid, size_t len)
{
    return uid && len && len == v->output_len && !memcmp(uid, v->output, len);
}
bool ap2_volume_get(struct ap2_volume *v, const uint8_t *uid, size_t len, unsigned *milli)
{
    pthread_mutex_lock(&v->lock);
    bool ok = matches(v, uid, len) && v->known && !v->uncertain;
    if (ok) *milli = v->milli;
    pthread_mutex_unlock(&v->lock);
    return ok;
}
/* Allocate local ordinals monotonically even across rebinds. */
static bool start(struct ap2_volume *v, uint64_t now)
{
    if (v->ordinal == UINT64_MAX || now > UINT64_MAX - 3000) return false;
    ++v->ordinal; v->deadline = now + 3000; v->executing = true;
    return true;
}
bool ap2_volume_set(struct ap2_volume *v, const uint8_t *uid, size_t len,
    unsigned milli, uint64_t now)
{
    if (milli > 1000) return false;
    pthread_mutex_lock(&v->lock);
    bool ok = matches(v, uid, len) && v->callback && !v->uncertain;
    bool dispatch = false;
    if (ok && v->executing) { v->trailing = milli; v->have_trailing = true; }
    else if (ok) ok = dispatch = start(v, now);
    uint64_t generation = v->generation, ordinal = v->ordinal;
    ap2_volume_request_cb callback = v->callback;
    void *userdata = v->userdata;
    pthread_mutex_unlock(&v->lock);
    if (dispatch) callback(userdata, generation, ordinal, milli);
    return ok;
}
void ap2_volume_tick(struct ap2_volume *v, uint64_t now)
{
    pthread_mutex_lock(&v->lock);
    if (v->executing && now >= v->deadline) {
        v->executing = v->have_trailing = v->known = false;
        v->uncertain = true; /* timeout is NOT cancellation */
    }
    pthread_mutex_unlock(&v->lock);
}
bool ap2_volume_complete(struct ap2_volume *v, uint64_t generation, uint64_t ordinal,
    const char *result, uint64_t revision, bool known, unsigned milli, uint64_t now)
{
    if (!result || milli > 1000 || (!strcmp(result, "committed") != known) || (strcmp(result, "committed") &&
        strcmp(result, "rejected") && strcmp(result, "failed") && strcmp(result, "unknown")))
        return false;
    ap2_volume_tick(v, now);
    pthread_mutex_lock(&v->lock);
    bool ok = v->output_len && generation == v->generation && v->executing &&
        ordinal == v->ordinal && revision > v->revision;
    bool dispatch = false;
    if (ok) {
        v->revision = revision;
        v->known = !strcmp(result, "committed") && known;
        v->milli = milli; v->executing = false;
        v->uncertain = !strcmp(result, "unknown");
        if (v->have_trailing && !v->uncertain) dispatch = start(v, now);
        v->have_trailing = false;
    }
    uint64_t next = v->ordinal;
    unsigned trailing = v->trailing;
    ap2_volume_request_cb callback = v->callback;
    void *userdata = v->userdata;
    pthread_mutex_unlock(&v->lock);
    if (dispatch && callback) callback(userdata, generation, next, trailing);
    return ok;
}

static const char *const keys[] = {"SESSION_VOLUME_GENERATION", "SESSION_VOLUME_REVISION",
    "SESSION_VOLUME_ORDINAL", "SESSION_VOLUME_KNOWN", "SESSION_VOLUME_MILLI",
    "SESSION_VOLUME_OUTPUT_UID_HEX", "SESSION_VOLUME_ENDPOINT_UID_HEX", "SESSION_VOLUME_RESULT",
    "STREAM_VOLUME_ORDINAL", "STREAM_VOLUME_LEVEL"};
bool ap2_volume_stage_key(struct ap2_volume_stage *s, const char *key, const char *value)
{
    if (strncmp(key, "SESSION_VOLUME_", 15) && strncmp(key, "STREAM_VOLUME_", 14)) return false;
    s->stream |= !strncmp(key, "STREAM_VOLUME_", 14);
    s->session |= !strncmp(key, "SESSION_VOLUME_", 15);
    if (s->stream && s->session) s->invalid = true;
    /* Both namespaces use the same staging generation slot, but cannot mix. */
    if (!strcmp(key, "STREAM_VOLUME_GENERATION")) key = keys[0];
    for (unsigned i = 0; i < 10; ++i) if (!strcmp(key, keys[i])) {
        if ((s->seen & (1u << i)) || strlen(value) > 256) s->invalid = true;
        else { strcpy(s->values[i], value); s->seen |= 1u << i; }
        return true;
    }
    s->invalid = true;
    return true;
}
static bool number(const char *p, uint64_t *out)
{
    if (!*p) return false;
    uint64_t n = 0;
    for (; *p; ++p) {
        if (*p < '0' || *p > '9' || n > (UINT64_MAX - (unsigned)(*p - '0')) / 10) return false;
        n = n * 10 + (unsigned)(*p - '0');
    }
    *out = n; return true;
}
static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool uid(const char *p, uint8_t *out, size_t *len)
{
    *len = strlen(p) / 2;
    if (strlen(p) % 2 || *len > 128) return false;
    for (size_t i = 0; i < *len; ++i) {
        int a = nibble(p[i * 2]), b = nibble(p[i * 2 + 1]);
        if (a < 0 || b < 0) return false;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return true;
}
bool ap2_volume_stage_action(struct ap2_volume_stage *s, const char *action,
    struct ap2_volume_transaction *t)
{
    struct ap2_volume_stage copy = *s;
    memset(s, 0, sizeof(*s)); memset(t, 0, sizeof(*t));
    unsigned mask;
    if (!strcmp(action, "SESSION_VOLUME_BIND")) mask = 1 | 32 | 64;
    else if (!strcmp(action, "SESSION_VOLUME_UNBIND")) mask = 1;
    else if (!strcmp(action, "SESSION_VOLUME_STATE")) mask = 1 | 2 | 8;
    else if (!strcmp(action, "SESSION_VOLUME_COMPLETE")) mask = 1 | 2 | 4 | 8 | 128;
    else if (!strcmp(action, "STREAM_VOLUME_APPLY")) mask = 1 | 256 | 512;
    else return false;
    if (copy.stream != !strcmp(action, "STREAM_VOLUME_APPLY")) return false;
    uint64_t known = 0, milli = 0, level = 0;
    if (copy.invalid || !number(copy.values[0], &t->generation) || !t->generation) return false;
    if (mask & 8) {
        if (!number(copy.values[3], &known) || known > 1) return false;
        if (known) mask |= 16;
    }
    if (copy.seen != mask) return false;
    if ((mask & 2) && (!number(copy.values[1], &t->revision) || !t->revision)) return false;
    if ((mask & 4) && (!number(copy.values[2], &t->ordinal) || !t->ordinal)) return false;
    if ((mask & 16) && (!number(copy.values[4], &milli) || milli > 1000)) return false;
    if ((mask & 32) && (!uid(copy.values[5], t->output, &t->output_len) || !t->output_len)) return false;
    if ((mask & 64) && !uid(copy.values[6], t->endpoint, &t->endpoint_len)) return false;
    if (mask & 128) {
        const char *r = copy.values[7];
        if (strcmp(r, "committed") && strcmp(r, "rejected") && strcmp(r, "failed") && strcmp(r, "unknown")) return false;
        if ((!strcmp(r, "committed")) != (known != 0)) return false;
        strcpy(t->result, r);
    }
    if ((mask & 256) && (!number(copy.values[8], &t->ordinal) || !t->ordinal)) return false;
    if ((mask & 512) && (!number(copy.values[9], &level) || level > 100)) return false;
    t->known = known; t->milli = (unsigned)milli; t->level = (unsigned)level;
    return true;
}
