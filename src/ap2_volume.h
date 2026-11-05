/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AP2_VOLUME_H
#define AP2_VOLUME_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

/* One backend binding, one executing operation and one replaceable tail.
 * Callbacks run outside this lock. UIDs never leave this object.
 * Unbind/rebind invalidates results, not an already-dispatched callback: the
 * backend must reject a request whose generation is no longer its current
 * owner. Keep callback/userdata alive until all dispatching threads are joined;
 * destroying this object is not a cancellation or callback-lifetime barrier. */
typedef void (*ap2_volume_request_cb)(void *, uint64_t, uint64_t, unsigned);
struct ap2_volume {
    pthread_mutex_t lock;
    uint64_t generation, revision, ordinal, deadline;
    unsigned milli, trailing;
    bool known, executing, have_trailing, uncertain;
    uint8_t output[128], endpoint[128];
    size_t output_len, endpoint_len;
    ap2_volume_request_cb callback;
    void *userdata;
};
bool ap2_volume_init(struct ap2_volume *v);
void ap2_volume_destroy(struct ap2_volume *v);
bool ap2_volume_bind(struct ap2_volume *v, uint64_t generation,
    const uint8_t *output, size_t output_len, const uint8_t *endpoint, size_t endpoint_len);
bool ap2_volume_state(struct ap2_volume *v, uint64_t generation, uint64_t revision,
    bool known, unsigned milli);
bool ap2_volume_complete(struct ap2_volume *v, uint64_t generation, uint64_t ordinal,
    const char *result, uint64_t revision, bool known, unsigned milli, uint64_t now);
void ap2_volume_unbind(struct ap2_volume *v, uint64_t generation);
bool ap2_volume_get(struct ap2_volume *v, const uint8_t *uid, size_t len, unsigned *milli);
bool ap2_volume_set(struct ap2_volume *v, const uint8_t *uid, size_t len,
    unsigned milli, uint64_t now);
void ap2_volume_tick(struct ap2_volume *v, uint64_t now);

/* Strict one-shot staging. No fields survive ANY ACTION attempt. The caller's
 * FIFO reader owns this object; overflow/reset must invalidate it as well. */
struct ap2_volume_stage { char values[10][257]; unsigned seen; bool invalid, stream, session; };
struct ap2_volume_transaction {
    uint64_t generation, revision, ordinal;
    unsigned milli, level;
    bool known;
    uint8_t output[128], endpoint[128];
    size_t output_len, endpoint_len;
    char result[10];
};
bool ap2_volume_stage_key(struct ap2_volume_stage *s, const char *key, const char *value);
bool ap2_volume_stage_action(struct ap2_volume_stage *s, const char *action,
    struct ap2_volume_transaction *t);
#endif
