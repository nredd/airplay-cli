/*
 * Copyright (C) 2024-2026 Music Assistant Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "raop_response.h"
#include "ap2_io.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define RESPONSE_HEADER_COUNT 64
#define RESPONSE_HEADER_BYTES 65536
#define RESPONSE_BODY_BYTES 1048576

/* Return line length only after CRLF; malformed framing is failure. */
static int response_line(int fd, char *line, size_t capacity, uint64_t deadline,
                         size_t *remaining)
{
    size_t used = 0;
    bool carriage_return = false;
    while (*remaining) {
        uint8_t byte;
        if (ap2_io_read_deadline(fd, &byte, 1, deadline) != 1) return -1;
        --*remaining;
        if (carriage_return) {
            if (byte != '\n') return -1;
            line[used] = 0;
            return (int)used;
        }
        if (!byte || byte == '\n') return -1;
        if (byte == '\r') carriage_return = true;
        else {
            if (used + 1 >= capacity) return -1;
            line[used++] = (char)byte;
        }
    }
    return -1;
}

static bool response_length(const char *text, size_t *length)
{
    while (*text == ' ' || *text == '\t') text++;
    if (!isdigit((unsigned char)*text)) return false;
    size_t value = 0;
    while (isdigit((unsigned char)*text)) {
        unsigned digit = (unsigned)(*text++ - '0');
        if (value > (RESPONSE_BODY_BYTES - digit) / 10) return false;
        value = value * 10 + digit;
    }
    while (*text == ' ' || *text == '\t') text++;
    if (*text) return false;
    *length = value;
    return true;
}

static bool response_header_name(const char *name)
{
    if (!*name) return false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        bool letter = (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z');
        bool digit = *p >= '0' && *p <= '9';
        if (!letter && !digit && !strchr("!#$%&'*+-.^_`|~", *p)) return false;
    }
    return true;
}

bool raop_read_required_response(int *fd, key_data_t *headers,
                                 char **body, int *body_length)
{
    if (!fd || *fd < 0) return false;
    key_data_t parsed[RESPONSE_HEADER_COUNT] = {0};
    char line[2048];
    char *data = NULL;
    size_t remaining = RESPONSE_HEADER_BYTES, length = 0, count = 0;
    bool length_seen = false;
    uint64_t deadline = ap2_io_monotonic_ms() + 10000;
    if (body) *body = NULL;
    if (body_length) *body_length = 0;
    if (response_line(*fd, line, sizeof(line), deadline, &remaining) <= 0) goto fail;
    char *save = NULL;
    char *protocol = strtok_r(line, " ", &save);
    char *status = strtok_r(NULL, " ", &save);
    if (!protocol || strcmp(protocol, "RTSP/1.0") || !status || strlen(status) != 3 ||
        status[0] < '1' || status[0] > '5' || status[1] < '0' || status[1] > '9' ||
        status[2] < '0' || status[2] > '9') goto fail;
    bool accepted = !strcmp(status, "200");
    for (;;) {
        int size = response_line(*fd, line, sizeof(line), deadline, &remaining);
        if (size < 0) goto fail;
        if (!size) break;
        if (count == RESPONSE_HEADER_COUNT - 1 || line[0] == ' ' || line[0] == '\t') goto fail;
        char *colon = strchr(line, ':');
        if (!colon || colon == line) goto fail;
        *colon++ = 0;
        if (!response_header_name(line)) goto fail;
        if (!strcasecmp(line, "Content-Length")) {
            if (length_seen || !response_length(colon, &length)) goto fail;
            length_seen = true;
        }
        parsed[count].key = strdup(line);
        if (!parsed[count].key) goto fail;
        parsed[count].data = strdup(colon);
        if (!parsed[count].data) goto fail;
        count++;
    }
    if (length) {
        data = malloc(length);
        if (!data) goto fail;
        size_t used = 0;
        while (used < length) {
            ssize_t bytes = ap2_io_read_deadline(*fd, (uint8_t *)data + used,
                                               length - used, deadline);
            if (bytes <= 0) goto fail;
            used += (size_t)bytes;
        }
    }
    if (!accepted) {
        kd_free(parsed);
        free(data);
        return false;
    }
    if (headers) memcpy(headers, parsed, (count + 1) * sizeof(*parsed));
    else kd_free(parsed);
    if (body) *body = data;
    else free(data);
    if (body_length) *body_length = (int)length;
    return true;
fail:
    kd_free(parsed);
    free(data);
    close(*fd);
    *fd = -1;
    return false;
}
