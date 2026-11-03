/*
 * Copyright (C) 2024-2026 Music Assistant Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef RAOP_RESPONSE_H
#define RAOP_RESPONSE_H
#include "cross_util.h"
/* Read a required RAOP response with one ten-second monotonic budget.
 * Malformed/incomplete responses release allocations and invalidate *fd.
 * Complete non-200 responses return false but retain the drained transport.
 * headers is an empty destination with space for 64 key_data_t entries,
 * as in libraop. Successful outputs transfer allocation ownership. */
bool raop_read_required_response(int *fd, key_data_t *headers,
                                 char **body, int *body_length);
#endif
