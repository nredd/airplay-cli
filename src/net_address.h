/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NET_ADDRESS_H
#define NET_ADDRESS_H

#include <stdbool.h>
#include <netinet/in.h>

/* Resolve one IPv4 stream endpoint. Leaves address unchanged on failure. */
bool resolve_ipv4_address(const char *hostname, struct in_addr *address);

#endif
