/* SPDX-License-Identifier: Apache-2.0 */
#include "net_address.h"

#include <netdb.h>
#include <string.h>

bool resolve_ipv4_address(const char *hostname, struct in_addr *address)
{
    if (!hostname || !*hostname || !address) return false;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *result = NULL;
    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) return false;
    bool found = false;
    for (struct addrinfo *item = result; item; item = item->ai_next) {
        if (item->ai_family != AF_INET || !item->ai_addr ||
            item->ai_addrlen < sizeof(struct sockaddr_in)) continue;
        struct sockaddr_in endpoint;
        memcpy(&endpoint, item->ai_addr, sizeof(endpoint));
        *address = endpoint.sin_addr;
        found = true;
        break;
    }
    freeaddrinfo(result);
    return found;
}
