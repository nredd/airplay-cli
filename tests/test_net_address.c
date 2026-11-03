#include "net_address.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

static struct addrinfo result;
static unsigned calls, frees;
static int resolver_error;

int test_getaddrinfo(const char *node, const char *service,
                    const struct addrinfo *hints, struct addrinfo **out)
{
    calls++;
    if (strcmp(node, "synthetic") || service || hints->ai_family != AF_INET ||
        hints->ai_socktype != SOCK_STREAM) return EAI_FAIL;
    if (resolver_error) return resolver_error;
    *out = &result;
    return 0;
}

void test_freeaddrinfo(struct addrinfo *entry)
{
    if (entry == &result) frees++;
}

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

int main(void)
{
    struct in_addr address = { .s_addr = 123 };
    CHECK(!resolve_ipv4_address(NULL, &address));
    CHECK(!resolve_ipv4_address("", &address));
    CHECK(!resolve_ipv4_address("synthetic", NULL));
    CHECK(calls == 0 && address.s_addr == 123);
    resolver_error = EAI_NONAME;
    CHECK(!resolve_ipv4_address("synthetic", &address));
    CHECK(frees == 0 && address.s_addr == 123);
    resolver_error = 0;
    result.ai_family = AF_INET6;
    CHECK(!resolve_ipv4_address("synthetic", &address));
    CHECK(frees == 1 && address.s_addr == 123);
    result.ai_family = AF_INET;
    CHECK(!resolve_ipv4_address("synthetic", &address));
    CHECK(frees == 2 && address.s_addr == 123);

    /* Byte storage deliberately avoids alignment assumptions in address copy. */
    unsigned char storage[sizeof(struct sockaddr_in) + 1];
    struct sockaddr_in endpoint = { .sin_family = AF_INET };
    CHECK(inet_pton(AF_INET, "127.0.0.1", &endpoint.sin_addr) == 1);
    memcpy(storage + 1, &endpoint, sizeof(endpoint));
    result.ai_addr = (struct sockaddr *)(storage + 1);
    result.ai_addrlen = sizeof(endpoint) - 1;
    CHECK(!resolve_ipv4_address("synthetic", &address));
    CHECK(frees == 3 && address.s_addr == 123);
    result.ai_addrlen = sizeof(endpoint);
    CHECK(resolve_ipv4_address("synthetic", &address));
    CHECK(frees == 4 && address.s_addr == endpoint.sin_addr.s_addr);
    puts("IPv4 resolver tests passed");
    return 0;
}
