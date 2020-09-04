#pragma once

#include "nanocbor/nanocbor.h"

#include "cc.h"
#include "uip.h"

#define NANOCBOR_CHECK(expr) \
    do { \
        const int result = (expr); \
        if (result < 0) \
        { \
            LOG_ERR("Failed '" CC_STRINGIFY(expr) "' at " __FILE__ ":" CC_STRINGIFY(__LINE__) " (result=%d)\n", result); \
            return result; \
        } \
    } while (0)

#define NANOCBOR_GET_OBJECT(dec, obj) \
    do { \
        size_t len; \
        NANOCBOR_CHECK(nanocbor_get_bstr(dec, (const uint8_t**)obj, &len)); \
        if (len != sizeof(**obj)) \
        { \
            LOG_ERR("Failed NANOCBOR_GET_OBJECT at " __FILE__ ":" CC_STRINGIFY(__LINE__) " (%zu != %zu)\n", len, sizeof(**obj)); \
            return -1; \
        } \
    } while (0)

#define IPV6ADDR_CBOR_MAX_LEN ((1) + (16))

int nanocbor_fmt_ipaddr(nanocbor_encoder_t *enc, const uip_ip6addr_t *addr);
int nanocbor_get_ipaddr(nanocbor_value_t *cvalue, const uip_ip6addr_t **addr);

int nanocbor_get_bstr_of_len(nanocbor_value_t *cvalue, uint8_t *buf, size_t len);
