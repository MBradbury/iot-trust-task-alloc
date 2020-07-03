#pragma once

#include "nanocbor/nanocbor.h"

#include "uip.h"

#define PP_STR(x) PP_STR_(x)
#define PP_STR_(x) #x

#define NANOCBOR_CHECK(expr) \
    do { \
        const int result = (expr); \
        if (result < 0) \
        { \
            LOG_ERR("Failed '" PP_STR(expr) "' at " __FILE__ ":" PP_STR(__LINE__) " (result=%d)\n", result); \
            return result; \
        } \
    } while (0)

#define NANOCBOR_GET_OBJECT(dec, obj) \
    do { \
        size_t len; \
        NANOCBOR_CHECK(nanocbor_get_bstr(dec, (const uint8_t**)obj, &len)); \
        if (len != sizeof(**obj)) \
        { \
            LOG_ERR("Failed NANOCBOR_GET_OBJECT at " __FILE__ ":" PP_STR(__LINE__) " (%zu != %zu)\n", len, sizeof(**obj)); \
            return -1; \
        } \
    } while (0)

int nanocbor_fmt_ipaddr(nanocbor_encoder_t *enc, const uip_ip6addr_t *addr);

int nanocbor_get_ipaddr(nanocbor_value_t *cvalue, const uip_ip6addr_t **addr);
