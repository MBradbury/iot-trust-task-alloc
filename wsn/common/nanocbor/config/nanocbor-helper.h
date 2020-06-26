#pragma once

#include "nanocbor/nanocbor.h"

#define PP_STR(x) PP_STR_(x)
#define PP_STR_(x) #x

#define NANOCBOR_CHECK(expr) \
    do { \
        int result = (expr); \
        if (result < 0) \
        { \
            LOG_ERR("Failed '" PP_STR(expr) " on line " PP_STR(__LINE__) " in file " __FILE__ " (result=%d)\n", result); \
            return result; \
        } \
    } while (0)

#define NANOCBOR_GET_OBJECT(dec, obj) \
    do { \
        size_t len; \
        NANOCBOR_CHECK(nanocbor_get_bstr(dec, (const uint8_t**)obj, &len)); \
        if (len != sizeof(**obj)) \
        { \
            LOG_ERR("Failed NANOCBOR_GET_OBJECT on line " PP_STR(__LINE__) " in file " __FILE__ " (%zu != %zu)\n", len, sizeof(**obj)); \
            return -1; \
        } \
    } while (0)
