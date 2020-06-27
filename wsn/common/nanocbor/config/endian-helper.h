#pragma once

#include "uipopt.h"

#include "machine/endian.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#if UIP_BYTE_ORDER != UIP_LITTLE_ENDIAN
#error "Compiler byte order differs from UIP byte order"
#endif

#define htobe16(x) __bswap16(x)
#define htole16(x) (uint16_t)(x)
#define be16toh(x) __bswap16(x)
#define le16toh(x) (uint16_t)(x)

#define htobe32(x) __bswap32(x)
#define htole32(x) (uint32_t)(x)
#define be32toh(x) __bswap32(x)
#define le32toh(x) (uint32_t)(x)

#define htobe64(x) __bswap64(x)
#define htole64(x) (uint64_t)(x)
#define be64toh(x) __bswap64(x)
#define le64toh(x) (uint64_t)(x)

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#if UIP_BYTE_ORDER == UIP_LITTLE_ENDIAN
#error "Compiler byte order differs from UIP byte order"
#endif

#define htobe16(x) (uint16_t)(x)
#define htole16(x) __bswap16(x)
#define be16toh(x) (uint16_t)(x)
#define le16toh(x) __bswap16(x)

#define htobe32(x) (uint32_t)(x)
#define htole32(x) __bswap32(x)
#define be32toh(x) (uint32_t)(x)
#define le32toh(x) __bswap32(x)

#define htobe64(x) (uint64_t)(x)
#define htole64(x) __bswap64(x)
#define be64toh(x) (uint64_t)(x)
#define le64toh(x) __bswap64(x)

#else
#error "Unknown byte order"
#endif

/* BSD Names */

#define betoh16(x) be16toh(x)
#define betoh32(x) be32toh(x)
#define betoh64(x) be64toh(x)
#define letoh16(x) le16toh(x)
#define letoh32(x) le32toh(x)
#define letoh64(x) le64toh(x)
