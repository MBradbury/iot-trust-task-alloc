#include "nanocbor-helper.h"

#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "nanocbor"
#define LOG_LEVEL LOG_LEVEL_ERR
/*-------------------------------------------------------------------------------------------------------------------*/
// Tags defined at https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
#define NANOCBOR_TAG_NETWORK_ADDRESS 260
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_fmt_ipaddr(nanocbor_encoder_t *enc, const uip_ip6addr_t *addr)
{
    int ret;

#if 0
    // Tag is the correct way to do this, it will also add 3 bytes of overhead (1 for tag, 2 for tag value)
    ret = nanocbor_fmt_tag(enc, NANOCBOR_TAG_NETWORK_ADDRESS);
    if (ret < 0)
    {
        return ret;
    }
#endif

    ret = nanocbor_put_bstr(enc, addr->u8, sizeof(*addr));

    return ret;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_get_ipaddr(nanocbor_value_t *cvalue, const uip_ip6addr_t **addr)
{
#if 0
    int ret;

    // Tag is the correct way to do this, it will also add 3 bytes of overhead (1 for tag, 2 for tag value)
    uint32_t tag;
    ret = nanocbor_get_tag(cvalue, &tag);
    if (ret < 0)
    {
        return ret;
    }

    if (tag != NANOCBOR_TAG_NETWORK_ADDRESS)
    {
        return NANOCBOR_ERR_INVALID_TAG;
    }
#endif

    NANOCBOR_GET_OBJECT(cvalue, addr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_get_bstr_of_len(nanocbor_value_t *cvalue, uint8_t *buf, size_t len)
{
    const uint8_t* bufptr;
    size_t bufptr_length;
    NANOCBOR_CHECK(nanocbor_get_bstr(cvalue, &bufptr, &bufptr_length));

    if (bufptr_length > len)
    {
        return NANOCBOR_ERR_OVERFLOW;
    }
    if (bufptr_length < len)
    {
        return NANOCBOR_ERR_TOO_SMALL;
    }

    memcpy(buf, bufptr, len);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
