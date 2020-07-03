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

    ret = nanocbor_fmt_tag(enc, NANOCBOR_TAG_NETWORK_ADDRESS);
    if (ret < 0)
    {
        return ret;
    }

    ret = nanocbor_put_bstr(enc, addr->u8, sizeof(*addr));

    return ret;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_get_ipaddr(nanocbor_value_t *cvalue, const uip_ip6addr_t **addr)
{
    int ret;

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

    NANOCBOR_GET_OBJECT(cvalue, addr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
