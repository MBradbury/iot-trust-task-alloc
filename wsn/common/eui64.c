#include "eui64.h"
#include "base16.h"
#include "linkaddr.h"
#include "uip-ds6.h"
#include "root-endpoint.h"
#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
const uint8_t* current_eui64(void)
{
    return linkaddr_node_addr.u8;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void eui64_from_ipaddr(const uip_ip6addr_t* ipaddr, uint8_t* eui64)
{
    uip_lladdr_t lladdr;
    uip_ds6_set_lladdr_from_iid(&lladdr, ipaddr);

    // Need to unset this value
    if (uip_ip6addr_cmp(ipaddr, &root_ep.ipaddr))
    {
        lladdr.addr[0] ^= 0x02;
    }

    memcpy(eui64, &lladdr, EUI64_LENGTH);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void eui64_to_ipaddr(const uint8_t* eui64, uip_ip6addr_t* ipaddr)
{
    uip_lladdr_t lladdr;
    memcpy(&lladdr, eui64, EUI64_LENGTH);

    // Need to unset this value
    if (uip_ip6addr_cmp(ipaddr, &root_ep.ipaddr))
    {
        lladdr.addr[0] ^= 0x02;
    }

    memset(ipaddr, 0, sizeof(*ipaddr));

    ipaddr->u8[0] = 0xFD;
    ipaddr->u8[1] = 0x00;

    uip_ds6_set_addr_iid(ipaddr, &lladdr);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool eui64_from_str(const char* eui64_str, uint8_t* eui64)
{
    int len = strlen(eui64_str);
    return eui64_from_strn(eui64_str, len, eui64);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool eui64_from_strn(const char* eui64_str, size_t length, uint8_t* eui64)
{
    if (length != EUI64_LENGTH * 2)
    {
        return false;
    }

    ssize_t filled = base16_decode_length(eui64_str, length, eui64, EUI64_LENGTH);

    return filled == EUI64_LENGTH;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int eui64_to_str(const uint8_t* eui64, char* eui64_str, size_t eui64_str_size)
{
    return snprintf(eui64_str, eui64_str_size,
                    "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                    eui64[0], eui64[1], eui64[2], eui64[3],
                    eui64[4], eui64[5], eui64[6], eui64[7]);
}
/*-------------------------------------------------------------------------------------------------------------------*/
