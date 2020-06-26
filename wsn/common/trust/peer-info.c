#include "peer-info.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#include "lib/list.h"
#include "lib/memb.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef NUM_PEERS
#define NUM_PEERS 16
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(peers_memb, peer_t, NUM_PEERS);
/*-------------------------------------------------------------------------------------------------------------------*/
LIST(peers);
/*-------------------------------------------------------------------------------------------------------------------*/
static peer_t*
peer_new(void)
{
    peer_t* peer = memb_alloc(&peers_memb);
    if (peer == NULL)
    {
        return NULL;
    }

    return peer;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
peer_free(peer_t* peer)
{
    memb_free(&peers_memb, peer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_info_init(void)
{
    memb_init(&peers_memb);
    list_init(peers);
}
/*-------------------------------------------------------------------------------------------------------------------*/
peer_t*
peer_info_add(const uip_ipaddr_t* addr)
{
    peer_t* peer;

    // First lets check if we already have a record of this peer
    peer = peer_info_find(addr);
    if (peer != NULL)
    {
        return peer;
    }

    peer = peer_new();
    if (peer == NULL)
    {
        return NULL;
    }

    uip_ipaddr_copy(&peer->addr, addr);

    return peer;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
peer_info_remove(peer_t* peer)
{
    list_remove(peers, peer);

    peer_free(peer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
peer_t*
peer_info_iter(void)
{
    return list_head(peers);
}
/*-------------------------------------------------------------------------------------------------------------------*/
peer_t*
peer_info_next(peer_t* iter)
{
    return list_item_next(iter);
}
/*-------------------------------------------------------------------------------------------------------------------*/
peer_t*
peer_info_find(const uip_ipaddr_t* addr)
{
    for (peer_t* iter = peer_info_iter(); iter != NULL; iter = peer_info_next(iter))
    {
        if (uip_ip6addr_cmp(&iter->addr, addr) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
