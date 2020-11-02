#include "peer-info.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#include "lib/list.h"
#include "lib/memb.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-peer"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef NUM_PEERS
#define NUM_PEERS 8
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(peers_memb, peer_t, NUM_PEERS);
MEMB(peer_edges_memb, peer_edge_t, NUM_PEERS * NUM_EDGE_RESOURCES);
MEMB(peer_capabilities_memb, peer_edge_capability_t, NUM_PEERS * NUM_EDGE_RESOURCES * NUM_EDGE_CAPABILITIES);
/*-------------------------------------------------------------------------------------------------------------------*/
LIST(peers);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
peer_capability_free(peer_edge_capability_t* peer_cap)
{
    memb_free(&peer_capabilities_memb, peer_cap);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
peer_edge_free(peer_edge_t* peer_edge)
{
    for (peer_edge_capability_t* iter = list_head(peer_edge->capabilities); iter != NULL; )
    {
        peer_edge_capability_t* const next = list_item_next(iter);

        peer_capability_free(iter);

        iter = next;
    }

    memb_free(&peer_edges_memb, peer_edge);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static peer_t*
peer_new(void)
{
    peer_t* peer = memb_alloc(&peers_memb);
    if (peer == NULL)
    {
        return NULL;
    }

    peer_tm_init(&peer->tm);

    LIST_STRUCT_INIT(peer, edges);

    return peer;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
peer_free(peer_t* peer)
{
    // Free each piece of edge info provided
    for (peer_edge_t* iter = list_head(peer->edges); iter != NULL; )
    {
        peer_edge_t* const next = list_item_next(iter);

        peer_edge_free(iter);

        iter = next;
    }

    memb_free(&peers_memb, peer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_info_init(void)
{
    LOG_DBG("Initialising peer info\n");

    memb_init(&peers_memb);
    memb_init(&peer_edges_memb);
    memb_init(&peer_capabilities_memb);

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
    peer->last_seen = PEER_LAST_SEEN_INVALID;

    list_push(peers, peer);

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
void peer_info_remove_edges(edge_resource_t* edge)
{
    // Remove information about the provided edge from each peer
    for (peer_t* peer = list_head(peers); peer != NULL; peer = list_item_next(peer))
    {
        for (peer_edge_t* iter = list_head(peer->edges); iter != NULL; )
        {
            peer_edge_t* const next = list_item_next(iter);

            if (iter->edge == edge)
            {
                peer_edge_free(iter);
            }

            iter = next;
        }
    }
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
        if (uip_ip6addr_cmp(&iter->addr, addr))
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static peer_edge_t* peer_info_find_edge(peer_t* peer, edge_resource_t* edge)
{
    for (peer_edge_t* iter = list_head(peer->edges); iter != NULL; iter = list_item_next(iter))
    {
        if (iter->edge == edge)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static peer_edge_capability_t* peer_info_find_capability(peer_edge_t* peer_edge, edge_capability_t* cap)
{
    for (peer_edge_capability_t* iter = list_head(peer_edge->capabilities); iter != NULL; iter = list_item_next(iter))
    {
        if (iter->cap == cap)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool peer_info_update_edge(peer_t* peer, edge_resource_t* edge, const edge_resource_tm_t* tm)
{
    peer_edge_t* peer_edge = peer_info_find_edge(peer, edge);
    if (peer_edge == NULL)
    {
        peer_edge = memb_alloc(&peer_edges_memb);
        if (peer_edge == NULL)
        {
            LOG_ERR("Out of memory peer_edges_memb\n");
            return false;
        }

        LIST_STRUCT_INIT(peer_edge, capabilities);

        peer_edge->edge = edge;

        list_push(peer->edges, peer_edge);
    }

    peer_edge->tm = *tm;

    LOG_DBG("Updated peer ");
    LOG_DBG_6ADDR(&peer->addr);
    LOG_DBG_(" edge '%s' to ", edge_info_name(edge));
    edge_resource_tm_print(tm);
    LOG_DBG_("\n");

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool peer_info_update_capability(peer_t* peer, edge_resource_t* edge, edge_capability_t* cap, const edge_capability_tm_t* tm)
{
    peer_edge_t* peer_edge = peer_info_find_edge(peer, edge);
    if (peer_edge == NULL)
    {
        peer_edge = memb_alloc(&peer_edges_memb);
        if (peer_edge == NULL)
        {
            LOG_ERR("Out of memory peer_edges_memb\n");
            return false;
        }

        LIST_STRUCT_INIT(peer_edge, capabilities);

        peer_edge->edge = edge;

        list_push(peer->edges, peer_edge);
    }

    peer_edge_capability_t* peer_cap = peer_info_find_capability(peer_edge, cap);
    if (peer_cap == NULL)
    {
        peer_cap = memb_alloc(&peer_capabilities_memb);
        if (peer_cap == NULL)
        {
            LOG_ERR("Out of memory peer_capabilities_memb\n");
            return false;
        }

        peer_cap->cap = cap;

        list_push(peer_edge->capabilities, peer_cap);
    }

    peer_cap->tm = *tm;

    LOG_DBG("Updated peer ");
    LOG_DBG_6ADDR(&peer->addr);
    LOG_DBG_(" edge '%s' capability '%s' to ", edge_info_name(edge), cap->name);
    edge_capability_tm_print(tm);
    LOG_DBG_("\n");

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
