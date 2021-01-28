#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include "contiki.h"
#include "net/ipv6/uip.h"

#include "trust-model.h"
#include "edge-info.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define PEER_LAST_SEEN_INVALID UINT32_MAX
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct peer_edge_capability {
    struct peer_edge_capability* next;

    edge_capability_t* cap;
    edge_capability_tm_t tm;

} peer_edge_capability_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct peer_edge {
    struct peer_edge* next;

    edge_resource_t* edge;
    edge_resource_tm_t tm;

    LIST_STRUCT(capabilities);

} peer_edge_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct peer
{
    struct peer *next;

    uip_ipaddr_t addr;

    // Time in peer's local clock (non-monotonic)
    uint32_t last_seen;

    peer_tm_t tm;

    LIST_STRUCT(edges);

} peer_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_info_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
peer_t* peer_info_add(const uip_ipaddr_t* addr);
void peer_info_remove(peer_t* peer);
void peer_info_remove_edges(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
peer_t* peer_info_find(const uip_ipaddr_t* addr);
/*-------------------------------------------------------------------------------------------------------------------*/
peer_edge_t* peer_info_find_edge(peer_t* peer, edge_resource_t* edge);
peer_edge_capability_t* peer_info_find_capability(peer_edge_t* peer_edge, edge_capability_t* cap);
/*-------------------------------------------------------------------------------------------------------------------*/
peer_t* peer_info_iter(void);
peer_t* peer_info_next(peer_t* iter);
/*-------------------------------------------------------------------------------------------------------------------*/
bool peer_info_update_edge(peer_t* peer, edge_resource_t* edge, const edge_resource_tm_t* tm);
bool peer_info_update_capability(peer_t* peer, edge_resource_t* edge, edge_capability_t* cap, const edge_capability_tm_t* tm);
/*-------------------------------------------------------------------------------------------------------------------*/
