#pragma once

#include "contiki.h"
#include "net/ipv6/uip.h"
#include "lib/list.h"

#include <stdbool.h>

#include "trust-common.h"
#include "trust-model.h"
#include "stereotype-tags.h"

#include "coap-endpoint.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef NUM_EDGE_RESOURCES
#define NUM_EDGE_RESOURCES 4
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef NUM_EDGE_CAPABILITIES
#define NUM_EDGE_CAPABILITIES 3
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define EDGE_CAPABILITY_NO_FLAGS 0
#define EDGE_CAPABILITY_ACTIVE (1 << 0)
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_capability
{
    struct edge_capability *next;

    char name[EDGE_CAPABILITY_NAME_LEN + 1];

    uint32_t flags;

    edge_capability_tm_t tm;

} edge_capability_t;
/*-------------------------------------------------------------------------------------------------------------------*/
#define EDGE_RESOURCE_NO_FLAGS 0
#define EDGE_RESOURCE_ACTIVE (1 << 0)
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_resource
{
    struct edge_resource *next;

    coap_endpoint_t ep;

    uint32_t flags;

    edge_resource_tm_t tm;

    LIST_STRUCT(capabilities);

} edge_resource_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_info_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_add(const uip_ipaddr_t* addr);
bool edge_info_remove(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_find_addr(const uip_ipaddr_t* addr);
edge_resource_t* edge_info_find_eui64(const uint8_t* eui64);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_iter(void);
edge_resource_t* edge_info_next(edge_resource_t* iter);
/*-------------------------------------------------------------------------------------------------------------------*/
size_t edge_info_count(void);
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_info_is_active(const edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_add(edge_resource_t* edge, const char* name);
bool edge_info_capability_remove_by_name(edge_resource_t* edge, const char* name);
bool edge_info_capability_remove(edge_resource_t* edge, edge_capability_t* capability);
void edge_info_capability_clear(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_find(edge_resource_t* edge, const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_capability_is_active(const edge_capability_t* capability);
/*-------------------------------------------------------------------------------------------------------------------*/
extern process_event_t pe_edge_capability_add;
extern process_event_t pe_edge_capability_remove;
/*-------------------------------------------------------------------------------------------------------------------*/
const char* edge_info_name(const edge_resource_t* edge); // TODO: Remove this function
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_info_has_active_capability(const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
