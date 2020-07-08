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
typedef struct edge_capability
{
    struct edge_capability *next;

    char name[EDGE_CAPABILITY_NAME_LEN + 1];

    edge_capability_tm_t tm;

} edge_capability_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_resource
{
    struct edge_resource *next;

    coap_endpoint_t ep;

    char name[MQTT_IDENTITY_LEN + 1];

    bool active;

    stereotype_tags_t tags;

    edge_resource_tm_t tm;

    LIST_STRUCT(capabilities);

} edge_resource_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_info_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_add(const uip_ipaddr_t* addr, const char* ident, const stereotype_tags_t* tags);
void edge_info_remove(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_find_addr(const uip_ipaddr_t* addr);
edge_resource_t* edge_info_find_ident(const char* ident);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_iter(void);
edge_resource_t* edge_info_next(edge_resource_t* iter);
/*-------------------------------------------------------------------------------------------------------------------*/
size_t edge_info_count(void);
/*-------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_add(edge_resource_t* edge, const char* name);
bool edge_info_capability_remove_by_name(edge_resource_t* edge, const char* name);
bool edge_info_capability_remove(edge_resource_t* edge, edge_capability_t* capability);
void edge_info_capability_clear(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_find(edge_resource_t* edge, const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
extern process_event_t pe_edge_capability_add;
extern process_event_t pe_edge_capability_remove;
/*-------------------------------------------------------------------------------------------------------------------*/
