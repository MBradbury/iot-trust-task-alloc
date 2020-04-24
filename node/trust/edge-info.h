#pragma once

#include "contiki.h"
#include "net/ipv6/uip.h"
#include "lib/list.h"

#include <stdbool.h>

#include "trust-common.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define PROCESS_EVENT_EDGE_CAPABILITY_ADD 0x10
#define PROCESS_EVENT_EDGE_CAPABILITY_REMOVE 0x11
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_capability
{
	struct edge_capability *next;

	char name[EDGE_CAPABILITY_NAME_LEN + 1];
} edge_capability_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_resource
{
	struct edge_resource *next;

	uip_ipaddr_t addr;
	char name[MQTT_IDENTITY_LEN + 1];

	LIST_STRUCT(capabilities);
} edge_resource_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_info_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_add(uip_ipaddr_t addr, const char* ident);
void edge_info_remove(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_find_addr(uip_ipaddr_t addr);
edge_resource_t* edge_info_find_ident(const char* ident);
/*-------------------------------------------------------------------------------------------------------------------*/
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_add(edge_resource_t* edge, const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_find(edge_resource_t* edge, const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
