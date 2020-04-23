#pragma once

#include "contiki.h"
#include "net/ipv6/uip.h"
#include "lib/list.h"

#include <stdbool.h>

/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_capability
{
	struct edge_capability *next;
	
	const char* name;
} edge_capability_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_resource
{
	struct edge_resource *next;

	uip_ipaddr_t addr;

	LIST_STRUCT(capabilities);
} edge_resource_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_info_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_add(uip_ipaddr_t addr);
bool edge_info_remove(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
