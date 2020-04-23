#include "edge-info.h"

#include "lib/memb.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef NUM_EDGE_RESOURCES
#define NUM_EDGE_RESOURCES 16
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef NUM_EDGE_CAPABILITIES
#define NUM_EDGE_CAPABILITIES 2
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(edge_resources_memb, edge_resource_t, NUM_EDGE_RESOURCES);
MEMB(edge_capabilities_memb, edge_capability_t, NUM_EDGE_RESOURCES * NUM_EDGE_CAPABILITIES);
/*-------------------------------------------------------------------------------------------------------------------*/
LIST(edge_resources);
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_info_init(void)
{
	memb_init(&edge_resources_memb);
	memb_init(&edge_capabilities_memb);
	list_init(edge_resources);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_add(uip_ipaddr_t addr, const char* ident)
{
	edge_resource_t* edge;

	// First lets check if we already have a record of this edge resource
	edge = edge_info_find_ident(ident);
	if (egde != NULL)
	{
		return edge;
	}

	edge_resource_t* edge = memb_alloc(&edge_resources_memb);
	if (!edge)
	{
		return NULL;
	}

	uip_ipaddr_copy(&edge->addr, &addr);
	strcpy(edge->name, ident);

	LIST_STRUCT_INIT(edge, capabilities);

	list_push(edge_resources, edge);

	return edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_info_remove(edge_resource_t* edge)
{
	int ret;

	list_remove(edge_resources, edge);

	ret = memb_free(&edge_resources_memb, edge);

	return ret == 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_find_addr(uip_ipaddr_t addr)
{
	for (edge_resource_t* iter = list_head(edge_resources); iter != NULL; iter = list_next(iter))
	{
		if (uip_ip6addr_cmp(iter->addr, addr) == 0)
		{
			return iter;
		}
	}

	return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_find_ident(const char* ident)
{
	for (edge_resource_t* iter = list_head(edge_resources); iter != NULL; iter = list_next(iter))
	{
		if (strcmp(iter->name, ident) == 0)
		{
			return iter;
		}
	}

	return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/