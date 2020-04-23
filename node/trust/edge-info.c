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
edge_resource_t* edge_info_add(uip_ipaddr_t addr)
{
	edge_resource_t* edge = memb_alloc(&edge_resources_memb);
	if (!edge)
	{
		return NULL;
	}

	uip_ipaddr_copy(&edge->addr, &addr);

	LIST_STRUCT_INIT(edge, capabilities);

	list_push(edge_resources, edge);

	return edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_info_remove(edge_resource_t* edge)
{
	int ret;

	ret = memb_free(&edge_resources_memb, edge);

	return ret == 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
