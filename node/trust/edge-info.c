#include "edge-info.h"

#include "lib/memb.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef NUM_EDGE_RESOURCES
#define NUM_EDGE_RESOURCES 4
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
static edge_capability_t* edge_capability_new(void)
{
    edge_capability_t* capability = memb_alloc(&edge_capabilities_memb);
    if (capability == NULL)
    {
        return NULL;
    }

    return capability;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void edge_capability_free(edge_capability_t* capability)
{
    memb_free(&edge_capabilities_memb, capability);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_resource_t* edge_resource_new(void)
{
    edge_resource_t* edge = memb_alloc(&edge_resources_memb);
    if (edge == NULL)
    {
        return NULL;
    }

    LIST_STRUCT_INIT(edge, capabilities);

    return edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void edge_resource_free(edge_resource_t* edge)
{
    // Free capabilities
    edge_capability_t* capability;
    while ((capability = list_pop(edge->capabilities)) != NULL)
    {
        edge_capability_free(capability);
    }

    memb_free(&edge_resources_memb, edge);
}
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
    if (edge != NULL)
    {
        return edge;
    }

    edge = edge_resource_new();
    if (edge == NULL)
    {
        return NULL;
    }

    uip_ipaddr_copy(&edge->addr, &addr);
    strcpy(edge->name, ident);

    list_push(edge_resources, edge);

    return edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_info_remove(edge_resource_t* edge)
{
    list_remove(edge_resources, edge);

    edge_resource_free(edge);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_iter(void)
{
    return list_head(edge_resources);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_next(edge_resource_t* iter)
{
    return list_item_next(iter);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_find_addr(uip_ipaddr_t addr)
{
    for (edge_resource_t* iter = list_head(edge_resources); iter != NULL; iter = list_item_next(iter))
    {
        if (uip_ip6addr_cmp(&iter->addr, &addr) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* edge_info_find_ident(const char* ident)
{
    for (edge_resource_t* iter = list_head(edge_resources); iter != NULL; iter = list_item_next(iter))
    {
        if (strcmp(iter->name, ident) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_add(edge_resource_t* edge, const char* name)
{
    edge_capability_t* capability;

    capability = edge_info_capability_find(edge, name);
    if (capability != NULL)
    {
        return capability;
    }

    capability = edge_capability_new();
    if (capability == NULL)
    {
        return NULL;
    }

    strncpy(capability->name, name, EDGE_CAPABILITY_NAME_LEN);

    list_push(edge->capabilities, capability);

    return capability;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t* edge_info_capability_find(edge_resource_t* edge, const char* name)
{
    for (edge_capability_t* iter = list_head(edge->capabilities); iter != NULL; iter = list_item_next(iter))
    {
        if (strcmp(iter->name, name) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
