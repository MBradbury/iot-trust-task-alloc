#include "edge-info.h"

#include "lib/memb.h"
#include "os/sys/log.h"

#include "coap-constants.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-edge"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(edge_resources_memb, edge_resource_t, NUM_EDGE_RESOURCES);
MEMB(edge_capabilities_memb, edge_capability_t, NUM_EDGE_RESOURCES * NUM_EDGE_CAPABILITIES);
/*-------------------------------------------------------------------------------------------------------------------*/
LIST(edge_resources);
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_capability_t*
edge_capability_new(edge_resource_t* edge)
{
    // This edge already has the maximum number of capabilities it is allowed to have
    if (list_length(edge->capabilities) >= NUM_EDGE_CAPABILITIES)
    {
        LOG_ERR("Cannot allocate another capability for edge %s, as it has reached the maximum number allowed\n",
            edge->name);
        return NULL;
    }

    edge_capability_t* cap = memb_alloc(&edge_capabilities_memb);
    if (cap == NULL)
    {
        return NULL;
    }

    edge_capability_tm_init(&cap->tm);

    return cap;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_free(edge_capability_t* capability)
{
    memb_free(&edge_capabilities_memb, capability);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_resource_t*
edge_resource_new(void)
{
    edge_resource_t* edge = memb_alloc(&edge_resources_memb);
    if (edge == NULL)
    {
        return NULL;
    }

    edge_resource_tm_init(&edge->tm);

    LIST_STRUCT_INIT(edge, capabilities);

    return edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_resource_free(edge_resource_t* edge)
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
void
edge_info_init(void)
{
    LOG_DBG("Initialising edge info\n");

    memb_init(&edge_resources_memb);
    memb_init(&edge_capabilities_memb);
    list_init(edge_resources);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t*
edge_info_add(const uip_ipaddr_t* addr, const char* ident)
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

    uip_ipaddr_copy(&edge->ep.ipaddr, addr);
    edge->ep.secure = 0;
    edge->ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    strcpy(edge->name, ident);

    list_push(edge_resources, edge);

    edge->flags = EDGE_RESOURCE_NO_FLAGS;

    return edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
edge_info_remove(edge_resource_t* edge)
{
    list_remove(edge_resources, edge);

    edge_resource_free(edge);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t*
edge_info_iter(void)
{
    return list_head(edge_resources);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t*
edge_info_next(edge_resource_t* iter)
{
    return list_item_next(iter);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t*
edge_info_find_addr(const uip_ipaddr_t* addr)
{
    for (edge_resource_t* iter = list_head(edge_resources); iter != NULL; iter = list_item_next(iter))
    {
        if (uip_ip6addr_cmp(&iter->ep.ipaddr, addr))
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t*
edge_info_find_ident(const char* ident)
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
size_t edge_info_count(void)
{
    return list_length(edge_resources);
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t*
edge_info_capability_add(edge_resource_t* edge, const char* name)
{
    edge_capability_t* capability;

    capability = edge_info_capability_find(edge, name);
    if (capability != NULL)
    {
        return capability;
    }

    capability = edge_capability_new(edge);
    if (capability == NULL)
    {
        return NULL;
    }

    strncpy(capability->name, name, EDGE_CAPABILITY_NAME_LEN);

    list_push(edge->capabilities, capability);

    return capability;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_info_capability_remove(edge_resource_t* edge, edge_capability_t* capability)
{
    bool removed = list_remove(edge->capabilities, capability);

    if (removed)
    {
        edge_capability_free(capability);
    }

    return removed;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_info_capability_remove_by_name(edge_resource_t* edge, const char* name)
{
    edge_capability_t* capability;

    capability = edge_info_capability_find(edge, name);
    if (capability == NULL)
    {
        return false;
    }

    return edge_info_capability_remove(edge, capability);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_info_capability_clear(edge_resource_t* edge)
{
    edge_capability_t* iter = list_head(edge->capabilities);
    while (iter != NULL)
    {
        edge_capability_t* capability = iter;

        // Find next item before removing to prevent use-after-free
        iter = list_item_next(iter);

        edge_info_capability_remove(edge, capability);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_capability_t*
edge_info_capability_find(edge_resource_t* edge, const char* name)
{
    if (edge == NULL)
    {
        return NULL;
    }

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
