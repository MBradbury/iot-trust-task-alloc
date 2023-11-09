#include "capability-info.h"
#include "trust-model.h"

#include "eui64.h"

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
#ifndef TRUST_MODEL_HAS_PER_CAPABILITY_INFO
#   define NUM_CAPABILITIES 0
#   pragma message "No space for per-capability trust information has been allocated"
#else
#   define NUM_CAPABILITIES NUM_EDGE_CAPABILITIES
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(capabilities_memb, capability_t, NUM_CAPABILITIES);
/*-------------------------------------------------------------------------------------------------------------------*/
LIST(capabilities);
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
free_up_capabilities(void)
{
    // TODO: might need to address bias in which inactive edge is selected for removal

    for (capability_t* eiter = list_head(capabilities); eiter != NULL; eiter = list_item_next(eiter))
    {
        // Remove information on capabilities for which there are no active capabilities
        if (!edge_info_has_active_capability(eiter->name))
        {
            return capability_info_remove(eiter);
        }
    }

    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static capability_t*
capability_new(void)
{
    capability_t* cap = memb_alloc(&capabilities_memb);
    if (cap == NULL)
    {
        free_up_capabilities();

        cap = memb_alloc(&capabilities_memb);
        if (cap == NULL)
        {
            return NULL;
        }
    }

    capability_tm_init(&cap->tm);

    return cap;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
capability_free(capability_t* cap)
{
    memb_free(&capabilities_memb, cap);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
capability_info_init(void)
{
    LOG_DBG("Initialising capability info\n");

    memb_init(&capabilities_memb);
    list_init(capabilities);
}
/*-------------------------------------------------------------------------------------------------------------------*/
capability_t*
capability_info_add(const char* name)
{
    capability_t* cap;

    // First lets check if we already have a record of this capability
    cap = capability_info_find(name);
    if (cap != NULL)
    {
        return cap;
    }

    cap = capability_new();
    if (cap == NULL)
    {
        return NULL;
    }

    strcpy(cap->name, name);

    list_push(capabilities, cap);

    return cap;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
capability_info_remove(capability_t* cap)
{
    bool removed = list_remove(capabilities, cap);

    if (removed)
    {
        capability_free(cap);
    }

    return removed;
}
/*-------------------------------------------------------------------------------------------------------------------*/
capability_t*
capability_info_iter(void)
{
    return list_head(capabilities);
}
/*-------------------------------------------------------------------------------------------------------------------*/
capability_t*
capability_info_next(capability_t* iter)
{
    return list_item_next(iter);
}
/*-------------------------------------------------------------------------------------------------------------------*/
capability_t*
capability_info_find(const char* name)
{
    for (capability_t* iter = list_head(capabilities); iter != NULL; iter = list_item_next(iter))
    {
        if (strcmp(iter->name, name) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
size_t capability_info_count(void)
{
    return list_length(capabilities);
}
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef TRUST_MODEL_HAS_PER_CAPABILITY_INFO
void capability_tm_init(capability_tm_t* cap_tm)
{
    // Provide empty init function
}
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
