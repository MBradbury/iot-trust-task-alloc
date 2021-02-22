#include "trust-choose.h"
#include "trust-model.h"
#include "edge-info.h"
#include "random-helpers.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-badl"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Only support choosing nodes that are good
edge_resource_t* choose_edge(const char* capability_name)
{
    edge_resource_t* candidates[NUM_EDGE_RESOURCES];
    uint8_t candidates_len = 0;

    //LOG_DBG("Choosing an edge to submit task for %s\n", capability_name);

    for (edge_resource_t* iter = edge_info_iter(); iter != NULL; iter = edge_info_next(iter))
    {
        //LOG_DBG("Considering edge %s with ", edge_info_name(iter));
        //edge_resource_tm_print(&iter->tm);
        //LOG_DBG_("\n");

        // Skip inactive edges
        if (!edge_info_is_active(iter))
        {
            continue;
        }

        // Make sure the edge has the desired capability
        edge_capability_t* capability = edge_info_capability_find(iter, capability_name);
        if (capability == NULL)
        {
            //LOG_DBG("Excluding edge %s because it lacks the capability\n", edge_info_name(iter));
            continue;
        }

        // Skip inactive capabilities
        if (!edge_capability_is_active(capability))
        {
            continue;
        }

        // Can't use this node if it is bad
        if (!edge_is_good(iter))
        {
            //LOG_DBG("Excluding edge %s because it is bad\n", edge_info_name(iter));
            continue;
        }

        if (candidates_len == CC_ARRAY_SIZE(candidates))
        {
            LOG_WARN("Insufficient memory allocated to candidates\n");
            continue;
        }

        // Record this as a potential candidate
        candidates[candidates_len++] = iter;
    }

    //LOG_DBG("There are %u candidates\n", candidates_len);

    if (candidates_len == 0)
    {
        return NULL;
    }
    else
    {
        uint16_t idx = random_in_range_unbiased(0, candidates_len-1);

        edge_resource_t* chosen = candidates[idx];

        //LOG_DBG("Choosing candidate at index %u of %u candidates_len which is %s\n", idx, candidates_len, chosen->name);

        return chosen;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
