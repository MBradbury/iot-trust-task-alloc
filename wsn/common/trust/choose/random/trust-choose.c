#include "trust-choose.h"
#include "trust-model.h"
#include "edge-info.h"
#include "random-helpers.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-random"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Use a random edge node we are aware of that supports
// the requested capability
edge_resource_t* choose_edge(const char* capability_name)
{
    edge_resource_t* candidates[NUM_EDGE_RESOURCES];
    uint16_t candidates_len = 0;

    for (edge_resource_t* iter = edge_info_iter(); iter != NULL; iter = edge_info_next(iter))
    {
        // Skip inactive edges
        if (!edge_info_is_active(iter))
        {
            continue;
        }

        edge_capability_t* capability = edge_info_capability_find(iter, capability_name);
        if (capability == NULL)
        {
            continue;
        }

        // Skip inactive capabilities
        if (!edge_capability_is_active(capability))
        {
            continue;
        }

        // Consider this edge
        candidates[candidates_len] = iter;
        candidates_len++;
    }

    // No valid options
    if (candidates_len == 0)
    {
        return NULL;
    }

    uint16_t idx = random_in_range_unbiased(0, candidates_len-1);

    return candidates[idx];
}
/*-------------------------------------------------------------------------------------------------------------------*/
