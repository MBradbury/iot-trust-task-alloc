#include "trust-choose.h"
#include "trust-model.h"
#include "edge-info.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-fcfs"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Use the first edge node we are aware of that supports
// the provided capability
edge_resource_t* choose_edge(const char* capability_name)
{
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
        
        // Use the first edge we find that we can use
        return iter;
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
