#include "trust-choose.h"
#include "trust-model.h"
#include "edge-info.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-high"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Pick the edge node with the highest trust level that supports
// the provided capability.
edge_resource_t* choose_edge(const char* capability_name)
{
    edge_resource_t* best_edge = NULL;

    // Start trust at -1, so even edges with 0 trust will be considered
    float best_trust = -1.0f;

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
            LOG_WARN("Cannot find capability %s for edge %s\n", capability_name, edge_info_name(iter));
            continue;
        }

        // Skip inactive capabilities
        if (!edge_capability_is_active(capability))
        {
            continue;
        }

        float trust_value = calculate_trust_value(iter, capability);

        LOG_INFO("Trust value for edge %s and capability %s=%f\n",
            edge_info_name(iter), capability_name, trust_value);

        if (trust_value > best_trust)
        {
            best_edge = iter;
            best_trust = trust_value;
        }
    }

    return best_edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
