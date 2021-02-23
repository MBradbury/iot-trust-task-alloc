#include "trust-choose.h"
#include "trust-model.h"
#include "edge-info.h"
#include "random-helpers.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-band"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Note: BAND_SIZE should be set such that the stereotypical trust value is within 1 - BAND_SIZE
// Otherwise new entrants will always be excluded
#ifndef BAND_SIZE
#define BAND_SIZE 0.25f
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Pick randomly from the set of nodes within the highest
// populated band.
edge_resource_t* choose_edge(const char* capability_name)
{
    edge_resource_t* candidates[NUM_EDGE_RESOURCES];
    float trust_values[NUM_EDGE_RESOURCES];

    float highest_trust = 0;

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

        if (candidates_len == CC_ARRAY_SIZE(candidates))
        {
            LOG_WARN("Insufficient memory allocated to candidates\n");
            continue;
        }

        const float trust_value = calculate_trust_value(iter, capability);

        // Record this as a potential candidate
        candidates[candidates_len] = iter;
        trust_values[candidates_len] = trust_value;

        LOG_INFO("Trust value for edge %s and capability %s=%f at %u/%u\n",
            edge_info_name(iter), capability_name, trust_value, candidates_len, NUM_EDGE_RESOURCES);

        // Record the highest trust seen
        if (trust_value > highest_trust)
        {
            highest_trust = trust_value;
        }

        candidates_len++;
    }

    LOG_DBG("Filtering candidates, looking for those in the range [%f, %f]\n",
        highest_trust - BAND_SIZE, highest_trust);

    uint8_t new_idx = 0;

    // Candidates need to have a trust value between [highest_trust - BAND_SIZE, highest_trust]
    // So lets remove any edges we are not considering
    for (uint8_t i = 0; i < candidates_len; ++i)
    {
        if (trust_values[i] >= highest_trust - BAND_SIZE /*&& trust_values[i] <= highest_trust*/)
        {
            candidates[new_idx] = candidates[i];
            trust_values[new_idx] = trust_values[i];

            new_idx++;
        }
    }

    LOG_DBG("There are %u candidates (previously %u)\n", new_idx, candidates_len);

    candidates_len = new_idx;

    if (candidates_len == 0)
    {
        return NULL;
    }
    else
    {
        uint16_t idx = random_in_range_unbiased(0, candidates_len-1);

        edge_resource_t* chosen = candidates[idx];

        LOG_DBG("Choosing candidate at index %u of %u candidates_len which is %s\n",
            idx, candidates_len, edge_info_name(chosen));

        return chosen;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
