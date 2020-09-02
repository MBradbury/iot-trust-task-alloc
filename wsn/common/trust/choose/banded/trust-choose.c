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
#ifndef BAND_SIZE
#define BAND_SIZE 0.1f
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
        //LOG_DBG("Considering edge %s with ", iter->name);
        //edge_resource_tm_print(&iter->tm);
        //LOG_DBG_("\n");

        // Make sure the edge has the desired capability
        edge_capability_t* capability = edge_info_capability_find(iter, capability_name);
        if (capability == NULL)
        {
            //LOG_DBG("Excluding edge %s because it lacks the capability\n", iter->name);
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
            iter->name, capability_name, trust_value, candidates_len, NUM_EDGE_RESOURCES);

        candidates_len++;

        // Record the highest trust seen
        if (trust_values[candidates_len] > highest_trust)
        {
            highest_trust = trust_values[candidates_len];
        }
    }

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

    candidates_len = new_idx;

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
