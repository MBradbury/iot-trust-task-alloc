#include "trust-choose.h"
#include "trust-model.h"
#include "edge-info.h"
#include "os/sys/log.h"
#include "os/lib/random.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-prop"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Divide up RANDOM_RAND_MAX proportionally based on the trust values of the edge capability
// Pick the edge that a ranom number fall into the range of
edge_resource_t* choose_edge(const char* capability_name)
{
    edge_resource_t* candidates[NUM_EDGE_RESOURCES];
    float trust_values[NUM_EDGE_RESOURCES];
    uint16_t trust_values_boundaries[NUM_EDGE_RESOURCES];

    float trust_values_sum = 0.0f;

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

        candidates_len++;

        trust_values_sum += trust_value;
    }

    for (uint8_t i = 0; i != candidates_len; ++i)
    {
        // Normalise the trust values so they sum to 1
        trust_values[i] /= trust_values_sum;

        // What proportion of RANDOM_RAND_MAX is this normalised trust value
        trust_values_boundaries[i] = (uint16_t)(trust_values[i] * RANDOM_RAND_MAX);
    }

    LOG_DBG("There are %u candidates \n", candidates_len);

    if (candidates_len == 0)
    {
        return NULL;
    }
    else
    {
        // Random number in range from 0 to RANDOM_RAND_MAX
        const uint16_t rnd = random_rand();

        uint16_t previous = 0;

        uint8_t idx;
        edge_resource_t* chosen = NULL;

        for (uint8_t i = 0; i != candidates_len; ++i)
        {
            if (previous <= rnd && rnd < previous + trust_values_boundaries[i])
            {
                idx = i;
                chosen = candidates[i];
                break;
            }

            previous += trust_values_boundaries[i];
        }

        if (chosen == NULL)
        {
            LOG_ERR("There is a problem with the maths (previous=%" PRIu16 ", upper=%" PRIu16 ", RANDOM_RAND_MAX=%" PRIu16 ")\n",
                previous, trust_values_boundaries[candidates_len - 1], RANDOM_RAND_MAX);

            idx = candidates_len - 1;
        }

        LOG_DBG("Choosing candidate at index %u of %u candidates_len which is %s\n",
            idx, candidates_len, edge_info_name(chosen));

        return chosen;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
