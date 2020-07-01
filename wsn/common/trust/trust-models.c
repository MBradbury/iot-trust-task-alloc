#include "trust-models.h"

extern const trust_weight_t trust_weights[];
extern const uint8_t trust_weights_len;

float find_trust_weight(uint16_t id)
{
    for (uint8_t i = 0; i != trust_weights_len; ++i)
    {
        const trust_weight_t* iter = &trust_weights[i];

        if (iter->id == id)
        {
            return iter->weight;
        }
    }

    return 0.0f;
}

__attribute__((__weak__)) void tm_update_task_submission(edge_resource_t* edge, edge_capability_t* cap, const tm_task_submission_info_t* info)
{
}

__attribute__((__weak__)) void tm_update_task_result(edge_resource_t* edge, edge_capability_t* cap, const tm_task_result_info_t* info)
{
}

__attribute__((__weak__)) void tm_update_announce(edge_resource_t* edge, edge_capability_t* cap, const tm_announce_info_t* info)
{
}

__attribute__((__weak__)) void tm_update_result_quality(edge_resource_t* edge, edge_capability_t* cap, const tm_result_quality_info_t* info)
{
}

__attribute__((__weak__)) void tm_update_result_latency(edge_resource_t* edge, edge_capability_t* cap, const tm_result_latency_info_t* info)
{
}

__attribute__((__weak__)) void tm_update_task_observation(peer_t* peer, const tm_task_observation_info_t* info)
{
}
