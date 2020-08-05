#include "trust-models.h"
#include "os/sys/log.h"
#include "list.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-comm"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
LIST(trust_weights);
/*-------------------------------------------------------------------------------------------------------------------*/
void trust_weights_init(void)
{
    list_init(trust_weights);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void trust_weights_add(trust_weights_t* item)
{
    list_add(trust_weights, item);
}
/*-------------------------------------------------------------------------------------------------------------------*/
trust_weights_t* trust_weights_find(const char* application_name)
{
    for (trust_weights_t* iter = list_head(trust_weights); iter != NULL; iter = list_item_next(iter))
    {
        if (strcmp(iter->application_name, application_name) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
float find_trust_weight(const char* application_name, uint16_t id)
{
    trust_weights_t* weights = trust_weights_find(application_name);
    if (weights == NULL)
    {
        LOG_ERR("Failed to find trust weight information for %s\n", application_name);
        return 0.0f;
    }

    for (uint8_t i = 0; i != weights->num; ++i)
    {
        const trust_weight_t* iter = &weights->weights[i];

        if (iter->id == id)
        {
            return iter->weight;
        }
    }

    return 0.0f;
}
/*-------------------------------------------------------------------------------------------------------------------*/
__attribute__((__weak__)) void tm_update_task_submission(edge_resource_t* edge, edge_capability_t* cap, const tm_task_submission_info_t* info)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
__attribute__((__weak__)) void tm_update_task_result(edge_resource_t* edge, edge_capability_t* cap, const tm_task_result_info_t* info)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
__attribute__((__weak__)) void tm_update_announce(edge_resource_t* edge, edge_capability_t* cap, const tm_announce_info_t* info)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
__attribute__((__weak__)) void tm_update_result_quality(edge_resource_t* edge, edge_capability_t* cap, const tm_result_quality_info_t* info)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
__attribute__((__weak__)) void tm_update_result_latency(edge_resource_t* edge, edge_capability_t* cap, const tm_result_latency_info_t* info)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
__attribute__((__weak__)) void tm_update_challenge_response(edge_resource_t* edge, const tm_challenge_response_info_t* info)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
__attribute__((__weak__)) void tm_update_task_observation(peer_t* peer, const tm_task_observation_info_t* info)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
