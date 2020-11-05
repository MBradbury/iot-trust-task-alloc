#include "trust-model.h"
#include "trust-models.h"
#include "float-helpers.h"
#include "applications.h"
#include "stereotypes.h"
#include "keystore.h"
#include <stdio.h>
#include <math.h>
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-comm"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_init(edge_resource_tm_t* tm)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_print(const edge_resource_tm_t* tm)
{
    printf("EdgeResourceTM(");
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_init(edge_capability_tm_t* tm)
{
    hmm_init_default(&tm->hmm);
    tm->first = true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_print(const edge_capability_tm_t* tm)
{
    printf("EdgeCapTM(");
    printf("hmm=");
    hmm_print(&tm->hmm);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_init(peer_tm_t* tm)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_print(const peer_tm_t* tm)
{
    printf("PeerTM(");
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
float calculate_trust_value(edge_resource_t* edge, edge_capability_t* cap)
{
    // What is the probability that the next observation will be good
    return hmm_one_observation_probability(&cap->tm.hmm, HMM_OBS_TASK_RESULT_QUALITY_CORRECT);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_task_submission(edge_resource_t* edge, edge_capability_t* cap, const tm_task_submission_info_t* info)
{
    bool should_update;
    const bool good = tm_task_submission_good(info, &should_update);

    if (!should_update)
    {
        return;
    }

    LOG_INFO("Updating Edge %s capability %s TM task_submission (req=%d, coap=%d): ",
        edge_info_name(edge), cap->name, info->coap_request_status, info->coap_status);
    edge_capability_tm_print(&cap->tm);
    LOG_INFO_(" -> ");

    if (!good)
    {
        hmm_update(&cap->tm.hmm, HMM_OBS_TASK_SUBMISSION_ACK_TIMEDOUT, cap->tm.first);
        cap->tm.first = false;
    }

    edge_capability_tm_print(&cap->tm);
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_task_result(edge_resource_t* edge, edge_capability_t* cap, const tm_task_result_info_t* info)
{
    LOG_INFO("Updating Edge %s capability %s TM task_result (result=%d): ", edge_info_name(edge), cap->name, info->result);
    edge_capability_tm_print(&cap->tm);
    LOG_INFO_(" -> ");

    if (info->result != TM_TASK_RESULT_INFO_SUCCESS)
    {
        hmm_update(&cap->tm.hmm, HMM_OBS_TASK_RESPONSE_TIMEDOUT, cap->tm.first);
        cap->tm.first = false;
    }

    edge_capability_tm_print(&cap->tm);
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_result_quality(edge_resource_t* edge, edge_capability_t* cap, const tm_result_quality_info_t* info)
{
    LOG_INFO("Updating Edge %s capability %s TM result_quality (good=%d): ", edge_info_name(edge), cap->name, info->good);
    edge_capability_tm_print(&cap->tm);
    LOG_INFO_(" -> ");

    if (info->good)
    {
        hmm_update(&cap->tm.hmm, HMM_OBS_TASK_RESULT_QUALITY_CORRECT, cap->tm.first);
        cap->tm.first = false;
    }
    else
    {
        hmm_update(&cap->tm.hmm, HMM_OBS_TASK_RESULT_QUALITY_INCORRECT, cap->tm.first);
        cap->tm.first = false;
    }

    edge_capability_tm_print(&cap->tm);
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef APPLICATION_CHALLENGE_RESPONSE
void tm_update_challenge_response(edge_resource_t* edge, const tm_challenge_response_info_t* info)
{
    bool should_update;
    const bool good = tm_challenge_response_good(info, &should_update);

    if (!should_update)
    {
        return;
    }

    edge_capability_t* cap = edge_info_capability_find(edge, CHALLENGE_RESPONSE_APPLICATION_NAME);
    if (cap == NULL)
    {
        LOG_ERR("Failed to find cr application\n");
        return;
    }

    const tm_result_quality_info_t info2 = { .good = good };
    tm_update_result_quality(edge, cap, &info2);
}
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_resource(nanocbor_encoder_t* enc, const edge_resource_tm_t* edge)
{
    NANOCBOR_CHECK(nanocbor_fmt_null(enc));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_capability(nanocbor_encoder_t* enc, const edge_capability_tm_t* cap)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 2));
    NANOCBOR_CHECK(hmm_serialise(enc, &cap->hmm));
    NANOCBOR_CHECK(nanocbor_fmt_bool(enc, cap->first));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust_edge_resource(nanocbor_value_t* dec, edge_resource_tm_t* edge)
{
    NANOCBOR_CHECK(nanocbor_get_null(dec));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust_edge_capability(nanocbor_value_t* dec, edge_capability_tm_t* cap)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(hmm_deserialise(&arr, &cap->hmm));
    NANOCBOR_CHECK(nanocbor_get_bool(&arr, &cap->first));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
