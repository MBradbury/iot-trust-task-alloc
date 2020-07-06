#include "trust-model.h"
#include "trust-models.h"
#include "float-helpers.h"
#include <stdio.h>
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
    beta_dist_init(&tm->task_submission, 1, 1);
    beta_dist_init(&tm->task_result, 1, 1);

    //poisson_observation_init(&tm->announce);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_print(const edge_resource_tm_t* tm)
{
    printf("EdgeResourceTM(");
    printf("TaskSub=");
    dist_print(&tm->task_submission);
    printf(",TaskRes=");
    dist_print(&tm->task_result);
    //printf(",Announce=");
    //dist_print(&tm->announce);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_init(edge_capability_tm_t* tm)
{
    beta_dist_init(&tm->result_quality, 1, 1);
    //beta_dist_init(&tm->latency, 1, 1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_print(const edge_capability_tm_t* tm)
{
    printf("EdgeResourceTM(");
    printf("ResQual=");
    dist_print(&tm->result_quality);
    //printf(",Latency=");
    //dist_print(&tm->latency);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_init(peer_tm_t* tm)
{
    //beta_dist_init(&tm->task_observation, 1, 1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_print(const peer_tm_t* tm)
{
    printf("EdgeResourceTM(");
    //printf("TaskObserve=");
    //dist_print(&tm->task_observation);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
static float calculate_trust_value(edge_resource_t* edge, edge_capability_t* capability)
{
    float trust = 0;
    float w_total = 0;
    float w, e;

    w = find_trust_weight(capability->name, TRUST_METRIC_TASK_SUBMISSION);
    e = beta_dist_expected(&edge->tm.task_submission);
    trust += w * e;
    w_total += w;

    w = find_trust_weight(capability->name, TRUST_METRIC_TASK_RESULT);
    e = beta_dist_expected(&edge->tm.task_result);
    trust += w * e;
    w_total += w;

    w = find_trust_weight(capability->name, TRUST_METRIC_RESULT_QUALITY);
    e = beta_dist_expected(&capability->tm.result_quality);
    trust += w * e;
    w_total += w;

    // The weights should add up to be 1, check this
    if (!isclose(w_total, 1.0f))
    {
        LOG_ERR("The trust weights should total up to be close to 1, they are %f\n", w_total);
    }

    return trust;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* choose_edge(const char* capability_name)
{
    edge_resource_t* best_edge = NULL;

    // Start trust at -1, so even edges with 0 trust will be considered
    float best_trust = -1.0f;

    for (edge_resource_t* iter = edge_info_iter(); iter != NULL; iter = edge_info_next(iter))
    {
        edge_capability_t* capability = edge_info_capability_find(iter, capability_name);
        if (capability == NULL)
        {
            LOG_WARN("Cannot find capability %s for edge %s\n", capability_name, iter->name);
            continue;
        }

        float trust_value = calculate_trust_value(iter, capability);

        LOG_INFO("Trust value for edge %s and capability %s=%d%%\n", iter->name, capability_name, (int)(trust_value*100));

        if (trust_value > best_trust)
        {
            best_edge = iter;
            best_trust = trust_value;
        }
    }

    return best_edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_task_submission(edge_resource_t* edge, edge_capability_t* cap, const tm_task_submission_info_t* info)
{
    if (info->coap_request_status == COAP_REQUEST_STATUS_RESPONSE &&
        (info->coap_status >= CREATED_2_01 && info->coap_status <= CONTENT_2_05))
    {
        beta_dist_add_good(&edge->tm.task_submission);
    }
    else
    {
        beta_dist_add_bad(&edge->tm.task_submission);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_task_result(edge_resource_t* edge, edge_capability_t* cap, const tm_task_result_info_t* info)
{
    if (info->good)
    {
        beta_dist_add_good(&edge->tm.task_result);
    }
    else
    {
        beta_dist_add_bad(&edge->tm.task_result);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_result_quality(edge_resource_t* edge, edge_capability_t* cap, const tm_result_quality_info_t* info)
{
    if (info->good)
    {
        beta_dist_add_good(&cap->tm.result_quality);
    }
    else
    {
        beta_dist_add_bad(&cap->tm.result_quality);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_resource(nanocbor_encoder_t* enc, const edge_resource_tm_t* edge)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 1));
    NANOCBOR_CHECK(dist_serialise(enc, &edge->task_submission));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_capability(nanocbor_encoder_t* enc, const edge_capability_tm_t* cap)
{
    NANOCBOR_CHECK(nanocbor_fmt_null(enc));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust_edge_resource(nanocbor_value_t* dec, edge_resource_tm_t* edge)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));
    NANOCBOR_CHECK(dist_deserialise(&arr, &edge->task_submission));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust_edge_capability(nanocbor_value_t* dec, edge_capability_tm_t* cap)
{
    NANOCBOR_CHECK(nanocbor_get_null(dec));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
