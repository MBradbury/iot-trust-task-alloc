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
// Higher this weight, the more recent values have an impact
#ifndef THROUGHPUT_EWMA_WEIGHT
#define THROUGHPUT_EWMA_WEIGHT 0.6f
#endif
_Static_assert(THROUGHPUT_EWMA_WEIGHT >= 0);
_Static_assert(THROUGHPUT_EWMA_WEIGHT <= 1);
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef THROUGHPUT_EXCLUSION_THRESHOLD
#define THROUGHPUT_EXCLUSION_THRESHOLD 10
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef THROUGHPUT_GLOBAL_ACCEPTABLE
#define THROUGHPUT_GLOBAL_ACCEPTABLE 0.4f
#endif
_Static_assert(THROUGHPUT_GLOBAL_ACCEPTABLE >= 0);
_Static_assert(THROUGHPUT_GLOBAL_ACCEPTABLE <= 1);
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef THROUGHPUT_LOCAL_LOWER
#define THROUGHPUT_LOCAL_LOWER 0.25f
#endif
_Static_assert(THROUGHPUT_LOCAL_LOWER >= 0);
_Static_assert(THROUGHPUT_LOCAL_LOWER <= 1);
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef THROUGHPUT_LOCAL_HIGHER
#define THROUGHPUT_LOCAL_HIGHER 0.75f
#endif
_Static_assert(THROUGHPUT_LOCAL_HIGHER >= 0);
_Static_assert(THROUGHPUT_LOCAL_HIGHER <= 1);
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef EXPECTED_TIME_THROUGHPUT_BAD
#error "Must set EXPECTED_TIME_THROUGHPUT_BAD to be the number of seconds willing to wait before an edge's throughput may become good again"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef EXPECTED_TIME_THROUGHPUT_BAD_TO_GOOD_PR
#error "Must set EXPECTED_TIME_THROUGHPUT_BAD_TO_GOOD_PR to be likelihood the bad time has passed"
#endif
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
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_print(const edge_resource_tm_t* tm)
{
    printf("EdgeResourceTM(");
    printf("TaskSub=");
    dist_print(&tm->task_submission);
    printf(",TaskRes=");
    dist_print(&tm->task_result);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_init(edge_capability_tm_t* tm)
{
    beta_dist_init(&tm->result_quality, 1, 1);
    gaussian_dist_init_empty(&tm->throughput_in);
    gaussian_dist_init_empty(&tm->throughput_out);
    gaussian_dist_init_empty(&tm->throughput_in_ewma);
    gaussian_dist_init_empty(&tm->throughput_out_ewma);

    // Assume edge starts as good
    tm->throughput_good = true;

    exponential_dist_init(
        &tm->throughput_goodness_change,
        1.0f / (EXPECTED_TIME_THROUGHPUT_BAD * CLOCK_SECOND));

    tm->throughput_last_became_bad = (clock_time_t)-1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_print(const edge_capability_tm_t* tm)
{
    printf("EdgeCapTM(");
    printf("ResQual=");
    dist_print(&tm->result_quality);
    printf(",ThroughputIn=");
    dist_print(&tm->throughput_in);
    printf("+ewma:");
    dist_print(&tm->throughput_in_ewma);
    printf(",ThroughputOut=");
    dist_print(&tm->throughput_out);
    printf("+ewma:");
    dist_print(&tm->throughput_out_ewma);
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
void capability_tm_init(capability_tm_t* tm)
{
    gaussian_dist_init_empty(&tm->throughput_in);
    gaussian_dist_init_empty(&tm->throughput_out);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void capability_tm_print(const capability_tm_t* tm)
{
    printf("CapTM(");
    printf("ThroughputIn=");
    dist_print(&tm->throughput_in);
    printf(",ThroughputOut=");
    dist_print(&tm->throughput_out);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
static float pr_value_lt_norm(const gaussian_dist_t* norm, const gaussian_dist_t* ewma)
{
    // Return middle value when no data in distributions
    if (norm->count == 0 || ewma->count == 0)
    {
        return 0.5f;
    }

    // In the EWMA distribution what is the probability of observing a value
    // greater than the mean calculated via an unweighted average

    if (ewma->variance == 0.0f)
    {
        if (norm->mean < ewma->mean)
        {
            return 1.0f;
        }
        else
        {
            return 0.0f;
        }
    }
    else
    {
        return gaussian_dist_cdf(ewma, norm->mean);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static float pr_value_ge_norm(const gaussian_dist_t* norm, const gaussian_dist_t* ewma)
{
    return 1.0f - pr_value_lt_norm(norm, ewma);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static float goodness_pge_local(const edge_resource_t* edge, const edge_capability_t* capability)
{
    const gaussian_dist_t* in = &capability->tm.throughput_in;
    const gaussian_dist_t* out = &capability->tm.throughput_out;

    const gaussian_dist_t* in_ewma = &capability->tm.throughput_in_ewma;
    const gaussian_dist_t* out_ewma = &capability->tm.throughput_out_ewma;

    const float in_pr = pr_value_ge_norm(in, in_ewma);
    const float out_pr = pr_value_ge_norm(out, out_ewma);

    const float result = (in_pr + out_pr) / 2.0f;

    LOG_INFO("goodness_of_throughput[%s, %s](%f,%f) = %f",
        edge_info_name(edge), capability->name,
        in_pr, out_pr, result);
    LOG_INFO_(" in-norm:");
    gaussian_dist_print(in);
    LOG_INFO_(" out-norm:");
    gaussian_dist_print(out);
    LOG_INFO_(" in-ewma:");
    gaussian_dist_print(in_ewma);
    LOG_INFO_(" out-ewma:");
    gaussian_dist_print(out_ewma);
    LOG_INFO_("\n");

    return result;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static float goodness_plt_global(const edge_resource_t* edge, const edge_capability_t* capability, const capability_t* global_cap)
{
    const gaussian_dist_t* in = &capability->tm.throughput_in;
    const gaussian_dist_t* out = &capability->tm.throughput_out;

    const gaussian_dist_t* in_global = &global_cap->tm.throughput_in;
    const gaussian_dist_t* out_global = &global_cap->tm.throughput_out;

    const float in_pr = pr_value_lt_norm(in, in_global);
    const float out_pr = pr_value_lt_norm(out, out_global);

    const float result = (in_pr + out_pr) / 2.0f;

    LOG_INFO("goodness_p2[%s, %s](%f,%f) = %f",
        edge_info_name(edge), capability->name,
        in_pr, out_pr, result);
    LOG_INFO_(" in-norm:");
    gaussian_dist_print(in);
    LOG_INFO_(" out-norm:");
    gaussian_dist_print(out);
    LOG_INFO_(" in-global:");
    gaussian_dist_print(in_global);
    LOG_INFO_(" out-global:");
    gaussian_dist_print(out_global);
    LOG_INFO_("\n");

    return result;
}
/*-------------------------------------------------------------------------------------------------------------------*/
float calculate_trust_value(edge_resource_t* edge, edge_capability_t* capability)
{
    // Get the stereotype that may inform the trust value
    edge_stereotype_t* s = NULL;
    public_key_item_t* item = keystore_find_addr(&edge->ep.ipaddr);
    if (item != NULL)
    {
        s = edge_stereotype_find(&item->cert.tags);
    }

    float trust = 0;
    float w_total = 0;
    float w, e;

    beta_dist_t temp;

    w = find_trust_weight(capability->name, TRUST_METRIC_TASK_SUBMISSION);
    beta_dist_combine(&edge->tm.task_submission, s ? &s->edge_tm.task_submission : NULL, &temp);
    e = beta_dist_expected(&temp);
    trust += w * e;
    w_total += w;

    w = find_trust_weight(capability->name, TRUST_METRIC_TASK_RESULT);
    beta_dist_combine(&edge->tm.task_result, s ? &s->edge_tm.task_result : NULL, &temp);
    e = beta_dist_expected(&temp);
    trust += w * e;
    w_total += w;

    w = find_trust_weight(capability->name, TRUST_METRIC_RESULT_QUALITY);
    e = beta_dist_expected(&capability->tm.result_quality);
    trust += w * e;
    w_total += w;

#if defined(APPLICATION_CHALLENGE_RESPONSE) && defined(TRUST_MODEL_USE_CHALLENGE_RESPONSE)
    // This application is special, as its result quality applies to
    // other applications too (as long as they specify a weight for it).
    edge_capability_t* cr = edge_info_capability_find(edge, CHALLENGE_RESPONSE_APPLICATION_NAME);
    if (cr != NULL)
    {
        w = find_trust_weight(capability->name, TRUST_METRIC_CHALLENGE_RESP);
        e = beta_dist_expected(&cr->tm.result_quality);
        trust += w * e;
        w_total += w;
    }
#endif

    // The weights should add up to be 1, check this
    if (!isclose(w_total, 1.0f))
    {
        LOG_ERR("The trust weights should total up to be close to 1, they are %f\n", w_total);
    }

    return trust;
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
    beta_dist_print(&edge->tm.task_submission);
    LOG_INFO_(" -> ");

    if (good)
    {
        beta_dist_add_good(&edge->tm.task_submission);
    }
    else
    {
        beta_dist_add_bad(&edge->tm.task_submission);
    }

    beta_dist_print(&edge->tm.task_submission);
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_task_result(edge_resource_t* edge, edge_capability_t* cap, const tm_task_result_info_t* info)
{
    LOG_INFO("Updating Edge %s capability %s TM task_result (result=%d): ", edge_info_name(edge), cap->name, info->result);
    beta_dist_print(&edge->tm.task_result);
    LOG_INFO_(" -> ");

    if (info->result == TM_TASK_RESULT_INFO_SUCCESS)
    {
        beta_dist_add_good(&edge->tm.task_result);
    }
    else
    {
        beta_dist_add_bad(&edge->tm.task_result);
    }

    beta_dist_print(&edge->tm.task_result);
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_result_quality(edge_resource_t* edge, edge_capability_t* cap, const tm_result_quality_info_t* info)
{
    LOG_INFO("Updating Edge %s capability %s TM result_quality (good=%d): ", edge_info_name(edge), cap->name, info->good);
    beta_dist_print(&cap->tm.result_quality);
    LOG_INFO_(" -> ");

    if (info->good)
    {
        beta_dist_add_good(&cap->tm.result_quality);
    }
    else
    {
        beta_dist_add_bad(&cap->tm.result_quality);
    }

    beta_dist_print(&cap->tm.result_quality);
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_task_throughput(edge_resource_t* edge, edge_capability_t* cap, const tm_throughput_info_t* info)
{
    capability_t* global_cap = capability_info_find(cap->name);
    if (global_cap == NULL)
    {
        LOG_ERR("Failed to find per-capability trust information for %s\n", cap->name);
    }

    const float p1 = goodness_pge_local(edge, cap);
    const float p2 = goodness_plt_global(edge, cap, global_cap);

    // Don't start excluding edges for the first few tasks
    // It takes time to build up the distributions appropriately
    if (cap->tm.throughput_in.count >= THROUGHPUT_EXCLUSION_THRESHOLD &&
        cap->tm.throughput_out.count >= THROUGHPUT_EXCLUSION_THRESHOLD)
    {
        if (p1 <= THROUGHPUT_LOCAL_LOWER && p2 < THROUGHPUT_GLOBAL_ACCEPTABLE)
        {
            LOG_INFO("Goodness of throughput = %f, goodness p2 = %f, setting to bad\n", p1, p2);
            cap->tm.throughput_good = false;
            cap->tm.throughput_last_became_bad = clock_time();
        }

        if (p1 >= THROUGHPUT_LOCAL_HIGHER && p2 >= THROUGHPUT_GLOBAL_ACCEPTABLE)
        {
            const bool was_bad = !cap->tm.throughput_good;

            LOG_INFO("Goodness of throughput = %f, goodness p2 = %f, setting to good\n", p1, p2);
            cap->tm.throughput_good = true;

            if (was_bad)
            {
                const clock_time_t time_between_change = clock_time() - cap->tm.throughput_last_became_bad;

                LOG_INFO("Revised throughput_goodness_change from ");
                exponential_dist_print(&cap->tm.throughput_goodness_change);

                // Update the time between changes
                exponential_dist_mle_update(
                    &cap->tm.throughput_goodness_change,
                    time_between_change);

                LOG_INFO_(" to ");
                exponential_dist_print(&cap->tm.throughput_goodness_change);
                LOG_INFO_(" [time_between_change=%"PRIu32"]\n", time_between_change);
            }
        }
    }
    else
    {
        LOG_INFO("Goodness of throughput = %f, goodness p2 = %f, not changing goodness\n", p1, p2);
    }

    if (info->direction == TM_THROUGHPUT_IN)
    {
        LOG_INFO("Updating Edge %s capability %s TM throughput in (%" PRIu32 " bytes/second): ",
        edge_info_name(edge), cap->name, info->throughput);
        gaussian_dist_print(&cap->tm.throughput_in);
        LOG_INFO_(" ewma:");
        gaussian_dist_print(&cap->tm.throughput_in_ewma);
        LOG_INFO_(" -> ");

        gaussian_dist_update(&cap->tm.throughput_in, info->throughput);
        gaussian_dist_update_ewma(&cap->tm.throughput_in_ewma, info->throughput, THROUGHPUT_EWMA_WEIGHT);

        gaussian_dist_print(&cap->tm.throughput_in);
        LOG_INFO_(" ewma:");
        gaussian_dist_print(&cap->tm.throughput_in_ewma);
        LOG_INFO_("\n");

        if (global_cap)
        {
            LOG_INFO("Updating Global capability %s TM throughput in (%" PRIu32 " bytes/second): ",
            global_cap->name, info->throughput);
            gaussian_dist_print(&global_cap->tm.throughput_in);
            LOG_INFO_(" -> ");
            gaussian_dist_update(&global_cap->tm.throughput_in, info->throughput);
            gaussian_dist_print(&global_cap->tm.throughput_in);
            LOG_INFO_("\n");
        }
    }
    else if (info->direction == TM_THROUGHPUT_OUT)
    {
        LOG_INFO("Updating Edge %s capability %s TM throughput out (%" PRIu32 " bytes/second): ",
        edge_info_name(edge), cap->name, info->throughput);
        gaussian_dist_print(&cap->tm.throughput_out);
        LOG_INFO_(" ewma:");
        gaussian_dist_print(&cap->tm.throughput_out_ewma);
        LOG_INFO_(" -> ");

        gaussian_dist_update(&cap->tm.throughput_out, info->throughput);
        gaussian_dist_update_ewma(&cap->tm.throughput_out_ewma, info->throughput, THROUGHPUT_EWMA_WEIGHT);

        gaussian_dist_print(&cap->tm.throughput_out);
        LOG_INFO_(" ewma:");
        gaussian_dist_print(&cap->tm.throughput_out_ewma);
        LOG_INFO_("\n");

        if (global_cap)
        {
            LOG_INFO("Updating Global capability %s TM throughput out (%" PRIu32 " bytes/second): ",
            global_cap->name, info->throughput);
            gaussian_dist_print(&global_cap->tm.throughput_out);
            LOG_INFO_(" -> ");
            gaussian_dist_update(&global_cap->tm.throughput_out, info->throughput);
            gaussian_dist_print(&global_cap->tm.throughput_out);
            LOG_INFO_("\n");
        }
    }
    else
    {
        LOG_ERR("Unknown throughput direction\n");
    }
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
bool edge_capability_is_good(struct edge_resource* edge, struct edge_capability* capability)
{
    if (capability->tm.throughput_good)
    {
        return true;
    }

    // Currently bad, might be time to reconsider the edge?

    // How much time has past since becoming bad
    const clock_time_t time_between_change = clock_time() - capability->tm.throughput_last_became_bad;

    // What is the likelihood we have become good again?
    // May still be bad, but could be worth trying this edge node again
    const float cdf = exponential_dist_cdf(
        &capability->tm.throughput_goodness_change,
        time_between_change);

    LOG_INFO("Considering if bad Edge %s Capability %s has become good. Time between change = %" PRIu32 "s. Pr(TBC > X) = %f",
        edge_info_name(edge), capability->name,
        time_between_change / CLOCK_SECOND,
        cdf);

    return cdf >= EXPECTED_TIME_THROUGHPUT_BAD_TO_GOOD_PR;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_resource(nanocbor_encoder_t* enc, const edge_resource_tm_t* edge)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 2));
    NANOCBOR_CHECK(dist_serialise(enc, &edge->task_submission));
    NANOCBOR_CHECK(dist_serialise(enc, &edge->task_result));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_capability(nanocbor_encoder_t* enc, const edge_capability_tm_t* cap)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 3));
    NANOCBOR_CHECK(dist_serialise(enc, &cap->result_quality));
    NANOCBOR_CHECK(dist_serialise(enc, &cap->throughput_in));
    NANOCBOR_CHECK(dist_serialise(enc, &cap->throughput_out));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust_edge_resource(nanocbor_value_t* dec, edge_resource_tm_t* edge)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));
    NANOCBOR_CHECK(dist_deserialise(&arr, &edge->task_submission));
    NANOCBOR_CHECK(dist_deserialise(&arr, &edge->task_result));

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
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));
    NANOCBOR_CHECK(dist_deserialise(&arr, &cap->result_quality));
    NANOCBOR_CHECK(dist_deserialise(&arr, &cap->throughput_in));
    NANOCBOR_CHECK(dist_deserialise(&arr, &cap->throughput_out));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
