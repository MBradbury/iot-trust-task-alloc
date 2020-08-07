#include "trust-model.h"
#include "trust-models.h"
#include "random-helpers.h"
#include <stdio.h>
#include "assert.h"
#include "os/sys/log.h"
#include "os/sys/cc.h"
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
    tm->epoch_number = 0;
    tm->blacklisted = false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_print(const edge_resource_tm_t* tm)
{
    printf("EdgeResourceTM(");
    printf("epoch=%" PRIu32 ",", tm->epoch_number);
    printf("blacklisted=%d", tm->blacklisted);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_init(edge_capability_tm_t* tm)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_print(const edge_capability_tm_t* tm)
{
    printf("EdgeCapTM()");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_init(peer_tm_t* tm)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_print(const peer_tm_t* tm)
{
    printf("PeerTM()");
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* choose_edge(const char* capability_name)
{
    edge_resource_t* candidates[NUM_EDGE_RESOURCES];
    uint8_t candidates_len = 0;

    for (edge_resource_t* iter = edge_info_iter(); iter != NULL; iter = edge_info_next(iter))
    {
        // Make sure the edge has the desired capability
        edge_capability_t* capability = edge_info_capability_find(iter, capability_name);
        if (capability == NULL)
        {
            continue;
        }

        // Can't use this node if it has been blacklisted
        if (iter->tm.blacklisted)
        {
            continue;
        }

        if (candidates_len == CC_ARRAY_SIZE(candidates))
        {
            LOG_WARN("Insufficient memory allocated to candidates\n");
            continue;
        }

        // Record this as a potential candidate
        candidates[candidates_len++] = iter;
    }

    if (candidates_len == 0)
    {
        return NULL;
    }
    else
    {
        uint16_t idx = random_in_range_unbiased(0, candidates_len-1);

        return candidates[idx];
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_challenge_response(edge_resource_t* edge, const tm_challenge_response_info_t* info)
{
    bool should_update = true;
    bool good;

    switch (info->type)
    {
    case TM_CHALLENGE_RESPONSE_ACK:
    {
        // info->coap_status and info->coap_request_status
        good =
            (info->coap_request_status == COAP_REQUEST_STATUS_RESPONSE) &&
            (info->coap_status >= CREATED_2_01 && info->coap_status <= CONTENT_2_05);

        // Only update if we don't get an ack
        // and this is not COAP_REQUEST_STATUS_FINISHED
        should_update = !good && (info->coap_request_status != COAP_REQUEST_STATUS_FINISHED);

    } break;

    case TM_CHALLENGE_RESPONSE_TIMEOUT:
    {
        // Always update on a timeout
        good = !info->never_received && !info->received_late;
    } break;

    case TM_CHALLENGE_RESPONSE_RESP:
    {
        // Always update when a response is received
        good = info->challenge_successful;

        // If challenge_late is set, then we should have already handled TM_CHALLENGE_RESPONSE_TIMEOUT
        // so should not attempt to update the state.
        should_update = !info->challenge_late;
    } break;

    default:
    {
        assert(false);
    } break;
    }

    if (should_update)
    {
        LOG_INFO("Updating Edge %s TM cr (type=%d,good=%d): ",
            edge->name, info->type, good);
        edge_resource_tm_print(&edge->tm);
        LOG_INFO_(" -> ");

        if (good)
        {
            if (edge->tm.blacklisted)
            {
                edge->tm.epoch_number += 1;
                edge->tm.blacklisted = false;
            }
        }
        else
        {
            if (!edge->tm.blacklisted)
            {
                edge->tm.epoch_number += 1;
                edge->tm.blacklisted = true;
            }
        }

        edge_resource_tm_print(&edge->tm);
        LOG_INFO_("\n");
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_resource(nanocbor_encoder_t* enc, const edge_resource_tm_t* edge)
{
    NANOCBOR_CHECK(nanocbor_fmt_null(enc));

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
    NANOCBOR_CHECK(nanocbor_get_null(dec));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust_edge_capability(nanocbor_value_t* dec, edge_capability_tm_t* cap)
{
    NANOCBOR_CHECK(nanocbor_get_null(dec));
    
    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
