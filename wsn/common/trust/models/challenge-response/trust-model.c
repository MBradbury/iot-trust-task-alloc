#include "trust-model.h"
#include "trust-models.h"
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
    tm->bad = false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_print(const edge_resource_tm_t* tm)
{
    printf("EdgeResourceTM(");
    printf("epoch=%" PRIu32 ",", tm->epoch_number);
    printf("bad=%d", tm->bad);
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
bool edge_is_good(edge_resource_t* edge)
{
    return !edge->tm.bad;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_challenge_response(edge_resource_t* edge, const tm_challenge_response_info_t* info)
{
    bool should_update;
    const bool good = tm_challenge_response_good(info, &should_update);

    if (should_update)
    {
        LOG_INFO("Updating Edge %s TM cr (type=%d,good=%d): ",
            edge_info_name(edge), info->type, good);
        edge_resource_tm_print(&edge->tm);
        LOG_INFO_(" -> ");

        if (good)
        {
            if (edge->tm.bad)
            {
                edge->tm.epoch_number += 1;
                edge->tm.bad = false;
            }
        }
        else
        {
            if (!edge->tm.bad)
            {
                edge->tm.epoch_number += 1;
                edge->tm.bad = true;
            }
        }

        edge_resource_tm_print(&edge->tm);
        LOG_INFO_("\n");
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_resource(nanocbor_encoder_t* enc, const edge_resource_tm_t* edge)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 2));
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, edge->epoch_number));
    NANOCBOR_CHECK(nanocbor_fmt_bool(enc, edge->bad));

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
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &edge->epoch_number));
    NANOCBOR_CHECK(nanocbor_get_bool(&arr, &edge->bad));

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
