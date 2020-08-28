#include "trust-model.h"
#include "trust-models.h"
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
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_print(const edge_resource_tm_t* tm)
{
    printf("EdgeResourceTM()");
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
