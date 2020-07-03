#pragma once

#include "distributions.h"

#include "nanocbor-helper.h"

struct edge_resource;

/*-------------------------------------------------------------------------------------------------------------------*/
#define HAS_TRUST_METRIC_TASK_SUBMISSION
//#define HAS_TRUST_METRIC_TASK_RESULT
//#define HAS_TRUST_METRIC_ANNOUNCE
// Per-Edge interactions
typedef struct edge_resource_tm {
    // When submitting a task, did the Edge accept it correctly?
    beta_dist_t task_submission;

    // Was a task result received when it was expected
    //beta_dist_t task_result;

    // Are periodic announces being sent as often as expected
    //poisson_observation_t announce;

} edge_resource_tm_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_init(edge_resource_tm_t* tm);
void edge_resource_tm_print(const edge_resource_tm_t* tm);
/*-------------------------------------------------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------------------------------------------------*/
//#define HAS_TRUST_METRIC_RESULT_QUALITY
//#define HAS_TRUST_METRIC_RESULT_LATENCY
// Per-Application of Edge interactions
typedef struct edge_capability_tm {
    // Was the result correct or not (nodes do not have the capability to evaluate response 'goodness')
    //beta_dist_t result_quality;

    // How long did it take to receive a response?
    //beta_dist_t latency;

} edge_capability_tm_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_init(edge_capability_tm_t* tm);
void edge_capability_tm_print(const edge_capability_tm_t* tm);
/*-------------------------------------------------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------------------------------------------------*/
//#define HAS_TRUST_METRIC_TASK_OBSERVATION
typedef struct peer_tm {
    // Did the peer deliver a task observation when it was expected?
    //beta_dist_t task_observation;

} peer_tm_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_init(peer_tm_t* tm);
void peer_tm_print(const peer_tm_t* tm);
/*-------------------------------------------------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------------------------------------------------*/
struct edge_resource* choose_edge(const char* capability_name);
/*-------------------------------------------------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust_edge_resource(nanocbor_encoder_t* enc, const edge_resource_tm_t* edge);
int serialise_trust_edge_capability(nanocbor_encoder_t* enc, const edge_capability_tm_t* cap);
int deserialise_trust_edge_resource(nanocbor_value_t* dec, edge_resource_tm_t* edge);
int deserialise_trust_edge_capability(nanocbor_value_t* dec, edge_capability_tm_t* cap);
/*-------------------------------------------------------------------------------------------------------------------*/
