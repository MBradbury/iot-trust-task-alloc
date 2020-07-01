#pragma once

#include <stdint.h>

#include "edge-info.h"
#include "peer-info.h"

#include "coap-constants.h"
#include "coap-request-state.h"

#define TRUST_MODEL_BASIC 1
#define TRUST_MODEL_CONTINUOUS 2

typedef struct {
    uint16_t id;
    float weight;
} trust_weight_t;

float find_trust_weight(uint16_t id);

// Edge resource metrics
#define TRUST_METRIC_TASK_SUBMISSION  1001
#define TRUST_METRIC_TASK_RESULT      1002
#define TRUST_METRIC_ANNOUNCE         1003

// Edge capability metrics
#define TRUST_METRIC_RESULT_QUALITY   2001
#define TRUST_METRIC_RESULT_LATENCY   2002

// Peer metrics
#define TRUST_METRIC_TASK_OBSERVATION 3001

typedef struct {
    coap_status_t coap_status;
    coap_request_status_t coap_request_status;
} tm_task_submission_info_t;

typedef struct {

} tm_task_result_info_t;

typedef struct {

} tm_announce_info_t;

typedef struct {

} tm_result_quality_info_t;

typedef struct {

} tm_result_latency_info_t;

typedef struct {

} tm_task_observation_info_t;

void tm_update_task_submission(edge_resource_t* edge, edge_capability_t* cap, const tm_task_submission_info_t* info);
void tm_update_task_result(edge_resource_t* edge, edge_capability_t* cap, const tm_task_result_info_t* info);
void tm_update_announce(edge_resource_t* edge, edge_capability_t* cap, const tm_announce_info_t* info);
void tm_update_result_quality(edge_resource_t* edge, edge_capability_t* cap, const tm_result_quality_info_t* info);
void tm_update_result_latency(edge_resource_t* edge, edge_capability_t* cap, const tm_result_latency_info_t* info);
void tm_update_task_observation(peer_t* peer, const tm_task_observation_info_t* info);
