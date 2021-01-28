#pragma once

#include <stdint.h>

#include "edge-info.h"
#include "peer-info.h"

#include "coap-constants.h"
#include "coap-request-state.h"
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    uint16_t id;
    float weight;
} trust_weight_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct trust_weights {
    struct trust_weights* next;

    const char* application_name;
    const trust_weight_t* weights;
    uint8_t num;

} trust_weights_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void trust_weights_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
void trust_weights_add(trust_weights_t* item);
/*-------------------------------------------------------------------------------------------------------------------*/
trust_weights_t* trust_weights_find(const char* application_name);
/*-------------------------------------------------------------------------------------------------------------------*/
float find_trust_weight(const char* application_name, uint16_t id);
/*-------------------------------------------------------------------------------------------------------------------*/
#define TRUST_MODEL_INVALID_TAG UINT32_MAX
/*-------------------------------------------------------------------------------------------------------------------*/
// Trust model configurations
#define TRUST_CONF_REPUTATION_WEIGHT  0001
/*-------------------------------------------------------------------------------------------------------------------*/
// Edge resource metrics
#define TRUST_METRIC_TASK_SUBMISSION  1001
#define TRUST_METRIC_TASK_RESULT      1002
#define TRUST_METRIC_ANNOUNCE         1003
#define TRUST_METRIC_CHALLENGE_RESP   1004
/*-------------------------------------------------------------------------------------------------------------------*/
// Edge capability metrics
#define TRUST_METRIC_RESULT_QUALITY   2001
#define TRUST_METRIC_RESULT_LATENCY   2002
/*-------------------------------------------------------------------------------------------------------------------*/
// Peer metrics
#define TRUST_METRIC_TASK_OBSERVATION 3001
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    coap_status_t coap_status;
    coap_request_status_t coap_request_status;
} tm_task_submission_info_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef enum {
    TM_TASK_RESULT_INFO_SUCCESS = 0,
    TM_TASK_RESULT_INFO_FAIL = 1,
    TM_TASK_RESULT_INFO_TIMEOUT = 2
} tm_task_result_type_t;

typedef struct {
    tm_task_result_type_t result;
} tm_task_result_info_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {

} tm_announce_info_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    bool good;
} tm_result_quality_info_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {

} tm_result_latency_info_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef enum {
    TM_CHALLENGE_RESPONSE_ACK = 0,
    TM_CHALLENGE_RESPONSE_TIMEOUT = 1,
    TM_CHALLENGE_RESPONSE_RESP = 2
} tm_challenge_response_type_t;

typedef struct {
    tm_challenge_response_type_t type;

    union {
        // TM_CHALLENGE_RESPONSE_ACK
        struct {
            coap_status_t coap_status;
            coap_request_status_t coap_request_status;
        };

        // TM_CHALLENGE_RESPONSE_TIMEOUT
        struct {
            bool never_received;
            bool received_late;
        };

        // TM_CHALLENGE_RESPONSE_RESP
        struct {
            bool challenge_successful;
            bool challenge_late;
        };
    };
} tm_challenge_response_info_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {

} tm_task_observation_info_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void tm_update_task_submission(edge_resource_t* edge, edge_capability_t* cap, const tm_task_submission_info_t* info);
void tm_update_task_result(edge_resource_t* edge, edge_capability_t* cap, const tm_task_result_info_t* info);
void tm_update_announce(edge_resource_t* edge, edge_capability_t* cap, const tm_announce_info_t* info);
void tm_update_result_quality(edge_resource_t* edge, edge_capability_t* cap, const tm_result_quality_info_t* info);
void tm_update_result_latency(edge_resource_t* edge, edge_capability_t* cap, const tm_result_latency_info_t* info);
void tm_update_challenge_response(edge_resource_t* edge, const tm_challenge_response_info_t* info);
void tm_update_task_observation(peer_t* peer, const tm_task_observation_info_t* info);
/*-------------------------------------------------------------------------------------------------------------------*/
bool tm_task_submission_good(const tm_task_submission_info_t* info, bool* should_update);
bool tm_challenge_response_good(const tm_challenge_response_info_t* info, bool* should_update);
/*-------------------------------------------------------------------------------------------------------------------*/
