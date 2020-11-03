#pragma once

#include "contiki.h"

#include "edge-info.h"

#include "nanocbor/nanocbor.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define APPLICATION_NAME_MAX_LEN 8
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef APPLICATION_MONITORING
#include "monitoring.h"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef APPLICATION_ROUTING
#include "routing.h"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef APPLICATION_CHALLENGE_RESPONSE
#include "challenge-response.h"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
struct process* find_process_with_name(const char* name);
struct process* find_process_for_capability(const edge_capability_t* cap);
/*-------------------------------------------------------------------------------------------------------------------*/
void post_to_capability_process(const edge_capability_t* cap, process_event_t pe, void* data);
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_add_common(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_remove_common(edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    uint32_t mean;
    uint32_t maximum;
    uint32_t minimum;
    uint32_t variance;
} application_stats_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void application_stats_init(application_stats_t* application_stats);
/*-------------------------------------------------------------------------------------------------------------------*/
#define APPLICATION_STATS_MAX_CBOR_LENGTH ((1) + (1 + 4)*4)

int application_stats_serialise(const application_stats_t* application_stats, uint8_t* buffer, size_t len);
int application_stats_nil_serialise(uint8_t* buffer, size_t len);
/*-------------------------------------------------------------------------------------------------------------------*/
int application_stats_deserialise(nanocbor_value_t* dec, application_stats_t* application_stats);
/*-------------------------------------------------------------------------------------------------------------------*/
