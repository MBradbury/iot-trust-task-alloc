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
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_add_common(edge_resource_t* edge, const char* uri);
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_remove_common(edge_resource_t* edge, const char* uri);
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
int format_application_stats(const application_stats_t* application_stats, uint8_t* buffer, size_t len);
int format_nil_application_stats(uint8_t* buffer, size_t len);
/*-------------------------------------------------------------------------------------------------------------------*/
int get_application_stats(nanocbor_value_t* dec, application_stats_t* application_stats);
/*-------------------------------------------------------------------------------------------------------------------*/
