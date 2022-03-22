#pragma once

#include <stdbool.h>

#include "edge-info.h"
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    const char* name;
    const char* uri;

    bool running;

#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    clock_time_t out_time;
    size_t out_len;

    clock_time_t in_time;
    size_t in_len;
#endif

} app_state_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void app_state_init(app_state_t* state, const char* name, const char* uri);
/*-------------------------------------------------------------------------------------------------------------------*/
bool app_state_edge_capability_add(app_state_t* state, edge_resource_t* edge);
bool app_state_edge_capability_remove(app_state_t* state, edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
// Throughput is measured in bytes per clock ticks
// One second is CLOCK_SECOND ticks (defaults to 32)
void app_state_throughput_start_out(app_state_t* state, size_t len);
uint32_t app_state_throughput_end_out(app_state_t* state);
void app_state_throughput_start_in(app_state_t* state, size_t len);
void app_state_throughput_update_in(app_state_t* state, size_t len);
uint32_t app_state_throughput_end_in(app_state_t* state);
/*-------------------------------------------------------------------------------------------------------------------*/
