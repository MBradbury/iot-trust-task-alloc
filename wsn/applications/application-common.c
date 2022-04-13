#include "application-common.h"
#include "applications.h"

#include <math.h>

#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "apps"
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
void app_state_init(app_state_t* state, const char* name, const char* uri)
{
    state->running = false;
    state->name = name;
    state->uri = uri;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool app_state_edge_capability_add(app_state_t* state, edge_resource_t* edge)
{
    LOG_INFO("Notified of edge ");
    LOG_INFO_6ADDR(&edge->ep.ipaddr);
    LOG_INFO_(" capability %s\n", state->name);

    const bool prev_running = state->running;

    state->running = edge_info_has_active_capability(state->name);

    edge_capability_add_common(edge);

    // Did we start?
    return !prev_running && state->running;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool app_state_edge_capability_remove(app_state_t* state, edge_resource_t* edge)
{
    LOG_INFO("Notified edge ");
    LOG_INFO_6ADDR(&edge->ep.ipaddr);
    LOG_INFO_(" no longer has capability %s\n", state->name);

    const bool prev_running = state->running;

    state->running = edge_info_has_active_capability(state->name);

    edge_capability_remove_common(edge);

    // Did we stop?
    return prev_running && !state->running;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void app_state_throughput_start_out(app_state_t* state, size_t len)
{
#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    state->out_time = clock_time();
    state->out_len = len;
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
uint32_t app_state_throughput_end_out(app_state_t* state, clock_time_t now)
{
#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    const clock_time_t time_taken = now - state->out_time;

    const float time_taken_sec = time_taken / (float)CLOCK_SECOND;
    const float throughput_bytes_per_sec = state->out_len / time_taken_sec;

    return (uint32_t)ceilf(throughput_bytes_per_sec);
#else
    return 0;
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
void app_state_throughput_start_in(app_state_t* state, size_t len)
{
#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    state->in_time = clock_time();
    state->in_len = len;
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
void app_state_throughput_update_in(app_state_t* state, size_t len)
{
#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    state->in_len += len;
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
uint32_t app_state_throughput_end_in(app_state_t* state, clock_time_t now)
{
#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    const clock_time_t time_taken = now - state->in_time;

    const float time_taken_sec = time_taken / (float)CLOCK_SECOND;
    const float throughput_bytes_per_sec = state->in_len / time_taken_sec;

    return (uint32_t)ceilf(throughput_bytes_per_sec);
#else
    return 0;
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
