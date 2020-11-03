#include "application-common.h"
#include "applications.h"

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
