#pragma once

#include <stdbool.h>

#include "edge-info.h"
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    const char* name;
    const char* uri;

    bool running;

} app_state_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void app_state_init(app_state_t* state, const char* name, const char* uri);
/*-------------------------------------------------------------------------------------------------------------------*/
bool app_state_edge_capability_add(app_state_t* state, edge_resource_t* edge);
bool app_state_edge_capability_remove(app_state_t* state, edge_resource_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
