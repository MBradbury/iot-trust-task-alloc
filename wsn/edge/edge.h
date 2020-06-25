#pragma once

#include "contiki.h"
/*-------------------------------------------------------------------------------------------------------------------*/
extern const char* const application_names[APPLICATION_NUM];
extern bool applications_available[APPLICATION_NUM];
/*-------------------------------------------------------------------------------------------------------------------*/
extern bool resource_rich_edge_started;
/*-------------------------------------------------------------------------------------------------------------------*/
// Process event that is sent to relevant applications when
// application data is received over the serial line
extern process_event_t pe_data_from_resource_rich_node;
/*-------------------------------------------------------------------------------------------------------------------*/
bool application_available(const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
