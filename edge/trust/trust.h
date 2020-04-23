#pragma once

#include "mqtt.h"

#include <stddef.h>

/*-------------------------------------------------------------------------------------------------------------------*/
mqtt_status_t
publish_announce(struct mqtt_connection* conn, char* app_buffer, size_t app_buffer_len);
/*-------------------------------------------------------------------------------------------------------------------*/
mqtt_status_t
publish_add_capability(struct mqtt_connection* conn, char* app_buffer, size_t app_buffer_len, const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
mqtt_status_t
publish_remove_capability(struct mqtt_connection* conn, char* app_buffer, size_t app_buffer_len, const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/