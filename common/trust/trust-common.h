#pragma once

#include <stdint.h>
#include <stddef.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define MQTT_EDGE_NAMESPACE "edge"
#define MQTT_EDGE_NAMESPACE_LEN 4

#define MQTT_IDENTITY_LEN (8 * 2) // Eight two character hex digits

#define EDGE_CAPABILITY_NAME_LEN 15

#define MQTT_EDGE_ACTION_ANNOUNCE "announce"
#define MQTT_EDGE_ACTION_CAPABILITY "capability"
#define MQTT_EDGE_ACTION_CAPABILITY_ADD "add"
#define MQTT_EDGE_ACTION_CAPABILITY_REMOVE "remove"
/*-------------------------------------------------------------------------------------------------------------------*/
void trust_common_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust(void* trust_info, uint8_t* buffer, size_t buffer_len);
int deserialise_trust(void* trust_info, const uint8_t* buffer, size_t buffer_len);
/*-------------------------------------------------------------------------------------------------------------------*/
