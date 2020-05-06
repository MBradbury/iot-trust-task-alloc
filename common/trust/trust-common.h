#pragma once

/*-------------------------------------------------------------------------------------------------------------------*/
#define MQTT_EDGE_NAMESPACE "iot/edge"
#define MQTT_EDGE_NAMESPACE_LEN 8

#define MQTT_IDENTITY_LEN 12

#define EDGE_CAPABILITY_NAME_LEN 15

#define MQTT_EDGE_ACTION_ANNOUNCE "announce"
#define MQTT_EDGE_ACTION_CAPABILITY "capability"
#define MQTT_EDGE_ACTION_CAPABILITY_ADD "add"
#define MQTT_EDGE_ACTION_CAPABILITY_REMOVE "remove"
/*-------------------------------------------------------------------------------------------------------------------*/
void
trust_common_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/