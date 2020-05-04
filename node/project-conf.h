#pragma once

//#define LOG_CONF_LEVEL_COAP                        LOG_LEVEL_DBG

//#define UIP_CONF_UDP_CONNS 4

// Use MQTT Version 3.1.1
//#define MQTT_CONF_VERSION MQTT_PROTOCOL_VERSION_3_1_1

// This is the address of the observer node connected to the border router
#define MQTT_CLIENT_CONF_BROKER_IP_ADDR "fd00::1"

/*
 * The Organisation ID.
 *
 * When in Watson mode, the example will default to Org ID "quickstart" and
 * will connect using non-authenticated mode. If you want to use registered
 * devices, set your Org ID here and then make sure you set the correct token
 * through MQTT_CLIENT_CONF_AUTH_TOKEN.
 */
#ifndef MQTT_CLIENT_CONF_ORG_ID
#define MQTT_CLIENT_CONF_ORG_ID "quickstart"
#endif

/*
 * The MQTT username.
 *
 * Ignored in Watson mode: In this mode the username is always "use-token-auth"
 */
#define MQTT_CLIENT_CONF_USERNAME "mqtt-client-username"

/*
 * The MQTT auth token (password) used when connecting to the MQTT broker.
 *
 * Used with as well as without Watson.
 *
 * Transported in cleartext!
 */
#define MQTT_CLIENT_CONF_AUTH_TOKEN "AUTHTOKEN"
