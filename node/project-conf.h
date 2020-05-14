#pragma once

// Disable Low Power Mode 2 to enable access to all them RAM
// See: https://github.com/contiki-ng/contiki-ng/wiki/Platform-zoul#low-power-modes
#define LPM_CONF_MAX_PM 1

#define LOG_CONF_LEVEL_COAP LOG_LEVEL_WARN

#define UIP_CONF_UDP_CONNS 4
#define QUEUEBUF_CONF_NUM 4
#define NBR_TABLE_CONF_MAX_NEIGHBORS 6
#define NETSTACK_MAX_ROUTE_ENTRIES 6

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


#define COAP_DTLS_PSK_DEFAULT_IDENTITY "username"
#define COAP_DTLS_PSK_DEFAULT_KEY "password"

#define COAP_MAX_CHUNK_SIZE 256
