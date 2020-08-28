#pragma once

// Disable Low Power Mode 2 to enable access to all them RAM
// See: https://github.com/contiki-ng/contiki-ng/wiki/Platform-zoul#low-power-modes
#define LPM_CONF_MAX_PM 1

#define LOG_CONF_LEVEL_COAP LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_OSCORE LOG_LEVEL_INFO

// This is the address of the observer node connected to the border router
#define MQTT_CLIENT_CONF_BROKER_IP_ADDR "fd00::1"

#define COAP_MAX_CHUNK_SIZE 256

// Enable coloured log prefix
#define LOG_CONF_WITH_COLOR 1
