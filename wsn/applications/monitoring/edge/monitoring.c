#include "monitoring.h"
#include "application-serial.h"
#include "trust/trust.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "serial-line.h"

#include "coap.h"
#include "coap-callback-api.h"

#include "keystore.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#endif

#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" MONITORING_APPLICATION_NAME
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(environment_monitoring, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
res_coap_envmon_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

// TODO: See RFC6690 Section 3.1 for what to set rt to
// https://tools.ietf.org/html/rfc6690#section-3.1
RESOURCE(res_coap_envmon,
         "title=\"Environment Monitoring\";rt=\"envmon\"",
         NULL,                         /*GET*/
         res_coap_envmon_post_handler, /*POST*/
         NULL,                         /*PUT*/
         NULL                          /*DELETE*/);

static void
res_coap_envmon_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    const char* uri_path;
    int uri_len = coap_get_header_uri_path(request, &uri_path);

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received envmon data uri=%.*s, payload=%.*s from ", uri_len, uri_path, payload_len, (const char*)payload);
    coap_endpoint_log(request->src_ep);
    LOG_DBG_("\n");

    // Send data to connected edge node for processing
    printf(APPLICATION_SERIAL_PREFIX MONITORING_APPLICATION_NAME ":%u:%.*s\n", payload_len, payload_len, (const char*)payload);
}
/*-------------------------------------------------------------------------------------------------------------------*/
#define START_MESSAGE "start"
#define STOP_MESSAGE "stop"
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_serial_message(const char* data)
{
    const char* const data_end = data + strlen(data);

    LOG_DBG("Received serial message %s of length %u\n", data, data_end - data);

    // Check that the input is from the edge
    if (data_end - data < strlen(APPLICATION_SERIAL_PREFIX) ||
        strncmp(APPLICATION_SERIAL_PREFIX, data, strlen(APPLICATION_SERIAL_PREFIX)) != 0)
    {
        LOG_DBG("Serial input is not from edge\n");
        return;
    }

    data += strlen(APPLICATION_SERIAL_PREFIX);

    // Check that the input is for this application
    if (data_end - data < strlen(MONITORING_APPLICATION_NAME) ||
        strncmp(MONITORING_APPLICATION_NAME, data, strlen(MONITORING_APPLICATION_NAME)) != 0)
    {
        LOG_DBG("Serial input is not for the " MONITORING_APPLICATION_NAME " application\n");
        return;
    }

    data += strlen(MONITORING_APPLICATION_NAME);

    if (data_end - data < 1 ||
        *data != ':')
    {
        LOG_DBG("Missing separator\n");
        return;
    }

    data += 1;

    if (data_end - data >= strlen(START_MESSAGE) &&
        strncmp(START_MESSAGE, data, strlen(START_MESSAGE)) == 0)
    {
        LOG_INFO("publishing add capability\n");
        publish_add_capability(MONITORING_APPLICATION_NAME);
    }
    else if (data_end - data >= strlen(STOP_MESSAGE) &&
             strncmp(STOP_MESSAGE, data, strlen(STOP_MESSAGE)) == 0)
    {
        LOG_INFO("publishing remove capability\n");
        publish_remove_capability(MONITORING_APPLICATION_NAME);
    }
    else
    {
        LOG_ERR("Unsure what to do with %.*s\n", data_end - data, data);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    coap_activate_resource(&res_coap_envmon, MONITORING_APPLICATION_URI);

#ifdef WITH_OSCORE
    oscore_protect_resource(&res_coap_envmon);
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(environment_monitoring, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == serial_line_event_message)
        {
            process_serial_message(data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
