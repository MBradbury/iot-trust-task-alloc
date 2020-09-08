#include "monitoring.h"
#include "application-serial.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"

#include "nanocbor/nanocbor.h"

#include "edge.h"
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
PROCESS(monitoring_process, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
res_coap_envmon_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

// TODO: See RFC6690 Section 3.1 for what to set rt to
// https://tools.ietf.org/html/rfc6690#section-3.1
static
RESOURCE(res_coap,
         "title=\"Environment Monitoring\";rt=\"" MONITORING_APPLICATION_NAME "\"",
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

    LOG_DBG("Received envmon data uri=%.*s, payload_len=%d from ", uri_len, uri_path, payload_len);
    LOG_DBG_COAP_EP(request->src_ep);
    LOG_DBG_("\n");

    // Send data to connected edge node for processing
    printf(APPLICATION_SERIAL_PREFIX MONITORING_APPLICATION_NAME SERIAL_SEP);
    uiplib_ipaddr_print(&request->src_ep->ipaddr);
    printf(SERIAL_SEP "%u" SERIAL_SEP, payload_len);
    for (int i = 0; i != payload_len; ++i)
    {
        printf("%02X", payload[i]);
    }
    printf("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    coap_activate_resource(&res_coap, MONITORING_APPLICATION_URI);

#ifdef WITH_OSCORE
    oscore_protect_resource(&res_coap);
#endif

    init_trust_weights_monitoring();
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(monitoring_process, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == pe_data_from_resource_rich_node)
        {
            //LOG_INFO("Received pe_data_from_resource_rich_node %s\n", (const char*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
