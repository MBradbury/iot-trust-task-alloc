#include "monitoring.h"

#include "contiki.h"
#include "os/sys/log.h"

#include "coap.h"
#include "coap-callback-api.h"

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

  LOG_DBG("Received envmon data uri=%.*s, payload=%.*s\n", uri_len, uri_path, payload_len, (const char*)payload);

  // TODO: set response?
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
	coap_activate_resource(&res_coap_envmon, MONITORING_APPLICATION_URI);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(environment_monitoring, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
