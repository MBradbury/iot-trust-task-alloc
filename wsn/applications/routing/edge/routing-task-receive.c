#include "edge-routing.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-log.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#endif

#include "nanocbor-helper.h"

#include "application-serial.h"
#include "serial-helpers.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" ROUTING_APPLICATION_NAME
#ifdef APP_ROUTING_LOG_LEVEL
#define LOG_LEVEL APP_ROUTING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
extern routing_stats_t routing_stats;
/*-------------------------------------------------------------------------------------------------------------------*/
static int
format_result_stats(uint8_t* buffer, size_t len)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buffer, len);

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 4));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, routing_stats.mean));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, routing_stats.maximum));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, routing_stats.minimum));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, routing_stats.variance));

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
format_nil_stats(uint8_t* buffer, size_t len)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buffer, len);

    NANOCBOR_CHECK(nanocbor_fmt_null(&enc));

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

// TODO: See RFC6690 Section 3.1 for what to set rt to
// https://tools.ietf.org/html/rfc6690#section-3.1
static
RESOURCE(res_coap,
         "title=\"Routing\";rt=\"" ROUTING_APPLICATION_NAME "\"",
         NULL,                         /*GET*/
         post_handler,                 /*POST*/
         NULL,                         /*PUT*/
         NULL                          /*DELETE*/);

static uint8_t response_buffer[(1) + (1 + 4)*4];

static void
post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    const char* uri_path;
    int uri_len = coap_get_header_uri_path(request, &uri_path);

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received envmon data uri=%.*s, payload_len=%d from ", uri_len, uri_path, payload_len);
    LOG_DBG_COAP_EP(request->src_ep);
    LOG_DBG_("\n");

    // Send data to connected edge node for processing
    printf(APPLICATION_SERIAL_PREFIX ROUTING_APPLICATION_NAME SERIAL_SEP);
    uiplib_ipaddr_print(&request->src_ep->ipaddr);
    printf(SERIAL_SEP "%u" SERIAL_SEP, payload_len);
    for (int i = 0; i != payload_len; ++i)
    {
        printf("%02X", payload[i]);
    }
    printf("\n");

    // TODO: need to implement some sort of ack feature

    // Set response - the stats of how long jobs might take
    int len = format_result_stats(response_buffer, sizeof(response_buffer));
    if (len <= 0)
    {
        LOG_ERR("Failed to include job stats in response\n");
        len = format_nil_stats(response_buffer, sizeof(response_buffer));
    }

    if (len >= 0)
    {
        coap_set_header_content_format(response, APPLICATION_CBOR);
        coap_set_payload(response, response_buffer, len);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
routing_taskrecv_init(void)
{
    coap_activate_resource(&res_coap, ROUTING_APPLICATION_URI);

#ifdef WITH_OSCORE
    oscore_protect_resource(&res_coap);
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
