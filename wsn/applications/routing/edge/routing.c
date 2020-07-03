#include "routing.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"

#include "nanocbor-helper.h"

#include "edge.h"
#include "keystore.h"
#include "application-serial.h"
#include "serial-helpers.h"
#include "base64.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#endif

#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" ROUTING_APPLICATION_NAME
#ifdef APP_ROUTING_LOG_LEVEL
#define LOG_LEVEL APP_ROUTING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static uint32_t mean, maximum, minimum, variance;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(routing_process, ROUTING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
static int
format_result_stats(uint8_t* buffer, size_t len)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buffer, len);

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 4));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, mean));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, maximum));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, minimum));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, variance));

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
res_coap_envmon_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

// TODO: See RFC6690 Section 3.1 for what to set rt to
// https://tools.ietf.org/html/rfc6690#section-3.1
static
RESOURCE(res_coap,
         "title=\"Routing\";rt=\"" ROUTING_APPLICATION_NAME "\"",
         NULL,                         /*GET*/
         res_coap_envmon_post_handler, /*POST*/
         NULL,                         /*PUT*/
         NULL                          /*DELETE*/);

static uint8_t response_buffer[(1) + (1 + 4)*4];

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
    printf(APPLICATION_SERIAL_PREFIX ROUTING_APPLICATION_NAME SERIAL_SEP);
    uiplib_ipaddr_print(&request->src_ep->ipaddr);
    printf(SERIAL_SEP "%u" SERIAL_SEP, payload_len);
    for (int i = 0; i != payload_len; ++i)
    {
        printf("%02X", payload[i]);
    }
    printf("\n");

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
static int
process_task_stats(const char* data, const char* data_end)
{
    uint32_t scn_mean, scn_max, scn_min, scn_var;

    uint8_t buffer[(1) + (1 + 4)*4];
    size_t buffer_len = sizeof(buffer);
    if (!base64_decode(data, data_end - data, buffer, &buffer_len))
    {
        LOG_ERR("!base64_decode 1\n");
        return -1;
    }

    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, buffer, buffer_len);

    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&dec, &arr));

    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &scn_mean));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &scn_max));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &scn_min));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &scn_var));

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_leave_container 2\n");
        return -1;
    }

    nanocbor_leave_container(&dec, &arr);

    if (!nanocbor_at_end(&dec))
    {
        LOG_ERR("!nanocbor_leave_container 3\n");
        return -1;
    }

    LOG_DBG("Updated routing stats: "
            "mean %"PRIu32" -> %"PRIu32", "
            "min %"PRIu32" -> %"PRIu32", "
            "max %"PRIu32" -> %"PRIu32", "
            "var %"PRIu32" -> %"PRIu32"\n",
            mean, scn_mean,
            minimum, scn_min,
            maximum, scn_max,
            variance, scn_var);

    mean = scn_mean;
    minimum = scn_min;
    maximum = scn_max;
    variance = scn_var;

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_task_resp1(const char* data, const char* data_end)
{
    // <target>|<n>|<status>

    const char* sep1 = strchr(data, '|');
    if (sep1 == NULL)
    {
        LOG_ERR("strchr 1\n");
        return;
    }

    const char* sep2 = strchr(sep1+1, '|');
    if (sep2 == NULL)
    {
        LOG_ERR("strchr 2\n");
        return;
    }

    char uip_buffer[UIPLIB_IPV6_MAX_STR_LEN];
    memset(uip_buffer, 0, sizeof(uip_buffer));
    strncpy(uip_buffer, data, sep1 - data);

    uip_ip6addr_t addr;
    if (!uiplib_ip6addrconv(uip_buffer, &addr))
    {
        LOG_ERR("uiplib_ip6addrconv 2\n");
        return;
    }

    unsigned long n = strtoul(sep1+1, NULL, 10);

    unsigned long status = strtoul(sep2+1, NULL, 10);

    LOG_INFO("Task response: result=%lu n=%lu target=", status, n);
    LOG_INFO_6ADDR(&addr);
    LOG_INFO_("\n");

    // TODO: include somewhere if we are going to process this message
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_task_resp2(const char* data, const char* data_end)
{
    // <i>/<n>|<message>

    const char* slashpos = strchr(data, '/');
    if (slashpos == NULL)
    {
        LOG_ERR("strchr 1\n");
        return;
    }

    const char* seppos = strchr(data, '|');
    if (seppos == NULL)
    {
        LOG_ERR("strchr 2\n");
        return;
    }

    unsigned long i = strtoul(data, NULL, 10);
    unsigned long n = strtoul(slashpos+1, NULL, 10);

    uint8_t buffer[COAP_MAX_CHUNK_SIZE];
    size_t len = sizeof(buffer);
    if (!base64_decode(seppos+1, data_end - (seppos+1), buffer, &len))
    {
        LOG_ERR("base64_decode 3 (ret=%d)\n", len);
        return;
    }

    LOG_WARN("Sending task response %lu/%lu of length %zu not yet implemented\n", i, n, len);

    // TODO: send the buffer back to the target node
    // TODO: want to use block1 to send the data in multiple packets
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
ack_serial_input(void)
{
    printf(APPLICATION_SERIAL_PREFIX ROUTING_APPLICATION_NAME SERIAL_SEP "ack\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_serial_input(const char* data)
{
    const char* data_end = data + strlen(data);

    if (!match_action(data, data_end, SERIAL_SEP))
    {
        return;
    }
    data += strlen(SERIAL_SEP);

    if (match_action(data, data_end, "stats" SERIAL_SEP))
    {
        data += strlen("stats" SERIAL_SEP);
        process_task_stats(data, data_end);
        ack_serial_input();
    }
    else if (match_action(data, data_end, "resp1" SERIAL_SEP))
    {
        data += strlen("resp1" SERIAL_SEP);
        process_task_resp1(data, data_end);
        ack_serial_input();
    }
    else if (match_action(data, data_end, "resp2" SERIAL_SEP))
    {
        data += strlen("resp2" SERIAL_SEP);
        process_task_resp2(data, data_end);
        ack_serial_input();
    }
    else
    {
        LOG_ERR("Unknown action '%s'\n", data);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    coap_activate_resource(&res_coap, ROUTING_APPLICATION_URI);

#ifdef WITH_OSCORE
    oscore_protect_resource(&res_coap);
#endif

    init_trust_weights_routing();

    // Set to a default value
    mean = minimum = maximum = variance = 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(routing_process, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == pe_data_from_resource_rich_node)
        {
            LOG_INFO("Received pe_data_from_resource_rich_node %s\n", (const char*)data);
            process_serial_input((const char*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
