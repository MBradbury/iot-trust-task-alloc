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
ack_serial_input(void)
{
    printf(APPLICATION_SERIAL_PREFIX ROUTING_APPLICATION_NAME SERIAL_SEP "ack\n");
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
static coap_message_t msg;
static coap_endpoint_t ep;
static coap_callback_request_state_t coap_callback;
static bool coap_callback_in_use;
static uint8_t msg_buf[COAP_MAX_CHUNK_SIZE];
/*-------------------------------------------------------------------------------------------------------------------*/
static void
send_callback(coap_callback_request_state_t* callback_state)
{
    switch (callback_state->state.status)
    {
    case COAP_REQUEST_STATUS_RESPONSE:
    {
        coap_message_t* response = callback_state->state.response;

        if (response->code == CONTENT_2_05)
        {
            LOG_DBG("Message send complete with code CONTENT_2_05 (len=%d)\n", response->payload_len);
        }
        else
        {
            LOG_WARN("Message send failed with code (%u) '%.*s' (len=%d)\n",
                response->code, response->payload_len, response->payload, response->payload_len);
        }
    } break;

    case COAP_REQUEST_STATUS_MORE:
    {
        LOG_ERR("Unhandled COAP_REQUEST_STATUS_MORE\n");
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        coap_callback_in_use = false;

        // Once the send is finished we need to ack, so if there is more data to send the
        // resource rich application will now send this data to us.
        ack_serial_input();
    } break;

    case COAP_REQUEST_STATUS_TIMEOUT:
    {
        LOG_ERR("Failed to send message with status %d (timeout)\n", callback_state->state.status);
        coap_callback_in_use = false;
    } break;

    case COAP_REQUEST_STATUS_BLOCK_ERROR:
    {
        LOG_ERR("Failed to send message with status %d (block error)\n", callback_state->state.status);
        coap_callback_in_use = false;
    } break;

    default:
    {
        LOG_ERR("Failed to send message with status %d\n", callback_state->state.status);
        coap_callback_in_use = false;
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
process_task_resp_send_status(pyroutelib3_status_t status)
{
    if (coap_callback_in_use)
    {
        return -1;
    }

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, msg_buf, sizeof(msg_buf));

    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, status));

    int ret;

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, ROUTING_APPLICATION_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, nanocbor_encoded_len(&enc));

    ret = coap_send_request(&coap_callback, &ep, &msg, send_callback);
    if (ret)
    {
        coap_callback_in_use = true;
        LOG_DBG("Message sent to ");
        LOG_DBG_COAP_EP(&ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
process_task_resp_send_success(unsigned long i, unsigned long n, size_t len)
{
    if (coap_callback_in_use)
    {
        return -1;
    }

    int ret;

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, ROUTING_APPLICATION_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, len);

    // i starts at 0
    const bool coap_block1_more = ((i + 1) != n);

    ret = coap_set_header_block1(&msg, i, coap_block1_more, len);
    if (!ret)
    {
        LOG_ERR("coap_set_header_block1 failed (%lu, %" PRIu8 ", %zu)\n", i, coap_block1_more, len);
    }

    ret = coap_send_request(&coap_callback, &ep, &msg, send_callback);
    if (ret)
    {
        coap_callback_in_use = true;
        LOG_DBG("Message sent to ");
        LOG_DBG_COAP_EP(&ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }

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

    if (!uiplib_ip6addrconv(uip_buffer, &ep.ipaddr))
    {
        LOG_ERR("uiplib_ip6addrconv 2\n");
        return;
    }

    ep.secure = 0;
    ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    const unsigned long n = strtoul(sep1+1, NULL, 10);

    const pyroutelib3_status_t status = (pyroutelib3_status_t)strtoul(sep2+1, NULL, 10);

    LOG_INFO("Task response: result=%d n=%lu target=", status, n);
    LOG_INFO_6ADDR(&ep.ipaddr);
    LOG_INFO_("\n");

    process_task_resp_send_status(status);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
process_task_resp2(const char* data, const char* data_end)
{
    if (coap_callback_in_use)
    {
        return -1;
    }

    // <i>/<n>|<message>

    const char* slashpos = strchr(data, '/');
    if (slashpos == NULL)
    {
        LOG_ERR("strchr 1\n");
        return -1;
    }

    const char* seppos = strchr(data, '|');
    if (seppos == NULL)
    {
        LOG_ERR("strchr 2\n");
        return -1;
    }

    unsigned long i = strtoul(data, NULL, 10);
    unsigned long n = strtoul(slashpos+1, NULL, 10);

    size_t len = sizeof(msg_buf);
    if (!base64_decode(seppos+1, data_end - (seppos+1), msg_buf, &len))
    {
        LOG_ERR("base64_decode 3 (ret=%d)\n", len);
        return -1;
    }

    LOG_DBG("Sending task response %lu/%lu of length %zu\n", i, n, len);

    // Send the buffer back to the target node
    // Use block1 to send the data in multiple packets
    process_task_resp_send_success(i, n, len);

    return 0;
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
    }
    else if (match_action(data, data_end, "resp2" SERIAL_SEP))
    {
        data += strlen("resp2" SERIAL_SEP);
        process_task_resp2(data, data_end);
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

    coap_callback_in_use = false;
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
