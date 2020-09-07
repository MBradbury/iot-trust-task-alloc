#include "routing-edge.h"
#include "applications.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#include "keystore-oscore.h"
#endif

#include "nanocbor-helper.h"

#include "application-serial.h"
#include "base64.h"
#include "serial-helpers.h"
#include "timed-unlock.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" ROUTING_APPLICATION_NAME
#ifdef APP_ROUTING_LOG_LEVEL
#define LOG_LEVEL APP_ROUTING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
extern application_stats_t routing_stats;
/*-------------------------------------------------------------------------------------------------------------------*/
static int
process_task_stats(const char* data, const char* data_end)
{
    application_stats_t scn;

    uint8_t buffer[APPLICATION_STATS_MAX_CBOR_LENGTH];
    size_t buffer_len = sizeof(buffer);
    if (!base64_decode(data, data_end - data, buffer, &buffer_len))
    {
        LOG_ERR("!base64_decode 1\n");
        return -1;
    }

    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, buffer, buffer_len);

    NANOCBOR_CHECK(application_stats_deserialise(&dec, &scn));

    if (!nanocbor_at_end(&dec))
    {
        LOG_ERR("!nanocbor_at_end\n");
        return -1;
    }

    LOG_DBG("Updated routing stats: "
            "mean %"PRIu32" -> %"PRIu32", "
            "min %"PRIu32" -> %"PRIu32", "
            "max %"PRIu32" -> %"PRIu32", "
            "var %"PRIu32" -> %"PRIu32"\n",
            routing_stats.mean, scn.mean,
            routing_stats.minimum, scn.minimum,
            routing_stats.maximum, scn.maximum,
            routing_stats.variance, scn.variance);

    routing_stats = scn;

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
ack_serial_input(void)
{
    printf(APPLICATION_SERIAL_PREFIX ROUTING_APPLICATION_NAME SERIAL_SEP "ack\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_endpoint_t ep;
static coap_callback_request_state_t coap_callback;
static timed_unlock_t coap_callback_in_use;
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
        else if (response->code == CONTINUE_2_31)
        {
            LOG_DBG("Message send complete with code CONTINUE_2_31 (len=%d)\n", response->payload_len);
        }
        else
        {
            LOG_WARN("Message send failed with code (%u) '%.*s' (len=%d)\n",
                response->code, response->payload_len, response->payload, response->payload_len);
        }
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        timed_unlock_unlock(&coap_callback_in_use);

        // Once the send is finished we need to ack, so if there is more data to send the
        // resource rich application will now send this data to us.
        ack_serial_input();
    } break;

    default:
    {
        LOG_ERR("Failed to send message due to %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        timed_unlock_unlock(&coap_callback_in_use);
        ack_serial_input();
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
process_task_resp_send_status(pyroutelib3_status_t status)
{
    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_ERR("CoAP coallback in use so cannot send task response\n");
        return false;
    }

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, msg_buf, sizeof(msg_buf));

    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, status));

    int ret;

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, ROUTING_APPLICATION_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, nanocbor_encoded_len(&enc));

    coap_set_random_token(&msg);

#ifdef WITH_OSCORE
    keystore_protect_coap_with_oscore(&msg, &ep);
#endif

    ret = coap_send_request(&coap_callback, &ep, &msg, send_callback);
    if (ret)
    {
        timed_unlock_lock(&coap_callback_in_use);
        LOG_DBG("Message sent to ");
        LOG_DBG_COAP_EP(&ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }

    return ret != 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
process_task_resp_send_success(unsigned long i, unsigned long n, size_t len)
{
    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_ERR("CoAP coallback in use so cannot send task response\n");
        return false;
    }

    int ret;

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, ROUTING_APPLICATION_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, len);

    coap_set_random_token(&msg);

#ifdef WITH_OSCORE
    keystore_protect_coap_with_oscore(&msg, &ep);
#endif

    // i starts at 0
    const bool coap_block1_more = ((i + 1) != n);

    // TODO: block len should be a power of 2 (i.e.,64)
    ret = coap_set_header_block1(&msg, i, coap_block1_more, 64);
    if (!ret)
    {
        LOG_ERR("coap_set_header_block1 failed (%lu, %" PRIu8 ", %zu)\n", i, coap_block1_more, len);
    }

    ret = coap_send_request(&coap_callback, &ep, &msg, send_callback);
    if (ret)
    {
        timed_unlock_lock(&coap_callback_in_use);
        LOG_DBG("Message sent to ");
        LOG_DBG_COAP_EP(&ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }

    return ret != 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
process_task_resp1(const char* data, const char* data_end)
{
    // <target>|<n>|<status>

    const char* sep1 = strchr(data, '|');
    if (sep1 == NULL)
    {
        LOG_ERR("strchr 1\n");
        return false;
    }

    const char* sep2 = strchr(sep1+1, '|');
    if (sep2 == NULL)
    {
        LOG_ERR("strchr 2\n");
        return false;
    }

    char uip_buffer[UIPLIB_IPV6_MAX_STR_LEN];
    memset(uip_buffer, 0, sizeof(uip_buffer));
    strncpy(uip_buffer, data, sep1 - data);

    if (!uiplib_ip6addrconv(uip_buffer, &ep.ipaddr))
    {
        LOG_ERR("uiplib_ip6addrconv 2\n");
        return false;
    }

    ep.secure = 0;
    ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    const unsigned long n = strtoul(sep1+1, NULL, 10);

    const pyroutelib3_status_t status = (pyroutelib3_status_t)strtoul(sep2+1, NULL, 10);

    LOG_INFO("Task response: result=%d n=%lu target=", status, n);
    LOG_INFO_6ADDR(&ep.ipaddr);
    LOG_INFO_("\n");

    return process_task_resp_send_status(status);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
process_task_resp2(const char* data, const char* data_end)
{
    // <i>/<n>|<message>

    const char* slashpos = strchr(data, '/');
    if (slashpos == NULL)
    {
        LOG_ERR("strchr 1\n");
        return false;
    }

    const char* seppos = strchr(data, '|');
    if (seppos == NULL)
    {
        LOG_ERR("strchr 2\n");
        return false;
    }

    unsigned long i = strtoul(data, NULL, 10);
    unsigned long n = strtoul(slashpos+1, NULL, 10);

    size_t len = sizeof(msg_buf);
    if (!base64_decode(seppos+1, data_end - (seppos+1), msg_buf, &len))
    {
        LOG_ERR("base64_decode 3 (ret=%d)\n", len);
        return false;
    }

    LOG_DBG("Sending task response %lu/%lu of length %zu\n", i, n, len);

    // Send the buffer back to the target node
    // Use block1 to send the data in multiple packets
    return process_task_resp_send_success(i, n, len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
routing_taskresp_process_serial_input(const char* data)
{
    const char* data_end = data + strlen(data);

    if (!match_action(data, data_end, SERIAL_SEP))
    {
        return;
    }
    data += strlen(SERIAL_SEP);

    bool should_ack = true;

    if (match_action(data, data_end, "stats" SERIAL_SEP))
    {
        data += strlen("stats" SERIAL_SEP);
        process_task_stats(data, data_end);
    }
    else if (match_action(data, data_end, "resp1" SERIAL_SEP))
    {
        data += strlen("resp1" SERIAL_SEP);
        bool result = process_task_resp1(data, data_end);

        // Only send an ack if we failed to send a message.
        // Do not ack here on success, as we need to do so after we are ready to send the next message.
        should_ack = !result;
    }
    else if (match_action(data, data_end, "resp2" SERIAL_SEP))
    {
        data += strlen("resp2" SERIAL_SEP);
        bool result = process_task_resp2(data, data_end);

        // Only send an ack if we failed to send a message.
        // Do not ack here on success, as we need to do so after we are ready to send the next message.
        should_ack = !result;
    }
    else
    {
        LOG_ERR("Unknown action '%s'\n", data);
    }

    if (should_ack)
    {
        ack_serial_input();
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
routing_taskresp_init(void)
{
    timed_unlock_init(&coap_callback_in_use, "routing-task-response", (1 * 60 * CLOCK_SECOND));
}
/*-------------------------------------------------------------------------------------------------------------------*/
