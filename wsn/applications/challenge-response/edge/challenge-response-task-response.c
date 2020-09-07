#include "challenge-response-edge.h"
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
#define LOG_MODULE "A-" CHALLENGE_RESPONSE_APPLICATION_NAME
#ifdef APP_CHALLENGE_RESPONSE_LOG_LEVEL
#define LOG_LEVEL APP_CHALLENGE_RESPONSE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
extern application_stats_t cr_stats;
/*-------------------------------------------------------------------------------------------------------------------*/
static int
process_task_stats(const char* data, const char* data_end)
{
    application_stats_t scn;

    uint8_t buffer[APPLICATION_STATS_MAX_CBOR_LENGTH];
    size_t buffer_len = sizeof(buffer);
    if (!base64_decode(data, data_end - data, buffer, &buffer_len))
    {
        LOG_ERR("!base64_decode\n");
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
            cr_stats.mean, scn.mean,
            cr_stats.minimum, scn.minimum,
            cr_stats.maximum, scn.maximum,
            cr_stats.variance, scn.variance);

    cr_stats = scn;

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
ack_serial_input(void)
{
    printf(APPLICATION_SERIAL_PREFIX CHALLENGE_RESPONSE_APPLICATION_NAME SERIAL_SEP "ack\n");
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
process_task_resp_send_result(size_t len)
{
    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_ERR("CoAP callback in use so cannot send task response\n");
        return false;
    }

    int ret;

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, CHALLENGE_RESPONSE_APPLICATION_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, len);

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
process_task_resp(const char* data, const char* data_end)
{
    // <target>|<result>

    const char* sep1 = strchr(data, '|');
    if (sep1 == NULL)
    {
        LOG_ERR("strchr 1\n");
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

    size_t len = sizeof(msg_buf);
    if (!base64_decode(sep1+1, data_end - (sep1+1), msg_buf, &len))
    {
        LOG_ERR("base64_decode (ret=%d)\n", len);
        return false;
    }

    LOG_INFO("Task response: (len=%zu) target=", len);
    LOG_INFO_6ADDR(&ep.ipaddr);
    LOG_INFO_("\n");

    return process_task_resp_send_result(len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
cr_taskresp_process_serial_input(const char* data)
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
    else if (match_action(data, data_end, "resp" SERIAL_SEP))
    {
        data += strlen("resp" SERIAL_SEP);
        bool result = process_task_resp(data, data_end);

        // Only send an ack if we failed to send a message.
        // Do not ack here on success, as we need to do so after we are ready to send the next message.
        if (!result)
        {
            ack_serial_input();
        }
    }
    else
    {
        LOG_ERR("Unknown action '%s'\n", data);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
cr_taskresp_init(void)
{
    timed_unlock_init(&coap_callback_in_use, "challenge-response-task-response", (1 * 60 * CLOCK_SECOND));
}
/*-------------------------------------------------------------------------------------------------------------------*/
