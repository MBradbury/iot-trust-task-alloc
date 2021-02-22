#include "monitoring.h"
#include "application-common.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "dev/cc2538-sensors.h"
#include "os/lib/assert.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"

#include "nanocbor-helper.h"

#include <stdio.h>

#include "edge-info.h"
#include "trust.h"
#include "trust-models.h"
#include "trust-choose.h"
#include "applications.h"
#include "keystore-oscore.h"
#include "timed-unlock.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" MONITORING_APPLICATION_NAME
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define LONG_PUBLISH_PERIOD (CLOCK_SECOND * 60 * 1)
#define SHORT_PUBLISH_PERIOD (CLOCK_SECOND * 10)
#define CONNECT_PERIOD (CLOCK_SECOND * 5)
/*-------------------------------------------------------------------------------------------------------------------*/
static app_state_t app_state;
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_endpoint_t ep;
static coap_callback_request_state_t coap_callback;
static timed_unlock_t coap_callback_in_use;
static uint8_t msg_buf[(1) + (1 + sizeof(uint32_t)) + (1 + sizeof(int)) + (1 + sizeof(int))];
/*-------------------------------------------------------------------------------------------------------------------*/
static int
generate_sensor_data(uint8_t* buf, size_t buf_len)
{
    uint32_t time_secs = clock_seconds();

    int temp_value = cc2538_temp_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);
    int vdd3_value = vdd3_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buf_len);

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 3));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, time_secs));
    NANOCBOR_CHECK(nanocbor_fmt_int(&enc, temp_value));
    NANOCBOR_CHECK(nanocbor_fmt_int(&enc, vdd3_value));

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_periodic_timer, publish_short_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static void
send_callback(coap_callback_request_state_t* callback_state)
{
    tm_task_submission_info_t info = {
        .coap_status = NO_ERROR,
        .coap_request_status = callback_state->state.status
    };

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

        info.coap_status = response->code;
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        timed_unlock_unlock(&coap_callback_in_use);
    } break;

    default:
    {
        LOG_ERR("Failed to send message due to %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        timed_unlock_unlock(&coap_callback_in_use);
    } break;
    }

    edge_resource_t* edge = edge_info_find_addr(&ep.ipaddr);
    if (edge == NULL)
    {
        LOG_WARN("Edge ");
        LOG_WARN_COAP_EP(&ep);
        LOG_WARN_(" was removed between sending a task and receiving an acknowledgement\n");
        return;
    }

    // Find the information on the capability for this edge
    // If this capability no longer exists, then the Edge has informed us that it no longer
    // offers that capability
    edge_capability_t* cap = edge_info_capability_find(edge, MONITORING_APPLICATION_NAME);
    if (cap == NULL)
    {
        LOG_WARN("Edge ");
        LOG_WARN_COAP_EP(&ep);
        LOG_WARN_(" removed capability " MONITORING_APPLICATION_NAME " between sending a task and receiving a acknowledgement\n");
        return;
    }

    tm_update_task_submission(edge, cap, &info);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_action(void)
{
    int ret;

    etimer_reset(&publish_periodic_timer);

    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return;
    }

    int len = generate_sensor_data(msg_buf, sizeof(msg_buf));
    if (len <= 0 || len > sizeof(msg_buf))
    {
        LOG_ERR("Failed to generated message (%d)\n", len);
        return;
    }

    LOG_DBG("Generated message (len=%d)\n", len);

    // Choose an Edge node to send information to
    edge_resource_t* edge = choose_edge(MONITORING_APPLICATION_NAME);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find an edge resource to send task to\n");
        return;
    }

    // We need to store a local copy of the edge target
    // As the edge resource object may be removed by the time we receive a response
    coap_endpoint_copy(&ep, &edge->ep);

    if (!coap_endpoint_is_connected(&ep))
    {
        LOG_DBG("We are not connected to ");
        LOG_DBG_COAP_EP(&ep);
        LOG_DBG_(", so will initiate a connection to it.\n");

        // Initiate a connect
        coap_endpoint_connect(&ep);

        // Wait for a bit and then try sending again
        etimer_set(&publish_short_timer, SHORT_PUBLISH_PERIOD);
        return;
    }

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, MONITORING_APPLICATION_URI);
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
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_add(edge_resource_t* edge)
{
    if (app_state_edge_capability_add(&app_state, edge))
    {
        LOG_INFO("Starting periodic timer to send information\n");

        // Setup a periodic timer that expires after PERIOD seconds.
        etimer_set(&publish_periodic_timer, LONG_PUBLISH_PERIOD);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_remove(edge_resource_t* edge)
{
    if (app_state_edge_capability_remove(&app_state, edge))
    {
        LOG_INFO("Stop sending information, no edges to process it\n");

        etimer_stop(&publish_periodic_timer);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(monitoring_process, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    init_trust_weights_monitoring();

    SENSORS_ACTIVATE(cc2538_temp_sensor);
    SENSORS_ACTIVATE(vdd3_sensor);

    app_state_init(&app_state, MONITORING_APPLICATION_NAME, MONITORING_APPLICATION_URI);

    timed_unlock_init(&coap_callback_in_use, "monitoring", (1 * 60 * CLOCK_SECOND));
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(monitoring_process, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == PROCESS_EVENT_TIMER && (data == &publish_periodic_timer || data == &publish_short_timer)) {
            periodic_action();
        }

        if (ev == pe_edge_capability_add) {
            edge_capability_add((edge_resource_t*)data);
        }

        if (ev == pe_edge_capability_remove) {
            edge_capability_remove((edge_resource_t*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
