#include "contiki.h"
#include "os/sys/log.h"
#include "dev/cc2538-sensors.h"
#include "os/lib/assert.h"

#include "coap.h"
#include "coap-callback-api.h"

#include <stdio.h>

#include "monitoring.h"
#include "edge-info.h"
#include "trust.h"
#include "applications.h"

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
#define TMP_BUF_SZ 64
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static bool coap_callback_in_use;
static char msg_buf[TMP_BUF_SZ];
/*-------------------------------------------------------------------------------------------------------------------*/
static int
generate_sensor_data(char* buf, size_t buf_len)
{
    uint32_t time_secs = clock_seconds();

    int temp_value = cc2538_temp_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);
    int vdd3_value = vdd3_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);

    int would_have_written = snprintf(buf, buf_len,
        "{"
            "\"time\":%" PRIu32 ","
            "\"temp\":%d,"
            "\"vdd3\":%d"
        "}",
        time_secs, temp_value, vdd3_value
    );

    return would_have_written;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_periodic_timer, publish_short_timer;
static uint8_t capability_count;
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
            LOG_DBG("Message send failed with code (%c) '%.*s' (len=%d)\n",
                response->code, response->payload_len, response->payload, response->payload_len);
        }

        // TODO: record information on Edge response
    } break;

    case COAP_REQUEST_STATUS_MORE:
    {
        LOG_ERR("Unhandled COAP_REQUEST_STATUS_MORE\n");
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        coap_callback_in_use = false;
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
static void
periodic_action(void)
{
    int ret;

    etimer_reset(&publish_periodic_timer);

    if (coap_callback_in_use)
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

    LOG_DBG("Generated message %s\n", msg_buf);

    // Choose an Edge node to send information to
    edge_resource_t* edge = choose_edge(MONITORING_APPLICATION_NAME);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find an edge resource to send task to\n");
        return;
    }

    if (!coap_endpoint_is_connected(&edge->ep))
    {
        LOG_DBG("We are not connected to ");
        coap_endpoint_log(&edge->ep);
        LOG_DBG_(", so will initiate a connection to it.\n");

        // Initiate a connect
        coap_endpoint_connect(&edge->ep);

        // Wait for a bit and then try sending again
        etimer_set(&publish_short_timer, SHORT_PUBLISH_PERIOD);
        return;
    }

    // TODO: encrypt and sign message

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);

    ret = coap_set_header_uri_path(&msg, MONITORING_APPLICATION_URI);
    if (ret <= 0)
    {
        LOG_DBG("coap_set_header_uri_path failed %d\n", ret);
        return;
    }
    
    coap_set_header_content_format(&msg, APPLICATION_JSON);
    coap_set_payload(&msg, msg_buf, len);

    ret = coap_send_request(&coap_callback, &edge->ep, &msg, send_callback);
    if (ret)
    {
        coap_callback_in_use = true;
        LOG_DBG("Message sent to ");
        coap_endpoint_log(&edge->ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }

    // TODO: Record metrics about tasks sent to edge nodes and their ability to respond in the trust model
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_add(edge_resource_t* edge)
{
    LOG_DBG("Notified of edge %s capability\n", edge->name);

    capability_count += 1;

    if (capability_count == 1)
    {
        LOG_DBG("Starting periodic timer to send information\n");

        // Setup a periodic timer that expires after PERIOD seconds.
        etimer_set(&publish_periodic_timer, LONG_PUBLISH_PERIOD);
    }

    edge_capability_add_common(edge, MONITORING_APPLICATION_URI);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_remove(edge_resource_t* edge)
{
    LOG_DBG("Notified edge %s no longer has capability\n", edge->name);

    capability_count -= 1;

    if (capability_count == 0)
    {
        LOG_DBG("Stop sending information, no edges to process it\n");

        etimer_stop(&publish_periodic_timer);
    }

    edge_capability_remove_common(edge, MONITORING_APPLICATION_URI);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(environment_monitoring, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(environment_monitoring, ev, data)
{
    PROCESS_BEGIN();

    SENSORS_ACTIVATE(cc2538_temp_sensor);
    SENSORS_ACTIVATE(vdd3_sensor);

    capability_count = 0;
    coap_callback_in_use = false;

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
