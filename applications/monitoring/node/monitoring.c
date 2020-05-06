#include "contiki.h"
#include "os/sys/log.h"
#include "dev/cc2538-sensors.h"

#include "coap.h"
#include "coap-callback-api.h"

#include <stdio.h>

#include "monitoring.h"
#include "edge-info.h"
#include "trust.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" MONITORING_APPLICATION_NAME
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define PERIOD (CLOCK_SECOND * 60)
#define CONNECT_PERIOD (CLOCK_SECOND * 1)
/*-------------------------------------------------------------------------------------------------------------------*/
#define TMP_BUF_SZ 64
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static coap_endpoint_t ep;
static bool coap_callback_in_use;
static char msg_buf[TMP_BUF_SZ];
/*-------------------------------------------------------------------------------------------------------------------*/
static int
generate_sensor_data(char* buf, size_t buf_len)
{
    int temp_value = cc2538_temp_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);
    int vdd3_value = vdd3_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);

    int would_have_written = snprintf(buf, buf_len,
        "{"
            "\"temp\":%d,"
            "\"vdd3\":%d"
        "}",
        temp_value, vdd3_value
    );

    return would_have_written;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_info_get_server_endpoint(edge_resource_t* edge, coap_endpoint_t* ep)
{
    uip_ip6addr_copy(&ep->ipaddr, &edge->addr);
    ep->secure = 0;
    ep->port = UIP_HTONS(COAP_DEFAULT_PORT);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_periodic_timer;
static bool started;
/*-------------------------------------------------------------------------------------------------------------------*/
static void
send_callback(coap_callback_request_state_t *callback_state)
{
    if (!coap_callback_in_use)
    {
        return;
    }

    coap_message_t* response = callback_state->state.response;

    if ((callback_state->state.status == COAP_REQUEST_STATUS_FINISHED ||
        callback_state->state.status == COAP_REQUEST_STATUS_RESPONSE) && response != NULL)
    {
        LOG_DBG("Message sent with code (%d) %.*s (len=%d)\n",
            response->code, response->payload_len, response->payload, response->payload_len);
    }
    else
    {
        if (callback_state->state.status == COAP_REQUEST_STATUS_TIMEOUT)
        {
            LOG_ERR("Failed to send message with status %d (timeout)\n", callback_state->state.status);
        }
        else
        {
            LOG_ERR("Failed to send message with status %d\n", callback_state->state.status);
        }
    }

    coap_callback_in_use = false;

    etimer_reset(&publish_periodic_timer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_action(void)
{
    int ret;

    if (coap_callback_in_use)
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return;
    }

    coap_callback_in_use = true;

    int len = generate_sensor_data(msg_buf, sizeof(msg_buf));
    if (len <= 0 || len > sizeof(msg_buf))
    {
        LOG_ERR("Failed to generated message (%d)\n", len);
        coap_callback_in_use = false;
        return;
    }

    LOG_DBG("Generated message %s\n", msg_buf);

    // Choose an Edge node to send information to
    edge_resource_t* edge = choose_edge(MONITORING_APPLICATION_NAME);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find an edge resource to send task to\n");
        coap_callback_in_use = false;
        return;
    }

    edge_info_get_server_endpoint(edge, &ep);

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);

    ret = coap_set_header_uri_path(&msg, MONITORING_APPLICATION_URI);
    if (ret <= 0)
    {
        LOG_DBG("coap_set_header_uri_path failed %d\n", ret);
        coap_callback_in_use = false;
        return;
    }
    
    coap_set_header_content_format(&msg, APPLICATION_JSON);
    coap_set_payload(&msg, msg_buf, len);

    ret = coap_send_request(&coap_callback, &ep, &msg, send_callback);
    if (ret)
    {
        LOG_DBG("Message sent to ");
        coap_endpoint_log(&ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
        coap_callback_in_use = false;
    }

    // TODO: Record metrics about tasks sent to edge nodes and their ability to respond in the trust model
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_add(edge_resource_t* edge)
{
    LOG_DBG("Notified of edge capability for %s\n", edge->name);

    if (!started)
    {
        LOG_DBG("Starting periodic timer to send information\n");

        // Setup a periodic timer that expires after PERIOD seconds.
        etimer_set(&publish_periodic_timer, PERIOD);
        started = true;

        // TODO: Open connection to edge node?
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(environment_monitoring, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(environment_monitoring, ev, data)
{
    PROCESS_BEGIN();

    SENSORS_ACTIVATE(cc2538_temp_sensor);
    SENSORS_ACTIVATE(vdd3_sensor);

    started = false;
    coap_callback_in_use = false;

    while (1)
    {
        PROCESS_YIELD();

        if (ev == PROCESS_EVENT_TIMER && data == &publish_periodic_timer) {
            periodic_action();
        }

        if (ev == pe_edge_capability_add) {
            edge_capability_add((edge_resource_t*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
