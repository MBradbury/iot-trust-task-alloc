#include "contiki.h"
#include "net/routing/routing.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/ipv6/sicslowpan.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/etimer.h"
#include "os/sys/log.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "oscore.h"

#include "crypto-support.h"
#include "keystore-oscore.h"
#include "timed-unlock.h"
#include "root-endpoint.h"

#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <assert.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "mqtt-conn"
#ifdef MQTT_CLIENT_CONF_LOG_LEVEL
#define LOG_LEVEL MQTT_CLIENT_CONF_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef TOPICS_TO_SUBSCRIBE_LEN
#error "Please define TOPICS_TO_SUBSCRIBE_LEN"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
typedef enum 
{
    TOPIC_STATE_NOT_SUBSCRIBED = 0,
    TOPIC_STATE_SUBSCRIBING    = 1,
    TOPIC_STATE_SUBSCRIBED     = 2,
} topic_subscribe_status_t;
/*-------------------------------------------------------------------------------------------------------------------*/
extern const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN];
static topic_subscribe_status_t topic_subscribe_status[TOPICS_TO_SUBSCRIBE_LEN];
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
/*-------------------------------------------------------------------------------------------------------------------*/
static process_event_t pe_state_machine;
/*-------------------------------------------------------------------------------------------------------------------*/
#define MQTT_URI_PATH "mqtt"
#define MQTT_TOPIC_QUERY_NAME "t"
/*-------------------------------------------------------------------------------------------------------------------*/
/* A timeout used when waiting to connect to a network */
#define NET_CONNECT_PERIODIC        (CLOCK_SECOND * 1)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Default configuration values */
#define DEFAULT_PING_INTERVAL       (CLOCK_SECOND * 30)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Payload length of ICMPv6 echo requests used to measure RSSI with def rt */
#define ECHO_REQ_PAYLOAD_LEN        20
/*-------------------------------------------------------------------------------------------------------------------*/
#define MAX_QUERY_LEN               128
#define MAX_COAP_PAYLOAD            COAP_MAX_CHUNK_SIZE
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static char uri_query[MAX_QUERY_LEN];
static uint8_t coap_payload[MAX_COAP_PAYLOAD];
static coap_callback_request_state_t coap_callback;
static timed_unlock_t coap_callback_in_use;
static uint16_t coap_callback_i;
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_periodic_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
/* Parent RSSI functionality */
static struct uip_icmp6_echo_reply_notification echo_reply_notification;
static struct etimer echo_request_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(mqtt_client_process, "MQTT Client");
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
have_connectivity(void)
{
    return uip_ds6_get_global(ADDR_PREFERRED) != NULL && uip_ds6_defrt_choose() != NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
echo_reply_handler(uip_ipaddr_t *source, uint8_t ttl, uint8_t *data, uint16_t datalen)
{
    if (uip_ip6addr_cmp(source, uip_ds6_defrt_choose())) {
        // Got ping from server, so we need to connect if not done so already
        LOG_DBG("Received ping reply from server, polling mqtt_client_process\n");
        process_post(&mqtt_client_process, pe_state_machine, NULL);

        // No need to keep pinging
        etimer_stop(&echo_request_timer);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
topic_init(void)
{
    for (size_t i = 0; i != TOPICS_TO_SUBSCRIBE_LEN; ++i)
    {
        topic_subscribe_status[i] = TOPIC_STATE_NOT_SUBSCRIBED;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
publish_callback(coap_callback_request_state_t *callback_state);
/*-------------------------------------------------------------------------------------------------------------------*/
bool
mqtt_over_coap_publish(const char* topic, const void* data, size_t data_len)
{
    int ret;

    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_ERR("Cannot perform mqtt_over_coap_publish as we are busy\n");
        return false;
    }

    if (!coap_endpoint_is_connected(&root_ep))
    {
        LOG_ERR("Cannot perform mqtt_over_coap_publish as the coap endpoint is not connected\n");
        return false;
    }

    timed_unlock_lock(&coap_callback_in_use);

    ret = snprintf(uri_query, sizeof(uri_query), MQTT_TOPIC_QUERY_NAME "=%s", topic);
    if (ret <= 0 || ret >= sizeof(uri_query))
    {
        LOG_ERR("snprintf uri_query failed %d\n", ret);
        timed_unlock_unlock(&coap_callback_in_use);
        return false;
    }
    
    coap_init_message(&msg, COAP_TYPE_CON, COAP_PUT, 0);
    coap_set_header_uri_path(&msg, MQTT_URI_PATH);
    coap_set_header_uri_query(&msg, uri_query);

    memcpy(coap_payload, data, data_len);

    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, coap_payload, data_len);

#if defined(WITH_OSCORE) && defined(AIOCOAP_SUPPORTS_OSCORE)
    coap_set_random_token(&msg);
    keystore_protect_coap_with_oscore(&msg, &root_ep);
#endif

    ret = coap_send_request(&coap_callback, &root_ep, &msg, publish_callback);
    if (ret)
    {
        LOG_DBG("Publish (%s) sent\n", topic);
    }
    else
    {
        LOG_ERR("Failed to publish with %d\n", ret);
        timed_unlock_unlock(&coap_callback_in_use);
    }

    return ret != 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
publish_callback(coap_callback_request_state_t *callback_state)
{
    switch (callback_state->state.status)
    {
    case COAP_REQUEST_STATUS_RESPONSE:
    {
        coap_message_t* response = callback_state->state.response;

        LOG_DBG("MQTT publish complete with code (%d) (len=%d)\n",
            response->code, response->payload_len);
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        timed_unlock_unlock(&coap_callback_in_use);
    } break;

    default:
    {
        LOG_ERR("MQTT publish: Failed to send message with status %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        timed_unlock_unlock(&coap_callback_in_use);
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int mqtt_over_coap_subscribe(const char* topic, uint16_t msg_id);
static void subscribe_callback(coap_callback_request_state_t *callback_state);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
subscribe(void)
{
    int ret;

    for (size_t i = 0; i != TOPICS_TO_SUBSCRIBE_LEN; ++i)
    {
        if (topic_subscribe_status[i] != TOPIC_STATE_NOT_SUBSCRIBED)
        {
            continue;
        }

        ret = mqtt_over_coap_subscribe(topics_to_suscribe[i], i);
        if (ret)
        {
            LOG_DBG("Subscription request (%u) sent\n", i);
            topic_subscribe_status[i] = TOPIC_STATE_SUBSCRIBING;

            // Once one request is sent, the queue becomes full.
            // So we need to wait for the topic to be subscribed before sending another request.
            break;
        }
        else
        {
            LOG_ERR("Failed to subscribe with %d\n", ret);
            etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
        }
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
mqtt_over_coap_subscribe(const char* topic, uint16_t msg_id)
{
    int ret;

    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_DBG("Cannot subscribe again, waiting for existing subscribe to finish\n");
        return -1;
    }

    timed_unlock_lock(&coap_callback_in_use);

    ret = snprintf(uri_query, sizeof(uri_query), MQTT_TOPIC_QUERY_NAME "=%s", topic);
    if (ret <= 0 || ret >= sizeof(uri_query))
    {
        LOG_ERR("snprintf uri_query failed %d\n", ret);
        return -1;
    }

    LOG_DBG("Subscribing to [%u]='%s'! (" MQTT_URI_PATH "?%s)\n", msg_id, topic, uri_query);

    coap_init_message(&msg, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(&msg, MQTT_URI_PATH);
    coap_set_header_uri_query(&msg, uri_query);

#if defined(WITH_OSCORE) && defined(AIOCOAP_SUPPORTS_OSCORE)
    coap_set_random_token(&msg);
    keystore_protect_coap_with_oscore(&msg, &root_ep);
#endif

    ret = coap_send_request(&coap_callback, &root_ep, &msg, &subscribe_callback);
    if (ret)
    {
        coap_callback_i = msg_id;
    }
    else
    {
        timed_unlock_unlock(&coap_callback_in_use);
    }

    return ret;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
subscribe_callback_end(void)
{
    timed_unlock_unlock(&coap_callback_in_use);

    // Poll the process to trigger subsequent subscribes
    process_post(&mqtt_client_process, pe_state_machine, NULL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
subscribe_callback(coap_callback_request_state_t *callback_state)
{
    LOG_DBG("Received subscribe callback\n");

    assert(callback_state != NULL);

    const uint16_t i = coap_callback_i;

    switch (callback_state->state.status)
    {
    case COAP_REQUEST_STATUS_RESPONSE:
    {
        coap_message_t* response = callback_state->state.response;

        if (response->code == CREATED_2_01)
        {
            LOG_DBG("Subscription to topic %s successful\n", topics_to_suscribe[i]);

            topic_subscribe_status[i] = TOPIC_STATE_SUBSCRIBED;
        }
        else
        {
            LOG_ERR("Failed to subscribe to topic %s with error (%d) %.*s (len=%d)\n",
                topics_to_suscribe[i], response->code,
                response->payload_len, response->payload, response->payload_len);

            topic_subscribe_status[i] = TOPIC_STATE_NOT_SUBSCRIBED;
        }
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        subscribe_callback_end();
    } break;

    default:
    {
        LOG_ERR("Failed to subscribe to topic %s: Failed to send message with status %s(%d)\n",
            topics_to_suscribe[i],
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);

        topic_subscribe_status[i] = TOPIC_STATE_NOT_SUBSCRIBED;
        subscribe_callback_end();
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
extern void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len);

static void
res_coap_mqtt_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_coap_mqtt,
         "title=\"MQTT-over-CoAP Notify\";rt=\"MQTT\"",
         NULL,                       /*GET*/
         res_coap_mqtt_post_handler, /*POST*/
         NULL,                       /*PUT*/
         NULL                        /*DELETE*/);

static void
res_coap_mqtt_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    const char* topic = NULL;
    int topic_len = coap_get_query_variable(request, MQTT_TOPIC_QUERY_NAME, &topic);

    if (!topic || topic_len <= 0)
    {
        LOG_WARN("No mqtt topic in query\n");
        coap_set_status_code(response, BAD_REQUEST_4_00);
        return;
    }

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received publish topic=%.*s, payload len=%d\n", topic_len, topic, payload_len);

    // Forward the publish back up to the clients
    mqtt_publish_handler(topic, topic + topic_len, payload, payload_len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
ping_parent(void)
{
    if (have_connectivity()) {
        const uip_ipaddr_t* defrt = uip_ds6_defrt_choose();
        LOG_DBG("Pinging parent ");
        LOG_DBG_6ADDR(defrt);
        LOG_DBG_("\n");
        uip_icmp6_send(defrt, ICMP6_ECHO_REQUEST, 0, ECHO_REQ_PAYLOAD_LEN);
    } else {
        LOG_WARN("ping_parent() is called while we don't have connectivity\n");
    }
    etimer_set(&echo_request_timer, DEFAULT_PING_INTERVAL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
state_machine(void)
{
    if (have_connectivity())
    {
        if (!coap_endpoint_is_connected(&root_ep))
        {
            LOG_DBG("Have connectivity, but coap endpoint not connected, connecting...\n");
            coap_endpoint_connect(&root_ep);
            etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
        }
        else
        {
            LOG_DBG("Have connectivity and coap endpoint connected, subscribing...\n");
            subscribe();
        }
    }
    else
    {
        LOG_DBG("No connectivity, so cannot attempt to connect to broker\n");
        ping_parent();
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
init(void)
{
    topic_init();

    timed_unlock_init(&coap_callback_in_use, "mqtt-over-coap", (1 * 60 * CLOCK_SECOND));

    uip_icmp6_echo_reply_callback_add(&echo_reply_notification, echo_reply_handler);
    etimer_set(&echo_request_timer, DEFAULT_PING_INTERVAL);

    coap_activate_resource(&res_coap_mqtt, MQTT_URI_PATH);

#if defined(WITH_OSCORE) && defined(AIOCOAP_SUPPORTS_OSCORE)
    oscore_protect_resource(&res_coap_mqtt);
#endif

    pe_state_machine = process_alloc_event();

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(mqtt_client_process, ev, data)
{
    PROCESS_BEGIN();

    if (!init())
    {
        PROCESS_EXIT();
    }

    while (1) {
        PROCESS_YIELD();

        if ((ev == PROCESS_EVENT_TIMER && data == &publish_periodic_timer) || ev == pe_state_machine) {
            state_machine();
        }

        if (ev == PROCESS_EVENT_TIMER && data == &echo_request_timer) {
            ping_parent();
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
