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

#include <string.h>
#include <strings.h>
#include <stdint.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "mqtt-conn"
#ifdef MQTT_CLIENT_CONF_LOG_LEVEL
#define LOG_LEVEL MQTT_CLIENT_CONF_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
/* MQTT broker address */
#ifdef MQTT_CLIENT_CONF_BROKER_IP_ADDR
#define MQTT_CLIENT_BROKER_IP_ADDR MQTT_CLIENT_CONF_BROKER_IP_ADDR
#else
#define MQTT_CLIENT_BROKER_IP_ADDR "fd00::1"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef TOPICS_TO_SUBSCRIBE_LEN
#error "Please define TOPICS_TO_SUBSCRIBE_LEN"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
typedef uint8_t topic_subscribe_status_t;
#define TOPIC_STATE_NOT_SUBSCRIBED   0
#define TOPIC_STATE_SUBSCRIBING      1
#define TOPIC_STATE_SUBSCRIBED       3
/*-------------------------------------------------------------------------------------------------------------------*/
extern const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN];
static topic_subscribe_status_t topic_subscribe_status[TOPICS_TO_SUBSCRIBE_LEN];
/*-------------------------------------------------------------------------------------------------------------------*/
extern void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
/*-------------------------------------------------------------------------------------------------------------------*/
/*
 * MQTT Org ID.
 *
 * If it equals "quickstart", the client will connect without authentication.
 * In all other cases, the client will connect with authentication mode.
 *
 * In Watson mode, the username will be "use-token-auth". In non-Watson mode
 * the username will be MQTT_CLIENT_USERNAME.
 *
 * In all cases, the password will be MQTT_CLIENT_AUTH_TOKEN.
 */
#ifdef MQTT_CLIENT_CONF_ORG_ID
#define MQTT_CLIENT_ORG_ID MQTT_CLIENT_CONF_ORG_ID
#else
#error "Need to define MQTT_CLIENT_CONF_ORG_ID"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
/* MQTT token */
#ifdef MQTT_CLIENT_CONF_AUTH_TOKEN
#define MQTT_CLIENT_AUTH_TOKEN MQTT_CLIENT_CONF_AUTH_TOKEN
#else
#define MQTT_CLIENT_AUTH_TOKEN "AUTHTOKEN"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef MQTT_CLIENT_CONF_USERNAME
#define MQTT_CLIENT_USERNAME MQTT_CLIENT_CONF_USERNAME
#else
#define MQTT_CLIENT_USERNAME "use-token-auth"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define COAP_CLIENT_CONF_BROKER_IP_ADDR "coap://[" MQTT_CLIENT_CONF_BROKER_IP_ADDR "]"
/*-------------------------------------------------------------------------------------------------------------------*/
/* A timeout used when waiting to connect to a network */
#define NET_CONNECT_PERIODIC        (CLOCK_SECOND * 1)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Default configuration values */
#define DEFAULT_KEEP_ALIVE_TIMER    (CLOCK_SECOND * 60)  // https://github.com/emqx/emqx-coap#coap-client-keep-alive
#define DEFAULT_PING_INTERVAL       (CLOCK_SECOND * 30)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Payload length of ICMPv6 echo requests used to measure RSSI with def rt */
#define ECHO_REQ_PAYLOAD_LEN   20
/*-------------------------------------------------------------------------------------------------------------------*/
/*
 * Buffers for Client ID and Topic.
 * Make sure they are large enough to hold the entire respective string
 *
 * d:quickstart:status:EUI64 is 32 bytes long
 * iot-2/evt/status/fmt/json is 25 bytes
 * We also need space for the null termination
 */
static char client_id[sizeof(MQTT_CLIENT_ORG_ID) + 1 + 12];
/*-------------------------------------------------------------------------------------------------------------------*/
//struct mqtt_connection conn;
static coap_endpoint_t server_ep;
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_callback_request_state_t coap_callback;
static bool coap_callback_in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_periodic_timer;
static struct etimer ping_mqtt_over_coap_timer;
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
    process_poll(&mqtt_client_process);

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
static bool
construct_client_id(void)
{
  int len = snprintf(client_id, sizeof(client_id), "%s:%02x%02x%02x%02x%02x%02x",
                     MQTT_CLIENT_ORG_ID,
                     linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
                     linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[5],
                     linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);

  /* len < 0: Error. Len >= BUFFER_SIZE: Buffer too small */
  if (len < 0 || len >= sizeof(client_id)) {
    printf("Insufficient length for client ID: %d, Buffer %d\n", len, sizeof(client_id));
    return false;
  }

  return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
init(void)
{
  if (!construct_client_id())
  {
    /* Fatal error. Client ID larger than the buffer */
    return false;
  }

  topic_init();

  coap_endpoint_parse(COAP_CLIENT_CONF_BROKER_IP_ADDR, strlen(COAP_CLIENT_CONF_BROKER_IP_ADDR), &server_ep);

  coap_callback_in_use = false;

  return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
mqtt_over_coap_publish(const char* topic, const char* data, size_t data_len)
{
  // https://github.com/emqx/emqx-coap#publish-example

  /*mqtt_status_t mqtt_publish(struct mqtt_connection *conn,
                           uint16_t *mid,
                           char *topic,
                           uint8_t *payload,
                           uint32_t payload_size,
                           mqtt_qos_level_t qos_level,
                           mqtt_retain_t retain);*/

  char uri_path[128];
  snprintf(uri_path, sizeof(uri_path), "mqtt/%s?c=%s&u=" MQTT_CLIENT_USERNAME "&p=" MQTT_CLIENT_AUTH_TOKEN, topic, client_id);
  // TODO: error checking

  coap_message_t msg;
  coap_init_message(&msg, COAP_TYPE_CON, COAP_PUT, 0);
  coap_set_header_uri_path(&msg, uri_path);

  int ret = coap_send_request(NULL, &server_ep, &msg, NULL);
  if (ret)
  {
    LOG_DBG("Publish (%s) sent\n", topic);
  }
  else
  {
    LOG_ERR("Failed to publish with %d\n", ret);
  }
  return ret != 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
subscribe_callback(coap_callback_request_state_t *callback_state)
{
  uint16_t i = callback_state->state.request->mid;

  // TODO: Check this correctly
  if (callback_state->state.status != COAP_REQUEST_STATUS_FINISHED)
  {
    topic_subscribe_status[i] = TOPIC_STATE_NOT_SUBSCRIBED;
  }
  else
  {
    topic_subscribe_status[i] = TOPIC_STATE_SUBSCRIBED;
  }

  // Poll the process to trigger subsequent subscribes
  process_poll(&mqtt_client_process);

  coap_callback_in_use = false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
mqtt_over_coap_subscribe(const char* topic, uint16_t msg_id)
{
  char uri_path[128];
  snprintf(uri_path, sizeof(uri_path), "mqtt/%s?c=%s&u=" MQTT_CLIENT_USERNAME "&p=" MQTT_CLIENT_AUTH_TOKEN, topic, client_id);
  // TODO: error checking

  coap_message_t msg;
  coap_init_message(&msg, COAP_TYPE_CON, COAP_GET, msg_id);
  coap_set_header_uri_path(&msg, uri_path);

  return coap_send_request(&coap_callback, &server_ep, &msg, &subscribe_callback);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
subscribe(void)
{
  /* Publish MQTT topic */
  // https://github.com/emqx/emqx-coap#subscribe-example

  int ret;

  for (size_t i = 0; i != TOPICS_TO_SUBSCRIBE_LEN; ++i)
  {
    if (topic_subscribe_status[i] != TOPIC_STATE_NOT_SUBSCRIBED)
    {
      continue;
    }

    LOG_DBG("Subscribing to [%u]='%s'!\n", i, topics_to_suscribe[i]);

    ret = mqtt_over_coap_subscribe(topics_to_suscribe[i], i);
    if (ret)
    {
      LOG_DBG("Subscription request (%u) sent\n", i);
      topic_subscribe_status[i] = TOPIC_STATE_SUBSCRIBING;

      coap_callback_in_use = true;

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
static void
ping_parent(void)
{
  if (have_connectivity()) {
    const uip_ipaddr_t* defrt = uip_ds6_defrt_choose();
    LOG_DBG("Pinging parent ");
    LOG_DBG_6ADDR(defrt);
    LOG_DBG_("!\n");
    uip_icmp6_send(defrt, ICMP6_ECHO_REQUEST, 0, ECHO_REQ_PAYLOAD_LEN);
  } else {
    LOG_WARN("ping_parent() is called while we don't have connectivity\n");
  }
  etimer_set(&echo_request_timer, DEFAULT_PING_INTERVAL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
ping_mqtt_over_coap(void)
{
  // As per https://github.com/emqx/emqx-coap#coap-client-keep-alive
  // To keep MQTT sessions online, a periodic GET needs to be sent.
  mqtt_over_coap_subscribe("ping", 0);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
state_machine(void)
{
  if (have_connectivity())
  {
    subscribe();
    //etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
  }
  else
  {
    LOG_DBG("No connectivity, so cannot attempt to connect to broker\n");
    ping_parent();
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(mqtt_client_process, ev, data)
{
  PROCESS_BEGIN();

  if (!init())
  {
    PROCESS_EXIT();
  }

  uip_icmp6_echo_reply_callback_add(&echo_reply_notification, echo_reply_handler);
  etimer_set(&echo_request_timer, DEFAULT_PING_INTERVAL);
  etimer_set(&ping_mqtt_over_coap_timer, DEFAULT_KEEP_ALIVE_TIMER);

  /* Main loop */
  while (1) {
    PROCESS_YIELD();

    if ((ev == PROCESS_EVENT_TIMER && data == &publish_periodic_timer) || ev == PROCESS_EVENT_POLL) {
      state_machine();
    }

    if (ev == PROCESS_EVENT_TIMER && data == &echo_request_timer) {
      ping_parent();
    }

    if (ev == PROCESS_EVENT_TIMER && data == &ping_mqtt_over_coap_timer) {
      ping_mqtt_over_coap();
    }
  }

  PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
