/*
 * Copyright (c) 2014, Texas Instruments Incorporated - http://www.ti.com/
 * Copyright (c) 2017, George Oikonomou - http://www.spd.gr
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*-------------------------------------------------------------------------------------------------------------------*/
#include "contiki.h"
#include "net/routing/routing.h"
#include "mqtt.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/ipv6/sicslowpan.h"
#include "sys/etimer.h"
#include "lib/sensors.h"
#include "dev/leds.h"
#include "os/sys/log.h"

#include <string.h>
#include <strings.h>
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
#ifdef MQTT_CLIENT_CONF_STATUS_LED
#define MQTT_CLIENT_STATUS_LED MQTT_CLIENT_CONF_STATUS_LED
#else
#define MQTT_CLIENT_STATUS_LED LEDS_GREEN
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
/* Connections and reconnections */
#define RECONNECT_INTERVAL         (CLOCK_SECOND * 2)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Various states */
static uint8_t state;
#define STATE_INIT            0
#define STATE_REGISTERED      1
#define STATE_CONNECTING      2
#define STATE_CONNECTED       3
#define STATE_DISCONNECTED    4
#define STATE_CONFIG_ERROR 0xFE
#define STATE_ERROR        0xFF
/*-------------------------------------------------------------------------------------------------------------------*/
/* A timeout used when waiting to connect to a network */
#define NET_CONNECT_PERIODIC        (CLOCK_SECOND * 1)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Default configuration values */
#define DEFAULT_TYPE_ID             "mqtt-client"
#define DEFAULT_BROKER_PORT         1883
#define DEFAULT_PUBLISH_INTERVAL    (30 * CLOCK_SECOND)
#define DEFAULT_KEEP_ALIVE_TIMER    60
#define DEFAULT_PING_INTERVAL       (CLOCK_SECOND * 30)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Payload length of ICMPv6 echo requests used to measure RSSI with def rt */
#define ECHO_REQ_PAYLOAD_LEN   20
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
/*-------------------------------------------------------------------------------------------------------------------*/
/* Maximum TCP segment size for outgoing segments of our socket */
#define MAX_TCP_SEGMENT_SIZE    32
/*-------------------------------------------------------------------------------------------------------------------*/
/*
 * Buffers for Client ID and Topic.
 * Make sure they are large enough to hold the entire respective string
 *
 * d:quickstart:status:EUI64 is 32 bytes long
 * iot-2/evt/status/fmt/json is 25 bytes
 * We also need space for the null termination
 */
#define BUFFER_SIZE 64
static char client_id[BUFFER_SIZE];
/*-------------------------------------------------------------------------------------------------------------------*/
/*
 * The main MQTT buffers.
 * We will need to increase if we start publishing more data.
 */
struct mqtt_connection conn;
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
static uint16_t topic_mid[TOPICS_TO_SUBSCRIBE_LEN];
/*-------------------------------------------------------------------------------------------------------------------*/
extern void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len);
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
    process_poll(&mqtt_client_process);

    // No need to keep pinging
    etimer_stop(&echo_request_timer);
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
topic_mid_indexof(uint16_t mid)
{
  for (int i = 0; i != TOPICS_TO_SUBSCRIBE_LEN; ++i)
  {
    if (topic_mid[i] == mid)
    {
      return i;
    }
  }

  return -1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
topic_init(void)
{
  for (size_t i = 0; i != TOPICS_TO_SUBSCRIBE_LEN; ++i)
  {
    topic_subscribe_status[i] = TOPIC_STATE_NOT_SUBSCRIBED;
  }

  memset(topic_mid, 0, sizeof(topic_mid));
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_event(struct mqtt_connection* m, mqtt_event_t event, void *data)
{
  switch (event)
  {
  case MQTT_EVENT_CONNECTED: {
    LOG_DBG("Application has a MQTT connection\n");
    state = STATE_CONNECTED;
    process_poll(&mqtt_client_process);
  } break;

  case MQTT_EVENT_DISCONNECTED: {
    LOG_DBG("MQTT Disconnect\n");
    state = STATE_DISCONNECTED;
    topic_init();
    process_poll(&mqtt_client_process);
  } break;

  case MQTT_EVENT_PUBLISH: {
    struct mqtt_message *msg_ptr = (struct mqtt_message *)data;

    // Implement first_flag in publish message?
    if (msg_ptr->first_chunk) {
      msg_ptr->first_chunk = 0;
      LOG_DBG("Application received publish for topic '%s'. Payload size is %i bytes.\n",
              msg_ptr->topic, msg_ptr->payload_length);
    }

    mqtt_publish_handler(msg_ptr->topic, msg_ptr->topic + strlen(msg_ptr->topic),
                         msg_ptr->payload_chunk, msg_ptr->payload_length);
  } break;

  case MQTT_EVENT_SUBACK: {
    mqtt_suback_event_t *suback_event = (mqtt_suback_event_t *)data;

    uint16_t mid = suback_event->mid;
    int i = topic_mid_indexof(mid);

    if (suback_event->success)
    {
      LOG_DBG("Application subscribed to topic %u successfully\n", mid);

      if (i != -1)
      {
        topic_subscribe_status[i] = TOPIC_STATE_SUBSCRIBED;
      }
    }
    else
    {
      LOG_DBG("Application failed to subscribe to topic (ret code %x)\n", suback_event->return_code);

      if (i != -1)
      {
        topic_subscribe_status[i] = TOPIC_STATE_NOT_SUBSCRIBED;
      }
    }

    if (i == -1)
    {
      LOG_ERR("Failed to find mid to update subscription of (mid=%u).\n", mid);
    }

    // Poll the process to trigger subsequent subscribes
    process_poll(&mqtt_client_process);
    
  } break;

  case MQTT_EVENT_UNSUBACK: {
    LOG_DBG("Application unsubscribed to topic successfully\n");
    // Never plan on this occuring
    // If this changes, then this needs to be implemented.
  } break;

  case MQTT_EVENT_PUBACK: {
    LOG_DBG("Publishing complete.\n");
  } break;


  case MQTT_EVENT_ERROR: {
    LOG_ERR("MQTT_EVENT_ERROR\n");
    state = STATE_ERROR;
  } break;

  case MQTT_EVENT_PROTOCOL_ERROR: {
    LOG_ERR("MQTT_EVENT_PROTOCOL_ERROR\n");
    state = STATE_ERROR;
  } break;

  case MQTT_EVENT_CONNECTION_REFUSED_ERROR: {
    LOG_ERR("MQTT_EVENT_CONNECTION_REFUSED_ERROR (status: %u)\n", *(uint8_t*)data);
    state = STATE_ERROR;
  } break;

  case MQTT_EVENT_DNS_ERROR: {
    LOG_ERR("MQTT_EVENT_DNS_ERROR\n");
    state = STATE_ERROR;
  } break;

  case MQTT_EVENT_NOT_IMPLEMENTED_ERROR: {
    LOG_ERR("MQTT_EVENT_NOT_IMPLEMENTED_ERROR\n");
    state = STATE_ERROR;
  } break;


  default:
    LOG_DBG("Application got a unhandled MQTT event: %i\n", event);
    break;
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
construct_client_id(void)
{
  int len = snprintf(client_id, BUFFER_SIZE, "%s:%02x%02x%02x%02x%02x%02x",
                     MQTT_CLIENT_ORG_ID,
                     linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
                     linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[5],
                     linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);

  /* len < 0: Error. Len >= BUFFER_SIZE: Buffer too small */
  if (len < 0 || len >= BUFFER_SIZE) {
    printf("Insufficient length for client ID: %d, Buffer %d\n", len, BUFFER_SIZE);
    return false;
  }

  return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
  if (!construct_client_id())
  {
    /* Fatal error. Client ID larger than the buffer */
    state = STATE_CONFIG_ERROR;
    return;
  }

  topic_init();

  state = STATE_INIT;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
subscribe(void)
{
  /* Publish MQTT topic */
  mqtt_status_t status;

  for (size_t i = 0; i != TOPICS_TO_SUBSCRIBE_LEN; ++i)
  {
    if (topic_subscribe_status[i] != TOPIC_STATE_NOT_SUBSCRIBED)
    {
      continue;
    }

    const char* sub_topic = topics_to_suscribe[i];

    LOG_DBG("Subscribing to [%u]='%s'!\n", i, sub_topic);

    status = mqtt_subscribe(&conn, &topic_mid[i], (char*)sub_topic, MQTT_QOS_LEVEL_0);
    if (status == MQTT_STATUS_OK)
    {
      LOG_DBG("Subscription request (%u) sent\n", topic_mid[i]);
      topic_subscribe_status[i] = TOPIC_STATE_SUBSCRIBING;

      // Once one request is sent, the queue becomes full.
      // So we need to wait for the topic to be subscribed before sending another request.
      break;
    }
    else
    {
      if (status == MQTT_STATUS_OUT_QUEUE_FULL)
      {
        LOG_ERR("Tried to subscribe but command queue was full!\n");
      }
      else
      {
        LOG_ERR("Failed to subscribe with %u\n", status);
      }
      etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
    }
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static mqtt_status_t
connect_to_broker(void)
{
  LOG_DBG("Sending connect request to broker at [" MQTT_CLIENT_BROKER_IP_ADDR "]:%u\n", DEFAULT_BROKER_PORT);

  /* Connect to MQTT server */
  mqtt_status_t status;
  status = mqtt_connect(&conn, (char*)MQTT_CLIENT_BROKER_IP_ADDR, DEFAULT_BROKER_PORT,
                        (DEFAULT_PUBLISH_INTERVAL * 3) / CLOCK_SECOND,
                        MQTT_CLEAN_SESSION_ON);
  if (status == MQTT_STATUS_OK)
  {
    state = STATE_CONNECTING;
  }
  else
  {
    LOG_ERR("mqtt_connect failed with error %u\n", status);
  }

  return status;
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
state_machine(void)
{
  mqtt_status_t status;

  LOG_DBG("state_machine() [state = %u]\n", state);

  switch (state)
  {
  case STATE_INIT:
    LOG_DBG("Performing init...\n");
    /* If we have just been configured register MQTT connection */
    /* _register() will set auto_reconnect. */
    status = mqtt_register(&conn, &mqtt_client_process, client_id, mqtt_event, MAX_TCP_SEGMENT_SIZE);
    if (status != MQTT_STATUS_OK)
    {
      LOG_ERR("mqtt_register failed\n");
    }

    mqtt_set_username_password(&conn, MQTT_CLIENT_USERNAME, MQTT_CLIENT_AUTH_TOKEN);

    state = STATE_REGISTERED;
    LOG_DBG("MQTT register complete!\n");
    // Continue

  case STATE_REGISTERED:
    if (have_connectivity())
    {
      LOG_DBG("Have connectivity, so attempting to connect to broker...\n");
      status = connect_to_broker();

      if (status == MQTT_STATUS_OK)
      {
        LOG_DBG("Connecting...\n");
      }
      else
      {
        etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
      }
    }
    else
    {
      LOG_DBG("No connectivity, so cannot attempt to connect to broker\n");
      ping_parent();
    }
    break;

  case STATE_CONNECTING:
    /* Not connected yet. Wait */
    LOG_DBG("Connecting...\n");
    break;

  case STATE_CONNECTED:
    LOG_DBG("Connected! Sending subscribe requests...\n");
    subscribe();
    break;

  case STATE_DISCONNECTED: {
    LOG_DBG("Disconnected, attempting to reconnect...\n");
    // Disconnect and backoff
    mqtt_disconnect(&conn);

    etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);

    state = STATE_REGISTERED;
  } break;

  case STATE_ERROR:
    // Try again in a bit
    state = STATE_REGISTERED;
    etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
    break;
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(mqtt_client_process, ev, data)
{
  PROCESS_BEGIN();

  init();

  uip_icmp6_echo_reply_callback_add(&echo_reply_notification, echo_reply_handler);
  etimer_set(&echo_request_timer, DEFAULT_PING_INTERVAL);

  /* Main loop */
  while (1) {
    PROCESS_YIELD();

    if ((ev == PROCESS_EVENT_TIMER && data == &publish_periodic_timer) || ev == PROCESS_EVENT_POLL) {
      state_machine();
    }

    if (ev == PROCESS_EVENT_TIMER && data == &echo_request_timer) {
      ping_parent();
    }
  }

  PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
