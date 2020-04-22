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

#include "mqtt-client.h"

#include <string.h>
#include <strings.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "mqtt-client"
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
/*
 * A timeout used when waiting for something to happen (e.g. to connect or to
 * disconnect)
 */
#define STATE_MACHINE_PERIODIC     (CLOCK_SECOND >> 1)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Provide visible feedback via LEDS during various states */
/* When connecting to broker */
#define CONNECTING_LED_DURATION    (CLOCK_SECOND >> 2)

/* Each time we try to publish */
#define PUBLISH_LED_ON_DURATION    (CLOCK_SECOND)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Connections and reconnections */
#define RETRY_FOREVER              0xFF
#define RECONNECT_INTERVAL         (CLOCK_SECOND * 2)

/*
 * Number of times to try reconnecting to the broker.
 * Can be a limited number (e.g. 3, 10 etc) or can be set to RETRY_FOREVER
 */
#define RECONNECT_ATTEMPTS         RETRY_FOREVER
#define CONNECTION_STABLE_TIME     (CLOCK_SECOND * 5)
static struct timer connection_life;
/*-------------------------------------------------------------------------------------------------------------------*/
/* Various states */
static uint8_t state;
#define STATE_INIT            0
#define STATE_REGISTERED      1
#define STATE_CONNECTING      2
#define STATE_CONNECTED       3
#define STATE_SUBSCRIBED      4
#define STATE_CONFIG_ERROR 0xFE
#define STATE_ERROR        0xFF
/*-------------------------------------------------------------------------------------------------------------------*/
/* A timeout used when waiting to connect to a network */
#define NET_CONNECT_PERIODIC        (CLOCK_SECOND >> 2)
#define NO_NET_LED_DURATION         (NET_CONNECT_PERIODIC >> 1)
/*-------------------------------------------------------------------------------------------------------------------*/
/* Default configuration values */
#define DEFAULT_TYPE_ID             "mqtt-client"
#define DEFAULT_BROKER_PORT         1883
#define DEFAULT_PUBLISH_INTERVAL    (30 * CLOCK_SECOND)
#define DEFAULT_KEEP_ALIVE_TIMER    60
#define DEFAULT_PING_INTERVAL       (CLOCK_SECOND * 30)
/*-------------------------------------------------------------------------------------------------------------------*/
#define MQTT_CLIENT_SENSOR_NONE     (void *)0xFFFFFFFF
/*-------------------------------------------------------------------------------------------------------------------*/
/* Payload length of ICMPv6 echo requests used to measure RSSI with def rt */
#define ECHO_REQ_PAYLOAD_LEN   20
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
/*-------------------------------------------------------------------------------------------------------------------*/
/**
 * \brief Data structure declaration for the MQTT client configuration
 */
typedef struct mqtt_client_config {
  const char* org_id;
  const char* broker_ip;
  const char* cmd_type;
  clock_time_t pub_interval;
  int def_rt_ping_interval;
  uint16_t broker_port;
} mqtt_client_config_t;
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
static struct mqtt_connection conn;
/*-------------------------------------------------------------------------------------------------------------------*/
#define QUICKSTART "quickstart"
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_periodic_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
/* Parent RSSI functionality */
static struct uip_icmp6_echo_reply_notification echo_reply_notification;
static struct etimer echo_request_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static mqtt_client_config_t conf;
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
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
pub_handler(const char *topic, uint16_t topic_len, const uint8_t *chunk, uint16_t chunk_len)
{
  LOG_DBG("Pub Handler: topic='%s' (len=%u), chunk_len=%u\n", topic,
          topic_len, chunk_len);

  /* If we don't like the length, ignore */
  if (topic_len != 23 || chunk_len != 1) {
    LOG_ERR("Incorrect topic or chunk len. Ignored\n");
    return;
  }

  /* If the format != json, ignore */
  if (strncmp(&topic[topic_len - 4], "json", 4) != 0) {
    LOG_ERR("Incorrect format\n");
    return;
  }

  if (strncmp(&topic[10], "leds", 4) == 0) {
    LOG_DBG("Received MQTT SUB\n");
    if (chunk[0] == '1') {
      leds_on(LEDS_RED);
    } else if (chunk[0] == '0') {
      leds_off(LEDS_RED);
    }
    return;
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_event(struct mqtt_connection* m, mqtt_event_t event, void *data)
{
  switch (event) {
  case MQTT_EVENT_CONNECTED: {
    LOG_DBG("Application has a MQTT connection\n");
    timer_set(&connection_life, CONNECTION_STABLE_TIME);
    state = STATE_CONNECTED;
    break;
  }
  case MQTT_EVENT_DISCONNECTED: {
    LOG_DBG("MQTT Disconnect. Reason %u\n", *((mqtt_event_t *)data));
    break;
  }
  case MQTT_EVENT_PUBLISH: {
    struct mqtt_message *msg_ptr = (struct mqtt_message *)data;

    /* Implement first_flag in publish message? */
    if (msg_ptr->first_chunk) {
      msg_ptr->first_chunk = 0;
      LOG_DBG("Application received publish for topic '%s'. Payload "
              "size is %i bytes.\n", msg_ptr->topic, msg_ptr->payload_length);
    }

    pub_handler(msg_ptr->topic, strlen(msg_ptr->topic),
                msg_ptr->payload_chunk, msg_ptr->payload_length);
    break;
  }
  case MQTT_EVENT_SUBACK: {
#if MQTT_311
    mqtt_suback_event_t *suback_event = (mqtt_suback_event_t *)data;

    if (suback_event->success) {
      LOG_DBG("Application is subscribed to topic successfully\n");
    } else {
      LOG_DBG("Application failed to subscribe to topic (ret code %x)\n", suback_event->return_code);
    }
#else
    LOG_DBG("Application is subscribed to topic successfully\n");
#endif
    break;
  }
  case MQTT_EVENT_UNSUBACK: {
    LOG_DBG("Application is unsubscribed to topic successfully\n");
    break;
  }
  /*case MQTT_EVENT_PUBACK: {
    LOG_DBG("Publishing complete.\n");
    break;
  }*/


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
static int
construct_client_id(void)
{
  int len = snprintf(client_id, BUFFER_SIZE, "d:%s:#:%02x%02x%02x%02x%02x%02x",
                     conf.org_id,
                     linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
                     linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[5],
                     linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);

  /* len < 0: Error. Len >= BUFFER_SIZE: Buffer too small */
  if (len < 0 || len >= BUFFER_SIZE) {
    LOG_ERR("Client ID: %d, Buffer %d\n", len, BUFFER_SIZE);
    return 0;
  }

  return 1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
update_config(void)
{
  if (!construct_client_id()) {
    /* Fatal error. Client ID larger than the buffer */
    state = STATE_CONFIG_ERROR;
    return;
  }

  state = STATE_INIT;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
init_config(void)
{
  /* Populate configuration with default values */
  memset(&conf, 0, sizeof(mqtt_client_config_t));

  conf.org_id = MQTT_CLIENT_ORG_ID;
  conf.broker_ip = MQTT_CLIENT_BROKER_IP_ADDR;

  conf.broker_port = DEFAULT_BROKER_PORT;
  conf.pub_interval = DEFAULT_PUBLISH_INTERVAL;
  conf.def_rt_ping_interval = DEFAULT_PING_INTERVAL;

  return 1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
subscribe(void)
{
  /* Publish MQTT topic in IBM quickstart format */
  mqtt_status_t status;

  const char* sub_topic = "iot/edge/#";

  status = mqtt_subscribe(&conn, NULL, (char*)sub_topic, MQTT_QOS_LEVEL_0);

  LOG_DBG("Subscribing to '%s'!\n", sub_topic);
  if (status == MQTT_STATUS_OUT_QUEUE_FULL)
  {
    LOG_ERR("Tried to subscribe but command queue was full!\n");
  }
  else
  {
    LOG_DBG("Subscribed!\n");
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
connect_to_broker(void)
{
  LOG_DBG("Sending connect request to broker at [%s]:%u\n", conf.broker_ip, conf.broker_port);

  /* Connect to MQTT server */
  mqtt_connect(&conn, (char*)conf.broker_ip, conf.broker_port,
               (conf.pub_interval * 3) / CLOCK_SECOND,
               MQTT_CLEAN_SESSION_ON);

  state = STATE_CONNECTING;
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
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
state_machine(void)
{
  mqtt_status_t status;

  LOG_DBG("state_machine() [state = %u]\n", state);

  switch (state) {
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
    LOG_DBG("init complete!\n");
    // Continue

  case STATE_REGISTERED:
    LOG_DBG("Performing register...\n");
    if (have_connectivity()) {
      /* Registered and with a public IP. Connect */
      LOG_DBG("Registered!\n");
      ping_parent();
      connect_to_broker();
    } else {
      LOG_DBG("Failed to register, cannot attempt connect\n");
    }
    etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
    return;

  case STATE_CONNECTING:
    /* Not connected yet. Wait */
    LOG_DBG("Connecting...\n");
    break;

  case STATE_CONNECTED:
    LOG_DBG("Connected! Sending subscribe request...\n");
    subscribe();
    return;

  case STATE_SUBSCRIBED:
    //LOG_DBG("Subscribed!\n");
    return;

  case STATE_ERROR:
    // Try again in a bit
    state = STATE_REGISTERED;
    etimer_set(&publish_periodic_timer, NET_CONNECT_PERIODIC);
    return;
  }

  /* If we didn't return so far, reschedule ourselves */
  etimer_set(&publish_periodic_timer, STATE_MACHINE_PERIODIC);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(mqtt_client_process, ev, data)
{
  PROCESS_BEGIN();

  printf("MQTT Client Process\n");

  if (init_config() != 1) {
    PROCESS_EXIT();
  }

  update_config();

  uip_icmp6_echo_reply_callback_add(&echo_reply_notification, echo_reply_handler);
  etimer_set(&echo_request_timer, conf.def_rt_ping_interval);

  /* Main loop */
  while (1) {
    PROCESS_YIELD();

    if ((ev == PROCESS_EVENT_TIMER && data == &publish_periodic_timer) || ev == PROCESS_EVENT_POLL) {
      state_machine();
    }

    if (ev == PROCESS_EVENT_TIMER && data == &echo_request_timer) {
      ping_parent();
      etimer_set(&echo_request_timer, conf.def_rt_ping_interval);
    }
  }

  PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
