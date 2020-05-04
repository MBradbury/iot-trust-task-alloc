#include "trust.h"

#include "contiki.h"
#include "os/net/linkaddr.h"
#include "os/sys/log.h"
#include "uip.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"

#include <stdio.h>

#include "applications.h"
#include "trust-common.h"
#include "mqtt-over-coap.h"

#include "monitoring.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define BASE_PUBLISH_TOPIC_LEN     (10 + MQTT_IDENTITY_LEN)
#define MAX_PUBLISH_TOPIC_LEN      (64)
#define MAX_PUBLISH_LEN            (128)
/*-------------------------------------------------------------------------------------------------------------------*/
static char pub_topic[MAX_PUBLISH_TOPIC_LEN];
/*-------------------------------------------------------------------------------------------------------------------*/
#define PUBLISH_ANNOUNCE_PERIOD    (CLOCK_SECOND * 120)
#define PUBLISH_CAPABILITY_PERIOD  (CLOCK_SECOND * 5)
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_announce_timer;
static struct etimer publish_capability_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
get_global_address(char* buf, size_t buf_len)
{
  for (int i = 0; i < UIP_DS6_ADDR_NB; i++)
  {
    uint8_t state = uip_ds6_if.addr_list[i].state;

    if (uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED))
    {
      uiplib_ipaddr_snprint(buf, buf_len, &uip_ds6_if.addr_list[i].ipaddr);
      return true;
    }
  }

  return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN] = {
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_ANNOUNCE,
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_ADD,
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_REMOVE,
};
/*-------------------------------------------------------------------------------------------------------------------*/
void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len)
{
    // Interested in "iot/edge/+/fmt/json" events
    LOG_DBG("Pub Handler: topic='%s' (len=%u), chunk_len=%u\n", topic, (topic_end - topic), chunk_len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_announce(void)
{
    int ret;

    snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN, MQTT_EDGE_ACTION_ANNOUNCE);
    // TODO: Error checking

    char ip_addr_buf[UIPLIB_IPV6_MAX_STR_LEN];
    ret = get_global_address(ip_addr_buf, sizeof(ip_addr_buf));
    if (!ret)
    {
        LOG_ERR("Failed to obtain global IP address\n");
        return false;
    }

    char publish_buffer[MAX_PUBLISH_LEN];
    int len = snprintf(publish_buffer, sizeof(publish_buffer),
        "{"
            "\"addr\":\"%s\""
        "}",
        ip_addr_buf
    );
    if (len <= 0 || len >= sizeof(publish_buffer))
    {
        return false;
    }

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, publish_buffer);

    return mqtt_over_coap_publish(pub_topic, publish_buffer, len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_add_capability(const char* name)
{
    snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
             MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_ADD, name);
    // TODO: Error checking

    char publish_buffer[MAX_PUBLISH_LEN];
    int len = snprintf(publish_buffer, sizeof(publish_buffer),
        "{"
        "}"
    );
    if (len <= 0 || len >= sizeof(publish_buffer))
    {
        return false;
    }

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, publish_buffer);

    return mqtt_over_coap_publish(pub_topic, publish_buffer, len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_remove_capability(const char* name)
{
    snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
        MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_REMOVE, name);
    // TODO: Error checking

    char publish_buffer[MAX_PUBLISH_LEN];
    int len = snprintf(publish_buffer, sizeof(publish_buffer),
        "{"
        "}"
    );
    if (len <= 0 || len >= sizeof(publish_buffer))
    {
        return false;
    }

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, publish_buffer);

    return mqtt_over_coap_publish(pub_topic, publish_buffer, len+1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_publish_announce(void)
{
    LOG_DBG("Attempting to publish announce...\n");
    bool ret = publish_announce();
    if (!ret)
    {
        LOG_DBG("Failed to publish announce\n");
    }
    else
    {
        LOG_DBG("Announce sent!\n");
        etimer_set(&publish_capability_timer, PUBLISH_CAPABILITY_PERIOD);
    }

    etimer_reset(&publish_announce_timer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_publish_capability(void)
{
    LOG_DBG("Attempting to publish capabilities...\n");
    // TODO: This needs to be based off services running on the Edge observer node this sensor node is connected to.

    publish_add_capability(MONITORING_APPLICATION_NAME);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    int len = snprintf(pub_topic, BASE_PUBLISH_TOPIC_LEN+1, MQTT_EDGE_NAMESPACE "/%02x%02x%02x%02x%02x%02x/",
                       linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
                       linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[5],
                       linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);
    if (len != BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("Failed to create pub_topic (%d != %u)\n", len, BASE_PUBLISH_TOPIC_LEN);
    }

    LOG_DBG("Base MQTT topic is set to %s\n", pub_topic);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
{
    PROCESS_BEGIN();

    init();

    /* Setup a periodic timer that expires after PERIOD seconds. */
    etimer_set(&publish_announce_timer, PUBLISH_ANNOUNCE_PERIOD);

    while (1)
    {
        PROCESS_YIELD();

        if (ev == PROCESS_EVENT_TIMER && data == &publish_announce_timer) {
          periodic_publish_announce();
        }

        if (ev == PROCESS_EVENT_TIMER && data == &publish_capability_timer) {
          periodic_publish_capability();
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
