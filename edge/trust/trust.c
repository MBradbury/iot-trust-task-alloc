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
static char pub_topic[MAX_PUBLISH_TOPIC_LEN];
/*-------------------------------------------------------------------------------------------------------------------*/
#define PUBLISH_PERIOD             (CLOCK_SECOND * 60)
/*-------------------------------------------------------------------------------------------------------------------*/
#define MAX_PUBLISH_LEN            (128)
static char publish_buffer[MAX_PUBLISH_LEN];
/*-------------------------------------------------------------------------------------------------------------------*/
extern struct mqtt_connection conn;
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
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_ADD
};
/*-------------------------------------------------------------------------------------------------------------------*/
void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len)
{
    // Interested in "iot/edge/+/fmt/json" events
    LOG_DBG("Pub Handler: topic='%s' (len=%u), chunk_len=%u\n", topic, (topic_end - topic), chunk_len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
mqtt_status_t
publish_announce(struct mqtt_connection* conn, char* app_buffer, size_t app_buffer_len)
{
    int ret;

    if (!conn || conn->state != MQTT_CONN_STATE_CONNECTED_TO_BROKER)
    {
        return MQTT_CONN_STATE_NOT_CONNECTED;
    }

    snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN, MQTT_EDGE_ACTION_ANNOUNCE);
    // TODO: Error checking

    char ip_addr_buf[UIPLIB_IPV6_MAX_STR_LEN];
    ret = get_global_address(ip_addr_buf, sizeof(ip_addr_buf));
    if (!ret)
    {
        LOG_ERR("Failed to obtain global IP address\n");
    }
    else
    {
        // TODO: handle
    }

    snprintf(app_buffer, app_buffer_len,
        "{"
            "\"addr\":\"%s\""
        "}",
        ip_addr_buf
    );
    // TODO: Error checking

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, app_buffer);

    return mqtt_publish(conn, NULL, pub_topic,
                        (uint8_t*)app_buffer, strlen(app_buffer),
                        MQTT_QOS_LEVEL_0, MQTT_RETAIN_ON);
}
/*-------------------------------------------------------------------------------------------------------------------*/
mqtt_status_t
publish_add_capability(struct mqtt_connection* conn, char* app_buffer, size_t app_buffer_len, const char* name)
{
    if (!conn || conn->state != MQTT_CONN_STATE_CONNECTED_TO_BROKER)
    {
        return MQTT_CONN_STATE_NOT_CONNECTED;
    }

    snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
             MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_ADD, name);
    // TODO: Error checking

    snprintf(app_buffer, app_buffer_len,
        "{"
        "}"
    );
    // TODO: Error checking

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, app_buffer);

    return mqtt_publish(conn, NULL, pub_topic,
                        (uint8_t*)app_buffer, strlen(app_buffer),
                        MQTT_QOS_LEVEL_0, MQTT_RETAIN_ON);
}
/*-------------------------------------------------------------------------------------------------------------------*/
mqtt_status_t
publish_remove_capability(struct mqtt_connection* conn, char* app_buffer, size_t app_buffer_len, const char* name)
{
    if (!conn || conn->state != MQTT_CONN_STATE_CONNECTED_TO_BROKER)
    {
        return MQTT_CONN_STATE_NOT_CONNECTED;
    }

    snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
        MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_REMOVE, name);
    // TODO: Error checking

    snprintf(app_buffer, app_buffer_len,
        "{"
        "}"
    );
    // TODO: Error checking

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, app_buffer);

    return mqtt_publish(conn, NULL, pub_topic,
                        (uint8_t*)app_buffer, strlen(app_buffer),
                        MQTT_QOS_LEVEL_0, MQTT_RETAIN_ON);
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
static struct etimer timer;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
{
    PROCESS_BEGIN();

    init();

    /* Setup a periodic timer that expires after PERIOD seconds. */
    etimer_set(&timer, PUBLISH_PERIOD);

    while (1)
    {
        LOG_DBG("Attemding to publish announce...\n");
        mqtt_status_t status = publish_announce(&conn, publish_buffer, sizeof(publish_buffer));
        if (status != MQTT_STATUS_OK)
        {
            LOG_DBG("Failed to publish announce (%u)\n", status);
        }

        /* Wait for the periodic timer to expire and then restart the timer. */
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
        etimer_reset(&timer);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
