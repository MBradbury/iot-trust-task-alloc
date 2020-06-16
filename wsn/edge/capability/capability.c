#include "capability.h"
#include "edge.h"

#include "contiki.h"
#include "os/net/linkaddr.h"
#include "os/net/ipv6/uip.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"
#include "os/sys/log.h"

#include <stdio.h>

#include "applications.h"
#include "trust-common.h"
#include "mqtt-over-coap.h"
#include "keys.h"

#include "monitoring.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define BASE_PUBLISH_TOPIC_LEN     (MQTT_EDGE_NAMESPACE_LEN + 1 + MQTT_IDENTITY_LEN + 1)
#define MAX_PUBLISH_TOPIC_LEN      (BASE_PUBLISH_TOPIC_LEN + 64)
/*-------------------------------------------------------------------------------------------------------------------*/
static char pub_topic[MAX_PUBLISH_TOPIC_LEN];
/*-------------------------------------------------------------------------------------------------------------------*/
#define PUBLISH_ANNOUNCE_PERIOD_SHORT   (CLOCK_SECOND * 2 * 60)
#define PUBLISH_ANNOUNCE_PERIOD_LONG    (PUBLISH_ANNOUNCE_PERIOD_SHORT * 15)
#define PUBLISH_CAPABILITY_PERIOD_SHORT (CLOCK_SECOND * 5)
#define PUBLISH_CAPABILITY_PERIOD_LONG  (PUBLISH_CAPABILITY_PERIOD_SHORT * (APPLICATION_NUM + 10))
#define PUBLISH_ANNOUNCE_SHORT_TO_LONG 5
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_announce_timer;
static struct etimer publish_capability_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static uint8_t announce_short_count;
/*-------------------------------------------------------------------------------------------------------------------*/
static uint8_t application_capability_publish_idx;
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
bool
publish_announce(void)
{
    int ret;

    ret = snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN, MQTT_EDGE_ACTION_ANNOUNCE);
    if (ret <= 0 || ret >= MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("snprintf pub_topic failed %d\n", ret);
        return false;
    }

    char ip_addr_buf[UIPLIB_IPV6_MAX_STR_LEN];
    ret = get_global_address(ip_addr_buf, sizeof(ip_addr_buf));
    if (!ret)
    {
        LOG_ERR("Failed to obtain global IP address\n");
        return false;
    }

    char publish_buffer[2 + 9 + UIPLIB_IPV6_MAX_STR_LEN + 1 + DTLS_EC_KEY_SIZE*4];
    ret = snprintf(publish_buffer, sizeof(publish_buffer),
        "{"
            "\"addr\":\"%s\""
        "}",
        ip_addr_buf
    );
    if (ret <= 0 || ret >= sizeof(publish_buffer))
    {
        return false;
    }

    char* buf_ptr = publish_buffer + ret + 1;

    // Include our public key and certificate here
    memcpy(buf_ptr + DTLS_EC_KEY_SIZE*0, our_key.pub_key.x, DTLS_EC_KEY_SIZE);
    memcpy(buf_ptr + DTLS_EC_KEY_SIZE*1, our_key.pub_key.y, DTLS_EC_KEY_SIZE);
    memcpy(buf_ptr + DTLS_EC_KEY_SIZE*2, our_pubkey_sig.r,  DTLS_EC_KEY_SIZE);
    memcpy(buf_ptr + DTLS_EC_KEY_SIZE*3, our_pubkey_sig.s,  DTLS_EC_KEY_SIZE);

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, publish_buffer);

    return mqtt_over_coap_publish(pub_topic, publish_buffer, ret+1+DTLS_EC_KEY_SIZE*4);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_unannounce(void)
{
    int ret;

    ret = snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN, MQTT_EDGE_ACTION_UNANNOUNCE);
    if (ret <= 0 || ret >= MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("snprintf pub_topic failed %d\n", ret);
        return false;
    }

    char ip_addr_buf[UIPLIB_IPV6_MAX_STR_LEN];
    ret = get_global_address(ip_addr_buf, sizeof(ip_addr_buf));
    if (!ret)
    {
        LOG_ERR("Failed to obtain global IP address\n");
        return false;
    }

    char publish_buffer[2 + 9 + UIPLIB_IPV6_MAX_STR_LEN + 1];
    ret = snprintf(publish_buffer, sizeof(publish_buffer),
        "{"
            "\"addr\":\"%s\""
        "}",
        ip_addr_buf
    );
    if (ret <= 0 || ret >= sizeof(publish_buffer))
    {
        return false;
    }

    LOG_DBG("Publishing unannounce [topic=%s, data=%s]\n", pub_topic, publish_buffer);

    return mqtt_over_coap_publish(pub_topic, publish_buffer, ret+1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_add_capability(const char* name)
{
    int ret;

    ret = snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
                   MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_ADD, name);
    if (ret <= 0 || ret >= MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("snprintf pub_topic failed %d\n", ret);
        return false;
    }

    char publish_buffer[2 + 1];
    ret = snprintf(publish_buffer, sizeof(publish_buffer),
        "{"
        "}"
    );
    if (ret <= 0 || ret >= sizeof(publish_buffer))
    {
        return false;
    }

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, publish_buffer);

    return mqtt_over_coap_publish(pub_topic, publish_buffer, ret+1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_remove_capability(const char* name)
{
    int ret;

    ret = snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
                   MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_REMOVE, name);
    if (ret <= 0 || ret >= MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("snprintf pub_topic failed %d\n", ret);
        return false;
    }

    char publish_buffer[2 + 1];
    ret = snprintf(publish_buffer, sizeof(publish_buffer),
        "{"
        "}"
    );
    if (ret <= 0 || ret >= sizeof(publish_buffer))
    {
        return false;
    }

    LOG_DBG("Publishing announce [topic=%s, data=%s]\n", pub_topic, publish_buffer);

    return mqtt_over_coap_publish(pub_topic, publish_buffer, ret+1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
trigger_faster_publish(void)
{
    clock_time_t remaining;

    remaining = timer_remaining(&publish_announce_timer.timer);
    if (remaining > PUBLISH_ANNOUNCE_PERIOD_SHORT)
    {
        etimer_reset_with_new_interval(&publish_announce_timer, PUBLISH_CAPABILITY_PERIOD_SHORT);
    }

    announce_short_count = 0;

    // Restart capability publishing from 1st capability
    application_capability_publish_idx = 0;

    etimer_stop(&publish_capability_timer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_publish_announce(void)
{
    bool ret;
    if (resource_rich_edge_started)
    {
        LOG_DBG("Attempting to publish announce...\n");
        ret = publish_announce();
    }
    else
    {
        LOG_DBG("Attempting to publish unannounce...\n");
        ret = publish_unannounce();
    }

    if (!ret)
    {
        LOG_ERR("Failed to publish (un)announce\n");
    }
    else
    {
        if (resource_rich_edge_started)
        {
            // Don't send capabilities until we have announced ourselves
            LOG_DBG("Announce sent! Starting capability publish timer...\n");
            etimer_set(&publish_capability_timer, PUBLISH_CAPABILITY_PERIOD_SHORT);
        }
        else
        {
            // Don't publish capabilities, if nothing connected
            etimer_stop(&publish_capability_timer);
        }
    }

    // If on the short interval, might need to transition to the long interval
    if (publish_announce_timer.timer.interval == PUBLISH_ANNOUNCE_PERIOD_SHORT)
    {
        // Only increment short count, if we managed to successfully publish the announce
        if (ret)
        {
            announce_short_count += 1;
        }

        if (announce_short_count >= PUBLISH_ANNOUNCE_SHORT_TO_LONG)
        {
            LOG_DBG("Moving to less frequent announce intervals\n");
            etimer_reset_with_new_interval(&publish_announce_timer, PUBLISH_ANNOUNCE_PERIOD_LONG);
        }
        else
        {
            etimer_reset(&publish_announce_timer);
        }
    }
    else
    {
        etimer_reset(&publish_announce_timer);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_publish_capability(void)
{
    // The current application we need to publish information about
    const char* application_name = application_names[application_capability_publish_idx];

    LOG_DBG("Attempting to publish capability for %s at %" PRIu8 "\n", application_name, application_capability_publish_idx);

    bool ret;

    // Check if it is available
    if (applications_available[application_capability_publish_idx])
    {
        ret = publish_add_capability(application_name);
    }
    else
    {
        ret = publish_remove_capability(application_name);
    }

    // Move onto next capability if we succeeded in publishing this one
    if (ret)
    {
        application_capability_publish_idx += 1;
    }
    else
    {
        LOG_ERR("Capability publish failed\n");
    }

    if (application_capability_publish_idx == APPLICATION_NUM)
    {
        etimer_reset_with_new_interval(&publish_capability_timer, PUBLISH_CAPABILITY_PERIOD_LONG);
        application_capability_publish_idx = 0;
    }
    else
    {
        etimer_reset_with_new_interval(&publish_capability_timer, PUBLISH_CAPABILITY_PERIOD_SHORT);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
init(void)
{
    // Create an id for this edge node
    int len = snprintf(pub_topic, BASE_PUBLISH_TOPIC_LEN+1, MQTT_EDGE_NAMESPACE "/%02x%02x%02x%02x%02x%02x%02x%02x/",
                       linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
                       linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[3],
                       linkaddr_node_addr.u8[4], linkaddr_node_addr.u8[5],
                       linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);
    if (len != BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("Failed to create pub_topic (%d != %u)\n", len, BASE_PUBLISH_TOPIC_LEN);
        return false;
    }

    LOG_DBG("Base MQTT topic is set to %s\n", pub_topic);

    trust_common_init();

    announce_short_count = 0;

    application_capability_publish_idx = 0;

    // Start timer for periodic announce
    etimer_set(&publish_announce_timer, PUBLISH_ANNOUNCE_PERIOD_SHORT);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(capability, "Announce and Capability process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(capability, ev, data)
{
    PROCESS_BEGIN();

    bool ret = init();
    if (!ret)
    {
        PROCESS_EXIT();
    }

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
