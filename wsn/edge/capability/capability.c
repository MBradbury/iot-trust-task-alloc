#include "capability.h"
#include "edge.h"

#include "contiki.h"
#include "os/net/linkaddr.h"
#include "os/net/ipv6/uip.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"
#include "os/sys/log.h"
#include "os/lib/assert.h"

#include "nanocbor-helper.h"

#include <stdio.h>

#include "applications.h"
#include "trust-common.h"
#include "mqtt-over-coap.h"
#include "keys.h"
#include "stereotype-tags.h"
#include "certificate.h"
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
#define PUBLISH_ANNOUNCE_PERIOD_SHORT   (CLOCK_SECOND * 30)
#define PUBLISH_ANNOUNCE_PERIOD_LONG    (PUBLISH_ANNOUNCE_PERIOD_SHORT * 2 * 15)
#define PUBLISH_CAPABILITY_PERIOD_SHORT (CLOCK_SECOND * 5)
#define PUBLISH_CAPABILITY_PERIOD_LONG  (PUBLISH_CAPABILITY_PERIOD_SHORT * (APPLICATION_NUM + 20))
#define PUBLISH_ANNOUNCE_SHORT_TO_LONG 3
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(capability, "Announce and Capability process");
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_announce_timer;
static struct etimer publish_capability_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static uint8_t announce_short_count;
/*-------------------------------------------------------------------------------------------------------------------*/
static uint8_t application_capability_publish_idx;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
get_global_address(uip_ip6addr_t* addr)
{
  for (int i = 0; i < UIP_DS6_ADDR_NB; i++)
  {
    uint8_t state = uip_ds6_if.addr_list[i].state;

    if (uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED))
    {
      uip_ipaddr_copy(addr, &uip_ds6_if.addr_list[i].ipaddr);
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

    uint8_t cbor_buffer[CERTIFICATE_CBOR_LENGTH];

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, cbor_buffer, sizeof(cbor_buffer));
    NANOCBOR_CHECK(certificate_encode(&enc, &our_cert));

    LOG_DBG("Publishing announce [topic=%s, datalen=%d]\n", pub_topic, nanocbor_encoded_len(&enc));

    assert(nanocbor_encoded_len(&enc) <= sizeof(cbor_buffer));

    return mqtt_over_coap_publish(pub_topic, cbor_buffer, nanocbor_encoded_len(&enc));
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

    uip_ip6addr_t ip_addr;
    ret = get_global_address(&ip_addr);
    if (!ret)
    {
        LOG_ERR("Failed to obtain global IP address\n");
        return false;
    }

    uint8_t cbor_buffer[(1) + IPV6ADDR_CBOR_MAX_LEN];

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, cbor_buffer, sizeof(cbor_buffer));

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 1));
    NANOCBOR_CHECK(nanocbor_fmt_ipaddr(&enc, &ip_addr));

    LOG_DBG("Publishing unannounce [topic=%s, datalen=%d]\n", pub_topic, nanocbor_encoded_len(&enc));

    assert(nanocbor_encoded_len(&enc) == sizeof(cbor_buffer));

    return mqtt_over_coap_publish(pub_topic, cbor_buffer, nanocbor_encoded_len(&enc));
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_add_capability(const char* name, bool include_certificate)
{
    int ret;

    ret = snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
                   MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_ADD, name);
    if (ret <= 0 || ret >= MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("snprintf pub_topic failed %d\n", ret);
        return false;
    }

    uint8_t cbor_buffer[(1) + (1) + CERTIFICATE_CBOR_LENGTH];

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, cbor_buffer, sizeof(cbor_buffer));

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 2));
    NANOCBOR_CHECK(nanocbor_fmt_bool(&enc, include_certificate));

    if (include_certificate)
    {
        NANOCBOR_CHECK(certificate_encode(&enc, &our_cert));
    }
    else
    {
        NANOCBOR_CHECK(nanocbor_fmt_null(&enc));
    }

    LOG_DBG("Publishing add [topic=%s, datalen=%d]\n", pub_topic, nanocbor_encoded_len(&enc));

    assert(nanocbor_encoded_len(&enc) <= sizeof(cbor_buffer));

    return mqtt_over_coap_publish(pub_topic, cbor_buffer, nanocbor_encoded_len(&enc));
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
publish_remove_capability(const char* name, bool include_certificate)
{
    int ret;

    ret = snprintf(pub_topic + BASE_PUBLISH_TOPIC_LEN, MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN,
                   MQTT_EDGE_ACTION_CAPABILITY "/%s/" MQTT_EDGE_ACTION_CAPABILITY_REMOVE, name);
    if (ret <= 0 || ret >= MAX_PUBLISH_TOPIC_LEN - BASE_PUBLISH_TOPIC_LEN)
    {
        LOG_ERR("snprintf pub_topic failed %d\n", ret);
        return false;
    }

    uint8_t cbor_buffer[(1) + (1) + CERTIFICATE_CBOR_LENGTH];

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, cbor_buffer, sizeof(cbor_buffer));

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 2));
    NANOCBOR_CHECK(nanocbor_fmt_bool(&enc, include_certificate));

    if (include_certificate)
    {
        NANOCBOR_CHECK(certificate_encode(&enc, &our_cert));
    }
    else
    {
        NANOCBOR_CHECK(nanocbor_fmt_null(&enc));
    }

    LOG_DBG("Publishing remove [topic=%s, datalen=%d]\n", pub_topic, nanocbor_encoded_len(&enc));

    assert(nanocbor_encoded_len(&enc) <= sizeof(cbor_buffer));

    return mqtt_over_coap_publish(pub_topic, cbor_buffer, nanocbor_encoded_len(&enc));
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
trigger_faster_publish(void)
{
    clock_time_t remaining;

    LOG_INFO("Triggering a faster publish of announce\n");

    remaining = timer_remaining(&publish_announce_timer.timer);
    if (remaining > PUBLISH_ANNOUNCE_PERIOD_SHORT)
    {
        LOG_DBG("publish_announce_timer: Resetting timer = %d\n", PUBLISH_ANNOUNCE_PERIOD_SHORT);

        // This function might be called outside of the capability context
        // so we need to ensure that the publish_announce_timer will be linked to the capability process
        PROCESS_CONTEXT_BEGIN(&capability);
        etimer_reset_with_new_interval(&publish_announce_timer, PUBLISH_ANNOUNCE_PERIOD_SHORT);
        PROCESS_CONTEXT_END(&capability);
    }
    else
    {
        LOG_DBG("publish_announce_timer: no need to reset, time remaining = %" PRIu32 " <= %d\n",
            remaining, PUBLISH_ANNOUNCE_PERIOD_SHORT);
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
        LOG_INFO("Attempting to publish announce...\n");
        ret = publish_announce();
    }
    else
    {
        LOG_INFO("Attempting to publish unannounce...\n");
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
            LOG_DBG("Announce sent! Starting capability publish timer.\n");
            etimer_set(&publish_capability_timer, PUBLISH_CAPABILITY_PERIOD_SHORT);
        }
        else
        {
            // Don't publish capabilities, if nothing connected
            LOG_DBG("Unannounce sent! Stopping capability publish timer.\n");
            etimer_stop(&publish_capability_timer);
        }
    }

    // If on the short interval, might need to transition to the long interval
    if (publish_announce_timer.timer.interval <= PUBLISH_ANNOUNCE_PERIOD_SHORT)
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
    // Do not include the certificate in these messages as they are intended to be lightweight and periodic
    if (applications_available[application_capability_publish_idx])
    {
        ret = publish_add_capability(application_name, false);
    }
    else
    {
        ret = publish_remove_capability(application_name, false);
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
