#include "trust.h"

#include "contiki.h"
#include "os/net/linkaddr.h"
#include "os/sys/log.h"
#include "uip.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"

#include <stdio.h>

/*-------------------------------------------------------------------------------------------------------------------*/
#define BASE_PUBLISH_TOPIC_LEN     (21)
#define ANNOUNCE_PUBLISH_TOPIC_LEN (BASE_PUBLISH_TOPIC_LEN + 9)
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-model"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static char base_pub_topic[BASE_PUBLISH_TOPIC_LEN + 1];
/*-------------------------------------------------------------------------------------------------------------------*/
static int
get_global_address(char* buf, size_t buf_len)
{
  for (int i = 0; i < UIP_DS6_ADDR_NB; i++)
  {
    uint8_t state = uip_ds6_if.addr_list[i].state;

    if (uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED))
    {
      uiplib_ipaddr_snprint(buf, buf_len, &uip_ds6_if.addr_list[i].ipaddr);
      return 1;
    }
  }

  return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
mqtt_status_t
publish_announce(struct mqtt_connection* conn, char* app_buffer, size_t app_buffer_len)
{
	int ret;

	char pub_topic[ANNOUNCE_PUBLISH_TOPIC_LEN + 1];
	snprintf(pub_topic, sizeof(pub_topic), "%s/announce", base_pub_topic);

	char ip_addr_buf[UIPLIB_IPV6_MAX_STR_LEN];
	ret = get_global_address(ip_addr_buf, sizeof(ip_addr_buf));
	if (!ret)
	{
		LOG_ERR("Failed to obtain global IP address\n");
	}

	snprintf(app_buffer, app_buffer_len,
		"{"
			"addr:%s"
		"}",
		ip_addr_buf
	);

	LOG_DBG("Publishing announce [topic=%s, data=%s]", pub_topic, app_buffer);

	return mqtt_publish(conn, NULL, pub_topic, (uint8_t*)app_buffer, strlen(app_buffer), MQTT_QOS_LEVEL_0, MQTT_RETAIN_ON);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
{
    PROCESS_BEGIN();

    snprintf(base_pub_topic, sizeof(base_pub_topic), "iot/edge/%02x%02x%02x%02x%02x%02x",
		linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
		linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[5],
		linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);

    LOG_DBG("Base MQTT topic is set to %s", base_pub_topic);

    while (1)
    {
    	PROCESS_YIELD();
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
