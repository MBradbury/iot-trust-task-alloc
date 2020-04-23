#include "trust.h"
#include "edge-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uiplib.h"

#include <stdio.h>
#include <ctype.h>

#include "trust-common.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-model"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN] = {
	MQTT_EDGE_NAMESPACE "/+/announce",
	MQTT_EDGE_NAMESPACE "/+/capability/+"
};
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_publish_announce_handler(const char *topic, uint16_t topic_len,
	                          const uint8_t *chunk, uint16_t chunk_len,
	                          const char* topic_identity)
{
	struct jsonparse_state state;
	jsonparse_setup(&state, (const char*)chunk, chunk_len);

	int next;

	if ((next = jsonparse_next(&state)) != '{')
	{
		LOG_ERR("jsonparse_next 1 (next=%d)\n", next);
		return;
	}

	if ((next = jsonparse_next(&state)) != JSON_TYPE_PAIR_NAME)
	{
		LOG_ERR("jsonparse_next 2 (next=%d)\n", next);
		return;
	}

	if (jsonparse_strcmp_value(&state, "addr") != 0)
	{
		LOG_ERR("jsonparse_next 3\n");
		return;
	}

	if ((next = jsonparse_next(&state)) != '"')
	{
		LOG_ERR("jsonparse_next 4 (next=%d)\n", next);
		return;
	}

	char ip_addr_buf[UIPLIB_IPV6_MAX_STR_LEN];
	jsonparse_copy_value(&state, ip_addr_buf, sizeof(ip_addr_buf));

	uip_ipaddr_t ip_addr;
	uiplib_ip6addrconv(ip_addr_buf, &ip_addr);

	if (jsonparse_next(&state) != '}')
	{
		LOG_ERR("jsonparse_next 5\n");
		return;
	}

	edge_resource_t* edge_resource = edge_info_add(ip_addr, topic_identity);
	if (edge_resource != NULL)
	{
		LOG_DBG("Received announce for %s with address %s\n", topic_identity, ip_addr_buf);
	}
	else
	{
		LOG_ERR("Failed to allocate edge resource\n");
	}
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_publish_capability_handler(const char *topic, uint16_t topic_len,
	                            const uint8_t *chunk, uint16_t chunk_len,
	                            const char* topic_identity)
{
	edge_resource_t* edge = edge_info_find_ident(topic_identity);
	if (edge == NULL)
	{
		LOG_ERR("Failed to find edge with identity %s\n", topic_identity);
		return;
	}

	// TODO: Parse capability name
	// TODO: Add to edge information
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
mqtt_publish_handler(const char *topic, uint16_t topic_len, const uint8_t *chunk, uint16_t chunk_len)
{
	// Interested in "iot/edge/+/fmt/json" events
	LOG_DBG("Pub Handler: topic='%s' (len=%u), chunk_len=%u\n", topic, topic_len, chunk_len);

	int ret;

	// First check that we are in the right namespace
	ret = strncmp(MQTT_EDGE_NAMESPACE, topic, MQTT_EDGE_NAMESPACE_LEN);
	if (ret != 0)
	{
		LOG_ERR("Initial prefix does not match " MQTT_EDGE_NAMESPACE "\n");
		return;
	}

	// Consume '/'
	topic += MQTT_EDGE_NAMESPACE_LEN;
	topic_len -= MQTT_EDGE_NAMESPACE_LEN;

	if (topic_len < 2 + MQTT_IDENTITY_LEN || *topic != '/')
	{
		LOG_ERR("Topic does not contain identity\n");
		return;
	}

	topic += 1;
	topic_len -= 1;

	// Check that the identiy is hex
	for (int i = 0; i != MQTT_IDENTITY_LEN; ++i)
	{
		if (!isxdigit(topic[i]))
		{
			LOG_ERR("Topic identity is in an invalid format (char %u = %c)\n", i, topic[i]);
			return;
		}
	}

	char topic_identity[MQTT_IDENTITY_LEN + 1];
	strncpy(topic_identity, topic, MQTT_IDENTITY_LEN);
	*(topic_identity + MQTT_IDENTITY_LEN) = '\0';

	topic += MQTT_IDENTITY_LEN;
	topic_len -= MQTT_IDENTITY_LEN;

	if (*topic != '/')
	{
		LOG_ERR("Bad separator\n");
		return;
	}

	topic += 1;
	topic_len -= 1;

	if (strcmp("announce", topic) == 0)
	{
		topic += strlen("announce");
		topic_len -= strlen("announce");

		mqtt_publish_announce_handler(topic, topic_len, chunk, chunk_len, topic_identity);
	}
	else if (strcmp("capability", topic) == 0)
	{
		topic += strlen("capability");
		topic_len -= strlen("capability");

		mqtt_publish_capability_handler(topic, topic_len, chunk, chunk_len, topic_identity);
	}
	else
	{
		LOG_ERR("Unknown topic\n");
	}
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{

}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
{
    PROCESS_BEGIN();

    init();
    edge_info_init();

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
