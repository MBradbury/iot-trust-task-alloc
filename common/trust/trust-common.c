#include "trust-common.h"
#include "edge-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"

#include <stdio.h>
#include <ctype.h>

#include "applications.h"
#include "trust-common.h"
#include "crypto-support.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-common"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN] = {
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_ANNOUNCE,
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_ADD,
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_REMOVE,
};
/*-------------------------------------------------------------------------------------------------------------------*/
process_event_t pe_edge_capability_add;
process_event_t pe_edge_capability_remove;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool is_our_addr(const uip_ip6addr_t* addr)
{
    for (int i = 0; i < UIP_DS6_ADDR_NB; i++)
    {
        uint8_t state = uip_ds6_if.addr_list[i].state;

        if (uip_ds6_if.addr_list[i].isused &&
            (state == ADDR_TENTATIVE || state == ADDR_PREFERRED) &&
            uip_ip6addr_cmp(addr, &uip_ds6_if.addr_list[i].ipaddr)
            )
        {
            return true;
        }
    }
    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_publish_announce_handler(const char *topic, const char* topic_end,
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

    edge_resource_t* edge_resource = edge_info_add(&ip_addr, topic_identity);
    if (edge_resource != NULL)
    {
        LOG_DBG("Received announce for %s with address %s\n", topic_identity, ip_addr_buf);
    }
    else
    {
        LOG_ERR("Failed to allocate edge resource\n");
    }

    // We should connect to the Edge resource that has announced themselves here
    // This means that if we are using DTLS, the handshake has already been performed,
    // so we will be ready to communicate tasks to them and receive responses.
    // This should only be done if another edge resource has been announced other
    // then ourselves.
    if (!is_our_addr(&ip_addr))
    {
        coap_endpoint_t ep;
        edge_info_get_server_endpoint(edge_resource, &ep, false);

        if (!coap_endpoint_is_connected(&ep))
        {
            LOG_DBG("Connecting to CoAP endpoint ");
            coap_endpoint_log(&ep);
            LOG_DBG_("\n");

            // TODO: delay this by a random amount to space out connects
            coap_endpoint_connect(&ep);
        }
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_publish_capability_handler(const char *topic, const char* topic_end,
                                const uint8_t *chunk, uint16_t chunk_len,
                                const char* topic_identity)
{
    edge_resource_t* edge = edge_info_find_ident(topic_identity);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find edge with identity %s\n", topic_identity);
        return;
    }

    // Format of topic is now in "/%s/add"

    if (*topic != '/')
    {
        LOG_ERR("Bad sep\n");
        return;
    }

    topic += 1;

    const char* next_slash = strchr(topic, '/');
    if (next_slash == NULL)
    {
        LOG_ERR("Bad sep\n");
        return;
    }

    // Check that capability name isn't too long
    ptrdiff_t distance = next_slash - topic;
    if (distance <= 0 || distance > EDGE_CAPABILITY_NAME_LEN)
    {
        LOG_ERR("Bad cap name\n");
        return;
    }

    // Parse capability name
    char capability_name[EDGE_CAPABILITY_NAME_LEN+1];
    strncpy(capability_name, topic, distance);
    capability_name[distance] = '\0';

    topic = next_slash + 1;

    if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_ADD, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_ADD)) == 0)
    {
        edge_capability_t* capability = edge_info_capability_add(edge, capability_name);
        if (capability == NULL)
        {
            LOG_ERR("Failed to create capability (%s) for edge with identity %s\n", capability_name, topic_identity);
            return;
        }

        struct jsonparse_state state;
        jsonparse_setup(&state, (const char*)chunk, chunk_len);

        int next;

        if ((next = jsonparse_next(&state)) != '{')
        {
            LOG_ERR("jsonparse_next 1 (next=%d)\n", next);
            return;
        }

        if ((next = jsonparse_next(&state)) != '}')
        {
            LOG_ERR("jsonparse_next 2 (next=%d)\n", next);
            return;
        }

        LOG_DBG("Added capability (%s) for edge with identity %s\n", capability_name, topic_identity);

        // We have at least one Edge resource to support this application, so we need to inform the process
        struct process* proc = find_process_with_name(capability_name);
        if (proc != NULL)
        {
            process_post(proc, pe_edge_capability_add, edge);
        }
        else
        {
            LOG_DBG("Failed to find a process running the application (%s)\n", capability_name);
        }
    }
    else if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_REMOVE, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_ADD)) == 0)
    {
        // TODO
        LOG_ERR("Not implemented (%.*s)\n", topic_end - topic, topic);
    }
    else
    {
        LOG_ERR("Unknown cap action (%.*s)\n", topic_end - topic, topic);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len)
{
    LOG_DBG("Pub Handler: topic='%.*s' (len=%u), chunk_len=%u\n", topic_end - topic, topic, topic_end - topic, chunk_len);

    int ret;

    // First check that we are in the right namespace
    ret = strncmp(MQTT_EDGE_NAMESPACE, topic, MQTT_EDGE_NAMESPACE_LEN);
    if (ret != 0)
    {
        LOG_ERR("Initial prefix does not match " MQTT_EDGE_NAMESPACE "\n");
        return;
    }

    // Consume MQTT_EDGE_NAMESPACE_LEN
    topic += MQTT_EDGE_NAMESPACE_LEN;

    if ((topic_end - topic) < 2 + MQTT_IDENTITY_LEN || *topic != '/')
    {
        LOG_ERR("Topic does not contain identity\n");
        return;
    }

    // Consume '/'
    topic += 1;

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

    if (*topic != '/')
    {
        LOG_ERR("Bad sep\n");
        return;
    }

    topic += 1;

    if (strncmp(MQTT_EDGE_ACTION_ANNOUNCE, topic, strlen(MQTT_EDGE_ACTION_ANNOUNCE)) == 0)
    {
        topic += strlen(MQTT_EDGE_ACTION_ANNOUNCE);

        mqtt_publish_announce_handler(topic, topic_end, chunk, chunk_len, topic_identity);
    }
    else if (strncmp(MQTT_EDGE_ACTION_CAPABILITY, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY)) == 0)
    {
        topic += strlen(MQTT_EDGE_ACTION_CAPABILITY);

        mqtt_publish_capability_handler(topic, topic_end, chunk, chunk_len, topic_identity);
    }
    else
    {
        LOG_ERR("Unknown topic '%.*s'\n", topic_end - topic, topic);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust(void* trust_info, uint8_t* buffer, size_t buffer_len)
{
    uint32_t time_secs = clock_seconds();

    int len = snprintf((char*)buffer, buffer_len,
        "{"
            "\"name\":\"serialised-trust\","
            "\"time\":%" PRIu32
        "}",
        time_secs
    );
    if (len < 0 || len >= buffer_len)
    {
        return -1;
    }

    // Include NUL byte
    len += 1;

    return len;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust(void* trust_info, const uint8_t* buffer, size_t buffer_len)
{
    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
trust_common_init(void)
{
    pe_edge_capability_add = process_alloc_event();
    pe_edge_capability_remove = process_alloc_event();

    crypto_support_init();
}
/*-------------------------------------------------------------------------------------------------------------------*/
