#include "trust-common.h"
#include "edge-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"
#include "assert.h"

#include <stdio.h>
#include <ctype.h>

#include "applications.h"
#include "trust-common.h"
#include "keystore.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-comm"
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
static bool is_our_ident(const char* ident)
{
    char our_ident[8 * 2 + 1];
    int len = snprintf(our_ident, sizeof(our_ident), "%02x%02x%02x%02x%02x%02x%02x%02x", 
        linkaddr_node_addr.u8[0], linkaddr_node_addr.u8[1],
        linkaddr_node_addr.u8[2], linkaddr_node_addr.u8[3],
        linkaddr_node_addr.u8[4], linkaddr_node_addr.u8[5],
        linkaddr_node_addr.u8[6], linkaddr_node_addr.u8[7]);
    if (len >= sizeof(our_ident))
    {
        LOG_ERR("Failed to create our ident %d >= %d\n", len, sizeof(our_ident));
        return false;
    }

    return strncmp(ident, our_ident, len) == 0;
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

    if (chunk[state.pos] != 0)
    {
        LOG_ERR("parse 6 (missing NUL)\n");
        return;
    }

    // We should add a record of other edge resources, but not ourselves.
    if (is_our_addr(&ip_addr))
    {
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
    if (!coap_endpoint_is_connected(&edge_resource->ep))
    {
        LOG_DBG("Connecting to CoAP endpoint ");
        coap_endpoint_log(&edge_resource->ep);
        LOG_DBG_("\n");

        // TODO: delay this by a random amount to space out connects
        coap_endpoint_connect(&edge_resource->ep);
    }

    // We are probably going to be interacting with this edge resource,
    // so ask for its public key. If this fails we will obtain the key later.

    if (state.pos + 1 + sizeof(ecdsa_secp256r1_pubkey_t) + sizeof(ecdsa_secp256r1_sig_t) != chunk_len)
    {
        LOG_ERR("%d + 1 + %u + %u != %u\n",
            state.pos, sizeof(ecdsa_secp256r1_pubkey_t), sizeof(ecdsa_secp256r1_sig_t), chunk_len);
        assert(false);
    }

    // Now we need to extract the public key and signature from the announce message
    const ecdsa_secp256r1_pubkey_t* pubkey = (const ecdsa_secp256r1_pubkey_t*)(chunk + state.pos + 1);
    const ecdsa_secp256r1_sig_t* sig = (const ecdsa_secp256r1_sig_t*)(chunk + state.pos + 1 + sizeof(ecdsa_secp256r1_pubkey_t));

    if (keystore_add_unverified(&ip_addr, pubkey, sig) == NULL)
    {
        request_public_key(&ip_addr);
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
        // Do not process capabilities we already know about
        edge_capability_t* capability = edge_info_capability_find(edge, capability_name);
        if (capability)
        {
            LOG_DBG("Notified of capability (%s) already known of\n", capability_name);
            return;
        }

        capability = edge_info_capability_add(edge, capability_name);
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
    else if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_REMOVE, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_REMOVE)) == 0)
    {
        // We have at least one Edge resource to support this application, so we need to inform the process
        struct process* proc = find_process_with_name(capability_name);
        if (proc != NULL)
        {
            process_post(proc, pe_edge_capability_remove, edge);
        }
        else
        {
            LOG_DBG("Failed to find a process running the application (%s)\n", capability_name);
        }

        bool result = edge_info_capability_remove(edge, capability_name);
        if (result)
        {
            LOG_DBG("Removed capability %s from %s\n", capability_name, topic_identity);
        }
        else
        {
            LOG_DBG("Cannot removed capability %s from %s as it does not have that capability\n",
                capability_name, topic_identity);
        }
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

    // No need to add information on ourselves
    if (is_our_ident(topic_identity))
    {
        return;
    }

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
int serialise_trust(void* trust_info, const uip_ipaddr_t* addr, uint8_t* buffer, size_t buffer_len)
{
    // TODO: could provide addr to request trust on specific nodes

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
    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int process_received_trust(void* trust_info, const uip_ipaddr_t* src, const uint8_t* buffer, size_t buffer_len)
{
    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
trust_common_init(void)
{
    pe_edge_capability_add = process_alloc_event();
    pe_edge_capability_remove = process_alloc_event();
}
/*-------------------------------------------------------------------------------------------------------------------*/