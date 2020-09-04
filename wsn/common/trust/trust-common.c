#include "trust-common.h"
#include "edge-info.h"
#include "peer-info.h"
#include "trust-models.h"
#include "stereotypes.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"
#include "assert.h"
#include "coap-log.h"

#include <stdio.h>
#include <ctype.h>

#include "applications.h"
#include "keystore.h"
#include "device-classes.h"

#include "nanocbor-helper.h"

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
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_UNANNOUNCE,
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
static bool is_our_eui64(const uint8_t* eui64)
{
    return memcmp(eui64, current_eui64(), EUI64_LENGTH) == 0;
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
static int
process_certificate(const char* topic_identity, const certificate_t* cert)
{
    // We should add a record of other edge resources, but not ourselves.
    // TODO: might need to change this, so we can have a trust model of beliefs about ourself
    if (is_our_eui64(cert->subject))
    {
        return -1;
    }

    uip_ip6addr_t ipaddr;
    ipaddr_from_eui64(cert->subject, &ipaddr);

    edge_resource_t* edge_resource = edge_info_add(&ipaddr, topic_identity);
    if (edge_resource != NULL)
    {
        LOG_DBG("Received certificate for %s with address ", topic_identity);
        LOG_DBG_6ADDR(&ipaddr);
        LOG_DBG_("\n");

        edge_resource->flags |= EDGE_RESOURCE_ACTIVE;
    }
    else
    {
        LOG_ERR("Failed to allocate edge resource %s with address ", topic_identity);
        LOG_DBG_6ADDR(&ipaddr);
        LOG_DBG_("\n");
        return -2;
    }

    // We should request stereotypes for this edge (if needed)
    stereotypes_request(edge_resource, &cert->tags);

    // We should connect to the Edge resource that has announced themselves here
    // This means that if we are using DTLS, the handshake has already been performed,
    // so we will be ready to communicate tasks to them and receive responses.
    if (!coap_endpoint_is_connected(&edge_resource->ep))
    {
        LOG_DBG("Connecting to CoAP endpoint ");
        LOG_DBG_COAP_EP(&edge_resource->ep);
        LOG_DBG_("\n");

        // TODO: delay this by a random amount to space out connects
        coap_endpoint_connect(&edge_resource->ep);
    }

    // We are probably going to be interacting with this edge resource,
    // so ask for its public key. If this fails we will obtain the key later.
    if (keystore_add_unverified(&ipaddr, cert) == NULL)
    {
        request_public_key(&ipaddr);
    }

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
mqtt_publish_announce_handler(const char *topic, const char* topic_end,
                              const uint8_t *chunk, uint16_t chunk_len,
                              const char* topic_identity)
{
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, chunk, chunk_len);

    certificate_t cert;
    NANOCBOR_CHECK(certificate_decode(&dec, &cert));
    return process_certificate(topic_identity, &cert);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
mqtt_publish_unannounce_handler(const char *topic, const char* topic_end,
                                const uint8_t *chunk, uint16_t chunk_len,
                                const char* topic_identity)
{
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, chunk, chunk_len);

    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&dec, &arr));

    const uip_ipaddr_t* ip_addr;
    NANOCBOR_CHECK(nanocbor_get_ipaddr(&arr, &ip_addr));

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_at_end 3\n");
        return -1;
    }

    // We should add a record of other edge resources, but not ourselves.
    if (is_our_addr(ip_addr))
    {
        return -1;
    }

    edge_resource_t* edge_resource = edge_info_find_ident(topic_identity);
    if (edge_resource != NULL)
    {
        LOG_DBG("Received unannounce for %s with address ", topic_identity);
        LOG_DBG_6ADDR(ip_addr);
        LOG_DBG_("\n");

        edge_resource->flags &= ~EDGE_RESOURCE_ACTIVE;

        edge_info_capability_clear(edge_resource);
    }
    else
    {
        LOG_ERR("Failed to find edge resource %s with address ", topic_identity);
        LOG_ERR_6ADDR(ip_addr);
        LOG_ERR_("\n");
    }

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
mqtt_publish_capability_add_handler(const char* topic_identity, const char* capability_name,
                                    const uint8_t *chunk, uint16_t chunk_len)
{
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, chunk, chunk_len);

    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&dec, &arr));

    bool certificate_included;
    NANOCBOR_CHECK(nanocbor_get_bool(&arr, &certificate_included));

    // This add message might have an embedded edge certificate
    // if so we should handle it
    if (certificate_included)
    {
        certificate_t cert;
        NANOCBOR_CHECK(certificate_decode(&arr, &cert));
        process_certificate(topic_identity, &cert);
    }
    else
    {
        NANOCBOR_CHECK(nanocbor_get_null(&arr));
    }

    edge_resource_t* edge = edge_info_find_ident(topic_identity);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find edge with identity %s\n", topic_identity);
        return -1;
    }

    // Do not process capabilities we already know about
    edge_capability_t* capability = edge_info_capability_find(edge, capability_name);
    if (capability)
    {
        LOG_DBG("Notified of capability (%s) already known of\n", capability_name);
        return -1;
    }

    capability = edge_info_capability_add(edge, capability_name);
    if (capability == NULL)
    {
        LOG_ERR("Failed to create capability (%s) for edge with identity %s\n", capability_name, edge->name);
        return -1;
    }

    LOG_INFO("Added capability (%s) for edge with identity %s\n", capability_name, edge->name);

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

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
mqtt_publish_capability_remove_handler(const char* topic_identity, const char* capability_name,
                                       const uint8_t *chunk, uint16_t chunk_len)
{
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, chunk, chunk_len);

    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&dec, &arr));

    bool certificate_included;
    NANOCBOR_CHECK(nanocbor_get_bool(&arr, &certificate_included));

    // This add message might have an embedded edge certificate
    // if so we should handle it
    if (certificate_included)
    {
        certificate_t cert;
        NANOCBOR_CHECK(certificate_decode(&arr, &cert));
        process_certificate(topic_identity, &cert);
    }
    else
    {
        NANOCBOR_CHECK(nanocbor_get_null(&arr));
    }

    edge_resource_t* edge = edge_info_find_ident(topic_identity);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find edge with identity %s\n", topic_identity);
        return -1;
    }

    // Check that this edge has this capability
    edge_capability_t* capability = edge_info_capability_find(edge, capability_name);
    if (capability == NULL)
    {
        LOG_DBG("Notified of removal of capability %s from %s, but had not recorded this previously.\n",
            capability_name, edge->name);
        return -1;
    }

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

    bool result = edge_info_capability_remove(edge, capability);
    if (result)
    {
        LOG_INFO("Removed capability %s from %s\n", capability_name, edge->name);
    }
    else
    {
        // Should never get here
        LOG_ERR("Cannot removed capability %s from %s as it does not have that capability\n",
            capability_name, edge->name);
    }

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
mqtt_publish_capability_handler(const char *topic, const char* topic_end,
                                const uint8_t *chunk, uint16_t chunk_len,
                                const char* topic_identity)
{
    // Format of topic is now in "/%s/add"

    if (*topic != '/')
    {
        LOG_ERR("Bad sep\n");
        return -1;
    }

    topic += 1;

    const char* next_slash = strchr(topic, '/');
    if (next_slash == NULL)
    {
        LOG_ERR("Bad sep\n");
        return -1;
    }

    // Check that capability name isn't too long
    ptrdiff_t distance = next_slash - topic;
    if (distance <= 0 || distance > EDGE_CAPABILITY_NAME_LEN)
    {
        LOG_ERR("Bad cap name\n");
        return -1;
    }

    // Parse capability name
    char capability_name[EDGE_CAPABILITY_NAME_LEN+1];
    strncpy(capability_name, topic, distance);
    capability_name[distance] = '\0';

    topic = next_slash + 1;

    if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_ADD, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_ADD)) == 0)
    {
        return mqtt_publish_capability_add_handler(topic_identity, capability_name, chunk, chunk_len);
    }
    else if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_REMOVE, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_REMOVE)) == 0)
    {
        return mqtt_publish_capability_remove_handler(topic_identity, capability_name, chunk, chunk_len);
    }
    else
    {
        LOG_WARN("Unknown cap action (%.*s)\n", topic_end - topic, topic);
        return -1;
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
    else if (strncmp(MQTT_EDGE_ACTION_UNANNOUNCE, topic, strlen(MQTT_EDGE_ACTION_UNANNOUNCE)) == 0)
    {
        topic += strlen(MQTT_EDGE_ACTION_UNANNOUNCE);

        mqtt_publish_unannounce_handler(topic, topic_end, chunk, chunk_len, topic_identity);
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
static int serialise_trust_edge_and_capabilities(nanocbor_encoder_t* enc, edge_resource_t* edge)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 2));
    NANOCBOR_CHECK(serialise_trust_edge_resource(enc, &edge->tm));

    NANOCBOR_CHECK(nanocbor_fmt_map(enc, list_length(edge->capabilities)));
    for (edge_capability_t* cap = list_head(edge->capabilities); cap != NULL; cap = list_item_next(cap))
    {
        NANOCBOR_CHECK(nanocbor_put_tstr(enc, cap->name));
        NANOCBOR_CHECK(serialise_trust_edge_capability(enc, &cap->tm));
    }

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust(const uip_ipaddr_t* addr, uint8_t* buffer, size_t buffer_len)
{
    // Can provide addr to request trust on specific nodes, when NULL is provided
    // Then details on all edges are sent

    const size_t num_edges = (addr == NULL) ? edge_info_count() : 1;

    uint32_t time_secs = clock_seconds();

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buffer, buffer_len);

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 2));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, time_secs));
    NANOCBOR_CHECK(nanocbor_fmt_map(&enc, num_edges));

    if (addr != NULL)
    {
        edge_resource_t* edge = edge_info_find_addr(addr);
        if (edge == NULL)
        {
            return -1;
        }

        NANOCBOR_CHECK(nanocbor_fmt_ipaddr(&enc, addr));
        NANOCBOR_CHECK(serialise_trust_edge_and_capabilities(&enc, edge));
    }
    else
    {
        for (edge_resource_t* iter = edge_info_iter(); iter != NULL; iter = edge_info_next(iter))
        {
            NANOCBOR_CHECK(nanocbor_fmt_ipaddr(&enc, &iter->ep.ipaddr));
            NANOCBOR_CHECK(serialise_trust_edge_and_capabilities(&enc, iter));
        }
    }

    assert(nanocbor_encoded_len(&enc) <= buffer_len);

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int deserialise_trust_edge_and_capabilities(nanocbor_value_t* dec, peer_t* peer, edge_resource_t* edge)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    edge_resource_tm_t edge_tm;
    NANOCBOR_CHECK(deserialise_trust_edge_resource(&arr, &edge_tm));

    peer_info_update_edge(peer, edge, &edge_tm);

    nanocbor_value_t map;
    NANOCBOR_CHECK(nanocbor_enter_map(&arr, &map));

    while (!nanocbor_at_end(&map))
    {
        const char* cap_name;
        size_t cap_name_len;
        NANOCBOR_CHECK(nanocbor_get_tstr(&map, &cap_name, &cap_name_len));

        if (cap_name_len > EDGE_CAPABILITY_NAME_LEN)
        {
            LOG_DBG("Skipping processing edge ");
            LOG_DBG_6ADDR(&edge->ep.ipaddr);
            LOG_DBG_(" capability %.*s (name too long)\n", cap_name_len, cap_name);

            NANOCBOR_CHECK(nanocbor_skip(&map));
            continue;
        }

        char cap_name_terminated[EDGE_CAPABILITY_NAME_LEN + 1];
        strncpy(cap_name_terminated, cap_name, cap_name_len);
        cap_name_terminated[cap_name_len] = '\0';

        edge_capability_t* cap = edge_info_capability_find(edge, cap_name_terminated);
        if (cap != NULL)
        {
            edge_capability_tm_t cap_tm;
            NANOCBOR_CHECK(deserialise_trust_edge_capability(&map, &cap_tm));

            peer_info_update_capability(peer, edge, cap, &cap_tm);
        }
        else
        {
            LOG_DBG("Skipping processing edge ");
            LOG_DBG_6ADDR(&edge->ep.ipaddr);
            LOG_DBG_(" unknown capability %.*s\n", cap_name_len, cap_name);

            NANOCBOR_CHECK(nanocbor_skip(&map));
        }
    }

    nanocbor_leave_container(&arr, &map);

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_at_end\n");
        return -1;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int process_received_trust(const uip_ipaddr_t* src, const uint8_t* buffer, size_t buffer_len)
{
    // Add or find peer
    peer_t* peer = peer_info_add(src);
    if (peer == NULL)
    {
        LOG_ERR("Failed to create peer data storage for ");
        LOG_ERR_6ADDR(src);
        LOG_ERR_("\n");
        return -1;
    }

    //const uint32_t previous_last_seen = peer->last_seen;

    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, buffer, buffer_len);

    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&dec, &arr));

    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &peer->last_seen));

    nanocbor_value_t map;
    NANOCBOR_CHECK(nanocbor_enter_map(&arr, &map));

    while (!nanocbor_at_end(&map))
    {
        const uip_ipaddr_t* ipaddr;
        NANOCBOR_CHECK(nanocbor_get_ipaddr(&map, &ipaddr));

        // TODO: in the future might want to consider creating an edge here
        // Risk of possible DoS via buffer exhaustion though
        edge_resource_t* edge = edge_info_find_addr(ipaddr);
        if (edge == NULL)
        {
            LOG_DBG("Skipping processing unknown edge ");
            LOG_DBG_6ADDR(ipaddr);
            LOG_DBG_("\n");

            NANOCBOR_CHECK(nanocbor_skip(&map));
        }
        else
        {
            NANOCBOR_CHECK(deserialise_trust_edge_and_capabilities(&map, peer, edge));
        }
    }

    if (!nanocbor_at_end(&map))
    {
        LOG_ERR("!nanocbor_at_end 4\n");
        return -1;
    }

    nanocbor_leave_container(&arr, &map);

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_at_end 5\n");
        return -1;
    }

    nanocbor_leave_container(&dec, &arr);

    return 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
trust_common_init(void)
{
    LOG_DBG("Initialising trust common\n");

    pe_edge_capability_add = process_alloc_event();
    pe_edge_capability_remove = process_alloc_event();

    trust_weights_init();

    stereotypes_init();
}
/*-------------------------------------------------------------------------------------------------------------------*/
