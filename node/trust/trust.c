#include "trust.h"
#include "edge-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uiplib.h"
#include "os/net/ipv6/uip-udp-packet.h"

#include <stdio.h>
#include <ctype.h>

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
#define TRUST_PROTO_PORT 1000
/*-------------------------------------------------------------------------------------------------------------------*/
process_event_t pe_edge_capability_add;
process_event_t pe_edge_capability_remove;
/*-------------------------------------------------------------------------------------------------------------------*/
#define TRUST_POLL_PERIOD (60 * CLOCK_SECOND)
static struct etimer periodic_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static struct uip_udp_conn* bcast_conn;
/*-------------------------------------------------------------------------------------------------------------------*/
const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN] = {
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_ANNOUNCE,
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_ADD
};
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
            LOG_DBG("Failed to find process running the application (%s)\n", capability_name);
        }
    }
    else if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_REMOVE, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_ADD)) == 0)
    {
        // TODO
        LOG_ERR("Not implemented (%s)\n", topic);
    }
    else
    {
        LOG_ERR("Unknown cap action (%s)\n", topic);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len)
{
    LOG_DBG("Pub Handler: topic='%s' (len=%u), chunk_len=%u\n", topic, topic_end - topic, chunk_len);

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
        LOG_ERR("Unknown topic '%s'\n", topic);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_resource_t* choose_edge(const char* capability_name)
{
    // For now FCFS
    for (edge_resource_t* iter = edge_info_iter(); iter != NULL; iter = edge_info_next(iter))
    {
        edge_capability_t* capability = edge_info_capability_find(iter, capability_name);
        if (capability != NULL)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
udp_rx_callback(const uip_ipaddr_t *sender_addr, uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr, uint16_t receiver_port,
                const uint8_t *data, uint16_t datalen)
{
    // TODO: process receive from neighbour
    LOG_DBG("Received trust info from [");
    LOG_DBG_6ADDR(sender_addr);
    LOG_DBG_("]:%u to [", sender_port);
    LOG_DBG_6ADDR(receiver_addr);
    LOG_DBG_("]:%u. Data=%s of length %u\n", receiver_port, (const char*)data, datalen);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
handle_tcpip_event(void)
{
    //static uint8_t databuffer[UIP_APPDATA_SIZE];

    // If we were called because of incoming data, we should call the reception callback.
    if (!uip_newdata())
    {
        return;
    }

    // TODO:
    // Copy the data from the uIP data buffer into our own buffer
    // to avoid the uIP buffer being messed with by the callee.
    //memcpy(databuffer, uip_appdata, uip_datalen());
    const uint8_t* databuffer = uip_appdata;

    // Call the client process. We use the PROCESS_CONTEXT mechanism
    // to temporarily switch process context to the client process.
    udp_rx_callback(&(UIP_IP_BUF->srcipaddr),
                    UIP_HTONS(UIP_UDP_BUF->srcport),
                    &(UIP_IP_BUF->destipaddr),
                    UIP_HTONS(UIP_UDP_BUF->destport),
                    databuffer, uip_datalen());
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_action(void)
{
    // TODO: Poll neighbours for trust information
    static const char* data = "trust-info-hello";

    // Set multicast address
    uip_create_linklocal_allnodes_mcast(&bcast_conn->ripaddr);

    uip_udp_packet_send(bcast_conn, data, strlen(data) + 1);

    // Restore to 'accept incoming from any IP'
    uip_create_unspecified(&bcast_conn->ripaddr);

    LOG_DBG("Sent trust info\n");

    etimer_reset(&periodic_timer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
init(void)
{
    pe_edge_capability_add = process_alloc_event();
    pe_edge_capability_remove = process_alloc_event();

    edge_info_init();

    etimer_set(&periodic_timer, TRUST_POLL_PERIOD);

    // Open UDP connection on port TRUST_PROTO_PORT that accepts all incoming packets
    bcast_conn = udp_new(NULL, UIP_HTONS(TRUST_PROTO_PORT), NULL);
    if (bcast_conn == NULL)
    {
        LOG_ERR("Failed to allocated UDP broadcast connection\n");
        return false;
    }
    else
    {
        udp_bind(bcast_conn, UIP_HTONS(TRUST_PROTO_PORT));
        LOG_DBG("Listening (local:%u, remote:%u)!\n", UIP_HTONS(bcast_conn->lport), UIP_HTONS(bcast_conn->rport));
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
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

        if (ev == PROCESS_EVENT_TIMER && data == &periodic_timer) {
            periodic_action();
        }

        if (ev == tcpip_event) {
            handle_tcpip_event();
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
