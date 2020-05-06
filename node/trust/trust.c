#include "trust.h"
#include "edge-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uiplib.h"
#include "os/net/ipv6/uip-udp-packet.h"

#ifdef WITH_DTLS
#include "tinydtls.h"
#include "dtls.h"
#endif

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
#define TRUST_POLL_PERIOD (60 * CLOCK_SECOND)
static struct etimer periodic_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static struct uip_udp_conn* bcast_conn;
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

    // TODO: digital signature

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

#ifdef WITH_DTLS
    dtls_init();
#endif

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
