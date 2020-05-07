#include "trust.h"
#include "edge-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-callback-api.h"

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
#define TRUST_POLL_PERIOD (5 * 60 * CLOCK_SECOND)
static struct etimer periodic_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static uint8_t coap_payload_get_buf[MAX_TRUST_PAYLOAD];
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
res_trust_get_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

static void
res_trust_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_trust,
         "title=\"Trust information\";rt=\"trust\"",
         res_trust_get_handler,  /*GET*/  // Handle requests for our trust information
         res_trust_post_handler, /*POST*/ // Handle periodic broadcasts of neighbour's information
         NULL,                   /*PUT*/
         NULL                    /*DELETE*/);

static void
res_trust_get_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    // Received a request for our trust information, need to respond to the requester

    // TODO: might ask for information on specific edge resource, so could only send that information

    int payload_len = serialise_trust(NULL, coap_payload_get_buf, sizeof(coap_payload_get_buf));
    if (payload_len <= 0 || payload_len > sizeof(coap_payload_get_buf))
    {
        LOG_DBG("serialise_trust failed %d\n", payload_len);
        //TODO: Set error code
        return;
    }

    // TODO: correct this implementation (setting payload works)
    coap_set_payload(response, coap_payload_get_buf, payload_len);
}

static void
res_trust_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    // Received trust information from another node, need to update our reputation database

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received trust info from ");
    coap_endpoint_log(request->src_ep);
    LOG_DBG_(" Data=%.*s of length %u\n", payload_len, (const char*)payload, payload_len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_action(void)
{
    int ret;

    etimer_reset(&periodic_timer);

    coap_endpoint_t ep;
    uip_create_linklocal_allnodes_mcast(&ep.ipaddr);
    ep.secure = 0;
    ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    // This is a non-confirmable message
    coap_message_t msg;
    coap_init_message(&msg, COAP_TYPE_NON, COAP_POST, 0);

    ret = coap_set_header_uri_path(&msg, TRUST_COAP_URI);
    if (ret <= 0)
    {
        LOG_DBG("coap_set_header_uri_path failed %d\n", ret);
        return;
    }

    uint8_t coap_payload_buf[MAX_TRUST_PAYLOAD];
    int payload_len = serialise_trust(NULL, coap_payload_buf, sizeof(coap_payload_buf));
    if (payload_len <= 0 || payload_len > sizeof(coap_payload_buf))
    {
        LOG_DBG("serialise_trust failed %d\n", payload_len);
        return;
    }

    coap_set_payload(&msg, coap_payload_buf, payload_len);

    // No callback is set, as no confirmation of the message being received will be sent to us
    coap_callback_request_state_t coap_callback;
    ret = coap_send_request(&coap_callback, &ep, &msg, NULL);
    if (ret)
    {
        LOG_DBG("coap_send_request trust done\n");
    }
    else
    {
        LOG_ERR("coap_send_request trust failed %d\n", ret);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
init(void)
{
    trust_common_init();
    edge_info_init();

    coap_activate_resource(&res_trust, TRUST_COAP_URI);

    etimer_set(&periodic_timer, TRUST_POLL_PERIOD);

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
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
