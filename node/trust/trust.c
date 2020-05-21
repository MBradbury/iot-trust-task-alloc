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
#include "crypto-support.h"
#include "keystore.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define TRUST_POLL_PERIOD (2 * 60 * CLOCK_SECOND)
static struct etimer periodic_timer;
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
    LOG_DBG("Generating trust info packet in response to a GET\n");

    // Received a request for our trust information, need to respond to the requester

    // TODO: might ask for information on specific edge resource, so could only send that information

    static uint8_t coap_payload_buf[MAX_TRUST_PAYLOAD];

    int payload_len = serialise_trust(NULL, coap_payload_buf, sizeof(coap_payload_buf));
    if (payload_len <= 0 || payload_len > sizeof(coap_payload_buf))
    {
        LOG_DBG("serialise_trust failed %d\n", payload_len);
        coap_set_status_code(response, INTERNAL_SERVER_ERROR_5_00);
        return;
    }

    // TODO: how to sign here?
    // Don't attempt to sign here

    // TODO: correct this implementation (setting payload works)
    coap_set_payload(response, coap_payload_buf, payload_len);
}

static void
res_trust_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    // Received trust information from another node, need to update our reputation database
    LOG_DBG("Received trust info packet via POST\n");

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received trust info from ");
    coap_endpoint_log(request->src_ep);
    LOG_DBG_(" Data=%.*s of length %u\n", payload_len, (const char*)payload, payload_len);

    public_key_item_t* key = keystore_find(&request->src_ep->ipaddr);
    if (key == NULL)
    {
        LOG_DBG("Missing public key, need to request it.\n");
        request_public_key(&request->src_ep->ipaddr);
    }
    else
    {
        LOG_DBG("Have public key.\n");
    }

    // TODO: add data to a queue for verification
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_endpoint_t ep;
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uint8_t coap_payload_buf[MAX_TRUST_PAYLOAD];
static bool in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool periodic_action(void)
{
    if (in_use)
    {
        LOG_WARN("Already doing a periodic action\n");
        return false;
    }

    in_use = true;

    etimer_reset(&periodic_timer);

    LOG_DBG("Generating a periodic trust info packet\n");

    uip_create_linklocal_allnodes_mcast(&ep.ipaddr);
    ep.secure = 0;
    ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    // This is a non-confirmable message
    coap_init_message(&msg, COAP_TYPE_NON, COAP_POST, 0);

    int ret = coap_set_header_uri_path(&msg, TRUST_COAP_URI);
    if (ret <= 0)
    {
        LOG_ERR("coap_set_header_uri_path failed %d\n", ret);
        return false;
    }

    int payload_len = serialise_trust(NULL, coap_payload_buf, sizeof(coap_payload_buf));
    if (payload_len <= 0 || payload_len > sizeof(coap_payload_buf))
    {
        LOG_ERR("serialise_trust failed %d\n", payload_len);
        return false;
    }

    if (!queue_message_to_sign(&trust_model, NULL, coap_payload_buf, sizeof(coap_payload_buf), payload_len))
    {
        LOG_ERR("trust periodic_action: Unable to sign message\n");
        return false;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void periodic_action_continue(void* data)
{
    messages_to_sign_entry_t* entry = (messages_to_sign_entry_t*)data;

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        int payload_len = entry->message_len + DTLS_EC_KEY_SIZE*2;
        int coap_payload_len = coap_set_payload(&msg, coap_payload_buf, payload_len);
        if (coap_payload_len < payload_len)
        {
            LOG_WARN("Messaged length truncated to = %d\n", coap_payload_len);
            // TODO: how to handle block-wise transfer?
        }

        // No callback is set, as no confirmation of the message being received will be sent to us
        int ret = coap_send_request(&coap_callback, &ep, &msg, NULL);
        if (ret)
        {
            LOG_DBG("coap_send_request trust done\n");
        }
        else
        {
            LOG_ERR("coap_send_request trust failed %d\n", ret);
        }
    }
    else
    {
        LOG_ERR("Sign of trust information failed %d\n", entry->result);
    }

    queue_message_to_sign_done(entry);

    in_use = false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool init(void)
{
    trust_common_init();
    edge_info_init();

    coap_activate_resource(&res_trust, TRUST_COAP_URI);

    etimer_set(&periodic_timer, TRUST_POLL_PERIOD);

    in_use = false;

    return true;
}
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
        PROCESS_WAIT_EVENT();

        if (ev == PROCESS_EVENT_TIMER && data == &periodic_timer)
        {
            periodic_action();
        }

        if (ev == pe_message_signed)
        {
            periodic_action_continue(data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
