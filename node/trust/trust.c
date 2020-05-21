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
        //TODO: Set error code
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
typedef struct
{
    struct pt pt;

    coap_endpoint_t ep;
    coap_message_t msg;
    uint8_t coap_payload_buf[MAX_TRUST_PAYLOAD];

    int payload_len;

    sign_state_t sign_state;

    coap_callback_request_state_t coap_callback;

} periodic_action_state_t;

PT_THREAD(periodic_action(periodic_action_state_t* state))
{
    PT_BEGIN(&state->pt);

    int ret;

    etimer_reset(&periodic_timer);

    LOG_DBG("Generating a periodic trust info packet\n");

    uip_create_linklocal_allnodes_mcast(&state->ep.ipaddr);
    state->ep.secure = 0;
    state->ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    // This is a non-confirmable message
    coap_init_message(&state->msg, COAP_TYPE_NON, COAP_POST, 0);

    ret = coap_set_header_uri_path(&state->msg, TRUST_COAP_URI);
    if (ret <= 0)
    {
        LOG_ERR("coap_set_header_uri_path failed %d\n", ret);
        PT_EXIT(&state->pt);
    }

    state->payload_len = serialise_trust(NULL, state->coap_payload_buf, sizeof(state->coap_payload_buf));
    if (state->payload_len <= 0 || state->payload_len > sizeof(state->coap_payload_buf))
    {
        LOG_DBG("serialise_trust failed %d\n", state->payload_len);
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Spawning PT to sign message of length %u...\n", state->payload_len);

    state->sign_state.process = &trust_model;
    PT_SPAWN(&state->pt, &state->sign_state.pt,
        ecc_sign(&state->sign_state, state->coap_payload_buf, sizeof(state->coap_payload_buf), state->payload_len));

    if (state->sign_state.ecc_sign_state.result != PKA_STATUS_SUCCESS)
    {
        LOG_ERR("Sign of trust information failed %d\n", state->sign_state.ecc_sign_state.result);
        PT_EXIT(&state->pt);
    }

    state->payload_len += state->sign_state.sig_len;

    LOG_DBG("Messaged signed new length = %u\n", state->payload_len);

    int payload_len = coap_set_payload(&state->msg, state->coap_payload_buf, state->payload_len);

    if (payload_len < state->payload_len)
    {
        LOG_WARN("Messaged length truncated to = %d\n", payload_len);
        // TODO: how to handle block-wise transfer?
    }

    // No callback is set, as no confirmation of the message being received will be sent to us
    ret = coap_send_request(&state->coap_callback, &state->ep, &state->msg, NULL);
    if (ret)
    {
        LOG_DBG("coap_send_request trust done\n");
    }
    else
    {
        LOG_ERR("coap_send_request trust failed %d\n", ret);
    }

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
init(void)
{
    trust_common_init();
    edge_info_init();

    coap_activate_resource(&res_trust, TRUST_COAP_URI);

    etimer_set(&periodic_timer, TRUST_POLL_PERIOD);

    pka_init();
    pka_disable();

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
        PROCESS_YIELD();

        if (ev == PROCESS_EVENT_TIMER && data == &periodic_timer) {
            static periodic_action_state_t state;
            PT_SPAWN(&trust_model.pt, &state.pt, periodic_action(&state));
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
