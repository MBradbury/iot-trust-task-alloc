#include "trust.h"
#include "edge-info.h"
#include "peer-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/memb.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"

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
#include "keystore-oscore.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef TRUST_TX_SIZE
#define TRUST_TX_SIZE 2
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef TRUST_RX_SIZE
#define TRUST_RX_SIZE 2
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define TRUST_POLL_PERIOD (2 * 60 * CLOCK_SECOND)
static struct etimer periodic_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct trust_tx_item
{
    coap_endpoint_t ep;
    coap_message_t msg;
    coap_callback_request_state_t coap_callback;
    uint8_t payload_buf[MAX_TRUST_PAYLOAD + DTLS_EC_SIG_SIZE];
} trust_tx_item_t;

MEMB(trust_tx_memb, trust_tx_item_t, TRUST_TX_SIZE);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct trust_rx_item
{
    public_key_item_t* key;
    uint8_t payload_buf[MAX_TRUST_PAYLOAD + DTLS_EC_SIG_SIZE];
} trust_rx_item_t;

MEMB(trust_rx_memb, trust_rx_item_t, TRUST_RX_SIZE);
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
    LOG_DBG("Generating trust info packet in response to a GET\n");

    trust_tx_item_t* item = memb_alloc(&trust_tx_memb);
    if (!item)
    {
        LOG_WARN("Cannot allocate memory for trust request\n");
        coap_set_status_code(response, SERVICE_UNAVAILABLE_5_03);
        return;
    }

    // This is a non-confirmable message
    coap_init_message(&item->msg, COAP_TYPE_NON, COAP_POST, 0);
    coap_set_header_uri_path(&item->msg, TRUST_COAP_URI);
    
    // Possibly a request for a specific edge resource, so could only send that information
    const uip_ipaddr_t* addr = NULL;

    const uint8_t* payload;
    int received_payload_len = coap_get_payload(request, &payload);
    if (received_payload_len == sizeof(uip_ipaddr_t))
    {
        addr = (const uip_ipaddr_t*)payload;
    }

    int payload_len = serialise_trust(addr, item->payload_buf, MAX_TRUST_PAYLOAD);
    if (payload_len <= 0 || payload_len > MAX_TRUST_PAYLOAD)
    {
        LOG_DBG("serialise_trust failed %d\n", payload_len);
        coap_set_status_code(response, INTERNAL_SERVER_ERROR_5_00);
        memb_free(&trust_tx_memb, item);
        return;
    }

    coap_set_header_content_format(&item->msg, APPLICATION_CBOR);

    // Save the target
    memcpy(&item->ep, request->src_ep, sizeof(item->ep));

    // Inform sender that the request has been created,
    // Will send the response in a subsequent message
    coap_set_status_code(response, CREATED_2_01);

    if (!queue_message_to_sign(&trust_model, item, item->payload_buf, sizeof(item->payload_buf), payload_len))
    {
        LOG_ERR("trust res_trust_get_handler: Unable to sign message\n");
        coap_set_status_code(response, INTERNAL_SERVER_ERROR_5_00);
        memb_free(&trust_tx_memb, item);
    }
}

static void
res_trust_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    // Received trust information from another node, need to update our reputation database
    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received trust info via POST from ");
    LOG_DBG_COAP_EP(request->src_ep);
    LOG_DBG_(" of length %d\n", payload_len);

    if (payload_len <= 0 || payload_len > (MAX_TRUST_PAYLOAD + DTLS_EC_SIG_SIZE))
    {
        LOG_WARN("Received payload either too short or too long for buffer %d (max %d)\n",
            payload_len, (MAX_TRUST_PAYLOAD + DTLS_EC_SIG_SIZE));
        coap_set_status_code(response, BAD_REQUEST_4_00);
        return;
    }

    public_key_item_t* key = keystore_find_addr(&request->src_ep->ipaddr);
    if (key == NULL)
    {
        LOG_DBG("Missing public key, need to request it.\n");
        request_public_key(&request->src_ep->ipaddr);

        // TODO: add to a queue, wait for public key then start the signing request
    }
    else
    {
        LOG_DBG("Have public key, adding to queue to be verified...\n");
        trust_rx_item_t* item = memb_alloc(&trust_rx_memb);
        if (!item)
        {
            LOG_ERR("res_trust_post_handler: out of memory\n");
            return;
        }

        item->key = key;
        memcpy(item->payload_buf, payload, payload_len);

        keystore_pin(key);

        if (!queue_message_to_verify(&trust_model, item, item->payload_buf, payload_len, &key->cert.public_key))
        {
            memb_free(&trust_rx_memb, item);
            keystore_unpin(key);
        }
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void trust_rx_continue(void* data)
{
    messages_to_verify_entry_t* entry = (messages_to_verify_entry_t*)data;
    trust_rx_item_t* item = (trust_rx_item_t*)entry->data;

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        uip_ipaddr_t ipaddr;
        eui64_to_ipaddr(item->key->cert.subject, &ipaddr);

        int payload_len = entry->message_len - DTLS_EC_SIG_SIZE;

        LOG_DBG("Trust payload verified (len=%d), need to merge with our db\n", payload_len);
        process_received_trust(&ipaddr, item->payload_buf, payload_len);
    }
    else
    {
        LOG_ERR("Verification of trust information failed %d, discarding it\n", entry->result);
    }

    keystore_unpin(item->key);

    queue_message_to_verify_done(entry);

    memb_free(&trust_rx_memb, item);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool periodic_action(void)
{
    trust_tx_item_t* item = memb_alloc(&trust_tx_memb);
    if (!item)
    {
        LOG_WARN("Cannot allocate memory for periodic_action trust request\n");
        return false;
    }

    LOG_DBG("Generating a periodic trust info packet\n");

    uip_create_linklocal_allnodes_mcast(&item->ep.ipaddr);
    item->ep.secure = 0;
    item->ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    // This is a non-confirmable message
    coap_init_message(&item->msg, COAP_TYPE_NON, COAP_POST, 0);
    coap_set_header_content_format(&item->msg, APPLICATION_CBOR);
    coap_set_header_uri_path(&item->msg, TRUST_COAP_URI);
    coap_set_random_token(&item->msg);

    int payload_len = serialise_trust(NULL, item->payload_buf, MAX_TRUST_PAYLOAD);
    if (payload_len <= 0 || payload_len > MAX_TRUST_PAYLOAD)
    {
        LOG_ERR("serialise_trust failed %d\n", payload_len);
        memb_free(&trust_tx_memb, item);
        return false;
    }

    if (!queue_message_to_sign(&trust_model, item, item->payload_buf, sizeof(item->payload_buf), payload_len))
    {
        LOG_ERR("trust periodic_action: Unable to sign message\n");
        memb_free(&trust_tx_memb, item);
        return false;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void trust_tx_continue(void* data)
{
    messages_to_sign_entry_t* entry = (messages_to_sign_entry_t*)data;
    trust_tx_item_t* item = entry->data;

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        int payload_len = entry->message_len + DTLS_EC_SIG_SIZE;
        int coap_payload_len = coap_set_payload(&item->msg, item->payload_buf, payload_len);
        if (coap_payload_len < payload_len)
        {
            LOG_WARN("Messaged length truncated to = %d\n", coap_payload_len);
        }

        // No callback is set, as no confirmation of the message being received will be sent to us
        int ret = coap_send_request(&item->coap_callback, &item->ep, &item->msg, NULL);
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

    memb_free(&trust_tx_memb, item);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void init(void)
{
    trust_common_init();
    edge_info_init();
    peer_info_init();

    coap_activate_resource(&res_trust, TRUST_COAP_URI);

    etimer_set(&periodic_timer, TRUST_POLL_PERIOD);

    memb_init(&trust_tx_memb);
    memb_init(&trust_rx_memb);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_WAIT_EVENT();

        if (ev == PROCESS_EVENT_TIMER && data == &periodic_timer)
        {
            etimer_reset(&periodic_timer);
            periodic_action();
        }

        if (ev == pe_message_signed)
        {
            trust_tx_continue(data);
        }

        if (ev == pe_message_verified)
        {
            trust_rx_continue(data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
