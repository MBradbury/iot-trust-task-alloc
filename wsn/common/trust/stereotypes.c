#include "stereotypes.h"
#include "trust-model.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"
#include "keystore-oscore.h"

#include "nanocbor-helper.h"

#include "os/sys/log.h"
#include "assert.h"

#define STEREOTYPE_URI "stereotype"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-comm"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
extern coap_endpoint_t server_ep;
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static bool coap_callback_in_use;
static uint8_t msg_buf[(1) + (1) + IPV6ADDR_CBOR_MAX_LEN + STEREOTYPE_TAGS_CBOR_MAX_LEN];

_Static_assert(TRUST_MODEL_TAG >= NANOCBOR_MIN_TINY_INTEGER, "TRUST_MODEL_TAG too small");
_Static_assert(TRUST_MODEL_TAG <= NANOCBOR_MAX_TINY_INTEGER, "TRUST_MODEL_TAG too large");
/*-------------------------------------------------------------------------------------------------------------------*/
static int serialise_request(nanocbor_encoder_t* enc, const edge_resource_t* edge)
{
    nanocbor_fmt_array(enc, 3);

    // Need to inform the server which trust model we are requesting information for
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, TRUST_MODEL_TAG));

    // Send the identity of the edge
    NANOCBOR_CHECK(nanocbor_fmt_ipaddr(enc, &edge->ep.ipaddr));

    // Send the Edge's tags
    NANOCBOR_CHECK(serialise_stereotype_tags(enc, &edge->tags));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int deserialise_response(nanocbor_value_t* dec)
{

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_sterotype_response(coap_message_t* response)
{
    const uint8_t* payload;
    int payload_len = coap_get_payload(response, &payload);

    unsigned int content_format;
    if (!coap_get_header_content_format(response, &content_format))
    {
        LOG_ERR("Received sterotype response had no content format\n");
        return;
    }
    if (content_format != APPLICATION_CBOR)
    {
        LOG_ERR("Received sterotype response not in CBOR format\n");
        return;
    }

    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, payload, payload_len);
    if (deserialise_response(&dec) != NANOCBOR_OK)
    {
        LOG_ERR("Failed to deserialise sterotype payload\n");
        return;
    }

    // TODO: Do something with this
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
send_callback(coap_callback_request_state_t* callback_state)
{
    switch (callback_state->state.status)
    {
    case COAP_REQUEST_STATUS_RESPONSE:
    {
        coap_message_t* response = callback_state->state.response;

        if (response->code == CONTENT_2_05)
        {
            LOG_DBG("Message send complete with code CONTENT_2_05 (len=%d)\n", response->payload_len);
            process_sterotype_response(response);
        }
        else
        {
            LOG_WARN("Message send failed with code (%u) '%.*s' (len=%d)\n",
                response->code, response->payload_len, response->payload, response->payload_len);
        }
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        coap_callback_in_use = false;
    } break;

    default:
    {
        LOG_ERR("Failed to send message due to %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        coap_callback_in_use = false;
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool stereotypes_request(const edge_resource_t* edge)
{
    if (!coap_callback_in_use)
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return false;
    }

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, msg_buf, sizeof(msg_buf));
    if (serialise_request(&enc, edge) != NANOCBOR_OK)
    {
        LOG_ERR("Failed to serialise the sterotype request\n");
        return false;
    }

    assert(nanocbor_encoded_len(&enc) <= sizeof(msg_buf));

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, STEREOTYPE_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, nanocbor_encoded_len(&enc));

    // Not yet with aiocoap
    //coap_set_random_token(&msg);

/*#ifdef WITH_OSCORE
    keystore_protect_coap_with_oscore(&msg, &server_ep);
#endif*/

    int ret = coap_send_request(&coap_callback, &server_ep, &msg, send_callback);
    if (ret)
    {
        coap_callback_in_use = true;
        LOG_DBG("Message sent to ");
        LOG_DBG_COAP_EP(&server_ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }

    return coap_callback_in_use;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void stereotypes_init(void)
{
    coap_callback_in_use = false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
