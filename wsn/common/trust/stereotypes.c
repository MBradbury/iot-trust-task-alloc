#include "stereotypes.h"
#include "trust-model.h"
#include "trust-models.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"
#include "keystore-oscore.h"
#include "timed-unlock.h"
#include "root-endpoint.h"
#include "keystore.h"

#include "nanocbor-helper.h"

#include "os/sys/log.h"
#include "assert.h"
#include "memb.h"
#include "list.h"

#define STEREOTYPE_URI "stereotype"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "stereotype"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(stereotypes_memb, edge_stereotype_t, MAX_NUM_STEREOTYPES);
LIST(stereotypes);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(stereotype, "stereotype");
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static timed_unlock_t coap_callback_in_use;
static uint8_t msg_buf[(1) + (1) + IPV6ADDR_CBOR_MAX_LEN + STEREOTYPE_TAGS_CBOR_MAX_LEN];

_Static_assert(TRUST_MODEL_TAG >= NANOCBOR_MIN_TINY_INTEGER, "TRUST_MODEL_TAG too small");
_Static_assert(TRUST_MODEL_TAG <= NANOCBOR_MAX_TINY_INTEGER, "TRUST_MODEL_TAG too large");
/*-------------------------------------------------------------------------------------------------------------------*/
edge_stereotype_t* edge_stereotype_find(const stereotype_tags_t* tags)
{
    for (edge_stereotype_t* s = list_head(stereotypes); s != NULL; s = list_item_next(s))
    {
        if (stereotype_tags_equal(&s->tags, tags))
        {
            return s;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int serialise_request(nanocbor_encoder_t* enc, const edge_resource_t* edge, const public_key_item_t* item)
{
    nanocbor_fmt_array(enc, 3);

    // Need to inform the server which trust model we are requesting information for
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, TRUST_MODEL_TAG));

    // Send the identity of the edge
    NANOCBOR_CHECK(nanocbor_fmt_ipaddr(enc, &edge->ep.ipaddr));

    // Send the Edge's tags
    NANOCBOR_CHECK(serialise_stereotype_tags(enc, &item->cert.tags));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int deserialise_response(nanocbor_value_t* dec, uint32_t* model, const uip_ip6addr_t** ipaddr, edge_stereotype_t* stereotype)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, model));

    NANOCBOR_CHECK(nanocbor_get_ipaddr(&arr, ipaddr));

    NANOCBOR_CHECK(deserialise_stereotype_tags(&arr, &stereotype->tags));

    NANOCBOR_CHECK(deserialise_trust_edge_resource(&arr, &stereotype->edge_tm));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

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
        LOG_ERR("Received stereotype response had no content format\n");
        return;
    }
    if (content_format != APPLICATION_CBOR)
    {
        LOG_ERR("Received stereotype response not in CBOR format\n");
        return;
    }

    uint32_t model = TRUST_MODEL_INVALID_TAG;
    const uip_ip6addr_t* addr = NULL;
    edge_stereotype_t stereotype;

    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, payload, payload_len);
    if (deserialise_response(&dec, &model, &addr, &stereotype) != NANOCBOR_OK)
    {
        LOG_ERR("Failed to deserialise sterotype payload\n");
        return;
    }

    edge_resource_t* edge = edge_info_find_addr(addr);
    if (edge)
    {
        // Clear that this edge needs stereotypes requested for it
        edge->flags &= ~EDGE_RESOURCE_STEREOTYPE_REQUEST;
    }
    else
    {
        LOG_WARN("Received stereotype information for unknown edge: ");
        LOG_WARN_6ADDR(addr);
        LOG_WARN_("\n");
    }

    // Unlikely to reach here, as this will likely cause a parsing error earlier
    if (model != TRUST_MODEL_TAG)
    {
        LOG_WARN("Received stereotype for incorrect model %"PRIu32" != " CC_STRINGIFY(TRUST_MODEL_TAG) "\n", model);
        return;
    }
    
    // If there is a stereotype already added with the same set of
    // tags then we need to update it.
    edge_stereotype_t* s = edge_stereotype_find(&stereotype.tags);
    if (s != NULL)
    {
        s->tags = stereotype.tags;
        s->edge_tm = stereotype.edge_tm;
    }
    // If not we need to add this sterotype.
    else
    {
        s = memb_alloc(&stereotypes_memb);
        if (s == NULL)
        {
            LOG_ERR("Insufficient memory for stereotype\n");
            return;
        }

        s->tags = stereotype.tags;
        s->edge_tm = stereotype.edge_tm;

        list_push(stereotypes, s);
    }
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
        timed_unlock_unlock(&coap_callback_in_use);

        // Poll to signal that a request has finished being processed
        process_poll(&stereotype);
    } break;

    default:
    {
        LOG_ERR("Failed to send message due to %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        timed_unlock_unlock(&coap_callback_in_use);
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool stereotypes_request(edge_resource_t* edge, const stereotype_tags_t* tags)
{
    /*public_key_item_t* item = keystore_find(&edge->ep.ipaddr);
    if (item == NULL)
    {
        LOG_ERR("Failed to find keystore entry for ");
        LOG_ERR_6ADDR(&edge->ep.ipaddr);
        LOG_ERR_("\n");
        return false;
    }*/

    //if (edge_stereotype_find(&item->cert.tags) != NULL)
    if (edge_stereotype_find(tags) != NULL)
    {
        LOG_DBG("No need to request stereotypes for %s as we already have them\n", edge->name);
        return false;
    }

    // Set that this edge needs stereotypes requested for it
    edge->flags |= EDGE_RESOURCE_STEREOTYPE_REQUEST;

    process_poll(&stereotype);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool stereotypes_send_request(const edge_resource_t* edge)
{
    public_key_item_t* item = keystore_find(&edge->ep.ipaddr);
    if (item == NULL)
    {
        LOG_ERR("Failed to find keystore entry for ");
        LOG_ERR_6ADDR(&edge->ep.ipaddr);
        LOG_ERR_("\n");
        return false;
    }

    if (edge_stereotype_find(&item->cert.tags) != NULL)
    {
        LOG_DBG("No need to request stereotypes for %s as we already have them\n", edge->name);
        return false;
    }

    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return false;
    }

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, msg_buf, sizeof(msg_buf));
    if (serialise_request(&enc, edge, item) != NANOCBOR_OK)
    {
        LOG_ERR("Failed to serialise the sterotype request\n");
        return false;
    }

    assert(nanocbor_encoded_len(&enc) <= sizeof(msg_buf));

    coap_init_message(&msg, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(&msg, STEREOTYPE_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, nanocbor_encoded_len(&enc));

    // Not yet with aiocoap
    //coap_set_random_token(&msg);

/*#ifdef WITH_OSCORE
    keystore_protect_coap_with_oscore(&msg, &root_ep);
#endif*/

    int ret = coap_send_request(&coap_callback, &root_ep, &msg, send_callback);
    if (ret)
    {
        timed_unlock_lock(&coap_callback_in_use);
        LOG_DBG("Stereotype request message sent to ");
        LOG_DBG_COAP_EP(&root_ep);
        LOG_DBG_(" for ");
        LOG_DBG_6ADDR(&edge->ep.ipaddr);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send stereotype request message with %d\n", ret);
    }

    return timed_unlock_is_locked(&coap_callback_in_use);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void stereotypes_init(void)
{
    memb_init(&stereotypes_memb);
    list_init(stereotypes);

    PROCESS_CONTEXT_BEGIN(&stereotype);
    timed_unlock_init(&coap_callback_in_use, "stereotypes", (1 * 60 * CLOCK_SECOND));
    PROCESS_CONTEXT_END(&stereotype);

    process_start(&stereotype, NULL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(stereotype, ev, data)
{
    PROCESS_BEGIN();

    while (1)
    {
        PROCESS_YIELD();

        if ((ev == pe_timed_unlock_unlocked && data == &coap_callback_in_use) || ev == PROCESS_EVENT_POLL)
        {
            // Do not expect this to be the case at this point
            if (!timed_unlock_is_locked(&coap_callback_in_use))
            {
                // See if there is an edge resource we need to get stereotype information for
                for (edge_resource_t* iter = edge_info_iter(); iter != NULL; iter = edge_info_next(iter))
                {
                    // Check if there is a request pending
                    if ((iter->flags & EDGE_RESOURCE_STEREOTYPE_REQUEST) != 0)
                    {
                        stereotypes_send_request(iter);
                        break;
                    }
                }
            }
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
