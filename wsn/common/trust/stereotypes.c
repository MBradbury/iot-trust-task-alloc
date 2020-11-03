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
LIST(stereotypes_requesting);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(stereotype, "stereotype");
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static timed_unlock_t coap_callback_in_use;
static uint8_t msg_buf[(1) + (1) + STEREOTYPE_TAGS_CBOR_MAX_LEN];

_Static_assert(TRUST_MODEL_TAG >= NANOCBOR_MIN_TINY_INTEGER, "TRUST_MODEL_TAG too small");
_Static_assert(TRUST_MODEL_TAG <= NANOCBOR_MAX_TINY_INTEGER, "TRUST_MODEL_TAG too large");
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_stereotype_t* edge_stereotype_find_in_list(const stereotype_tags_t* tags, list_t stereotypes_list)
{
    for (edge_stereotype_t* s = list_head(stereotypes_list); s != NULL; s = list_item_next(s))
    {
        if (stereotype_tags_equal(&s->tags, tags))
        {
            return s;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
edge_stereotype_t* edge_stereotype_find(const stereotype_tags_t* tags)
{
    return edge_stereotype_find_in_list(tags, stereotypes);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool edge_stereotype_remove_from_list(edge_stereotype_t* stereotype, list_t stereotypes_list)
{
    // Not managed by us, so can't free it
    if (!memb_inmemb(&stereotypes_memb, stereotype))
    {
        return false;
    }

    // Remove from list
    bool removed = list_remove(stereotypes_list, stereotype);
    if (!removed)
    {
        return false;
    }

    int free_result = memb_free(&stereotypes_memb, stereotype);

    return free_result == 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_stereotype_remove(edge_stereotype_t* stereotype)
{
    return edge_stereotype_remove_from_list(stereotype, stereotypes);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int serialise_request(nanocbor_encoder_t* enc, const stereotype_tags_t* tags)
{
    nanocbor_fmt_array(enc, 2);

    // Need to inform the server which trust model we are requesting information for
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, TRUST_MODEL_TAG));

    // Send the Edge's tags
    NANOCBOR_CHECK(serialise_stereotype_tags(enc, tags));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int deserialise_response(nanocbor_value_t* dec, uint32_t* model, edge_stereotype_t* stereotype)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, model));

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
    edge_stereotype_t stereotype;

    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, payload, payload_len);
    if (deserialise_response(&dec, &model, &stereotype) != NANOCBOR_OK)
    {
        LOG_ERR("Failed to deserialise sterotype payload\n");
        return;
    }

    // Unlikely to reach here, as this will likely cause a parsing error earlier
    if (model != TRUST_MODEL_TAG)
    {
        LOG_WARN("Received stereotype for incorrect model %"PRIu32" != " CC_STRINGIFY(TRUST_MODEL_TAG) "\n", model);
        return;
    }

    edge_stereotype_t* s = edge_stereotype_find_in_list(&stereotype.tags, stereotypes_requesting);
    if (s != NULL)
    {
        s->tags = stereotype.tags;
        s->edge_tm = stereotype.edge_tm;

        // Remove from request list and add to actual list
        list_remove(stereotypes_requesting, s);
        list_push(stereotypes, s);

        LOG_DBG("Added stereotype for trust model %" PRIu32 " and tag: ", model);
        stereotype_tags_print(&stereotype.tags);
        LOG_DBG_("\n");
    }
    else
    {
        // At this point something odd has happened,
        // we received a sterotype for tags that we did not request.
        LOG_WARN("Received sterotype for tags we did not ask for: ");
        stereotype_tags_print(&stereotype.tags);
        LOG_WARN_("\n");
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
static bool
stereotypes_free_up_space(void)
{
    // We have run out of space for stereotypes and now need to find some to remove.
    // We do not need to worry about race conditions as stereotypes will only be used during
    // trust calulcations and will not be referenced from elsewhere.

    for (edge_stereotype_t* s = list_head(stereotypes); s != NULL; s = list_item_next(s))
    {
        // 1. Remove any stereotypes that have a tag which is not one of the tags for the certificates
        if (!keystore_certificate_contains_tags(&s->tags))
        {
            if (edge_stereotype_remove(s))
            {
                return true;
            }
        }

        // TODO: Potentially consider removing stereotypes of low utility
    }

    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool stereotypes_request(const stereotype_tags_t* tags)
{
    if (edge_stereotype_find(tags) != NULL)
    {
        LOG_DBG("No need to request stereotypes for ");
        stereotype_tags_print(tags);
        LOG_DBG_(" as we already have them\n");
        return false;
    }

    if (edge_stereotype_find_in_list(tags, stereotypes_requesting) != NULL)
    {
        LOG_DBG("No need to request stereotypes for ");
        stereotype_tags_print(tags);
        LOG_DBG_(" as we are already requesting them\n");
        return false;
    }

    edge_stereotype_t* s = memb_alloc(&stereotypes_memb);
    if (s == NULL)
    {
        LOG_WARN("Insufficient memory for stereotype, looking for candidates to free...\n");

        if (!stereotypes_free_up_space())
        {
            LOG_ERR("Failed to free space for stereotype\n");
            return false;
        }
        else
        {
            s = memb_alloc(&stereotypes_memb);
            if (s == NULL)
            {
                LOG_ERR("Failed to allocate memory for stereotype\n");
                return false;
            }
            else
            {
                LOG_INFO("Successfully found memory for stereotype\n");
            }
        }
    }

    s->tags = *tags;

    list_push(stereotypes_requesting, s);

    process_poll(&stereotype);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool stereotypes_send_request(const stereotype_tags_t* tags)
{
    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return false;
    }

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, msg_buf, sizeof(msg_buf));
    if (serialise_request(&enc, tags) != NANOCBOR_OK)
    {
        LOG_ERR("Failed to serialise the sterotype request\n");
        return false;
    }

    assert(nanocbor_encoded_len(&enc) <= sizeof(msg_buf));

    coap_init_message(&msg, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(&msg, STEREOTYPE_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, nanocbor_encoded_len(&enc));

#if defined(WITH_OSCORE) && defined(AIOCOAP_SUPPORTS_OSCORE)
    coap_set_random_token(&msg);
    keystore_protect_coap_with_oscore(&msg, &root_ep);
#endif

    int ret = coap_send_request(&coap_callback, &root_ep, &msg, send_callback);
    if (ret)
    {
        timed_unlock_lock(&coap_callback_in_use);
        LOG_DBG("Stereotype request message sent to ");
        LOG_DBG_COAP_EP(&root_ep);
        LOG_DBG_(" for ");
        stereotype_tags_print(tags);
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
    list_init(stereotypes_requesting);

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

        // Either try to send when the coap lock is released or the process is polled
        if ((ev == pe_timed_unlock_unlocked && data == &coap_callback_in_use) || ev == PROCESS_EVENT_POLL)
        {
            // Do not expect this to be the case at this point
            if (!timed_unlock_is_locked(&coap_callback_in_use))
            {
                edge_stereotype_t* s = list_head(stereotypes_requesting);
                if (s)
                {
                    stereotypes_send_request(&s->tags);
                }
            }
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
