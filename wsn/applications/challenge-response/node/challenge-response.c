#include "challenge-response.h"
#include "application-serial.h"
#include "application-common.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/assert.h"
#include "list.h"
#include "memb.h"

#include "dev/sha256.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"

#include "nanocbor-helper.h"

#include <stdio.h>

#include "crypto-support.h"
#include "edge-info.h"
#include "trust.h"
#include "trust-models.h"
#include "applications.h"
#include "serial-helpers.h"
#include "timed-unlock.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#include "keystore-oscore.h"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// The number of bytes that will be checked for being 0 at the start of the hash
// Note this differs from blockchain mining difficulty, which checks the number of '0' characters at the start of the
// hex representation of the hash. So our difficulty is actually twice as hard as the same blockchain difficulty.
#ifndef CHALLENGE_DIFFICULTY
#define CHALLENGE_DIFFICULTY 2
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Must be in actual seconds and not in ticks for this sensor node, as we will send this duration to the edge node
#ifndef CHALLENGE_DURATION
#define CHALLENGE_DURATION (40) // seconds
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef CHALLENGE_PERIOD
#define CHALLENGE_PERIOD (clock_time_t)(2 * 60 * CLOCK_SECOND)
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
_Static_assert(CHALLENGE_DURATION * CLOCK_SECOND < CHALLENGE_PERIOD,
    "Challenge duration must be less than the challenge period");
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" CHALLENGE_RESPONSE_APPLICATION_NAME
#ifdef APP_CHALLENGE_RESPONSE_LOG_LEVEL
#define LOG_LEVEL APP_CHALLENGE_RESPONSE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static app_state_t app_state;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_challenger {
    struct edge_challenger* next;

    edge_resource_t* edge;
    challenge_t ch;

    clock_time_t generated;
    clock_time_t received;

} edge_challenger_t;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(challenge_response_process, CHALLENGE_RESPONSE_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(challengers_memb, edge_challenger_t, NUM_EDGE_RESOURCES);
LIST(challengers);
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_endpoint_t ep;
static coap_callback_request_state_t coap_callback;
static timed_unlock_t coap_callback_in_use;
static uint8_t msg_buf[(1) + (1 + sizeof(uint32_t)) + (1 + 32)];
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_challenger_t* next_challenge;
static struct etimer challenge_timer;
static struct etimer challenge_response_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_challenger_t*
find_edge_challenger(edge_resource_t* edge)
{
    for (edge_challenger_t* iter = list_head(challengers); iter != NULL; iter = list_item_next(iter))
    {
        if (iter->edge == edge)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
move_to_next_challenge(void)
{
    LOG_DBG("Moving to next challenge ");

    // Move to next challenge, if there is one
    if (next_challenge != NULL)
    {
        LOG_DBG_("currently ");
        LOG_DBG_6ADDR(&next_challenge->edge->ep.ipaddr);
        LOG_DBG_(" ");

        next_challenge = list_item_next(next_challenge);

        if (next_challenge != NULL)
        {
            LOG_DBG_("setting to ");
            LOG_DBG_6ADDR(&next_challenge->edge->ep.ipaddr);
            LOG_DBG_(" ");
        }
    }
    else
    {
        LOG_DBG_("currently NULL ");
    }
    
    // If there is no next challenge, move back to the list's head
    if (next_challenge == NULL)
    {
        next_challenge = list_head(challengers);

        LOG_DBG_("setting to ");
        LOG_DBG_6ADDR(next_challenge == NULL ? NULL : &next_challenge->edge->ep.ipaddr);
        LOG_DBG_(" ");
    }

    // Either we are on a new challenge, or
    // the final challenge might have been removed,
    // in either case we need to stop the timeout timer
    etimer_stop(&challenge_response_timer);

    LOG_DBG_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
generate_challenge(challenge_t* ch, uint8_t difficulty, uint32_t max_duration_secs)
{
    crypto_fill_random(ch->data, sizeof(ch->data));
    ch->difficulty = difficulty;
    ch->max_duration_secs = max_duration_secs;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
send_callback(coap_callback_request_state_t* callback_state)
{
    tm_challenge_response_info_t info = {
        .type = TM_CHALLENGE_RESPONSE_ACK,
        .coap_status = NO_ERROR,
        .coap_request_status = callback_state->state.status
    };

    switch (callback_state->state.status)
    {
    case COAP_REQUEST_STATUS_RESPONSE:
    {
        coap_message_t* response = callback_state->state.response;

        if (response->code == CONTENT_2_05)
        {
            LOG_DBG("Message send complete with code CONTENT_2_05 (len=%d)\n", response->payload_len);

            // Set a timer for when we expect a response by
            PROCESS_CONTEXT_BEGIN(&challenge_response_process);
            etimer_set(&challenge_response_timer, next_challenge->ch.max_duration_secs * CLOCK_SECOND);
            PROCESS_CONTEXT_END(&challenge_response_process);
        }
        else
        {
            LOG_WARN("Message send failed with code (%u) '%.*s' (len=%d)\n",
                response->code, response->payload_len, response->payload, response->payload_len);
        }

        info.coap_status = response->code;
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        timed_unlock_unlock(&coap_callback_in_use);
    } break;

    default:
    {
        LOG_ERR("Failed to send message due to %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        timed_unlock_unlock(&coap_callback_in_use);
    } break;
    }

    edge_resource_t* edge = edge_info_find_addr(&ep.ipaddr);
    if (edge == NULL)
    {
        LOG_WARN("Edge ");
        LOG_WARN_COAP_EP(&ep);
        LOG_WARN_(" was removed between sending a task and receiving an acknowledgement\n");
        return;
    }

    tm_update_challenge_response(edge, &info);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
challenge_response_timed_out(void)
{
    // Was there a previous challenge request and did we get a response?
    if (next_challenge != NULL)
    {
        const clock_time_t duration = next_challenge->ch.max_duration_secs * CLOCK_SECOND;

        const bool never_received = next_challenge->received <= next_challenge->generated;
        const bool received_late = next_challenge->received > next_challenge->generated + duration;

        // Only check if we have previously sent a challenge
        if (next_challenge->generated != 0 && (never_received || received_late))
        {
            LOG_WARN("Failed to receive challenge response from ");
            LOG_WARN_6ADDR(&next_challenge->edge->ep.ipaddr);
            LOG_WARN_(" in a suitable time (gen=%lu,recv=%lu,diff=%lu,dur=%ld)\n",
                next_challenge->generated,
                next_challenge->received,
                (int32_t)(next_challenge->received - next_challenge->generated),
                duration
            );

            const tm_challenge_response_info_t info = {
                .type = TM_CHALLENGE_RESPONSE_TIMEOUT,
                .never_received = never_received,
                .received_late = received_late,
            };

            tm_update_challenge_response(next_challenge->edge, &info);

            // Reset generation / receive counters
            next_challenge->generated = 0;
            next_challenge->received = 0;
        }
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_action(void)
{
    int ret;

    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return;
    }

    move_to_next_challenge();

    if (next_challenge == NULL)
    {
        LOG_WARN("No challenges possible\n");
        return;
    }

    generate_challenge(&next_challenge->ch, CHALLENGE_DIFFICULTY, CHALLENGE_DURATION);

    int len = nanocbor_fmt_challenge(msg_buf, sizeof(msg_buf), &next_challenge->ch);
    if (len <= 0 || len > sizeof(msg_buf))
    {
        LOG_ERR("Failed to generated message (%d)\n", len);
        return;
    }

    LOG_DBG("Generated message (len=%d) for challenge difficulty=%d and ", len, next_challenge->ch.difficulty);
    LOG_DBG_BYTES(next_challenge->ch.data, sizeof(next_challenge->ch.data));
    LOG_DBG_("\n");

    // Choose an Edge node to send information to
    edge_resource_t* edge = next_challenge->edge;

    // We need to store a local copy of the edge target
    // As the edge resource object may be removed by the time we receive a response
    coap_endpoint_copy(&ep, &edge->ep);

    if (!coap_endpoint_is_connected(&edge->ep))
    {
        LOG_DBG("We are not connected to ");
        LOG_DBG_COAP_EP(&ep);
        LOG_DBG_(", so will initiate a connection to it.\n");

        // Initiate a connect
        coap_endpoint_connect(&ep);

        // Wait for a bit and then try sending again
        //etimer_set(&publish_short_timer, SHORT_PUBLISH_PERIOD);
        //return;
    }

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);
    coap_set_header_uri_path(&msg, CHALLENGE_RESPONSE_APPLICATION_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, len);

    coap_set_random_token(&msg);

#ifdef WITH_OSCORE
    keystore_protect_coap_with_oscore(&msg, &ep);
#endif

    // Regord when we sent this challenge
    next_challenge->generated = clock_time();

    ret = coap_send_request(&coap_callback, &ep, &msg, send_callback);
    if (ret)
    {
        timed_unlock_lock(&coap_callback_in_use);
        LOG_DBG("Message sent to ");
        LOG_DBG_COAP_EP(&ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static uint8_t
sha256_hash_challenge_response(const challenge_t* c, const challenge_response_t* cr, uint8_t* hash)
{
    //LOG_DBG("Challenge prefix: ");
    //LOG_DBG_BYTES(cr->data_prefix, cr->data_length);
    //LOG_DBG_("\n");

    //LOG_DBG("Challenge data: ");
    //LOG_DBG_BYTES(c->data, sizeof(c->data));
    //LOG_DBG_("\n");

    sha256_state_t sha256_state;

    bool enabled = CRYPTO_IS_ENABLED();
    if (!enabled)
    {
        crypto_enable();
    }

    uint8_t ret;

    ret = sha256_init(&sha256_state);
    if (ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_init failed with %u\n", ret);
        goto end;
    }

    ret = sha256_process(&sha256_state, cr->data_prefix, cr->data_length);
    if (ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_process1 failed with %u\n", ret);
        goto end;
    }

    ret = sha256_process(&sha256_state, c->data, sizeof(c->data));
    if (ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_process2 failed with %u\n", ret);
        goto end;
    }

    ret = sha256_done(&sha256_state, hash);
    if (ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_done failed with %u\n", ret);
        goto end;
    }

    //LOG_DBG("Challenge hash: ");
    //LOG_DBG_BYTES(hash, SHA256_DIGEST_LEN_BYTES);
    //LOG_DBG_("\n");

end:
    if (!enabled)
    {
        crypto_disable();
    }

    return ret;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
check_first_n_zeros(const uint8_t* data, size_t data_len, size_t n)
{
    if (n > data_len)
    {
        return false;
    }

    for (size_t i = 0; i != n; ++i)
    {
        if (data[i] != 0)
        {
            return false;
        }
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
res_coap_cr_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

static
RESOURCE(res_coap,
         "title=\"Challenge Response\";rt=\"" CHALLENGE_RESPONSE_APPLICATION_NAME "\"",
         NULL,                          /*GET*/
         res_coap_cr_post_handler,      /*POST*/
         NULL,                          /*PUT*/
         NULL                           /*DELETE*/);

static void
res_coap_cr_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    int ret;

    // Record the time
    const clock_time_t received = clock_time();

    const char* uri_path;
    int uri_len = coap_get_header_uri_path(request, &uri_path);

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received challenge response data uri=%.*s, payload_len=%d from ", uri_len, uri_path, payload_len);
    LOG_DBG_COAP_EP(request->src_ep);
    LOG_DBG_("\n");

    tm_challenge_response_info_t info = {
        .type = TM_CHALLENGE_RESPONSE_RESP,
        .challenge_successful = false,
    };

    // Get the challenge
    edge_resource_t* edge = edge_info_find_addr(&request->src_ep->ipaddr);
    if (edge == NULL)
    {
        LOG_ERR("Challenge response from unknown edge\n");
        return;
    }

    edge_challenger_t* challenger = find_edge_challenger(edge);
    if (challenger == NULL)
    {
        LOG_ERR("Unable to find challenge sent to edge\n");
        goto end;
    }

    // Received a response, so do not want to timeout now
    etimer_stop(&challenge_response_timer);

    // Record when the response was received
    challenger->received = received;

    // Get the challenge response
    challenge_response_t cr;
    ret = nanocbor_get_challenge_response(payload, payload_len, &cr);
    if (ret != NANOCBOR_OK)
    {
        LOG_ERR("Failed to parse challenge respose from ");
        LOG_ERR_COAP_EP(request->src_ep);
        LOG_ERR_("\n");
        goto end;
    }

    // Validate the challenge response
    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    if (sha256_hash_challenge_response(&challenger->ch, &cr, digest) != CRYPTO_SUCCESS)
    {
        LOG_ERR("Challenge response hash failed\n");
        goto end;
    }

    // Check that digest meets the difficulty requirement
    info.challenge_successful = check_first_n_zeros(digest, sizeof(digest), challenger->ch.difficulty);

    // Record if this was received late
    info.challenge_late = (challenger->received - challenger->generated) > (challenger->ch.max_duration_secs * CLOCK_SECOND);

    LOG_INFO("Challenge response from ");
    LOG_INFO_6ADDR(&edge->ep.ipaddr);
    LOG_INFO_(" %s\n", info.challenge_successful ? "succeeded" : "failed");

    // Update trust model
end:
    tm_update_challenge_response(edge, &info);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_add(edge_resource_t* edge)
{
    if (app_state_edge_capability_add(&app_state, edge))
    {
        etimer_set(&challenge_timer, CHALLENGE_PERIOD);
    }

    // Check that we don't already have a challenger allocated
    // for this edge
    edge_challenger_t* c = find_edge_challenger(edge);
    if (c == NULL)
    {
        c = memb_alloc(&challengers_memb);
        if (c == NULL)
        {
            LOG_ERR("Failed to allocate edge_challenger\n");
        }
        else
        {
            c->edge = edge;
            c->generated = 0;
            c->received = 0;

            list_push(challengers, c);

            if (next_challenge == NULL)
            {
                move_to_next_challenge();
            }
        }
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_remove(edge_resource_t* edge)
{
    if (app_state_edge_capability_remove(&app_state, edge))
    {
        etimer_stop(&challenge_timer);
    }

    edge_challenger_t* c = find_edge_challenger(edge);
    if (c == NULL)
    {
        LOG_ERR("Failed to deallocate edge_challenger\n");
    }
    else
    {
        if (next_challenge == c)
        {
            move_to_next_challenge();
        }

        list_remove(challengers, c);
        memb_free(&challengers_memb, c);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    coap_activate_resource(&res_coap, CHALLENGE_RESPONSE_APPLICATION_URI);

#ifdef WITH_OSCORE
    oscore_protect_resource(&res_coap);
#endif

    app_state_init(&app_state, CHALLENGE_RESPONSE_APPLICATION_NAME, CHALLENGE_RESPONSE_APPLICATION_URI);

    timed_unlock_init(&coap_callback_in_use, "challenge-response", (1 * 60 * CLOCK_SECOND));

    memb_init(&challengers_memb);
    list_init(challengers);

    next_challenge = NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(challenge_response_process, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == PROCESS_EVENT_TIMER && data == &challenge_timer) {
            periodic_action();
            etimer_reset(&challenge_timer);
        }

        if (ev == PROCESS_EVENT_TIMER && data == &challenge_response_timer) {
            challenge_response_timed_out();
        }

        if (ev == pe_edge_capability_add) {
            edge_capability_add((edge_resource_t*)data);
        }

        if (ev == pe_edge_capability_remove) {
            edge_capability_remove((edge_resource_t*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
