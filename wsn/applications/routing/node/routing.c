#include "routing.h"
#include "application-serial.h"
#include "application-common.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/assert.h"
#include "os/dev/serial-line.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"
#include "coap-block1.h"

#include "nanocbor-helper.h"

#include <stdio.h>

#include "edge-info.h"
#include "trust.h"
#include "trust-models.h"
#include "trust-choose.h"
#include "applications.h"
#include "serial-helpers.h"
#include "float-helpers.h"
#include "timed-unlock.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#include "keystore-oscore.h"
#endif

#ifdef ROUTING_PERIODIC_TEST
#include "routing-periodic-test.h"
#endif

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" ROUTING_APPLICATION_NAME
#ifdef APP_ROUTING_LOG_LEVEL
#define LOG_LEVEL APP_ROUTING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static app_state_t app_state;
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_endpoint_t ep;
static coap_callback_request_state_t coap_callback;
static timed_unlock_t coap_callback_in_use;
static uint8_t msg_buf[(1) + (1 + sizeof(uint32_t)) + (1 + (1 + sizeof(float)) * 2) * 2];
/*-------------------------------------------------------------------------------------------------------------------*/
static timed_unlock_t task_in_use;
static coordinate_t task_src, task_dest;
static bool first_src_isclose;
/*-------------------------------------------------------------------------------------------------------------------*/
static int
generate_routing_request(uint8_t* buf, size_t buf_len, const coordinate_t* source, const coordinate_t* destination)
{
    uint32_t time_secs = clock_seconds();

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buf_len);

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 3));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, time_secs));
    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 2));
    NANOCBOR_CHECK(nanocbor_fmt_float(&enc, source->latitude));
    NANOCBOR_CHECK(nanocbor_fmt_float(&enc, source->longitude));
    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 2));
    NANOCBOR_CHECK(nanocbor_fmt_float(&enc, destination->latitude));
    NANOCBOR_CHECK(nanocbor_fmt_float(&enc, destination->longitude));

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
nanocbor_get_coordinate(nanocbor_value_t* dec, coordinate_t* coord)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    NANOCBOR_CHECK(nanocbor_get_float(&arr, &coord->latitude));
    NANOCBOR_CHECK(nanocbor_get_float(&arr, &coord->longitude));

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_leave_container\n");
        return -1;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int
nanocbor_get_coordinate_from_payload(nanocbor_value_t* dec, coordinate_t* coord, int pos)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    if (nanocbor_at_end(&arr))
    {
        return -1;
    }

    if (pos == 1)
    {
        NANOCBOR_CHECK(nanocbor_get_coordinate(&arr, coord));
    }
    else if (pos == -1)
    {
        // This should be at least 1, due to the previous check of nanocbor_at_end
        uint32_t remaining = arr.remaining;

        // Skip all but the last items
        for (uint32_t i = 0; i < remaining - 1; ++i)
        {
            NANOCBOR_CHECK(nanocbor_skip(&arr));
        }

        NANOCBOR_CHECK(nanocbor_get_coordinate(&arr, coord));
    }
    else
    {
        assert(false);
    }

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
send_callback(coap_callback_request_state_t* callback_state)
{
    tm_task_submission_info_t info = {
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
        }
        else
        {
            LOG_WARN("Message send failed with code (%u) '%.*s' (len=%d)\n",
                response->code, response->payload_len, response->payload, response->payload_len);
            timed_unlock_unlock(&task_in_use);
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
        timed_unlock_unlock(&task_in_use);
    } break;
    }

    edge_resource_t* edge = edge_info_find_addr(&ep.ipaddr);
    if (edge == NULL)
    {
        LOG_WARN("Edge ");
        LOG_WARN_COAP_EP(&ep);
        LOG_WARN_(" was removed between sending a task and receiving a acknowledgement\n");
        return;
    }

    // Find the information on the capability for this edge
    // If this capability no longer exists, then the Edge has informed us that it no longer
    // offers that capability
    edge_capability_t* cap = edge_info_capability_find(edge, ROUTING_APPLICATION_NAME);
    if (cap == NULL)
    {
        LOG_WARN("Edge ");
        LOG_WARN_COAP_EP(&ep);
        LOG_WARN_(" removed capability " ROUTING_APPLICATION_NAME " between sending a task and receiving a acknowledgement\n");
        return;
    }

    tm_update_task_submission(edge, cap, &info);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool parse_input(const char* data, coordinate_t* source, coordinate_t* destination)
{
    LOG_DBG("Received command input '%s' from user\n", data);

    const char* data_end = data + strlen(data);

    bool result = false;

    if (!match_action(data, data_end, APPLICATION_SERIAL_PREFIX))
    {
        goto end;
    }
    data += strlen(APPLICATION_SERIAL_PREFIX);

    if (!match_action(data, data_end, ROUTING_SUBMIT_TASK))
    {
        goto end;
    }
    data += strlen(ROUTING_SUBMIT_TASK);

    char* endptr;

    // Expect 2 floating point numbers that are comma separated
    source->latitude = strtof(data, &endptr);

    if (*endptr != ',' || endptr + 1 >= data_end)
    {
        goto end;
    }
    data = (const char*)endptr + 1;

    source->longitude = strtof(data, &endptr);

    // expect colon to separate source and destination
    if (*endptr != ':' || endptr + 1 >= data_end)
    {
        goto end;
    }
    data = (const char*)endptr + 1;

    // Expect 2 floating point numbers that are comma separated
    destination->latitude = strtof(data, &endptr);

    if (*endptr != ',' || endptr + 1 >= data_end)
    {
        goto end;
    }
    data = (const char*)endptr + 1;

    destination->longitude = strtof(data, &endptr);

    if (*endptr != '\0' || endptr == data || endptr != data_end)
    {
        goto end;
    }

    // Successfully parsed
    result = true;

end:
    if (!result)
    {
        LOG_ERR("Expected input to be in the format "
            APPLICATION_SERIAL_PREFIX ROUTING_SUBMIT_TASK "<src-lat>,<src-lon>:<dest-lat>,<dest-lon>\n");
    }

    return result;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
event_triggered_action(const char* data)
{
    int ret;

    if (timed_unlock_is_locked(&coap_callback_in_use))
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return;
    }

    if (timed_unlock_is_locked(&task_in_use))
    {
        LOG_WARN("Cannot generate a new task, as in process of processing one\n");
        return;
    }

    if (!parse_input(data, &task_src, &task_dest))
    {
        LOG_WARN("Invalid command '%s'\n", data);
        return;
    }

    if (!app_state.running)
    {
        LOG_WARN("No Edge servers available to process request\n");
        return;
    }

    int len = generate_routing_request(msg_buf, sizeof(msg_buf), &task_src, &task_dest);
    if (len <= 0 || len > sizeof(msg_buf))
    {
        LOG_ERR("Failed to generated message (%d)\n", len);
        return;
    }

    LOG_DBG("Generated message (len=%d) for path from (%f,%f) to (%f,%f)\n",
        len,
        task_src.latitude, task_src.longitude,
        task_dest.latitude, task_dest.longitude);

    // Choose an Edge node to send information to
    edge_resource_t* edge = choose_edge(ROUTING_APPLICATION_NAME);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find an edge resource to send task to\n");
        return;
    }

    // We need to store a local copy of the edge target
    // As the edge resource object may be removed by the time we receive a response
    coap_endpoint_copy(&ep, &edge->ep);

    if (!coap_endpoint_is_connected(&ep))
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
    coap_set_header_uri_path(&msg, ROUTING_APPLICATION_URI);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, len);

    coap_set_random_token(&msg);

#ifdef WITH_OSCORE
    keystore_protect_coap_with_oscore(&msg, &ep);
#endif

    ret = coap_send_request(&coap_callback, &ep, &msg, send_callback);
    if (ret)
    {
        timed_unlock_lock(&task_in_use);
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
static void
routing_response_process_status(coap_message_t *request)
{
    int ret;

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, payload, payload_len);

    uint32_t status;
    ret = nanocbor_get_uint32(&dec, &status);
    if (ret < 0)
    {
        LOG_ERR("Failed to parse contents of task response (ret=%d)\n", ret);
        status = ROUTING_PARSING_ERROR;
    }

    if (status == ROUTING_SUCCESS)
    {
        LOG_INFO("Routing task succeeded, waiting for task result data from server...\n");
    }
    else
    {
        LOG_ERR("Routing task failed with error %"PRIu32"\n", status);
    }

    // Update trust model
    edge_resource_t* edge = edge_info_find_addr(&request->src_ep->ipaddr);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find edge (");
        LOG_ERR_6ADDR(&request->src_ep->ipaddr);
        LOG_ERR_(") to update trust of\n");
        return;
    }

    edge_capability_t* cap = edge_info_capability_find(edge, ROUTING_APPLICATION_NAME);
    if (cap == NULL)
    {
        LOG_ERR("Failed to find edge (");
        LOG_ERR_6ADDR(&request->src_ep->ipaddr);
        LOG_ERR_(") capability %s to update trust of\n", ROUTING_APPLICATION_NAME);
        return;
    }

    // Update trust model with notification of task success/failure
    const tm_task_result_info_t info = {
        .result = (status == ROUTING_SUCCESS) ? TM_TASK_RESULT_INFO_SUCCESS : TM_TASK_RESULT_INFO_FAIL
    };
    tm_update_task_result(edge, cap, &info);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
routing_process_task_timeout(void)
{
    LOG_WARN("Timed out while waiting for response for the routing task\n");

    edge_resource_t* edge = edge_info_find_addr(&ep.ipaddr);
    if (!edge)
    {
        LOG_ERR("Unable to find edge this task was sent to: ");
        LOG_ERR_COAP_EP(coap_callback.state.remote_endpoint);
        LOG_ERR_("\n");
        return;
    }

    edge_capability_t* cap = edge_info_capability_find(edge, ROUTING_APPLICATION_NAME);
    if (!cap)
    {
        LOG_ERR("Failed to find capability " ROUTING_APPLICATION_NAME " for edge ");
        LOG_ERR_COAP_EP(coap_callback.state.remote_endpoint);
        LOG_ERR_("\n");
        return;
    }

    // When the response times out, we need to log that an error occurred
    const tm_task_result_info_t info = {
        .result = TM_TASK_RESULT_INFO_TIMEOUT
    };
    tm_update_task_result(edge, cap, &info);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
routing_process_task_result(coap_message_t *request, const tm_result_quality_info_t* info)
{
    edge_resource_t* edge = edge_info_find_addr(&request->src_ep->ipaddr);
    if (!edge)
    {
        LOG_ERR("Unable to find edge this task was sent to: ");
        LOG_ERR_COAP_EP(coap_callback.state.remote_endpoint);
        LOG_ERR_("\n");
        return;
    }

    edge_capability_t* cap = edge_info_capability_find(edge, ROUTING_APPLICATION_NAME);
    if (!cap)
    {
        LOG_ERR("Failed to find capability " ROUTING_APPLICATION_NAME " for edge ");
        LOG_ERR_COAP_EP(coap_callback.state.remote_endpoint);
        LOG_ERR_("\n");
        return;
    }

    tm_update_result_quality(edge, cap, info);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
res_coap_routing_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

// TODO: See RFC6690 Section 3.1 for what to set rt to
// https://tools.ietf.org/html/rfc6690#section-3.1
static
RESOURCE(res_coap,
         "title=\"Routing Response\";rt=\"" ROUTING_APPLICATION_NAME "\"",
         NULL,                          /*GET*/
         res_coap_routing_post_handler, /*POST*/
         NULL,                          /*PUT*/
         NULL                           /*DELETE*/);

static void
res_coap_routing_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    int ret;

    const char* uri_path;
    int uri_len = coap_get_header_uri_path(request, &uri_path);

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received routing data uri=%.*s, payload_len=%d from ", uri_len, uri_path, payload_len);
    LOG_DBG_COAP_EP(request->src_ep);
    LOG_DBG_("\n");

    // Check if we are expecting a response
    // We might have timed out
    if (!timed_unlock_is_locked(&task_in_use))
    {
        LOG_ERR("Received a task response that we were not expecting\n");

        // Inform the Edge that we don't want this result
        coap_set_status_code(response, BAD_REQUEST_4_00);
        return;
    }

    // Got a response within the time limit, so restart the timer for the next packet
    timed_unlock_restart_timer(&task_in_use);

    if (!coap_is_option(request, COAP_OPTION_BLOCK1))
    {
        // First message is whether the task succeeded or failed
        routing_response_process_status(request);
    }
    else
    {
        // Subsequent messages (after success) are the results 

        uint32_t b1_num;
        uint8_t b1_more;
        uint16_t b1_size;
        uint32_t b1_offset;
        ret = coap_get_header_block1(request, &b1_num, &b1_more, &b1_size, &b1_offset);

        // Must be okay as we've already checked if the block1 header is present
        if (!ret)
        {
            LOG_ERR("coap_get_header_block1 failed (with %d) but we already checked for block1...\n", ret);
            return;
        }

        LOG_DBG("block1: num=%" PRIu32 " more=%" PRIu8 " size=%" PRIu16 " offset=%" PRIu32 "\n",
            b1_num, b1_more, b1_size, b1_offset);


        // Set up appropriate block1 headers in the response.
        // Don't need to provide target and length as we will
        // not be using them to extract the data into a single location.
        // There is no limit to the data we can handle, so set UINT32_MAX.
        ret = coap_block1_handler(request, response, NULL, NULL, UINT32_MAX);
        if (ret < 0)
        {
            LOG_ERR("coap_block1_handler failed with %d\n", ret);
            return;
        }

        // Update trust model with success if the start and end are as expected

        // First block
        if (b1_num == 0)
        {
            // Check first item (origin) is as expected
            nanocbor_value_t dec;
            nanocbor_decoder_init(&dec, payload, payload_len);

            coordinate_t first;
            nanocbor_get_coordinate_from_payload(&dec, &first, 1);

            first_src_isclose = isclose(first.latitude, task_src.latitude) && isclose(first.longitude, task_src.longitude);

            if (!first_src_isclose)
            {
                LOG_WARN("Bad result from edge first=(%f,%f) src=(%f,%f) not close enough\n",
                    first.latitude, first.longitude,
                    task_src.latitude, task_src.longitude
                );
            }
        }

        // last block
        if (!b1_more)
        {
            // Check last item (destination) is as expected
            nanocbor_value_t dec;
            nanocbor_decoder_init(&dec, payload, payload_len);

            coordinate_t last;
            nanocbor_get_coordinate_from_payload(&dec, &last, -1);

            // Update trust model
            const bool last_dest_isclose = isclose(last.latitude, task_dest.latitude) && isclose(last.longitude, task_dest.longitude);

            if (!last_dest_isclose)
            {
                LOG_WARN("Bad result from edge last=(%f,%f) dest=(%f,%f) not close enough\n",
                    last.latitude, last.longitude,
                    task_dest.latitude, task_dest.longitude
                );
            }

            const tm_result_quality_info_t info = {
                .good = (first_src_isclose && last_dest_isclose)
            };

            routing_process_task_result(request, &info);

            timed_unlock_unlock(&task_in_use);
        }

        // TODO: output this information for the client
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_add(edge_resource_t* edge)
{
    app_state_edge_capability_add(&app_state, edge);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_remove(edge_resource_t* edge)
{
    app_state_edge_capability_remove(&app_state, edge);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(routing_process, ROUTING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    coap_activate_resource(&res_coap, ROUTING_APPLICATION_URI);

#ifdef WITH_OSCORE
    oscore_protect_resource(&res_coap);
#endif

    init_trust_weights_routing();

    app_state_init(&app_state, ROUTING_APPLICATION_NAME, ROUTING_APPLICATION_URI);

    timed_unlock_init(&coap_callback_in_use, "routing-coap", (1 * 60 * CLOCK_SECOND));
    timed_unlock_init(&task_in_use, "routing-task", (2 * 60 * CLOCK_SECOND));

#ifdef ROUTING_PERIODIC_TEST
    routing_periodic_test_init();
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(routing_process, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == serial_line_event_message) {
            event_triggered_action((const char*)data);
        }

        if (ev == pe_edge_capability_add) {
            edge_capability_add((edge_resource_t*)data);
        }

        if (ev == pe_edge_capability_remove) {
            edge_capability_remove((edge_resource_t*)data);
        }

        if (ev == pe_timed_unlock_unlocked && data == &task_in_use) {
            routing_process_task_timeout();
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
