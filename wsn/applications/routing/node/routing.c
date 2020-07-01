#include "routing.h"
#include "application-serial.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/assert.h"
#include "os/dev/serial-line.h"

#include "coap.h"
#include "coap-callback-api.h"
#include "coap-log.h"

#include "nanocbor-helper.h"

#include <stdio.h>

#include "monitoring.h"
#include "edge-info.h"
#include "trust.h"
#include "trust-models.h"
#include "applications.h"
#include "serial-helpers.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#endif

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" ROUTING_APPLICATION_NAME
#ifdef APP_ROUTING_LOG_LEVEL
#define LOG_LEVEL APP_ROUTING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static bool coap_callback_in_use;
static uint8_t msg_buf[(1) + (1 + sizeof(uint32_t)) + (1 + (1 + sizeof(float)) * 2) * 2];
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
static uint8_t capability_count;
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_task_ack(edge_resource_t* edge, edge_capability_t* cap, coap_message_t* response)
{
    // Do anything that needs to be done with the ack
    // e.g., record the estimated time until the task response is sent
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
send_callback(coap_callback_request_state_t* callback_state)
{
    edge_resource_t* edge = (edge_resource_t*)callback_state->state.user_data;
    edge_capability_t* cap = edge_info_capability_find(edge, MONITORING_APPLICATION_NAME);

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
            process_task_ack(edge, cap, response);
        }
        else
        {
            LOG_WARN("Message send failed with code (%u) '%.*s' (len=%d)\n",
                response->code, response->payload_len, response->payload, response->payload_len);
        }

        info.coap_status = response->code;
    } break;

    case COAP_REQUEST_STATUS_MORE:
    {
        LOG_ERR("Unhandled COAP_REQUEST_STATUS_MORE\n");
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        coap_callback_in_use = false;
    } break;

    case COAP_REQUEST_STATUS_TIMEOUT:
    {
        LOG_ERR("Failed to send message with status %d (timeout)\n", callback_state->state.status);
        coap_callback_in_use = false;
    } break;

    case COAP_REQUEST_STATUS_BLOCK_ERROR:
    {
        LOG_ERR("Failed to send message with status %d (block error)\n", callback_state->state.status);
        coap_callback_in_use = false;
    } break;

    default:
    {
        LOG_ERR("Failed to send message with status %d\n", callback_state->state.status);
        coap_callback_in_use = false;
    } break;
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

    if (coap_callback_in_use)
    {
        LOG_WARN("Cannot generate a new message, as in process of sending one\n");
        return;
    }

    coordinate_t source, destination;
    if (!parse_input(data, &source, &destination))
    {
        LOG_WARN("Invalid command '%s'\n", data);
        return;
    }

    int len = generate_routing_request(msg_buf, sizeof(msg_buf), &source, &destination);
    if (len <= 0 || len > sizeof(msg_buf))
    {
        LOG_ERR("Failed to generated message (%d)\n", len);
        return;
    }

    // TODO: %f isn't supported
    LOG_DBG("Generated message for path from (%f,%f) to (%f,%f) (len=%d)\n",
        source.latitude, source.longitude,
        destination.latitude, destination.longitude,
        len);

    // Choose an Edge node to send information to
    edge_resource_t* edge = choose_edge(ROUTING_APPLICATION_NAME);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find an edge resource to send task to\n");
        return;
    }

    if (!coap_endpoint_is_connected(&edge->ep))
    {
        LOG_DBG("We are not connected to ");
        LOG_DBG_COAP_EP(&edge->ep);
        LOG_DBG_(", so will initiate a connection to it.\n");

        // Initiate a connect
        coap_endpoint_connect(&edge->ep);

        // Wait for a bit and then try sending again
        //etimer_set(&publish_short_timer, SHORT_PUBLISH_PERIOD);
        //return;
    }

    // TODO: encrypt and sign message

    coap_init_message(&msg, COAP_TYPE_CON, COAP_POST, 0);

    ret = coap_set_header_uri_path(&msg, ROUTING_APPLICATION_URI);
    if (ret <= 0)
    {
        LOG_DBG("coap_set_header_uri_path failed %d\n", ret);
        return;
    }
    
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_payload(&msg, msg_buf, len);

    // Save the edge that this task is being submitted to
    coap_callback.state.user_data = edge;

    ret = coap_send_request(&coap_callback, &edge->ep, &msg, send_callback);
    if (ret)
    {
        coap_callback_in_use = true;
        LOG_DBG("Message sent to ");
        LOG_DBG_COAP_EP(&edge->ep);
        LOG_DBG_("\n");
    }
    else
    {
        LOG_ERR("Failed to send message with %d\n", ret);
    }
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
    const char* uri_path;
    int uri_len = coap_get_header_uri_path(request, &uri_path);

    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_DBG("Received routing data uri=%.*s, payload_len=%d from ", uri_len, uri_path, payload_len);
    LOG_DBG_COAP_EP(request->src_ep);
    LOG_DBG_("\n");

    // TODO: parse routing response

    // TODO: update trust model
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_add(edge_resource_t* edge)
{
    LOG_INFO("Notified of edge %s capability\n", edge->name);

    capability_count += 1;

    if (capability_count == 1)
    {
        LOG_INFO("Starting periodic timer to send information\n");
    }

    edge_capability_add_common(edge, ROUTING_APPLICATION_URI);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_remove(edge_resource_t* edge)
{
    LOG_INFO("Notified edge %s no longer has capability\n", edge->name);

    capability_count -= 1;

    if (capability_count == 0)
    {
        LOG_INFO("Stop sending information, no edges to process it\n");
    }

    edge_capability_remove_common(edge, ROUTING_APPLICATION_URI);
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

    capability_count = 0;
    coap_callback_in_use = false;
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
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
