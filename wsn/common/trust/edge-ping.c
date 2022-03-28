#include "edge-ping.h"
#include "edge-info.h"
#include "trust-models.h"

#include "uip-icmp6.h"

#include "etimer.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "edge-ping"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define ECHO_REQ_PAYLOAD_LEN 20
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef TRUST_MODEL_PERIODIC_EDGE_PING_INTERVAL
#define TRUST_MODEL_PERIODIC_EDGE_PING_INTERVAL 5
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(edge_ping_process, "edge-ping");
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer ping_timer;
static struct uip_icmp6_echo_reply_notification echo_notification;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool has_started;
static uip_ipaddr_t current_edge;
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_ping_start(void)
{
    LOG_INFO("Starting edge ping\n");
    process_start(&edge_ping_process, NULL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_resource_t* find_next_edge_from_scratch(void)
{
    edge_resource_t* edge = edge_info_iter();
    if (edge)
    {
        current_edge = edge->ep.ipaddr;
        has_started = true;
    }
    else
    {
        has_started = false;
    }

    return edge;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static edge_resource_t* find_next_edge(void)
{
    if (!has_started)
    {
        return find_next_edge_from_scratch();
    }
    else
    {
        edge_resource_t* edge = edge_info_find_addr(&current_edge);
        if (edge)
        {
            edge = edge_info_next(edge);
            if (edge)
            {
                current_edge = edge->ep.ipaddr;
                has_started = true;

                return edge;
            }
            else
            {
                return find_next_edge_from_scratch();
            }
        }
        else
        {
            return find_next_edge_from_scratch();
        }
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void periodic_action(void)
{
    // Work out who to send to next
    edge_resource_t* edge =find_next_edge();

    if (has_started)
    {
        LOG_INFO("Pinging edge ");
        LOG_INFO_6ADDR(&current_edge);
        LOG_INFO_("\n");

        uip_icmp6_send(&current_edge, ICMP6_ECHO_REQUEST, 0, ECHO_REQ_PAYLOAD_LEN);

        const tm_edge_ping_t info = {
            .action = TM_PING_SENT
        };

        tm_update_ping(edge, &info);
    }
    else
    {
        LOG_INFO("Not pinging any edge, as none available\n");
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void echo_callback(uip_ipaddr_t *source, uint8_t ttl, uint8_t *data, uint16_t datalen)
{
    LOG_INFO("Received ping response from ");
    LOG_INFO_6ADDR(&current_edge);
    LOG_INFO_("\n");

    edge_resource_t* edge = edge_info_find_addr(source);
    if (edge)
    {
        const tm_edge_ping_t info = {
            .action = TM_PING_RECEIVED
        };

        tm_update_ping(edge, &info);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(edge_ping_process, ev, data)
{
    PROCESS_BEGIN();

    has_started = false;

    // We want to get notified of ping responses
    uip_icmp6_echo_reply_callback_add(&echo_notification, &echo_callback);

    etimer_set(&ping_timer, TRUST_MODEL_PERIODIC_EDGE_PING_INTERVAL * CLOCK_SECOND);

    while (1)
    {
        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER && data == &ping_timer);

        periodic_action();

        etimer_reset(&ping_timer);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/