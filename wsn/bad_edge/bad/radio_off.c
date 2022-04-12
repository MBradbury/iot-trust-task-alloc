#if defined(EDGE_ATTACK_RADIO_OFF_INTERVAL) || defined(EDGE_ATTACK_RADIO_OFF_DURATION)

#include "contiki.h"
#include "sys/log.h"
#include "netstack.h"
#include "etimer.h"

#include "radio-off-driver.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "edge-ro"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef EDGE_ATTACK_RADIO_OFF_START
#error "Must define EDGE_ATTACK_RADIO_OFF_START"
#endif
#ifndef EDGE_ATTACK_RADIO_OFF_INTERVAL
#error "Must define EDGE_ATTACK_RADIO_OFF_INTERVAL"
#endif
#ifndef EDGE_ATTACK_RADIO_OFF_DURATION
#error "Must define EDGE_ATTACK_RADIO_OFF_DURATION"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(radio_off, "radio_off");
/*-------------------------------------------------------------------------------------------------------------------*/
#define RADIO_OFF_START (CLOCK_SECOND * (unsigned int)EDGE_ATTACK_RADIO_OFF_START)
#define RADIO_OFF_INTERVAL (CLOCK_SECOND * (unsigned int)EDGE_ATTACK_RADIO_OFF_INTERVAL)
#define RADIO_OFF_DURATION (CLOCK_SECOND * (unsigned int)EDGE_ATTACK_RADIO_OFF_DURATION)
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer radio_off_start_timer;
static struct etimer radio_off_wait_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(radio_off, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("Starting %s\n", PROCESS_NAME_STRING(PROCESS_CURRENT()));
    LOG_INFO("Turning radio off every %u for %u\n",
        (unsigned int)EDGE_ATTACK_RADIO_OFF_INTERVAL,
        (unsigned int)EDGE_ATTACK_RADIO_OFF_DURATION);

    etimer_set(&radio_off_start_timer, RADIO_OFF_START);

    // Just using NETSTACK_MAC.off() and NETSTACK_MAC.on() is insufficient
    // as it does nothing to prevent the MAC / routing drivers turning
    // the radio back on.
    // So we need to NOT yield control back to anyone else to ensure
    // that the radio is kept off.

    while (true)
    {
        LOG_INFO("Waiting for %lu seconds to turn radio off\n",
            radio_off_start_timer.timer.interval / CLOCK_SECOND);
        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER && data == &radio_off_start_timer);

        LOG_INFO("Turning MAC off\n");
        radio_off_driver_set(false);

        LOG_INFO("Waiting for %u seconds to turn radio on\n",
            (unsigned int)EDGE_ATTACK_RADIO_OFF_DURATION);
        etimer_set(&radio_off_wait_timer, RADIO_OFF_DURATION);
        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER && data == &radio_off_wait_timer);

        LOG_INFO("Turning MAC on\n");
        radio_off_driver_set(true);

        etimer_reset_with_new_interval(&radio_off_start_timer, RADIO_OFF_INTERVAL);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/

#endif
