#include "contiki.h"
#include "sys/log.h"
#include "netstack.h"
#include "etimer.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "attack-ro"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef ATTACK_RADIO_OFF_INTERVAL
#error "Must define ATTACK_RADIO_OFF_INTERVAL"
#endif
#ifndef ATTACK_RADIO_OFF_DURATION
#error "Must define ATTACK_RADIO_OFF_DURATION"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(radio_off, "radio_off");
/*-------------------------------------------------------------------------------------------------------------------*/
#define RADIO_OFF_INTERVAL (CLOCK_CONF_SECOND * (unsigned int)ATTACK_RADIO_OFF_INTERVAL)
#define RADIO_OFF_DURATION (CLOCK_CONF_SECOND * (unsigned int)ATTACK_RADIO_OFF_DURATION)
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer radio_off_start_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(radio_off, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("Starting %s\n", PROCESS_NAME_STRING(PROCESS_CURRENT()));
    LOG_INFO("Turning radio off every %u for %u\n",
        (unsigned int)ATTACK_RADIO_OFF_INTERVAL,
        (unsigned int)ATTACK_RADIO_OFF_DURATION);

    etimer_set(&radio_off_start_timer, RADIO_OFF_INTERVAL);

    // Just using NETSTACK_MAC.off() and NETSTACK_MAC.on() is insufficient
    // as it does nothing to prevent the MAC / routing drivers turning
    // the radio back on.
    // So we need to NOT yield control back to anyone else to ensure
    // that the radio is kept off.

    while (true)
    {
        LOG_INFO("Waiting for %u to turn radio off\n", (unsigned int)ATTACK_RADIO_OFF_INTERVAL);
        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER && data == &radio_off_start_timer);

        LOG_INFO("Turning MAC off\n");
        NETSTACK_MAC.off();

        LOG_INFO("Waiting for %u to turn radio on\n", (unsigned int)ATTACK_RADIO_OFF_DURATION);
        clock_wait(RADIO_OFF_DURATION);

        LOG_INFO("Turning MAC on\n");
        NETSTACK_MAC.on();

        etimer_restart(&radio_off_start_timer);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
