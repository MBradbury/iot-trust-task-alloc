// When testing we may be unable to manually provide input requesting a route calculation
// So this file can be compiled in to automatically generate routes.
/*-------------------------------------------------------------------------------------------------------------------*/
#include "routing-periodic-test.h"

#include "contiki.h"
#include "os/dev/serial-line.h"
#include "os/sys/log.h"

#include "routing.h"
#include "applications.h"
#include "application-serial.h"
#include "random-helpers.h"

#ifndef ROUTING_PERIODIC_TEST
#error "Must define ROUTING_PERIODIC_TEST to use"
#endif

/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef GENERATE_ROUTE_MIN_PERIOD
#define GENERATE_ROUTE_MIN_PERIOD (2 * 60)
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef GENERATE_ROUTE_MAX_PERIOD
#define GENERATE_ROUTE_MAX_PERIOD (3 * 60)
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" ROUTING_APPLICATION_NAME
#ifdef APP_ROUTING_LOG_LEVEL
#define LOG_LEVEL APP_ROUTING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer generate_route_timer;
static struct process* routing_application;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(routing_test_process, "Routing test process");
/*-------------------------------------------------------------------------------------------------------------------*/
void routing_periodic_test_init(void)
{
    process_start(&routing_test_process, NULL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool init(void)
{
    uint16_t rnd_period = random_in_range_unbiased(GENERATE_ROUTE_MIN_PERIOD, GENERATE_ROUTE_MAX_PERIOD);
    etimer_set(&generate_route_timer, rnd_period * CLOCK_SECOND);

    LOG_INFO("Started timer to generate route request in %" PRIu16 " seconds\n", rnd_period);

    routing_application = find_process_with_name(ROUTING_APPLICATION_NAME);
    if (routing_application == NULL)
    {
        LOG_ERR("Failed to find " ROUTING_APPLICATION_NAME " application process\n");
        return false;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void periodic_event(void)
{
    LOG_INFO("Periodic timer triggered, generating fake routing request\n");

    // UoW to Warwick Castle
    const char* buf = APPLICATION_SERIAL_PREFIX ROUTING_SUBMIT_TASK "52.384057,-1.561737:52.280302,-1.586839";

    // Simulate receiving a message over the serial input
    process_post_synch(routing_application, serial_line_event_message, (process_data_t)buf);

    // Restart timer
    uint16_t rnd_period = random_in_range_unbiased(GENERATE_ROUTE_MIN_PERIOD, GENERATE_ROUTE_MAX_PERIOD);
    etimer_reset_with_new_interval(&generate_route_timer, rnd_period * CLOCK_SECOND);

    LOG_INFO("Restarted timer to generate route request in %" PRIu16 " seconds\n", rnd_period);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(routing_test_process, ev, data)
{
    PROCESS_BEGIN();

    if (!init())
    {
        PROCESS_EXIT();
    }

    while (1)
    {
        PROCESS_YIELD();

        if (ev == PROCESS_EVENT_TIMER && data == &generate_route_timer) {
            periodic_event();
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
