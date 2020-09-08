#include "routing-edge.h"
#include "applications.h"

#include "contiki.h"
#include "os/sys/log.h"

#include "edge.h"

#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" ROUTING_APPLICATION_NAME
#ifdef APP_ROUTING_LOG_LEVEL
#define LOG_LEVEL APP_ROUTING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
application_stats_t routing_stats;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(routing_process, ROUTING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    routing_taskrecv_init();
    routing_taskresp_init();

    init_trust_weights_routing();

    application_stats_init(&routing_stats);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(routing_process, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == pe_data_from_resource_rich_node)
        {
            //LOG_INFO("Received pe_data_from_resource_rich_node %s\n", (const char*)data);
            routing_taskresp_process_serial_input((const char*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
