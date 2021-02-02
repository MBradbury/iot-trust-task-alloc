#include "challenge-response-edge.h"
#include "applications.h"

#include "contiki.h"
#include "os/sys/log.h"

#include "edge.h"

#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" CHALLENGE_RESPONSE_APPLICATION_NAME
#ifdef APP_CHALLENGE_RESPONSE_LOG_LEVEL
#define LOG_LEVEL APP_CHALLENGE_RESPONSE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
application_stats_t cr_stats;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(challenge_response_process, CHALLENGE_RESPONSE_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{
    cr_taskrecv_init();
    cr_taskresp_init();

    application_stats_init(&cr_stats);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(challenge_response_process, ev, data)
{
    PROCESS_BEGIN();

    init();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == pe_data_from_resource_rich_node)
        {
            //LOG_INFO("Received pe_data_from_resource_rich_node %s\n", (const char*)data);
            cr_taskresp_process_serial_input((const char*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
