#include "contiki.h"
#include "os/sys/log.h"

#include <stdio.h>

#include "monitoring.h"
#include "edge-info.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-envmon"
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(environment_monitoring, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(environment_monitoring, ev, data)
{
    PROCESS_BEGIN();

    while (1)
    {
        PROCESS_YIELD();
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
