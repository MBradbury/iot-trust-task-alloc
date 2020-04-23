#include "contiki.h"
#include "rpl.h"
#include "uiplib.h"
#include "os/sys/log.h"

#include <stdio.h>

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-envmon"
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
#include "contiki.h"

#include <string.h>
#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(environment_monitoring, "Environment Monitoring process");
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
