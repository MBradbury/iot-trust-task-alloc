#include "contiki.h"
#include "sys/log.h"

#include "timed-unlock.h"
#include "root-endpoint.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "node"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(trust_model);
PROCESS_NAME(keystore_add_verifier);
APPLICATION_PROCESSES_DECL;
PROCESS(node, "node");
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&node, &trust_model, &mqtt_client_process,
                    &keystore_add_verifier,
                    APPLICATION_PROCESSES);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(node, ev, data)
{
    PROCESS_BEGIN();

#ifdef BUILD_NUMBER
    LOG_INFO("BUILD NUMBER = %u\n", BUILD_NUMBER);
#endif
#ifdef ADDITIONAL_CFLAGS
    LOG_INFO("Built with ADDITIONAL_CFLAGS = '" ADDITIONAL_CFLAGS "'\n");
#endif

    timed_unlock_global_init();
    root_endpoint_init();

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
