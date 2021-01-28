#include "contiki.h"
#include "sys/log.h"

#include "timed-unlock.h"
#include "root-endpoint.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "attack"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(keystore_add_verifier);
//APPLICATION_PROCESSES_DECL;
ATTACK_PROCESSES_DECL;
PROCESS(adversary, "adversary");
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&adversary, &mqtt_client_process,
                    &keystore_add_verifier,
                    //APPLICATION_PROCESSES,
                    ATTACK_PROCESSES);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(adversary, ev, data)
{
    PROCESS_BEGIN();

#ifdef BUILD_NUMBER
    LOG_INFO("BUILD NUMBER = %u\n", BUILD_NUMBER);
#endif

    timed_unlock_global_init();
    root_endpoint_init();

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
