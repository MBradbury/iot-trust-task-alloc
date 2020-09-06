#include "contiki.h"
#include "timed-unlock.h"
#include "root-endpoint.h"
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(trust_model);
PROCESS_NAME(keystore_request);
PROCESS_NAME(keystore_add_verifier);
APPLICATION_PROCESSES_DECL;
PROCESS(node, "node");
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&node, &trust_model, &mqtt_client_process,
                    &keystore_request, &keystore_add_verifier,
                    APPLICATION_PROCESSES);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(node, ev, data)
{
    PROCESS_BEGIN();

    timed_unlock_global_init();
    root_endpoint_init();

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
