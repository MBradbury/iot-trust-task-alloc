#include "contiki.h"
#include "timed-unlock.h"
#include "root-endpoint.h"
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(trust_model);
PROCESS_NAME(keystore_req);
PROCESS_NAME(keystore_unver);
APPLICATION_PROCESSES_DECL;
PROCESS(node, "node");
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&node, &trust_model, &mqtt_client_process, &keystore_req, &keystore_unver, APPLICATION_PROCESSES);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(node, ev, data)
{
    PROCESS_BEGIN();

    timed_unlock_global_init();
    root_endpoint_init();

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
