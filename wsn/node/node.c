#include "contiki.h"

PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(trust_model);
PROCESS_NAME(keystore_req);
PROCESS_NAME(keystore_unver);
APPLICATION_PROCESSES_DECL;

AUTOSTART_PROCESSES(&trust_model, &mqtt_client_process, &keystore_req, &keystore_unver, APPLICATION_PROCESSES);
