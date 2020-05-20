#include "contiki.h"

PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(environment_monitoring);
PROCESS_NAME(trust_model);
PROCESS_NAME(keystore);

AUTOSTART_PROCESSES(&trust_model, &environment_monitoring, &mqtt_client_process, &keystore);
