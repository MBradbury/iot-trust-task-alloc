#include "contiki.h"

#include "applications.h"

PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(environment_monitoring);
PROCESS_NAME(trust_model);
PROCESS_NAME(keystore);

const char* const application_names[APPLICATION_NUM] = APPLICATION_NAMES;

AUTOSTART_PROCESSES(&trust_model, &environment_monitoring, &mqtt_client_process, &keystore);
