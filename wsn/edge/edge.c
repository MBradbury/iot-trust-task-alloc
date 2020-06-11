#include "contiki.h"
#include "serial-line.h"
#include "sys/log.h"

#include "edge.h"
#include "applications.h"
#include "application-serial.h"
#include "trust/trust.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "edge"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(environment_monitoring);
PROCESS_NAME(trust_model);
PROCESS_NAME(keystore_req);
PROCESS_NAME(keystore_unver);
PROCESS(edge, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
const char* const application_names[APPLICATION_NUM] = APPLICATION_NAMES;
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&edge, &trust_model, &environment_monitoring, &mqtt_client_process, &keystore_req, &keystore_unver);
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_serial_message(const char* data)
{
    const char* const data_end = data + strlen(data);

    LOG_DBG("Received serial message %s of length %u\n", data, data_end - data);

    // Check that the input is from the edge
    if (data_end - data < strlen(APPLICATION_SERIAL_PREFIX) ||
        strncmp(APPLICATION_SERIAL_PREFIX, data, strlen(APPLICATION_SERIAL_PREFIX)) != 0)
    {
        LOG_DBG("Serial input is not from edge\n");
        return;
    }

    data += strlen(APPLICATION_SERIAL_PREFIX);

    // Find the application name this message refers to
    char application_name[APPLICATION_NAME_MAX_LEN + 1];

    const char* application_name_end = strchr(data, ':');
    if (application_name_end == NULL)
    {
        LOG_DBG("Serial input is missing application name\n");
        return;
    }

    memset(application_name, 0, sizeof(application_name));
    memcpy(application_name, data, application_name_end - data);

    data = application_name_end + 1;

    if (data_end - data >= strlen(APPLICATION_SERIAL_START) &&
        strncmp(APPLICATION_SERIAL_START, data, strlen(APPLICATION_SERIAL_START)) == 0)
    {
        LOG_INFO("publishing add capability\n");
        publish_add_capability(application_name);
    }
    else if (data_end - data >= strlen(APPLICATION_SERIAL_STOP) &&
             strncmp(APPLICATION_SERIAL_STOP, data, strlen(APPLICATION_SERIAL_STOP)) == 0)
    {
        LOG_INFO("publishing remove capability\n");
        publish_remove_capability(application_name);
    }
    else if (data_end - data >= strlen(APPLICATION_SERIAL_APP) &&
             strncmp(APPLICATION_SERIAL_APP, data, strlen(APPLICATION_SERIAL_APP)) == 0)
    {
        data += strlen(APPLICATION_SERIAL_APP);

        // Send application data message to the relevant application
        struct process* proc = find_process_with_name(application_name);
        if (proc)
        {
            process_post_synch(proc, pe_data_from_resource_rich_node, (void*)data);
        }
        else
        {
            LOG_ERR("Unable to find process with the name %s\n", application_name);
        }
    }
    else
    {
        LOG_ERR("Unsure what to do with %.*s\n", data_end - data, data);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
process_event_t pe_data_from_resource_rich_node;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(edge, ev, data)
{
    PROCESS_BEGIN();

    pe_data_from_resource_rich_node = process_alloc_event();

    while (1)
    {
        PROCESS_YIELD();

        if (ev == serial_line_event_message)
        {
            process_serial_message(data);
        }
    }

    PROCESS_END();
}
