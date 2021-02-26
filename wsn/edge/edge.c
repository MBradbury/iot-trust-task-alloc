#include "contiki.h"
#include "serial-line.h"
#include "sys/log.h"

#include "edge.h"
#include "applications.h"
#include "application-serial.h"
#include "capability/capability.h"
#include "serial-helpers.h"
#include "stereotype-tags.h"
#include "timed-unlock.h"
#include "root-endpoint.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "edge"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(capability);
PROCESS_NAME(keystore_add_verifier);
APPLICATION_PROCESSES_DECL;
PROCESS(edge, "edge");
/*-------------------------------------------------------------------------------------------------------------------*/
const char* const application_names[APPLICATION_NUM] = APPLICATION_NAMES;
bool applications_available[APPLICATION_NUM];
bool resource_rich_edge_started;
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&edge, &capability, &mqtt_client_process,
                    &keystore_add_verifier,
                    APPLICATION_PROCESSES);
/*-------------------------------------------------------------------------------------------------------------------*/
static int8_t
index_of_application(const char* name)
{
    for (uint8_t i = 0; i != APPLICATION_NUM; ++i)
    {
        if (strcmp(name, application_names[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool application_available(const char* name)
{
    int8_t idx = index_of_application(name);
    return idx < 0 ? false : applications_available[idx];
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
set_all_applications_unavailable(void)
{
    memset(applications_available, 0, sizeof(applications_available));
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_application_serial_message(const char* data, const char* data_end)
{
    // Find the application name this message refers to
    char application_name[APPLICATION_NAME_MAX_LEN + 1];

    const char* application_name_end = strchr(data, *SERIAL_SEP);
    if (application_name_end == NULL)
    {
        LOG_DBG("Serial input is missing application name\n");
        return;
    }

    const size_t application_name_length = application_name_end - data;
    if (application_name_length == 0)
    {
        LOG_WARN("Application name too short\n");
        return;
    }
    if (application_name_length > APPLICATION_NAME_MAX_LEN)
    {
        LOG_WARN("Application name too long\n");
        return;
    }

    memcpy(application_name, data, application_name_length);
    application_name[application_name_length] = '\0';

    data = application_name_end + 1;

    int8_t idx = index_of_application(application_name);
    if (idx < 0)
    {
        LOG_ERR("Invalid application name %s\n", application_name);
        return;
    }

    if (match_action(data, data_end, APPLICATION_SERIAL_START))
    {
        applications_available[idx] = true;

        LOG_INFO("publishing add capability\n");
        publish_add_capability(application_name, true);

        // No need to trigger a faster publish of the announce here
        // as we will send the certificate with the add capability
    }
    else if (match_action(data, data_end, APPLICATION_SERIAL_STOP))
    {
        applications_available[idx] = false;

        LOG_INFO("publishing remove capability\n");
        publish_remove_capability(application_name, true);
    }
    else if (match_action(data, data_end, APPLICATION_SERIAL_APP))
    {
        data += strlen(APPLICATION_SERIAL_APP);

        // Send application data message to the relevant application
        struct process* proc = find_process_with_name(application_name);
        if (proc)
        {
            // Must be performed synchronously so data remains valid
            process_post_synch(proc, pe_data_from_resource_rich_node, (void*)data);
        }
        else
        {
            LOG_ERR("Unable to find process with the name %s\n", application_name);
        }
    }
    else
    {
        LOG_ERR("Unsure what to do with %s\n", data);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_edge_serial_message(const char* data, const char* data_end)
{
    if (match_action(data, data_end, EDGE_SERIAL_START))
    {
        LOG_INFO("Resource rich serial bridge has started\n");

        if (!resource_rich_edge_started)
        {
            resource_rich_edge_started = true;

            // Trigger a faster notification of announce
            trigger_faster_publish();
        }
    }
    else if (match_action(data, data_end, EDGE_SERIAL_STOP))
    {
        LOG_INFO("Resource rich serial bridge has stopped\n");

        set_all_applications_unavailable();

        if (resource_rich_edge_started)
        {
            resource_rich_edge_started = false;

            // Trigger a faster notification of unannounce
            trigger_faster_publish();
        }
    }
    else
    {
        LOG_ERR("Unknown edge action %s\n", data);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
process_serial_message(const char* data)
{
    const char* const data_end = data + strlen(data);

    //LOG_DBG("Received serial message %s of length %u\n", data, data_end - data);
    LOG_DBG("Received serial message of length %u\n", data_end - data);

    // Check that the input is from the edge
    if (match_action(data, data_end, APPLICATION_SERIAL_PREFIX))
    {
        data += strlen(APPLICATION_SERIAL_PREFIX);
        process_application_serial_message(data, data_end);
    }
    else if (match_action(data, data_end, EDGE_SERIAL_PREFIX))
    {
        data += strlen(EDGE_SERIAL_PREFIX);
        process_edge_serial_message(data, data_end);
    }
    else
    {
        LOG_ERR("Unknown serial message\n");
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
process_event_t pe_data_from_resource_rich_node;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(edge, ev, data)
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

    set_all_applications_unavailable();

    pe_data_from_resource_rich_node = process_alloc_event();

    resource_rich_edge_started = false;

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
/*-------------------------------------------------------------------------------------------------------------------*/
