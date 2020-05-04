#include "contiki.h"
#include "os/sys/log.h"
#include "dev/cc2538-sensors.h"

#include <stdio.h>

#include "monitoring.h"
#include "edge-info.h"
#include "trust.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" MONITORING_APPLICATION_NAME
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define PERIOD (CLOCK_SECOND * 60)
/*-------------------------------------------------------------------------------------------------------------------*/
#define TMP_BUF_SZ 64
/*-------------------------------------------------------------------------------------------------------------------*/
static char msg_buf[TMP_BUF_SZ];
/*-------------------------------------------------------------------------------------------------------------------*/
static int
generate_sensor_data(char* buf, size_t buf_len)
{
    int temp_value = cc2538_temp_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);
    int vdd3_value = vdd3_sensor.value(CC2538_SENSORS_VALUE_TYPE_CONVERTED);

    int would_have_written = snprintf(buf, buf_len,
        "{"
            "\"temp\":%d,"
            "\"vdd3\":%d"
        "}",
        temp_value, vdd3_value
    );

    return would_have_written;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer publish_periodic_timer;
static bool started;
/*-------------------------------------------------------------------------------------------------------------------*/
static void
periodic_action(void)
{
    int would_have_written = generate_sensor_data(msg_buf, sizeof(msg_buf));
    if (would_have_written < 0 || would_have_written > sizeof(msg_buf))
    {
        LOG_ERR("Failed to generated message (%d)\n", would_have_written);
    }

    LOG_DBG("Generated message %s\n", msg_buf);

    // Choose an Edge node to send information to
    edge_resource_t* edge = choose_edge(MONITORING_APPLICATION_NAME);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find an edge resource to send task to\n");
    }

    // TODO: Send task to edge node at 'edge->addr'
    

    // TODO: Record metrics about tasks sent to edge nodes and their ability to respond in the trust model

    etimer_reset(&publish_periodic_timer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
edge_capability_add(edge_resource_t* edge)
{
    LOG_DBG("Notified of edge capability for %s\n", edge->name);

    if (!started)
    {
        LOG_DBG("Starting periodic timer to send information\n");

        // Setup a periodic timer that expires after PERIOD seconds.
        etimer_set(&publish_periodic_timer, PERIOD);
        started = true;

        // TODO: Open connection to edge node?
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(environment_monitoring, MONITORING_APPLICATION_NAME);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(environment_monitoring, ev, data)
{
    PROCESS_BEGIN();

    SENSORS_ACTIVATE(cc2538_temp_sensor);
    SENSORS_ACTIVATE(vdd3_sensor);

    started = false;

    while (1)
    {
        PROCESS_YIELD();

        if (ev == PROCESS_EVENT_TIMER && data == &publish_periodic_timer) {
            periodic_action();
        }

        if (ev == pe_edge_capability_add) {
            edge_capability_add((edge_resource_t*)data);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
