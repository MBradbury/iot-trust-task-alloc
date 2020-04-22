#include "contiki.h"
#include "rpl.h"
#include "uiplib.h"
#include "os/sys/log.h"

#include <stdio.h>

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "app-monitoring"
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
#include "contiki.h"
#include "dev/cc2538-sensors.h"
#include "mqtt-client.h"

#include <string.h>
#include <stdio.h>
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

	int written = snprintf(buf, buf_len,
		"{"
			"\"temp\":%d,"
			"\"vdd3\":%d"
		"}",
		temp_value, vdd3_value
	);

	return written;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(environment_monitoring, "Environment Monitoring process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(environment_monitoring, ev, data)
{
    static struct etimer timer;
    static uip_ipaddr_t rpl_root_addr;
    static int ret;

    PROCESS_BEGIN();

    SENSORS_ACTIVATE(cc2538_temp_sensor);
    SENSORS_ACTIVATE(vdd3_sensor);

    /* Setup a periodic timer that expires after 10 seconds. */
    etimer_set(&timer, CLOCK_SECOND * 10);

    while(1)
    {
        // Check if we know who the DAG root is
        ret = rpl_dag_get_root_ipaddr(&rpl_root_addr);
        if (ret)
        {
            char buf[UIPLIB_IPV6_MAX_STR_LEN];
            uiplib_ipaddr_snprint(buf, sizeof(buf), &rpl_root_addr);
            LOG_DBG("RPL DAG root is %s\n", buf);
        }


        int written = generate_sensor_data(msg_buf, sizeof(msg_buf));
        if (written > 0 && written <= sizeof(msg_buf))
        {
        	LOG_DBG("Generated message %s\n", msg_buf);
        }

        /* Wait for the periodic timer to expire and then restart the timer. */
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
        etimer_reset(&timer);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
