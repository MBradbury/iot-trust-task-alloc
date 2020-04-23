#include "contiki.h"
#include "rpl.h"
#include "uiplib.h"
#include "os/sys/log.h"

#include <stdio.h>

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-envmon"
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
#include "contiki.h"
#include "dev/cc2538-sensors.h"

#include <string.h>
#include <stdio.h>

//#include "mqtt-conn.h"
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

    PROCESS_BEGIN();

    SENSORS_ACTIVATE(cc2538_temp_sensor);
    SENSORS_ACTIVATE(vdd3_sensor);

    /* Setup a periodic timer that expires after PERIOD seconds. */
    etimer_set(&timer, PERIOD);

    while (1)
    {
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
