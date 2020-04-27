#include "contiki.h"
//#include "rpl.h"
//#include "os/net/ipv6/uiplib.h"
//#include "os/sys/log.h"

//#include <stdio.h>

//PROCESS_NAME(hello_world_process);
PROCESS_NAME(mqtt_client_process);
PROCESS_NAME(environment_monitoring);
PROCESS_NAME(trust_model);

// TODO: Use NullNet for 1-hop broadcasts
// https://github.com/contiki-ng/contiki-ng/wiki/Documentation:-NullNet

// DTLS for encryption
// https://github.com/contiki-ng/contiki-ng/wiki/Documentation:-Communication-Security

// UDP comms
// https://github.com/contiki-ng/contiki-ng/wiki/Documentation:-UDP-communication

// MQTT for Edge pub/sub
// https://github.com/contiki-ng/contiki-ng/wiki/Tutorial:-MQTT

/*-------------------------------------------------------------------------------------------------------------------*/
/*#define LOG_MODULE "node"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif*/
/*-------------------------------------------------------------------------------------------------------------------*/
//PROCESS(hello_world_process, "Hello world process");
/*-------------------------------------------------------------------------------------------------------------------*/
/*PROCESS_THREAD(hello_world_process, ev, data)
{
    static struct etimer timer;
    static uip_ipaddr_t rpl_root_addr;
    static int ret;

    PROCESS_BEGIN();

    // Setup a periodic timer that expires after 60 seconds.
    etimer_set(&timer, CLOCK_SECOND * 120);

    while(1)
    {
        ret = rpl_dag_get_root_ipaddr(&rpl_root_addr);
        if (ret)
        {
            char buf[UIPLIB_IPV6_MAX_STR_LEN];
            uiplib_ipaddr_snprint(buf, sizeof(buf), &rpl_root_addr);
            LOG_DBG("RPL DAG root is %s\n", buf);
        }
        else
        {
            LOG_DBG("Not aware of the RPL DAG root\n");
        }

        // Wait for the periodic timer to expire and then restart the timer.
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
        etimer_reset(&timer);
    }

    PROCESS_END();
}*/
/*-------------------------------------------------------------------------------------------------------------------*/

AUTOSTART_PROCESSES(&trust_model, &environment_monitoring, &mqtt_client_process);
