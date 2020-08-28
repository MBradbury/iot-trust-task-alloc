#include "root-endpoint.h"

#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "common"
#ifdef MQTT_CLIENT_CONF_LOG_LEVEL
#define LOG_LEVEL MQTT_CLIENT_CONF_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_ERR
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef ROOT_IP_ADDR
#define ROOT_IP_ADDR "fd00::1"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define ROOT_COAP_ADDR "coap://[" ROOT_IP_ADDR "]"
/*-------------------------------------------------------------------------------------------------------------------*/
coap_endpoint_t root_ep;
/*-------------------------------------------------------------------------------------------------------------------*/
bool root_endpoint_init(void)
{
    int ret = coap_endpoint_parse(ROOT_COAP_ADDR, strlen(ROOT_COAP_ADDR), &root_ep);
    if (!ret)
    {
        LOG_ERR("CoAP Endpoint failed to be set to %s\n", ROOT_COAP_ADDR);
        return false;
    }
    else
    {
        LOG_DBG("CoAP Endpoint set to %s\n", ROOT_COAP_ADDR);
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
