#include "trust.h"

#include "contiki.h"
#include "os/sys/log.h"

#include <stdio.h>

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-model"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
void
process_mqtt_pub(const char *topic, uint16_t topic_len, const uint8_t *chunk, uint16_t chunk_len)
{
	// Interested in "iot/edge/+/fmt/json" events
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
{
    PROCESS_BEGIN();


    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
