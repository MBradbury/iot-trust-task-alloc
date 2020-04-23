#include "trust.h"
#include "edge-info.h"

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
const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN] = {
	"iot/edge/+/announce",
	"iot/edge/+/capability/+"
};
/*-------------------------------------------------------------------------------------------------------------------*/
void
mqtt_publish_handler(const char *topic, uint16_t topic_len, const uint8_t *chunk, uint16_t chunk_len)
{
	// Interested in "iot/edge/+/fmt/json" events
	LOG_DBG("Pub Handler: topic='%s' (len=%u), chunk_len=%u\n", topic, topic_len, chunk_len);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
init(void)
{

}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(trust_model, "Trust Model process");
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(trust_model, ev, data)
{
    PROCESS_BEGIN();

    init();
    edge_info_init();

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
