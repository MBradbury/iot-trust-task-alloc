#include "contiki.h"
#include "sys/log.h"

#include "trust.h" // from node/trust

#include "coap.h"
#include "coap-engine.h"
#include "coap-log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "attack-er"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(eavesdrop_reputation, "eavesdrop_reputation");
/*-------------------------------------------------------------------------------------------------------------------*/
static void
res_trust_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset);

RESOURCE(res_trust,
         "title=\"Trust information\";rt=\"trust\"",
         NULL,                   /*GET*/
         res_trust_post_handler, /*POST*/ // Handle periodic broadcasts of neighbour's information
         NULL,                   /*PUT*/
         NULL                    /*DELETE*/);

static void
res_trust_post_handler(coap_message_t *request, coap_message_t *response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
    // Received trust information from another node, need to update our reputation database
    const uint8_t* payload;
    int payload_len = coap_get_payload(request, &payload);

    LOG_INFO("Received trust info via POST from ");
    LOG_INFO_COAP_EP(request->src_ep);
    LOG_INFO_(" of length %d\n", payload_len);

    if (payload_len <= 0 || payload_len > (MAX_TRUST_PAYLOAD + DTLS_EC_SIG_SIZE))
    {
        LOG_WARN("Received payload either too short or too long for buffer %d (max %d)\n",
            payload_len, (MAX_TRUST_PAYLOAD + DTLS_EC_SIG_SIZE));
        coap_set_status_code(response, BAD_REQUEST_4_00);
        return;
    }

    // We have received the message, for this attack we will not try to verify it
    // This payload should not be encrypted, but we raw CBOR

    int reputation_payload_len = payload_len - DTLS_EC_SIG_SIZE;

    const uint8_t* raw_signature = payload + reputation_payload_len;

    LOG_INFO("Raw payload: ");
    LOG_INFO_BYTES(payload, reputation_payload_len);
    LOG_INFO_("\n");

    LOG_INFO("Raw Signature: ");
    LOG_INFO_BYTES(raw_signature, DTLS_EC_SIG_SIZE);
    LOG_INFO_("\n");
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(eavesdrop_reputation, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("Starting %s\n", PROCESS_NAME_STRING(PROCESS_CURRENT()));

    coap_activate_resource(&res_trust, TRUST_COAP_URI);

#if defined(WITH_OSCORE) && defined(WITH_GROUPCOM)
#   error "Cannot perform this attack with Group OSCORE"
#endif

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
