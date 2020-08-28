#include "contiki.h"
#include "crypto-support.h"
#include "random-helpers.h"
#include "assert.h"
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(profile, "profile");
PROCESS(profile_ecc_sign_verify, "profile_ecc_sign_verify");
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&profile);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(profile, ev, data)
{
    PROCESS_BEGIN();

    process_start(&profile_ecc_sign_verify, NULL);
    PROCESS_YIELD_UNTIL(!process_is_running(&profile_ecc_sign_verify));

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(profile_ecc_sign_verify, ev, data)
{
    PROCESS_BEGIN();

    crypto_support_init();

    static uint8_t message[1024 + DTLS_EC_SIG_SIZE];
    static uint16_t message_len = 0;

    static bool r;

    while (1)
    {
        // Generate some data 
        message_len = random_in_range_unbiased(1, 1024);

        r = crypto_fill_random(message, message_len);
        assert(r);
        

        r = queue_message_to_sign(&profile_ecc_sign_verify, NULL, message, sizeof(message), message_len);
        assert(r);

        PROCESS_WAIT_EVENT_UNTIL(ev == pe_message_signed);

        queue_message_to_sign_done((messages_to_sign_entry_t*)data);


        r = queue_message_to_verify(&profile_ecc_sign_verify, NULL, message, message_len + DTLS_EC_SIG_SIZE, &our_key.pub_key);
        assert(r);

        PROCESS_WAIT_EVENT_UNTIL(ev == pe_message_verified);

        queue_message_to_verify_done((messages_to_verify_entry_t*)data);
    }

    process_poll(&profile);

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
