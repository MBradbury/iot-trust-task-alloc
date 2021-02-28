#include "contiki.h"
#include "crypto-support.h"
#include "random-helpers.h"
#include "assert.h"
#include "rtimer.h"
#include "sys/log.h"
#include "oscore-crypto.h"
#include "cose.h"
#include "certificate.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "profile"
#define LOG_LEVEL LOG_LEVEL_DBG
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(profile, "profile");
PROCESS(profile_ecc_sign_verify, "profile_ecc_sign_verify");
PROCESS(profile_aes_ccm, "profile_aes_ccm");
/*-------------------------------------------------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&profile);
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(profile, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("There are " CC_STRINGIFY(RTIMER_SECOND) " ticks per second\n");

#if defined(PROFILE_ECC)
    LOG_INFO("Profiling ECC\n");

    process_start(&profile_ecc_sign_verify, NULL);
    PROCESS_YIELD_UNTIL(!process_is_running(&profile_ecc_sign_verify));

#elif defined(PROFILE_AES)
    LOG_INFO("Profiling AES\n");

    process_start(&profile_aes_ccm, NULL);
    PROCESS_YIELD_UNTIL(!process_is_running(&profile_aes_ccm));

#else
#   error "Not profiling anything"
#endif

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


        r = queue_message_to_verify(&profile_ecc_sign_verify, NULL, message, message_len + DTLS_EC_SIG_SIZE, &our_cert.public_key);
        assert(r);

        PROCESS_WAIT_EVENT_UNTIL(ev == pe_message_verified);

        queue_message_to_verify_done((messages_to_verify_entry_t*)data);


        static ecdh2_state_t state;
        state.ecc_multiply_state.process = &profile_ecc_sign_verify;
        PROCESS_PT_SPAWN(&state.pt, ecdh2(&state, &our_cert.public_key));
        assert(state.ecc_multiply_state.result == PKA_STATUS_SUCCESS);
    }

    process_poll(&profile);

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(profile_aes_ccm, ev, data)
{
    PROCESS_BEGIN();

    static uint8_t plaintext[1024];
    static uint16_t plaintext_len = 0;

    static uint8_t ciphertext[1024 + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN];
    static uint16_t ciphertext_len = 0;

    static uint8_t aad[35];

    static uint8_t key[COSE_algorithm_AES_CCM_16_64_128_KEY_LEN];

    static uint8_t nonce[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];

    static bool r;
    static int result;

    static rtimer_clock_t time;

    while (1)
    {
        // Generate some data
        plaintext_len = random_in_range_unbiased(1, 1024);
        r = crypto_fill_random(plaintext, plaintext_len);
        assert(r);

        r = crypto_fill_random(aad, sizeof(aad));
        assert(r);

        r = crypto_fill_random(key, sizeof(key));
        assert(r);

        r = crypto_fill_random(nonce, sizeof(nonce));
        assert(r);

        memcpy(ciphertext, plaintext, plaintext_len);


        LOG_DBG("Starting encrypt(%zu)...\n", plaintext_len);
        time = RTIMER_NOW();

        result = encrypt(
            COSE_Algorithm_AES_CCM_16_64_128,
            key, sizeof(key),
            nonce, sizeof(nonce),
            aad, sizeof(aad),
            ciphertext, plaintext_len);

        time = RTIMER_NOW() - time;
        LOG_DBG("encrypt(%zu), %" PRIu32 " us\n", plaintext_len, RTIMERTICKS_TO_US_64(time));

        assert(result > 0);

        ciphertext_len = result;

        LOG_DBG("Starting decrypt(%zu)...\n", plaintext_len);
        time = RTIMER_NOW();

        result = decrypt(
            COSE_Algorithm_AES_CCM_16_64_128,
            key, sizeof(key),
            nonce, sizeof(nonce),
            aad, sizeof(aad),
            ciphertext, ciphertext_len);

        time = RTIMER_NOW() - time;
        LOG_DBG("decrypt(%zu), %" PRIu32 " us\n", plaintext_len, RTIMERTICKS_TO_US_64(time));

        assert(result > 0);

        assert(memcmp(plaintext, ciphertext, plaintext_len) == 0);

        // Need to yield often enough to prevent the watchdog killing us
        PROCESS_PAUSE();
    }

    process_poll(&profile);

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
