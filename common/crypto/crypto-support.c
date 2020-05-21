#include "crypto-support.h"

#include "pt.h"
#include "pt-sem.h"
#include "os/sys/log.h"

#include "dev/sha256.h"

#include "random.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "crypto-support"
#ifdef CRYPTO_SUPPORT_LOG_LEVEL
#define LOG_LEVEL CRYPTO_SUPPORT_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static struct pt_sem crypto_processor_mutex;
/*-------------------------------------------------------------------------------------------------------------------*/
void
crypto_support_init(void)
{
    crypto_init();
    crypto_disable();
    PT_SEM_INIT(&crypto_processor_mutex, 1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
crypto_fill_random(uint8_t* buffer, size_t size_in_bytes)
{
    if (buffer == NULL)
    {
        return false;
    }

    for (int i = 0; i < size_in_bytes; ++i)
    {
        buffer[i] = random_rand() & 0xff;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
/*void hexdump(const char* name, const uint8_t* buffer, size_t len)
{
    LOG_DBG("%s: ", name);
    for (size_t i = 0; i != len; ++i)
    {
        LOG_DBG_("%02X", buffer[i]);
    }
    LOG_DBG_("\n");
}*/
/*-------------------------------------------------------------------------------------------------------------------*/
static inline
uint32_t dtls_uint8x4_to_uint32_left(const uint8_t* field)
{
  return ((uint32_t)field[0] << 24)
       | ((uint32_t)field[1] << 16)
       | ((uint32_t)field[2] <<  8)
       | ((uint32_t)field[3]      );
}
static void
ec_uint8v_to_uint32v(const uint8_t* data, size_t size_in_bytes, uint32_t* result)
{
    // dtls_ec_key_to_uint32l
    // The data provided in key is expected to be encoded in big-endian
    /*
        x-: 2D98EA01 F754D34B BC3003DF 5050200A BF445EC7 28556D7E D7D5C54C 55552B6D // Orig
        x+: 6D2B5555 4CC5D5D7 7E6D5528 C75E44BF 0A205050 DF0330BC 4BD354F7 01EA982D // New
    */
    for (int i = (size_in_bytes / sizeof(uint32_t)) - 1; i >= 0 ; i--)
    {
        *result = dtls_uint8x4_to_uint32_left(&data[i * sizeof(uint32_t)]);
        result++;
    }
}
static inline
void dtls_uint8x4_from_uint32_left(uint8_t* field, uint32_t data)
{
    field[0] = (uint8_t)((data & 0xFF000000) >> 24);
    field[1] = (uint8_t)((data & 0x00FF0000) >> 16);
    field[2] = (uint8_t)((data & 0x0000FF00) >>  8);
    field[3] = (uint8_t)((data & 0x000000FF)      );
}
static void
ec_uint32v_to_uint8v(const uint32_t* data, size_t size_in_bytes, uint8_t* result)
{
    /*
        x+: 6D2B5555 4CC5D5D7 7E6D5528 C75E44BF 0A205050 DF0330BC 4BD354F7 01EA982D // Orig
        x-: 2D98EA01 F754D34B BC3003DF 5050200A BF445EC7 28556D7E D7D5C54C 55552B6D // New
    */
    for (int i = (size_in_bytes / sizeof(uint32_t)) - 1; i >= 0 ; i--)
    {
        dtls_uint8x4_from_uint32_left(result, data[i]);

        result += sizeof(uint32_t);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
sha256_hash(const uint8_t* buffer, size_t len, uint8_t* hash)
{
    sha256_state_t sha256_state;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;

    LOG_DBG("Starting sha256()...\n");
    time = RTIMER_NOW();
#endif

    crypto_enable();
    sha256_init(&sha256_state);
    sha256_process(&sha256_state, buffer, len);
    sha256_done(&sha256_state, hash);
    crypto_disable();

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("sha256(), %" PRIu32 " us\n", (uint32_t)((uint64_t)time * 1000000 / RTIMER_SECOND));
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecc_sign(sign_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len))
{
    PT_BEGIN(&state->pt);

    if (buffer_len - msg_len < DTLS_EC_KEY_SIZE * 2)
    {
        LOG_ERR("Insufficient buffer space\n");
        state->ecc_sign_state.result = PKA_STATUS_INVALID_PARAM;
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Waiting for crypto processor to become available...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available!\n");

    state->sig_len = 0;

    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    sha256_hash(buffer, msg_len, digest);
    ec_uint8v_to_uint32v(digest, sizeof(digest), state->ecc_sign_state.hash);

    //hexdump("m", buffer, msg_len);
    //hexdump("h", (uint8_t*)state->ecc_sign_state.hash, SHA256_DIGEST_LEN_BYTES);

    state->ecc_sign_state.process = state->process;
    state->ecc_sign_state.curve_info = &nist_p_256;

    // Set secret key from our private key
    ec_uint8v_to_uint32v(our_key.priv_key, DTLS_EC_KEY_SIZE, state->ecc_sign_state.secret);

    //hexdump("p", our_key.priv_key, DTLS_EC_KEY_SIZE);

    crypto_fill_random((uint8_t*)state->ecc_sign_state.k_e, DTLS_EC_KEY_SIZE);

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecc_dsa_sign()...\n");
    state->time = RTIMER_NOW();
#endif

    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_sign_state.pt, ecc_dsa_sign(&state->ecc_sign_state));
    pka_disable();

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecc_dsa_sign(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));
#endif

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

    if (state->ecc_sign_state.result != PKA_STATUS_SUCCESS)
    {
        LOG_ERR("Failed to sign message with %d\n", state->ecc_sign_state.result);
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Message sign success!\n");
    //hexdump("r", (const uint8_t*)state->ecc_sign_state.point_r.x,   DTLS_EC_KEY_SIZE);
    //hexdump("s", (const uint8_t*)state->ecc_sign_state.signature_s, DTLS_EC_KEY_SIZE);

    // Add signature into the message
    ec_uint32v_to_uint8v(state->ecc_sign_state.point_r.x,   DTLS_EC_KEY_SIZE, buffer + msg_len                   );
    ec_uint32v_to_uint8v(state->ecc_sign_state.signature_s, DTLS_EC_KEY_SIZE, buffer + msg_len + DTLS_EC_KEY_SIZE);
    state->sig_len = DTLS_EC_KEY_SIZE * 2;

#if 0
    LOG_DBG("Performing sign self-check...\n");
    static verify_state_t test;
    test.process = state->process;
    PT_SPAWN(&state->pt, &test.pt, ecc_verify(&test, &our_key.pub_key, buffer, msg_len + state->sig_len));
    LOG_DBG("Sign self-check complete!\n");
#endif

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecc_verify(verify_state_t* state, const ecdsa_secp256r1_pubkey_t* pubkey, const uint8_t* buffer, size_t buffer_len))
{
    PT_BEGIN(&state->pt);

    // Extract signature
    if (buffer_len < DTLS_EC_KEY_SIZE * 2)
    {
        LOG_ERR("No signature\n");
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Waiting for crypto processor to become available...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available!\n");

    const size_t msg_len = buffer_len - DTLS_EC_KEY_SIZE * 2;

    const uint8_t* sig_r = buffer + msg_len;
    const uint8_t* sig_s = buffer + msg_len + DTLS_EC_KEY_SIZE;

    //hexdump("r", sig_r, DTLS_EC_KEY_SIZE);
    //hexdump("s", sig_s, DTLS_EC_KEY_SIZE);

    // Extract signature from buffer
    ec_uint8v_to_uint32v(sig_r, DTLS_EC_KEY_SIZE, state->ecc_verify_state.signature_r);
    ec_uint8v_to_uint32v(sig_s, DTLS_EC_KEY_SIZE, state->ecc_verify_state.signature_s);

    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    sha256_hash(buffer, msg_len, digest);
    ec_uint8v_to_uint32v(digest, sizeof(digest), state->ecc_verify_state.hash);

    //hexdump("m", buffer, msg_len);
    //hexdump("h", (uint8_t*)state->ecc_verify_state.hash, SHA256_DIGEST_LEN_BYTES);

    state->ecc_verify_state.process = state->process;
    state->ecc_verify_state.curve_info = &nist_p_256;

    ec_uint8v_to_uint32v(pubkey->x, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.x);
    ec_uint8v_to_uint32v(pubkey->y, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.y);

    //hexdump("x", pubkey->x, DTLS_EC_KEY_SIZE);
    //hexdump("y", pubkey->y, DTLS_EC_KEY_SIZE);

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecc_dsa_verify()...\n");
    state->time = RTIMER_NOW();
#endif

    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_verify_state.pt, ecc_dsa_verify(&state->ecc_verify_state));
    pka_disable();

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecc_dsa_verify(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));
#endif

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

    if (state->ecc_verify_state.result != PKA_STATUS_SUCCESS)
    {
        if (state->ecc_verify_state.result == PKA_STATUS_SIGNATURE_INVALID)
        {
            LOG_ERR("Failed to verify message with PKA_STATUS_SIGNATURE_INVALID\n");
        }
        else
        {
            LOG_ERR("Failed to verify message with %d\n", state->ecc_verify_state.result);
        }
    }
    else
    {
        LOG_DBG("Message verify success!\n");
    }

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
