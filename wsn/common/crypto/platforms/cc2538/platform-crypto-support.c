#include "platform-crypto-support.h"

#include "os/lib/random.h"
#include "os/sys/pt-sem.h"
#include "os/sys/rtimer.h"
#include "os/sys/log.h"

#include "dev/sha256.h"
#include "dev/ecc-curve.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "crypto-plat"
#ifdef CRYPTO_SUPPORT_LOG_LEVEL
#define LOG_LEVEL CRYPTO_SUPPORT_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define SHA256_DIGEST_LEN_BYTES (256 / 8)
/*-------------------------------------------------------------------------------------------------------------------*/
static struct pt_sem crypto_processor_mutex;
static process_event_t pe_crypto_lock_released;
/*-------------------------------------------------------------------------------------------------------------------*/
void platform_crypto_support_init(void)
{
    crypto_init();
    crypto_disable();

    pka_init();
    pka_disable();

    PT_SEM_INIT(&crypto_processor_mutex, 1);

    pe_crypto_lock_released = process_alloc_event();
    LOG_DBG("pe_crypto_lock_released = %u\n", pe_crypto_lock_released);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void 
inform_crypto_mutex_released(void)
{
    // Other processes waiting on semaphore might have some tasks to do
    if (process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL) != PROCESS_ERR_OK)
    {
        LOG_ERR("Failed to post pe_crypto_lock_released\n");
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
crypto_fill_random(uint8_t* buffer, size_t size_in_bytes)
{
    if (buffer == NULL)
    {
        return false;
    }

    // random_rand returns a uint16_t

    uint16_t* buffer_u16 = (uint16_t*)buffer;

    for (size_t i = 0; i < size_in_bytes / sizeof(uint16_t); ++i)
    {
        buffer_u16[i] = random_rand();
    }

    // Handle leftover byte
    if ((size_in_bytes % sizeof(uint16_t)) != 0)
    {
        buffer[size_in_bytes-1] = (uint8_t)random_rand();
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static inline
uint32_t ec_uint8x4_to_uint32_left(const uint8_t* field)
{
  return ((uint32_t)field[0] << 24)
       | ((uint32_t)field[1] << 16)
       | ((uint32_t)field[2] <<  8)
       | ((uint32_t)field[3]      );
}
static void
ec_uint8v_to_uint32v(const uint8_t* data, size_t size_in_bytes, uint32_t* result)
{
    // The data provided in key is expected to be encoded in big-endian
    /*
        x-: 2D98EA01 F754D34B BC3003DF 5050200A BF445EC7 28556D7E D7D5C54C 55552B6D // Orig
        x+: 6D2B5555 4CC5D5D7 7E6D5528 C75E44BF 0A205050 DF0330BC 4BD354F7 01EA982D // New
    */
    for (int i = (size_in_bytes / sizeof(uint32_t)) - 1; i >= 0 ; i--)
    {
        *result = ec_uint8x4_to_uint32_left(&data[i * sizeof(uint32_t)]);
        result++;
    }
}
static inline
void ec_uint8x4_from_uint32_left(uint8_t* field, uint32_t data)
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
        ec_uint8x4_from_uint32_left(result, data[i]);

        result += sizeof(uint32_t);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
uint8_t
sha256_hash(const uint8_t* buffer, size_t len, uint8_t* hash)
{
    sha256_state_t sha256_state;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;

    LOG_DBG("Starting sha256(%zu)...\n", len);
    time = RTIMER_NOW();
#endif

    bool enabled = CRYPTO_IS_ENABLED();
    if (!enabled)
    {
        crypto_enable();
    }

    uint8_t ret;

    ret = sha256_init(&sha256_state);
    if (ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_init failed with %u\n", ret);
        goto end;
    }

    ret = sha256_process(&sha256_state, buffer, len);
    if (ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_process failed with %u\n", ret);
        goto end;
    }

    ret = sha256_done(&sha256_state, hash);
    if (ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_done failed with %u\n", ret);
        goto end;
    }

end:
    if (!enabled)
    {
        crypto_disable();
    }

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("sha256(%zu), %" PRIu32 " us\n", len, RTIMERTICKS_TO_US_64(time));
#endif

    return ret;
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

    LOG_DBG("Waiting for crypto processor to become available (sign)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (sign)!\n");

    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    uint8_t sha256_ret = sha256_hash(buffer, msg_len, digest);
    if (sha256_ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_hash failed with %u\n", sha256_ret);
        state->ecc_sign_state.result = sha256_ret;

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

    ec_uint8v_to_uint32v(digest, sizeof(digest), state->ecc_sign_state.hash);

    state->ecc_sign_state.curve_info = &nist_p_256;

    // Set secret key from our private key
    ec_uint8v_to_uint32v(our_privkey.k, DTLS_EC_KEY_SIZE, state->ecc_sign_state.secret);

    crypto_fill_random((uint8_t*)state->ecc_sign_state.k_e, DTLS_EC_KEY_SIZE);

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecc_dsa_sign()...\n");
    static rtimer_clock_t time;
    time = RTIMER_NOW();
#endif

    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_sign_state.pt, ecc_dsa_sign(&state->ecc_sign_state));
    pka_disable();

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("ecc_dsa_sign(), %" PRIu32 " us\n", RTIMERTICKS_TO_US_64(time));
#endif

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
    inform_crypto_mutex_released();

    if (state->ecc_sign_state.result != PKA_STATUS_SUCCESS)
    {
        LOG_ERR("Failed to sign message with %d\n", state->ecc_sign_state.result);
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Message sign success!\n");

    // Add signature into the message
    ec_uint32v_to_uint8v(state->ecc_sign_state.point_r.x,   DTLS_EC_KEY_SIZE, buffer + msg_len                   );
    ec_uint32v_to_uint8v(state->ecc_sign_state.signature_s, DTLS_EC_KEY_SIZE, buffer + msg_len + DTLS_EC_KEY_SIZE);

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
        state->ecc_verify_state.result = PKA_STATUS_INVALID_PARAM;
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Waiting for crypto processor to become available (verify)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (verify)!\n");

    const size_t msg_len = buffer_len - DTLS_EC_KEY_SIZE * 2;

    const uint8_t* sig_r = buffer + msg_len;
    const uint8_t* sig_s = buffer + msg_len + DTLS_EC_KEY_SIZE;

    // Extract signature from buffer
    ec_uint8v_to_uint32v(sig_r, DTLS_EC_KEY_SIZE, state->ecc_verify_state.signature_r);
    ec_uint8v_to_uint32v(sig_s, DTLS_EC_KEY_SIZE, state->ecc_verify_state.signature_s);

    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    uint8_t sha256_ret = sha256_hash(buffer, msg_len, digest);
    if (sha256_ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_hash failed with %u\n", sha256_ret);
        state->ecc_verify_state.result = sha256_ret;

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

    ec_uint8v_to_uint32v(digest, sizeof(digest), state->ecc_verify_state.hash);

    state->ecc_verify_state.curve_info = &nist_p_256;

    ec_uint8v_to_uint32v(pubkey->x, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.x);
    ec_uint8v_to_uint32v(pubkey->y, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.y);

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecc_dsa_verify()...\n");
    static rtimer_clock_t time;
    time = RTIMER_NOW();
#endif

    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_verify_state.pt, ecc_dsa_verify(&state->ecc_verify_state));
    pka_disable();

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("ecc_dsa_verify(), %" PRIu32 " us\n", RTIMERTICKS_TO_US_64(time));
#endif

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

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
    inform_crypto_mutex_released();

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecdh2(ecdh2_state_t* state, const ecdsa_secp256r1_pubkey_t* other_pubkey))
{
    PT_BEGIN(&state->pt);

    LOG_DBG("Waiting for crypto processor to become available (echd2)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (echd2)!\n");

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecdh2()...\n");
    static rtimer_clock_t time;
    time = RTIMER_NOW();
#endif

    // Prepare Points
    state->ecc_multiply_state.curve_info = &nist_p_256;

    // Set point to be the input public key
    ec_uint8v_to_uint32v(other_pubkey->x, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.point_in.x);
    ec_uint8v_to_uint32v(other_pubkey->y, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.point_in.y);

    // Use our private key as the secret
    ec_uint8v_to_uint32v(our_privkey.k, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.secret);

    pka_enable();
    PT_SPAWN(&state->pt, &(state->ecc_multiply_state.pt), ecc_multiply(&state->ecc_multiply_state));
    pka_disable();

    if (state->ecc_multiply_state.result == PKA_STATUS_SUCCESS)
    {
        ec_uint32v_to_uint8v(state->ecc_multiply_state.point_out.x, DTLS_EC_KEY_SIZE, state->shared_secret);
    }

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("ecdh2(), %" PRIu32 " us\n", RTIMERTICKS_TO_US_64(time));
#endif

    if (state->ecc_multiply_state.result != PKA_STATUS_SUCCESS)
    {
        LOG_ERR("ecdh2 failed with %d\n", state->ecc_multiply_state.result);
    }
    else
    {
        LOG_DBG("echd2 success!\n");
    }

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
    inform_crypto_mutex_released();

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
