#include "platform-crypto-support.h"

#include "os/lib/random.h"
#include "os/sys/pt-sem.h"
#include "os/sys/rtimer.h"
#include "os/sys/log.h"

#include <stdint.h>
#include <inttypes.h>

#include "nrf_crypto_init.h"
#include "nrf_crypto_rng.h"

#include "assert.h"

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
bool platform_crypto_success(platform_crypto_result_t ret)
{
    return ret == NRF_SUCCESS;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void platform_crypto_support_init(void)
{
    // Make sure that nrf_crypto has been started
    assert(nrf_crypto_is_initialized());

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

    ret_code_t ret = nrf_crypto_rng_vector_generate(buffer, size_in_bytes);

    return platform_crypto_success(ret);
}
/*-------------------------------------------------------------------------------------------------------------------*/
platform_crypto_result_t
sha256_hash(const uint8_t* buffer, size_t len, uint8_t* hash)
{
    nrf_crypto_hash_context_t ctx;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;

    LOG_DBG("Starting sha256(%zu)...\n", len);
    time = RTIMER_NOW();
#endif
    platform_crypto_result_t ret;

    ret = nrf_crypto_hash_init(&ctx, &g_nrf_crypto_hash_sha256_info);
    if (ret != NRF_SUCCESS)
    {
        LOG_ERR("nrf_crypto_hash_init failed with %" CRYPTO_RESULT_SPEC "\n", ret);
        goto end;
    }

    ret = nrf_crypto_hash_update(&ctx, buffer, len);
    if (ret != NRF_SUCCESS)
    {
        LOG_ERR("nrf_crypto_hash_update failed with %" CRYPTO_RESULT_SPEC "\n", ret);
        goto end;
    }

    size_t digest_length = SHA256_DIGEST_LEN_BYTES;
    ret = nrf_crypto_hash_finalize(&ctx, hash, &digest_length);
    if (ret != NRF_SUCCESS)
    {
        LOG_ERR("nrf_crypto_hash_finalize failed with %" CRYPTO_RESULT_SPEC "\n", ret);
        goto end;
    }
    if (digest_length != SHA256_DIGEST_LEN_BYTES)
    {
        LOG_ERR("nrf_crypto_hash_finalize to create an appropriate digest length instead %zu\n", digest_length);
        ret = NRF_ERROR_INVALID_LENGTH;
        goto end;
    }

end:

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("sha256(%zu), %" PRIu32 " us\n", len, RTIMERTICKS_TO_US_64(time));
#endif

    return ret;
}
/*-------------------------------------------------------------------------------------------------------------------*/
platform_crypto_result_t platform_sha256_init(platform_sha256_context_t* ctx)
{
    return nrf_crypto_hash_init(ctx, &g_nrf_crypto_hash_sha256_info);
}
platform_crypto_result_t platform_sha256_update(platform_sha256_context_t* ctx, const uint8_t* buffer, size_t len)
{
    return nrf_crypto_hash_update(ctx, buffer, len);
}
platform_crypto_result_t platform_sha256_finalise(platform_sha256_context_t* ctx, uint8_t* hash)
{
    size_t digest_length = SHA256_DIGEST_LEN_BYTES;
    return nrf_crypto_hash_finalize(ctx, hash, &digest_length);
}
void platform_sha256_done(platform_sha256_context_t* ctx)
{
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecc_sign(sign_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len))
{
    PT_BEGIN(&state->pt);

    if (buffer_len - msg_len < DTLS_EC_KEY_SIZE * 2)
    {
        LOG_ERR("Insufficient buffer space\n");
        state->result = NRF_ERROR_INVALID_PARAM;
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Waiting for crypto processor to become available (sign)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (sign)!\n");

    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    uint8_t sha256_ret = sha256_hash(buffer, msg_len, digest);
    if (sha256_ret != NRF_SUCCESS)
    {
        LOG_ERR("sha256_hash failed with %u\n", sha256_ret);
        state->result = sha256_ret;

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecc_dsa_sign()...\n");
    static rtimer_clock_t time;
    time = RTIMER_NOW();
#endif

    nrf_crypto_ecc_private_key_t priv_key;
    state->result = nrf_crypto_ecc_private_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,
        &priv_key,
        our_privkey.k,
        DTLS_EC_KEY_SIZE);
    if (state->result != NRF_SUCCESS)
    {
        LOG_ERR("nrf_crypto_ecc_private_key_from_raw failed with %" CRYPTO_RESULT_SPEC "\n", state->result);

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

    size_t signature_length = NRF_CRYPTO_ECDSA_SECP256R1_SIGNATURE_SIZE;
    state->result = nrf_crypto_ecdsa_sign(
        &state->ctx,
        &priv_key,
        digest, SHA256_DIGEST_LEN_BYTES,
        state->signature, &signature_length
    );

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("nrf_crypto_ecdsa_sign(), %" PRIu32 " us\n", RTIMERTICKS_TO_US_64(time));
#endif

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
    inform_crypto_mutex_released();

    if (state->result != NRF_SUCCESS)
    {
        LOG_ERR("Failed to sign message with %" CRYPTO_RESULT_SPEC "\n", state->result);
        PT_EXIT(&state->pt);
    }

    if (signature_length != NRF_CRYPTO_ECDSA_SECP256R1_SIGNATURE_SIZE)
    {
        LOG_ERR("Failed to create correct signature length instead %zu\n", signature_length);
        state->result  = NRF_ERROR_INVALID_LENGTH;
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Message sign success!\n");

    // Add signature into the message
    memcpy(buffer + msg_len, state->signature, NRF_CRYPTO_ECDSA_SECP256R1_SIGNATURE_SIZE);

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
        state->result = NRF_ERROR_INVALID_PARAM;
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Waiting for crypto processor to become available (verify)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (verify)!\n");

    const size_t msg_len = buffer_len - DTLS_EC_KEY_SIZE * 2;

    const uint8_t* signature = buffer + msg_len;

    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    ret_code_t sha256_ret = sha256_hash(buffer, msg_len, digest);
    if (sha256_ret != NRF_SUCCESS)
    {
        LOG_ERR("sha256_hash failed with %" CRYPTO_RESULT_SPEC "\n", sha256_ret);

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecc_dsa_verify()...\n");
    static rtimer_clock_t time;
    time = RTIMER_NOW();
#endif

    nrf_crypto_ecc_public_key_t pub_key;
    state->result = nrf_crypto_ecc_public_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,
        &pub_key,
        (const uint8_t*)pubkey,
        sizeof(*pubkey));
    if (state->result != NRF_SUCCESS)
    {
        LOG_ERR("nrf_crypto_ecc_public_key_from_raw failed with %" CRYPTO_RESULT_SPEC "\n", state->result);

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

    state->result = nrf_crypto_ecdsa_verify(
        &state->ctx,
        &pub_key,
        digest, SHA256_DIGEST_LEN_BYTES,
        signature, DTLS_EC_KEY_SIZE * 2);

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("nrf_crypto_ecdsa_verify(), %" PRIu32 " us\n", RTIMERTICKS_TO_US_64(time));
#endif

    if (state->result != NRF_SUCCESS)
    {
        // TODO: fix
        /*if (state->result == PKA_STATUS_SIGNATURE_INVALID)
        {
            LOG_ERR("Failed to verify message with PKA_STATUS_SIGNATURE_INVALID\n");
        }
        else*/
        {
            LOG_ERR("Failed to verify message with %" CRYPTO_RESULT_SPEC "\n", state->result);
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

    nrf_crypto_ecc_public_key_t pub_key;
    state->result = nrf_crypto_ecc_public_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,
        &pub_key,
        (const uint8_t*)other_pubkey,
        sizeof(*other_pubkey));
    if (state->result != NRF_SUCCESS)
    {
        LOG_ERR("nrf_crypto_ecc_public_key_from_raw failed with %" CRYPTO_RESULT_SPEC "\n", state->result);

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

    nrf_crypto_ecc_private_key_t priv_key;
    state->result = nrf_crypto_ecc_private_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,
        &priv_key,
        our_privkey.k,
        DTLS_EC_KEY_SIZE);
    if (state->result != NRF_SUCCESS)
    {
        LOG_ERR("nrf_crypto_ecc_private_key_from_raw failed with %" CRYPTO_RESULT_SPEC "\n", state->result);

        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        inform_crypto_mutex_released();

        PT_EXIT(&state->pt);
    }

    size_t shared_secret_size = DTLS_EC_KEY_SIZE;
    state->result = nrf_crypto_ecdh_compute(
        &state->ctx,
        &priv_key,
        &pub_key,
        state->shared_secret, &shared_secret_size);

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    time = RTIMER_NOW() - time;
    LOG_DBG("ecdh2(), %" PRIu32 " us\n", RTIMERTICKS_TO_US_64(time));
#endif

    if (state->result != NRF_SUCCESS)
    {
        LOG_ERR("ecdh2 failed with %" CRYPTO_RESULT_SPEC "\n", state->result);
    }
    else
    {
        LOG_DBG("echd2 success!\n");
    }

    assert(shared_secret_size == DTLS_EC_KEY_SIZE);

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
    inform_crypto_mutex_released();

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
