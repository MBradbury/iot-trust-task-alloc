#include "crypto-support.h"

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
void
crypto_support_init(void)
{
    crypto_init();
    crypto_disable();
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
crypto_fill_random(uint8_t* buffer, size_t len)
{
    if (buffer == NULL)
    {
        return false;
    }

    for (int i = 0; i < len; ++i)
    {
        buffer[i] = random_rand() & 0xff;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static inline uint32_t
dtls_uint32_to_int(const unsigned char *field)
{
  return ((uint32_t)field[0] << 24)
       | ((uint32_t)field[1] << 16)
       | ((uint32_t)field[2] << 8 )
       | ((uint32_t)field[3]      );
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
dtls_ec_key_to_uint32(const uint8_t* key, size_t key_size, uint32_t* result) {
  int i;

  for (i = (key_size / sizeof(uint32_t)) - 1; i >= 0 ; i--) {
    *result = dtls_uint32_to_int(&key[i * sizeof(uint32_t)]);
    result++;
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
sha256_hash(const uint8_t* buffer, size_t len, uint8_t* hash)
{
    sha256_state_t sha256_state;
    rtimer_clock_t time;

    LOG_DBG("Starting sha256()...\n");
    time = RTIMER_NOW();
    crypto_enable();
    sha256_init(&sha256_state);
    sha256_process(&sha256_state, buffer, len);
    sha256_done(&sha256_state, hash);
    crypto_disable();
    time = RTIMER_NOW() - time;
    LOG_DBG("sha256(), %" PRIu32 " us\n", (uint32_t)((uint64_t)time * 1000000 / RTIMER_SECOND));
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecc_sign(sign_trust_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len))
{
    PT_BEGIN(&state->pt);

    state->sig_len = 0;

    sha256_hash(buffer, msg_len, (uint8_t*)state->ecc_sign_state.hash);

    state->ecc_sign_state.process = state->process;
    state->ecc_sign_state.curve_info = &nist_p_256;

    // Set secret key from our private key
    dtls_ec_key_to_uint32(our_key.priv_key, DTLS_EC_KEY_SIZE, state->ecc_sign_state.secret);

    crypto_fill_random((uint8_t*)state->ecc_sign_state.k_e, DTLS_EC_KEY_SIZE);

    LOG_DBG("Starting ecc_dsa_sign()...\n");
    state->time = RTIMER_NOW();
    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_sign_state.pt, ecc_dsa_sign(&state->ecc_sign_state));
    pka_disable();
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecc_dsa_sign(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));

    if (state->ecc_sign_state.result != PKA_STATUS_SUCCESS)
    {
        LOG_ERR("Failed to sign message with %d\n", state->ecc_sign_state.result);
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Message sign success!\n");

    // Add signature into the message
    memcpy(buffer + msg_len,                        state->ecc_sign_state.point_r.x,   sizeof(uint32_t) * 8);
    memcpy(buffer + msg_len + sizeof(uint32_t) * 8, state->ecc_sign_state.signature_s, sizeof(uint32_t) * 8);

    state->sig_len = sizeof(uint32_t) * 8 * 2;

#if 1
    static verify_trust_state_t test;
    test.process = state->process;
    PT_SPAWN(&state->pt, &test.pt, ecc_verify(&test, buffer, msg_len + state->sig_len));
#endif

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecc_verify(verify_trust_state_t* state, const uint8_t* buffer, size_t buffer_len))
{
    PT_BEGIN(&state->pt);

    // Extract signature
    if (buffer_len < sizeof(uint32_t) * 8 * 2)
    {
        LOG_ERR("No signature\n");
        PT_EXIT(&state->pt);
    }

    const uint8_t* sig_r = buffer + buffer_len - sizeof(uint32_t) * 8 * 2;
    const uint8_t* sig_s = buffer + buffer_len - sizeof(uint32_t) * 8;

    // Extract signature from buffer
    memcpy(state->ecc_verify_state.signature_r, sig_r, sizeof(uint32_t) * 8);
    memcpy(state->ecc_verify_state.signature_s, sig_s, sizeof(uint32_t) * 8);

    size_t msg_len = buffer_len - sizeof(uint32_t) * 8 * 2;

    sha256_hash(buffer, msg_len, (uint8_t*)state->ecc_verify_state.hash);

    state->ecc_verify_state.process = state->process;
    state->ecc_verify_state.curve_info = &nist_p_256;

    // TODO: get public key from key store
    dtls_ec_key_to_uint32(our_key.pub_key.x, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.x);
    dtls_ec_key_to_uint32(our_key.pub_key.y, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.y);

    state->time = RTIMER_NOW();
    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_verify_state.pt, ecc_dsa_verify(&state->ecc_verify_state));
    pka_disable();
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecc_dsa_verify(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));

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
