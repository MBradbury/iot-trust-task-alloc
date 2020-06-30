#include "crypto-support.h"

#include "pt.h"
#include "pt-sem.h"
#include "os/sys/log.h"
#include "os/lib/assert.h"
#include "os/lib/queue.h"
#include "os/lib/memb.h"

#include <limits.h>

#include "dtls-hmac.h"

//#include "random.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "crypto-sup"
#ifdef CRYPTO_SUPPORT_LOG_LEVEL
#define LOG_LEVEL CRYPTO_SUPPORT_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
static struct pt_sem crypto_processor_mutex;
/*-------------------------------------------------------------------------------------------------------------------*/
process_event_t pe_message_signed;
process_event_t pe_message_verified;
process_event_t pe_crypto_lock_released;
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(signer, "signer");
PROCESS(verifier, "verifier");
/*-------------------------------------------------------------------------------------------------------------------*/
void
crypto_support_init(void)
{
    crypto_init();
    crypto_disable();

    pka_init();
    pka_disable();

    PT_SEM_INIT(&crypto_processor_mutex, 1);

    pe_message_signed = process_alloc_event();
    pe_message_verified = process_alloc_event();
    pe_crypto_lock_released = process_alloc_event();

    LOG_DBG("pe_message_signed = %u\n", pe_message_signed);
    LOG_DBG("pe_message_verified = %u\n", pe_message_verified);
    LOG_DBG("pe_crypto_lock_released = %u\n", pe_crypto_lock_released);

    process_start(&signer, NULL);
    process_start(&verifier, NULL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    ecc_compare_state_t ecc_compare_state;

    uint8_t V[SHA256_DIGEST_LEN_BYTES];
    uint8_t K[SHA256_DIGEST_LEN_BYTES];
    uint8_t T[SHA256_DIGEST_LEN_BYTES];

    bool good_k;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;
#endif
} generate_k_state_t;

PT_THREAD(ecc_generate_k(generate_k_state_t* state, const uint8_t* digest));
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    generate_k_state_t ecc_generate_k_state;
    ecc_dsa_sign_state_t ecc_sign_state;

    uint16_t sig_len;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;
#endif
} sign_state_t;

PT_THREAD(ecc_sign(sign_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len));
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    ecc_dsa_verify_state_t ecc_verify_state;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;
#endif
} verify_state_t;

PT_THREAD(ecc_verify(verify_state_t* state, const ecdsa_secp256r1_pubkey_t* pubkey, const uint8_t* buffer, size_t buffer_len));
/*-------------------------------------------------------------------------------------------------------------------*/
/*static bool
crypto_fill_random(uint8_t* buffer, size_t size_in_bytes)
{
    if (buffer == NULL)
    {
        return false;
    }

    // random_rand return a uint16_t
    assert((size_in_bytes % sizeof(uint16_t)) == 0);

    uint16_t* buffer_u16 = (uint16_t*)buffer;

    for (int i = 0; i < size_in_bytes / sizeof(uint16_t); ++i)
    {
        buffer_u16[i] = random_rand();
    }

    return true;
}*/
/*-------------------------------------------------------------------------------------------------------------------*/
static bool bignum_is_zero(const uint8_t *number, const uint8_t number_size)
{
    for (uint8_t i = 0; i != number_size; ++i)
    {
        if (number[i] != 0)
        {
            return false;
        }
    }
    return true;
}
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
static uint8_t
sha256_hash(const uint8_t* buffer, size_t len, uint8_t* hash)
{
    sha256_state_t sha256_state;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;

    LOG_DBG("Starting sha256()...\n");
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
    LOG_DBG("sha256(), %" PRIu32 " us\n", (uint32_t)((uint64_t)time * 1000000 / RTIMER_SECOND));
#endif

    return ret;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecc_generate_k(generate_k_state_t* state, const uint8_t* digest))
{
    // Constants set up each time
    const uint8_t zero = 0;
    const uint8_t one = 1;

    PT_BEGIN(&state->pt);

    // Implementation of rfc6979
    // Create a deterministic k as per: https://tools.ietf.org/html/rfc6979#section-3.2

    state->good_k = false;

    // Set the compare state for later

    // Already in correct format
    // Contiki calls this parameter n whereas the RFC calls this q
    memcpy(state->ecc_compare_state.b, nist_p_256.n, DTLS_EC_KEY_SIZE);
    state->ecc_compare_state.size = DTLS_EC_KEY_SIZE;

    // 3.2b
    memset(state->V, 0x01, sizeof(state->V));

    // 3.2c
    memset(state->K, 0, sizeof(state->K));

    // 3.2d
    dtls_hmac_context_t ctx;
    dtls_hmac_init(&ctx, state->K, sizeof(state->K));
    dtls_hmac_update(&ctx, state->V, sizeof(state->V));
    dtls_hmac_update(&ctx, &zero, 1);
    dtls_hmac_update(&ctx, our_key.priv_key, DTLS_EC_KEY_SIZE);
    dtls_hmac_update(&ctx, digest, SHA256_DIGEST_LEN_BYTES);
    dtls_hmac_finalize(&ctx, state->K);

    // 3.2e
    dtls_hmac_init(&ctx, state->K, sizeof(state->K));
    dtls_hmac_update(&ctx, state->V, sizeof(state->V));
    dtls_hmac_finalize(&ctx, state->V);

    // 3.2f
    dtls_hmac_init(&ctx, state->K, sizeof(state->K));
    dtls_hmac_update(&ctx, state->V, sizeof(state->V));
    dtls_hmac_update(&ctx, &one, 1);
    dtls_hmac_update(&ctx, our_key.priv_key, DTLS_EC_KEY_SIZE);
    dtls_hmac_update(&ctx, digest, SHA256_DIGEST_LEN_BYTES);
    dtls_hmac_finalize(&ctx, state->K);

    // 3.2g
    dtls_hmac_init(&ctx, state->K, sizeof(state->K));
    dtls_hmac_update(&ctx, state->V, sizeof(state->V));
    dtls_hmac_finalize(&ctx, state->V);

    // 3.2h
    do {
        // 3.2h 2
        dtls_hmac_init(&ctx, state->K, sizeof(state->K));
        dtls_hmac_update(&ctx, state->V, sizeof(state->V));
        int len = dtls_hmac_finalize(&ctx, state->V);

        // hmac should always give a suitably long T
        assert(len == SHA256_DIGEST_LEN_BYTES);
        assert((nist_p_256.size * sizeof(uint32_t) * CHAR_BIT) == SHA256_DIGEST_LEN_BYTES * CHAR_BIT);

        memcpy(state->T, state->V, sizeof(state->V));

        // 3.2h 3 - Check that T is within the range [1,q-1]

        ec_uint8v_to_uint32v(state->T, DTLS_EC_KEY_SIZE, state->ecc_compare_state.a);
        
        PT_SPAWN(&state->pt, &state->ecc_compare_state.pt, ecc_compare(&state->ecc_compare_state));

        state->good_k = !bignum_is_zero(state->T, sizeof(state->T)) &&
                        state->ecc_compare_state.result == PKA_STATUS_A_LT_B;

        // 3.2h 3 - Update K and V
        if (!state->good_k)
        {
            dtls_hmac_init(&ctx, state->K, sizeof(state->K));
            dtls_hmac_update(&ctx, state->V, sizeof(state->V));
            dtls_hmac_update(&ctx, &zero, 1);
            dtls_hmac_finalize(&ctx, state->K);

            dtls_hmac_init(&ctx, state->K, sizeof(state->K));
            dtls_hmac_update(&ctx, state->V, sizeof(state->V));
            dtls_hmac_finalize(&ctx, state->V);
        }
    } while (!state->good_k);

    PT_END(&state->pt);
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

    state->sig_len = 0;

    uint8_t digest[SHA256_DIGEST_LEN_BYTES];
    uint8_t sha256_ret = sha256_hash(buffer, msg_len, digest);
    if (sha256_ret != CRYPTO_SUCCESS)
    {
        LOG_ERR("sha256_hash failed with %u\n", sha256_ret);
        state->ecc_sign_state.result = sha256_ret;
        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        PT_EXIT(&state->pt);
    }

    ec_uint8v_to_uint32v(digest, sizeof(digest), state->ecc_sign_state.hash);

    state->ecc_generate_k_state.process = state->process;
    state->ecc_sign_state.process = state->process;
    state->ecc_sign_state.curve_info = &nist_p_256;

    // Set secret key from our private key
    ec_uint8v_to_uint32v(our_key.priv_key, DTLS_EC_KEY_SIZE, state->ecc_sign_state.secret);

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecc_dsa_sign()...\n");
    state->time = RTIMER_NOW();
#endif

    pka_enable();

    PT_SPAWN(&state->pt, &state->ecc_generate_k_state.pt, ecc_generate_k(&state->ecc_generate_k_state, digest));
    if (!state->ecc_generate_k_state.good_k)
    {
        LOG_ERR("Failed to generate a good k with %u\n", state->ecc_generate_k_state.ecc_compare_state.result);
        state->ecc_sign_state.result = state->ecc_generate_k_state.ecc_compare_state.result;
        PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);
        pka_disable();
        PT_EXIT(&state->pt);
    }

    // Set k
    ec_uint8v_to_uint32v(state->ecc_generate_k_state.T, DTLS_EC_KEY_SIZE, state->ecc_sign_state.k_e);

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
        PT_EXIT(&state->pt);
    }

    ec_uint8v_to_uint32v(digest, sizeof(digest), state->ecc_verify_state.hash);

    state->ecc_verify_state.process = state->process;
    state->ecc_verify_state.curve_info = &nist_p_256;

    ec_uint8v_to_uint32v(pubkey->x, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.x);
    ec_uint8v_to_uint32v(pubkey->y, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.y);

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
QUEUE(messages_to_sign);
MEMB(messages_to_sign_memb, messages_to_sign_entry_t, MESSAGES_TO_SIGN_SIZE);
/*-------------------------------------------------------------------------------------------------------------------*/
QUEUE(messages_to_verify);
MEMB(messages_to_verify_memb, messages_to_verify_entry_t, MESSAGES_TO_VERIFY_SIZE);
/*-------------------------------------------------------------------------------------------------------------------*/
bool queue_message_to_sign(struct process* process, void* data,
                           uint8_t* message, uint16_t message_buffer_len, uint16_t message_len)
{
    messages_to_sign_entry_t* item = memb_alloc(&messages_to_sign_memb);
    if (!item)
    {
        LOG_WARN("queue_message_to_sign: out of memory\n");
        return false;
    }

    item->process = process;
    item->data = data;
    item->message = message;
    item->message_buffer_len = message_buffer_len;
    item->message_len = message_len;

    queue_enqueue(messages_to_sign, item);

    process_poll(&signer);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void queue_message_to_sign_done(messages_to_sign_entry_t* item)
{
    memb_free(&messages_to_sign_memb, item);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(signer, ev, data)
{
    PROCESS_BEGIN();

    queue_init(messages_to_sign);
    memb_init(&messages_to_sign_memb);

    while (1)
    {
        PROCESS_YIELD_UNTIL(!queue_is_empty(messages_to_sign));

        while (!queue_is_empty(messages_to_sign))
        {
            static messages_to_sign_entry_t* item;
            item = (messages_to_sign_entry_t*)queue_dequeue(messages_to_sign);

            static sign_state_t state;
            state.process = &signer;
            PROCESS_PT_SPAWN(&state.pt, ecc_sign(&state, item->message, item->message_buffer_len, item->message_len));

            item->result = state.ecc_sign_state.result;

            if (process_post(item->process, pe_message_signed, item) != PROCESS_ERR_OK)
            {
                LOG_ERR("Failed to post pe_message_signed to %s\n", item->process->name);
            }
        }

        // Other processes waiting on semaphore might have some tasks to do
        process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool queue_message_to_verify(struct process* process, void* data,
                             uint8_t* message, uint16_t message_len,
                             const ecdsa_secp256r1_pubkey_t* pubkey)
{
    messages_to_verify_entry_t* item = memb_alloc(&messages_to_verify_memb);
    if (!item)
    {
        LOG_WARN("queue_message_to_verify: out of memory\n");
        return false;
    }

    item->process = process;
    item->data = data;
    item->message = message;
    item->message_len = message_len;
    item->pubkey = pubkey;

    queue_enqueue(messages_to_verify, item);

    process_poll(&verifier);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void queue_message_to_verify_done(messages_to_verify_entry_t* item)
{
    memb_free(&messages_to_verify_memb, item);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(verifier, ev, data)
{
    PROCESS_BEGIN();

    queue_init(messages_to_verify);
    memb_init(&messages_to_verify_memb);

    while (1)
    {
        PROCESS_YIELD_UNTIL(!queue_is_empty(messages_to_verify));

        while (!queue_is_empty(messages_to_verify))
        {
            static messages_to_verify_entry_t* item;
            item = (messages_to_verify_entry_t*)queue_dequeue(messages_to_verify);

            static verify_state_t state;
            state.process = &verifier;
            PROCESS_PT_SPAWN(&state.pt, ecc_verify(&state, item->pubkey, item->message, item->message_len));

            item->result = state.ecc_verify_state.result;

            if (process_post(item->process, pe_message_verified, item) != PROCESS_ERR_OK)
            {
                LOG_ERR("Failed to post pe_message_verified to %s\n", item->process->name);
            }
        }

        // Other processes waiting on semaphore might have some tasks to do
        process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
#if 0
PT_THREAD(ecdh1(ecdh1_state_t* state))
{
    PT_BEGIN(&state->pt);

    LOG_DBG("Waiting for crypto processor to become available (echd1)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (echd1)!\n");

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecdh1()...\n");
    state->time = RTIMER_NOW();
#endif

    pka_enable();

    // Generate secrets make sure they are valid (smaller as order)
    state->ecc_compare_state.process = state->process;
    state->ecc_compare_state.size = nist_p_256.size;
    memcpy(state->ecc_compare_state.b, nist_p_256.n, DTLS_EC_KEY_SIZE);

    do {
        crypto_fill_random(state->secret, DTLS_EC_KEY_SIZE);
        memcpy(state->ecc_compare_state.a, state->secret, DTLS_EC_KEY_SIZE);

        PT_SPAWN(&state->pt, &state->ecc_compare_state.pt, ecc_compare(&state->ecc_compare_state));

    } while (state->ecc_compare_state.result != PKA_STATUS_A_LT_B);

    // Prepare Points
    state->ecc_multiply_state.process = state->process;
    state->ecc_multiply_state.curve_info = &nist_p_256;

    memcpy(state->ecc_multiply_state.point_in.x, nist_p_256.x, DTLS_EC_KEY_SIZE);
    memcpy(state->ecc_multiply_state.point_in.y, nist_p_256.y, DTLS_EC_KEY_SIZE);
    memcpy(state->ecc_multiply_state.secret, state->secret, DTLS_EC_KEY_SIZE);

    PT_SPAWN(&state->pt, &state->ecc_multiply_state.pt, ecc_multiply(&state->ecc_multiply_state));
    
    pka_disable();

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecdh1(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));
#endif

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

    PT_END(&state->pt);
}
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(ecdh2(ecdh2_state_t* state, const ecdsa_secp256r1_pubkey_t* other_pubkey))
{
    PT_BEGIN(&state->pt);

    LOG_DBG("Waiting for crypto processor to become available (echd2)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (echd2)!\n");

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    LOG_DBG("Starting ecdh2()...\n");
    state->time = RTIMER_NOW();
#endif

    // Prepare Points
    state->ecc_multiply_state.process = state->process;
    state->ecc_multiply_state.curve_info = &nist_p_256;

    // Set point to be the input public key
    ec_uint8v_to_uint32v(other_pubkey->x, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.point_in.x);
    ec_uint8v_to_uint32v(other_pubkey->y, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.point_in.y);

    // Use our privacy key as the secret
    ec_uint8v_to_uint32v(our_key.priv_key, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.secret);

    pka_enable();
    PT_SPAWN(&state->pt, &(state->ecc_multiply_state.pt), ecc_multiply(&state->ecc_multiply_state));
    pka_disable();

    if (state->ecc_multiply_state.result == PKA_STATUS_SUCCESS)
    {
        ec_uint32v_to_uint8v(state->ecc_multiply_state.point_out.x, DTLS_EC_KEY_SIZE, state->shared_secret);
    }

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecdh2(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));
#endif

    PT_SEM_SIGNAL(&state->pt, &crypto_processor_mutex);

    if (state->ecc_multiply_state.result != PKA_STATUS_SUCCESS)
    {
        LOG_ERR("ecdh2 failed with %d\n", state->ecc_multiply_state.result);
    }
    else
    {
        LOG_DBG("echd2 success!\n");
    }

    process_post(PROCESS_BROADCAST, pe_crypto_lock_released, NULL);

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
