#include "crypto-support.h"

#include "pt.h"
#include "pt-sem.h"
#include "os/sys/log.h"
#include "os/lib/assert.h"
#include "os/lib/queue.h"
#include "os/lib/memb.h"

#include "random.h"
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

    process_start(&signer, NULL);
    process_start(&verifier, NULL);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
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

    LOG_DBG("Waiting for crypto processor to become available (sign)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (sign)!\n");

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

    LOG_DBG("Waiting for crypto processor to become available (verify)...\n");
    PT_SEM_WAIT(&state->pt, &crypto_processor_mutex);
    LOG_DBG("Crypto processor available (verify)!\n");

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
QUEUE(messages_to_sign);
MEMB(messages_to_sign_memb, messages_to_sign_entry_t, MESSAGES_TO_SIGN_SIZE);
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
        PROCESS_YIELD();

        while (!queue_is_empty(messages_to_sign))
        {
            static messages_to_sign_entry_t* item;
            item = (messages_to_sign_entry_t*)queue_dequeue(messages_to_sign);

            static sign_state_t state;
            state.process = &signer;
            PT_SPAWN(&signer.pt, &state.pt, ecc_sign(&state, item->message, item->message_buffer_len, item->message_len));

            item->result = state.ecc_sign_state.result;

            if (process_post(item->process, pe_message_signed, item) != PROCESS_ERR_OK)
            {
                LOG_WARN("Failed to post pe_message_signed to %s\n", item->process->name);
            }
        }

        // Other queue might have some tasks to do
        process_poll(&verifier);
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
QUEUE(messages_to_verify);
MEMB(messages_to_verify_memb, messages_to_verify_entry_t, MESSAGES_TO_VERIFY_SIZE);
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
        PROCESS_YIELD();

        while (!queue_is_empty(messages_to_verify))
        {
            static messages_to_verify_entry_t* item;
            item = (messages_to_verify_entry_t*)queue_dequeue(messages_to_verify);

            static verify_state_t state;
            state.process = &verifier;
            PT_SPAWN(&verifier.pt, &state.pt, ecc_verify(&state, item->pubkey, item->message, item->message_len));

            item->result = state.ecc_verify_state.result;

            if (process_post(item->process, pe_message_verified, item) != PROCESS_ERR_OK)
            {
                LOG_WARN("Failed to post pe_message_verified to %s\n", item->process->name);
            }
        }

        // Other queue might have some tasks to do
        process_poll(&signer);
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

    pka_enable();

    // Prepare Points
    state->ecc_multiply_state.process = state->process;
    state->ecc_multiply_state.curve_info = &nist_p_256;

    ec_uint8v_to_uint32v(other_pubkey->x, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.point_in.x);
    ec_uint8v_to_uint32v(other_pubkey->y, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.point_in.y);

    ec_uint8v_to_uint32v(our_key.priv_key, DTLS_EC_KEY_SIZE, state->ecc_multiply_state.secret);

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

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
