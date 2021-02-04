#include "crypto-support.h"

#include "pt.h"
#include "os/sys/log.h"
#include "os/lib/assert.h"
#include "os/lib/queue.h"
#include "os/lib/memb.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef MESSAGES_TO_SIGN_SIZE
#define MESSAGES_TO_SIGN_SIZE 3
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef MESSAGES_TO_VERIFY_SIZE
#define MESSAGES_TO_VERIFY_SIZE 3
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "crypto-sup"
#ifdef CRYPTO_SUPPORT_LOG_LEVEL
#define LOG_LEVEL CRYPTO_SUPPORT_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
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
    platform_crypto_support_init();

    pe_message_signed = process_alloc_event();
    pe_message_verified = process_alloc_event();

    LOG_DBG("pe_message_signed = %u\n", pe_message_signed);
    LOG_DBG("pe_message_verified = %u\n", pe_message_verified);

    process_start(&signer, NULL);
    process_start(&verifier, NULL);
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

        static messages_to_sign_entry_t* sitem;
        sitem = (messages_to_sign_entry_t*)queue_dequeue(messages_to_sign);

        static sign_state_t sign_state;
        sign_state.ecc_sign_state.process = &signer;
        PROCESS_PT_SPAWN(&sign_state.pt, ecc_sign(&sign_state, sitem->message, sitem->message_buffer_len, sitem->message_len));

        sitem->result = ECC_SIGN_GET_RESULT(sign_state);

        if (process_post(sitem->process, pe_message_signed, sitem) != PROCESS_ERR_OK)
        {
            LOG_ERR("Failed to post pe_message_signed to %s\n", sitem->process->name);
        }

        // We don't want to hog signing messages, so allow the verifier to possibly jump in here
        PROCESS_PAUSE();
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool queue_message_to_verify(struct process* process, void* data,
                             const uint8_t* message, uint16_t message_len,
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

        static messages_to_verify_entry_t* vitem;
        vitem = (messages_to_verify_entry_t*)queue_dequeue(messages_to_verify);

        static verify_state_t verify_state;
        verify_state.ecc_verify_state.process = &verifier;
        PROCESS_PT_SPAWN(&verify_state.pt, ecc_verify(&verify_state, vitem->pubkey, vitem->message, vitem->message_len));

        vitem->result = ECC_VERIFY_GET_RESULT(verify_state);

        if (process_post(vitem->process, pe_message_verified, vitem) != PROCESS_ERR_OK)
        {
            LOG_ERR("Failed to post pe_message_verified to %s\n", vitem->process->name);
        }

        // We don't want to hog verifying messages, so allow the signer to possibly jump in here
        PROCESS_PAUSE();
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
