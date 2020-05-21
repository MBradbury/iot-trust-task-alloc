#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "keys.h"
#include "dev/ecc-algorithm.h"
#include "dev/ecc-curve.h"

#include "rtimer.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef MESSAGES_TO_SIGN_SIZE
#define MESSAGES_TO_SIGN_SIZE 10
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef MESSAGES_TO_VERIFY_SIZE
#define MESSAGES_TO_VERIFY_SIZE 10
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
void crypto_support_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

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
typedef struct messages_to_sign_entry
{
    struct messages_to_sign_entry* next;

    // The process to notify on end of sign
    struct process* process;

    uint8_t* message;
    uint16_t message_buffer_len;
    uint16_t message_len;

    // User supplied data
    void* data;

    // The result of signing
    uint8_t result;

} messages_to_sign_entry_t;
/*-------------------------------------------------------------------------------------------------------------------*/
bool queue_message_to_sign(struct process* process, void* data,
                           uint8_t* message, uint16_t message_buffer_len, uint16_t message_len);
void queue_message_to_sign_done(messages_to_sign_entry_t* item);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct messages_to_verify_entry
{
    struct messages_to_verify_entry* next;

    // The process to notify on end of sign
    struct process* process;

    const uint8_t* message;
    uint16_t message_len;

    const ecdsa_secp256r1_pubkey_t* pubkey;

    // User supplied data
    void* data;

    // The result of signing
    uint8_t result;

} messages_to_verify_entry_t;
/*-------------------------------------------------------------------------------------------------------------------*/
bool queue_message_to_verify(struct process* process, void* data,
                             uint8_t* message, uint16_t message_len,
                             const ecdsa_secp256r1_pubkey_t* pubkey);
void queue_message_to_verify_done(messages_to_verify_entry_t* item);
/*-------------------------------------------------------------------------------------------------------------------*/
extern process_event_t pe_message_signed;
extern process_event_t pe_message_verified;
/*-------------------------------------------------------------------------------------------------------------------*/
