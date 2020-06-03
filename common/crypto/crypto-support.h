#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "keys.h"
#include "dev/ecc-algorithm.h"
#include "dev/ecc-curve.h"
#include "dev/sha256.h"

#include "rtimer.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef SHA256_DIGEST_LEN_BYTES
#define SHA256_DIGEST_LEN_BYTES (256 / 8)
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef MESSAGES_TO_SIGN_SIZE
#define MESSAGES_TO_SIGN_SIZE 5
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef MESSAGES_TO_VERIFY_SIZE
#define MESSAGES_TO_VERIFY_SIZE 5
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
void crypto_support_init(void);
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

    // The result of signing
    uint8_t result;

    const ecdsa_secp256r1_pubkey_t* pubkey;

    // User supplied data
    void* data;

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
#if 0
typedef struct {
    struct pt      pt;
    struct process *process;

    uint8_t secret[DTLS_EC_KEY_SIZE];

    ecc_compare_state_t ecc_compare_state;
    ecc_multiply_state_t ecc_multiply_state;

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;
#endif
} ecdh1_state_t;

PT_THREAD(ecdh1(ecdh1_state_t* state));
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    ecc_multiply_state_t ecc_multiply_state;

    uint8_t shared_secret[SHA256_DIGEST_LEN_BYTES];

#ifdef CRYPTO_SUPPORT_TIME_METRICS
    rtimer_clock_t time;
#endif
} ecdh2_state_t;

PT_THREAD(ecdh2(ecdh2_state_t* state, const ecdsa_secp256r1_pubkey_t* other_pubkey));
/*-------------------------------------------------------------------------------------------------------------------*/
