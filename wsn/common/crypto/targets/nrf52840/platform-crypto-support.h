#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "pt.h"

#include "nrf_crypto_ecdsa.h"
#include "nrf_crypto_ecdh.h"

#include "keys.h"
/*-------------------------------------------------------------------------------------------------------------------*/
void platform_crypto_support_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
bool platform_crypto_success(ret_code_t ret);
/*-------------------------------------------------------------------------------------------------------------------*/
bool crypto_fill_random(uint8_t* buffer, size_t size_in_bytes);
/*-------------------------------------------------------------------------------------------------------------------*/
uint8_t sha256_hash(const uint8_t* buffer, size_t len, uint8_t* hash);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt pt;
    struct process *process;

    nrf_crypto_ecdsa_sign_context_t ctx;
    ret_code_t result;

    uint8_t signature[NRF_CRYPTO_ECDSA_SECP256R1_SIGNATURE_SIZE];

} sign_state_t;

PT_THREAD(ecc_sign(sign_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len));

#define ECC_SIGN_GET_RESULT(state) state.result
#define ECC_SIGN_GET_PROCESS(state) state.process
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt pt;
    struct process *process;

    nrf_crypto_ecdsa_verify_context_t ctx;
    ret_code_t result;
} verify_state_t;

PT_THREAD(ecc_verify(verify_state_t* state, const ecdsa_secp256r1_pubkey_t* pubkey, const uint8_t* buffer, size_t buffer_len));

#define ECC_VERIFY_GET_RESULT(state) state.result
#define ECC_VERIFY_GET_PROCESS(state) state.process
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt pt;
    struct process *process;

    nrf_crypto_ecdh_context_t ctx;
    ret_code_t result;

    uint8_t shared_secret[DTLS_EC_KEY_SIZE];
} ecdh2_state_t;

PT_THREAD(ecdh2(ecdh2_state_t* state, const ecdsa_secp256r1_pubkey_t* other_pubkey));

#define ECDH_GET_RESULT(state) state.result
#define ECDH_GET_PROCESS(state) state.process
/*-------------------------------------------------------------------------------------------------------------------*/
#define CRYPTO_RESULT_SPEC "lx"
/*-------------------------------------------------------------------------------------------------------------------*/
