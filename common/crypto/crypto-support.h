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
void crypto_support_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
bool crypto_fill_random(uint8_t* buffer, size_t len);
/*-------------------------------------------------------------------------------------------------------------------*/
void dtls_ec_key_to_uint32(const uint8_t* key, size_t key_size, uint32_t* result);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    ecc_dsa_sign_state_t ecc_sign_state;

    uint16_t sig_len;

    rtimer_clock_t time;

} sign_trust_state_t;

PT_THREAD(sign_trust(sign_trust_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len));
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    ecc_dsa_verify_state_t ecc_verify_state;

    rtimer_clock_t time;

} verify_trust_state_t;

PT_THREAD(verify_trust(verify_trust_state_t* state, const uint8_t* buffer, size_t buffer_len));
/*-------------------------------------------------------------------------------------------------------------------*/
