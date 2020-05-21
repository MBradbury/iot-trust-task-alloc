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
