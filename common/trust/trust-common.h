#pragma once

#include <stdint.h>
#include <stddef.h>

#include "keys.h"
#include "dev/ecc-algorithm.h"
#include "dev/ecc-curve.h"
#include "dev/sha256.h"

#include "rtimer.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define MQTT_EDGE_NAMESPACE "iot/edge"
#define MQTT_EDGE_NAMESPACE_LEN 8

#define MQTT_IDENTITY_LEN 12

#define EDGE_CAPABILITY_NAME_LEN 15

#define MQTT_EDGE_ACTION_ANNOUNCE "announce"
#define MQTT_EDGE_ACTION_CAPABILITY "capability"
#define MQTT_EDGE_ACTION_CAPABILITY_ADD "add"
#define MQTT_EDGE_ACTION_CAPABILITY_REMOVE "remove"
/*-------------------------------------------------------------------------------------------------------------------*/
void trust_common_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust(void* trust_info, uint8_t* buffer, size_t buffer_len);
int deserialise_trust(void* trust_info, const uint8_t* buffer, size_t buffer_len);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    sha256_state_t sha256_state;

    ecc_dsa_sign_state_t ecc_sign_state;

    rtimer_clock_t time;

    uint16_t sig_len;

} sign_trust_state_t;

PT_THREAD(sign_trust(sign_trust_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len));
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    struct pt      pt;
    struct process *process;

    sha256_state_t sha256_state;

    ecc_dsa_verify_state_t ecc_verify_state;

    rtimer_clock_t time;

} verify_trust_state_t;

PT_THREAD(verify_trust(verify_trust_state_t* state, const uint8_t* buffer, size_t buffer_len));
/*-------------------------------------------------------------------------------------------------------------------*/
