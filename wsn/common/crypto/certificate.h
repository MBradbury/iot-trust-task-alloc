#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
// Implementation similar to https://www.sciencedirect.com/science/article/pii/S0167404819302019
// Assumes that the profile is restricted to secp256r1 (aka prime256v1)
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdbool.h>

#include "nanocbor/nanocbor.h"

#include "eui64.h"
#include "keys.h"
#include "stereotype-tags.h"

#include "uip.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define TBS_CERTIFICATE_CBOR_LENGTH ( \
        (1) + \
            (1 + sizeof(uint32_t)) + \
            (1 + EUI64_LENGTH) + \
            (1 + (1 + sizeof(uint32_t)) + (1 + sizeof(uint32_t))) + \
            (1 + EUI64_LENGTH) + \
            STEREOTYPE_TAGS_CBOR_MAX_LEN + \
            (1 + 1 + DTLS_EC_KEY_SIZE*2) \
    )

#define CERTIFICATE_CBOR_LENGTH ( \
        (1) + \
            TBS_CERTIFICATE_CBOR_LENGTH + \
            (1 + 1 + DTLS_EC_SIG_SIZE) \
    )
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct certificate {
    uint32_t serial_number;

    // EUI-64, so needs to be 8 bytes
    uint8_t issuer[EUI64_LENGTH];
    uint8_t subject[EUI64_LENGTH];

    // UnixTime
    uint32_t validity_not_before;
    uint32_t validity_not_after;

    stereotype_tags_t tags;

    ecdsa_secp256r1_pubkey_t public_key;
    ecdsa_secp256r1_sig_t signature;

} certificate_t;
/*-------------------------------------------------------------------------------------------------------------------*/
int certificate_encode(nanocbor_encoder_t* enc, const certificate_t* certificate);
int certificate_encode_tbs(nanocbor_encoder_t* enc, const certificate_t* certificate);
/*-------------------------------------------------------------------------------------------------------------------*/
int certificate_decode(nanocbor_value_t* dec, certificate_t* certificate);
/*-------------------------------------------------------------------------------------------------------------------*/
extern const certificate_t our_cert;
extern const certificate_t root_cert;
/*-------------------------------------------------------------------------------------------------------------------*/
