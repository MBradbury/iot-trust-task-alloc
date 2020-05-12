#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdint.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define DTLS_EC_KEY_SIZE 32
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_pubkey {
    union {
        uint8_t u8[DTLS_EC_KEY_SIZE];
        uint32_t u32[DTLS_EC_KEY_SIZE / sizeof(uint32_t)];
    } x; /** < x part of the public key for the given private key > */

    union {
        uint8_t u8[DTLS_EC_KEY_SIZE];
        uint32_t u32[DTLS_EC_KEY_SIZE / sizeof(uint32_t)];
    } y; /** < y part of the public key for the given private key > */
} ecdsa_secp256r1_pubkey_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_key {
    union {
        uint8_t u8[DTLS_EC_KEY_SIZE];
        uint32_t u32[DTLS_EC_KEY_SIZE / sizeof(uint32_t)];
    } priv_key; /** < private key as bytes > */

  ecdsa_secp256r1_pubkey_t pub_key;
} ecdsa_secp256r1_key_t;
/*-------------------------------------------------------------------------------------------------------------------*/
extern const ecdsa_secp256r1_key_t our_key;
extern const ecdsa_secp256r1_pubkey_t root_key;
/*-------------------------------------------------------------------------------------------------------------------*/
