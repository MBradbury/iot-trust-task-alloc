#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdint.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define DTLS_EC_KEY_SIZE (8 * 4) // 32 bytes
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_pubkey {
    uint8_t x[DTLS_EC_KEY_SIZE]; /** < x part of the public key for the given private key > */
    uint8_t y[DTLS_EC_KEY_SIZE]; /** < y part of the public key for the given private key > */ 
} ecdsa_secp256r1_pubkey_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_key {
    uint8_t priv_key[DTLS_EC_KEY_SIZE]; /** < private key as bytes > */

    ecdsa_secp256r1_pubkey_t pub_key;
} ecdsa_secp256r1_key_t;
/*-------------------------------------------------------------------------------------------------------------------*/
extern const ecdsa_secp256r1_key_t our_key;
extern const ecdsa_secp256r1_pubkey_t root_key;
/*-------------------------------------------------------------------------------------------------------------------*/
