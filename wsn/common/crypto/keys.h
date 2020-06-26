#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdint.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define DTLS_EC_KEY_SIZE (8 * 4) // 32 bytes
#define DTLS_EC_SIG_SIZE (DTLS_EC_KEY_SIZE * 2)
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_pubkey {
    uint8_t x[DTLS_EC_KEY_SIZE]; /** < x part of the public key for the given private key (big-endian) > */
    uint8_t y[DTLS_EC_KEY_SIZE]; /** < y part of the public key for the given private key (big-endian) > */ 
} ecdsa_secp256r1_pubkey_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_key {
    uint8_t priv_key[DTLS_EC_KEY_SIZE]; /** < private key as bytes (big-endian) > */

    ecdsa_secp256r1_pubkey_t pub_key;
} ecdsa_secp256r1_key_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_sig {
    uint8_t r[DTLS_EC_KEY_SIZE];
    uint8_t s[DTLS_EC_KEY_SIZE];
} ecdsa_secp256r1_sig_t;
/*-------------------------------------------------------------------------------------------------------------------*/
extern const ecdsa_secp256r1_key_t our_key;
extern const ecdsa_secp256r1_sig_t our_pubkey_sig;
extern const ecdsa_secp256r1_pubkey_t root_key;
/*-------------------------------------------------------------------------------------------------------------------*/
