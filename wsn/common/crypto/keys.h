#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdint.h>
#include <limits.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define DTLS_EC_KEY_SIZE (256 / CHAR_BIT) // 256 bits
#define DTLS_EC_SIG_SIZE (DTLS_EC_KEY_SIZE * 2)
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_pubkey {
    uint8_t x[DTLS_EC_KEY_SIZE]; /** < x part of the public key for the given private key (big-endian) > */
    uint8_t y[DTLS_EC_KEY_SIZE]; /** < y part of the public key for the given private key (big-endian) > */ 
} ecdsa_secp256r1_pubkey_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_privkey {
    uint8_t k[DTLS_EC_KEY_SIZE]; /** < private key as bytes (big-endian) > */
} ecdsa_secp256r1_privkey_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct ecdsa_secp256r1_sig {
    uint8_t r[DTLS_EC_KEY_SIZE];
    uint8_t s[DTLS_EC_KEY_SIZE];
} ecdsa_secp256r1_sig_t;
/*-------------------------------------------------------------------------------------------------------------------*/
extern const ecdsa_secp256r1_privkey_t our_privkey;
/*-------------------------------------------------------------------------------------------------------------------*/
