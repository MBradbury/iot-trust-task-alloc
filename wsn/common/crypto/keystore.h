#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include "clock.h"
#include "net/ipv6/uip.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#endif

#include "certificate.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef PUBLIC_KEYSTORE_SIZE
#define PUBLIC_KEYSTORE_SIZE 12
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct public_key_item {
    struct public_key_item *next;

    certificate_t cert;

    uint8_t shared_secret[DTLS_EC_KEY_SIZE];

#ifdef WITH_OSCORE
    oscore_ctx_t context;
#endif

    clock_time_t age;

    uint16_t pin_count;
} public_key_item_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef enum {
    EVICT_NONE = 0,
    EVICT_OLDEST = 1,
} keystore_eviction_policy_t;
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t* keystore_add(const uip_ip6addr_t* addr,
                                const certificate_t* cert,
                                keystore_eviction_policy_t evict);
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t* keystore_add_unverified(
                                const uip_ip6addr_t* addr,
                                const certificate_t* cert);
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t* keystore_find(const uint8_t* eui64);
public_key_item_t* keystore_find_addr(const uip_ip6addr_t* addr);
const ecdsa_secp256r1_pubkey_t* keystore_find_pubkey(const uip_ip6addr_t* addr);
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_pin(public_key_item_t* item);
void keystore_unpin(public_key_item_t* item);
bool keystore_is_pinned(const public_key_item_t* item);
/*-------------------------------------------------------------------------------------------------------------------*/
bool request_public_key(const uip_ip6addr_t* addr);
/*-------------------------------------------------------------------------------------------------------------------*/
