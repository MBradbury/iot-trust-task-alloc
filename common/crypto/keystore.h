#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include "clock.h"
#include "net/ipv6/uip.h"

#include "keys.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define PUBLIC_KEYSTORE_SIZE 16
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct public_key_item {
    struct public_key_item *next;

    uip_ip6addr_t addr;
    ecdsa_secp256r1_pubkey_t pubkey;
    uint8_t shared_secret[32];
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
                                const ecdsa_secp256r1_pubkey_t* pubkey,
                                keystore_eviction_policy_t evict);
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t* keystore_find(const uip_ip6addr_t* addr);
const ecdsa_secp256r1_pubkey_t* keystore_find_pubkey(const uip_ip6addr_t* addr);
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_pin(public_key_item_t* item);
void keystore_unpin(public_key_item_t* item);
bool keystore_is_pinned(const public_key_item_t* item);
/*-------------------------------------------------------------------------------------------------------------------*/
bool request_public_key(const uip_ip6addr_t* addr);
/*-------------------------------------------------------------------------------------------------------------------*/
