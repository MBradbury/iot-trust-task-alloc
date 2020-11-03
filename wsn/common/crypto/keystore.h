#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
//#include "clock.h"
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

#ifdef WITH_OSCORE
    oscore_ctx_t context;
#endif

    //clock_time_t age;

    uint16_t pin_count;
} public_key_item_t;
/*-------------------------------------------------------------------------------------------------------------------*/
bool keystore_add(const certificate_t* cert);
bool keystore_remove(public_key_item_t* item);
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t* keystore_find(const uint8_t* eui64);
public_key_item_t* keystore_find_addr(const uip_ip6addr_t* addr);
const ecdsa_secp256r1_pubkey_t* keystore_find_pubkey(const uip_ip6addr_t* addr);
/*-------------------------------------------------------------------------------------------------------------------*/
bool keystore_certificate_contains_tags(const stereotype_tags_t* tags);
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_pin(public_key_item_t* item);
void keystore_unpin(public_key_item_t* item);
bool keystore_is_pinned(const public_key_item_t* item);
/*-------------------------------------------------------------------------------------------------------------------*/
bool request_public_key(const uip_ip6addr_t* addr);
/*-------------------------------------------------------------------------------------------------------------------*/
