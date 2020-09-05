#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "uip.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define EUI64_LENGTH 8
/*-------------------------------------------------------------------------------------------------------------------*/
const uint8_t* current_eui64(void);
/*-------------------------------------------------------------------------------------------------------------------*/
void eui64_from_ipaddr(const uip_ip6addr_t* ipaddr, uint8_t* eui64);
void eui64_to_ipaddr(const uint8_t* eui64, uip_ip6addr_t* ipaddr);
/*-------------------------------------------------------------------------------------------------------------------*/
bool eui64_from_str(const char* eui64_str, uint8_t* eui64);
bool eui64_from_strn(const char* eui64_str, size_t length, uint8_t* eui64);
int eui64_to_str(const uint8_t* eui64, char* eui64_str, size_t eui64_str_size);
/*-------------------------------------------------------------------------------------------------------------------*/
