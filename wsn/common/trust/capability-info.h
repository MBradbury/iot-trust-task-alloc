#pragma once

#include "contiki.h"
#include "net/ipv6/uip.h"
#include "lib/list.h"

#include <stdbool.h>

#include "trust-common.h"
#include "trust-model.h"
#include "stereotype-tags.h"
#include "edge-info.h"

#include "coap-endpoint.h"

// Provide empty capability struct when trust model does not provide one
#ifndef TRUST_MODEL_HAS_PER_CAPABILITY_INFO
typedef struct capability_tm
{
} capability_tm_t;

void capability_tm_init(capability_tm_t* cap_tm);
#endif

/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct capability
{
    struct capability *next;

    char name[EDGE_CAPABILITY_NAME_LEN + 1];

    capability_tm_t tm;

} capability_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void capability_info_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
capability_t* capability_info_add(const char* name);
bool capability_info_remove(capability_t* edge);
/*-------------------------------------------------------------------------------------------------------------------*/
capability_t* capability_info_find(const char* name);
/*-------------------------------------------------------------------------------------------------------------------*/
capability_t* capability_info_iter(void);
capability_t* capability_info_next(capability_t* iter);
/*-------------------------------------------------------------------------------------------------------------------*/
size_t capability_info_count(void);
/*-------------------------------------------------------------------------------------------------------------------*/


