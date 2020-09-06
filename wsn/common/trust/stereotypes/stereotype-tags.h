#pragma once

#include <stdint.h>

#include "nanocbor/nanocbor.h"

#include "device-classes.h"
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    uint8_t device_class;

} stereotype_tags_t;
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_stereotype_tags(nanocbor_encoder_t* enc, const stereotype_tags_t* tags);
int deserialise_stereotype_tags(nanocbor_value_t* dec, stereotype_tags_t* tags);
/*-------------------------------------------------------------------------------------------------------------------*/
#define STEREOTYPE_TAGS_CBOR_MAX_LEN ((1) + (1))
/*-------------------------------------------------------------------------------------------------------------------*/
bool stereotype_tags_equal(const stereotype_tags_t* a, const stereotype_tags_t* b);
/*-------------------------------------------------------------------------------------------------------------------*/
void stereotype_tags_print(const stereotype_tags_t* tags);
/*-------------------------------------------------------------------------------------------------------------------*/
