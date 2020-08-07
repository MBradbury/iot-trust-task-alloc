#pragma once
#include <stdint.h>
#include <stddef.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#define CHALLENGE_RESPONSE_APPLICATION_NAME "cr"
#define CHALLENGE_RESPONSE_APPLICATION_URI "cr"
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    uint8_t data[32];
    uint8_t difficulty;
    uint32_t max_duration_secs;
} challenge_t;
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    const uint8_t* data_prefix;
    uint8_t data_length;
    uint32_t duration_secs;
} challenge_response_t;
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_fmt_challenge(uint8_t* buf, size_t buf_len, const challenge_t* c);
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_get_challenge_response(const uint8_t* buf, size_t buf_len, challenge_response_t* cr);
/*-------------------------------------------------------------------------------------------------------------------*/
