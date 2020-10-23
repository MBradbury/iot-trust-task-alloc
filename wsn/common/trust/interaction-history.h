#pragma once
#include <stdint.h>
/*-------------------------------------------------------------------------------------------------------------------*/
#ifndef INTERACTION_HISTORY_SIZE
#define INTERACTION_HISTORY_SIZE 8
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct interaction_history
{
    // TODO: could consider better packing interactions (4 interactions per byte - 2 bits per interaction)
    uint8_t interactions[INTERACTION_HISTORY_SIZE];

    uint8_t head, tail;
    uint8_t count;

} interaction_history_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void interaction_history_init(interaction_history_t* hist);
/*-------------------------------------------------------------------------------------------------------------------*/
void interaction_history_push(interaction_history_t* hist, uint8_t interaction);
/*-------------------------------------------------------------------------------------------------------------------*/
const uint8_t* interaction_history_iter(const interaction_history_t* hist);
const uint8_t* interaction_history_next(const interaction_history_t* hist, const uint8_t* iter);
/*-------------------------------------------------------------------------------------------------------------------*/
void interaction_history_print(const interaction_history_t* hist);
/*-------------------------------------------------------------------------------------------------------------------*/
