#include "interaction-history.h"
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
/*-------------------------------------------------------------------------------------------------------------------*/
void interaction_history_init(interaction_history_t* hist)
{
    hist->head = hist->tail = 0;
    hist->count = 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void interaction_history_push(interaction_history_t* hist, uint8_t interaction)
{
    // If reachex maximum, then remove first element
    if (hist->count == INTERACTION_HISTORY_SIZE)
    {
        hist->head = (hist->head + 1) % INTERACTION_HISTORY_SIZE;
        hist->count -= 1;
    }

    hist->interactions[hist->tail] = interaction;

    hist->tail = (hist->tail + 1) % INTERACTION_HISTORY_SIZE;

    hist->count += 1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
const uint8_t* interaction_history_iter(const interaction_history_t* hist)
{
    if (hist->count == 0)
    {
        return NULL;
    }

    return &hist->interactions[hist->head];
}
/*-------------------------------------------------------------------------------------------------------------------*/
const uint8_t* interaction_history_next(const interaction_history_t* hist, const uint8_t* iter)
{
    ++iter;

    // Wrap around
    if (iter == hist->interactions + INTERACTION_HISTORY_SIZE)
    {
        iter = hist->interactions;
    }

    if (iter == hist->interactions + hist->tail)
    {
        return NULL;
    }
    else
    {
        return iter;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void interaction_history_print(const interaction_history_t* hist)
{
    printf("[");
    for (const uint8_t* iter = interaction_history_iter(hist); iter != NULL; iter = interaction_history_next(hist, iter))
    {
        printf("%" PRIu8 ", ", *iter);
    }
    printf("]");
}
/*-------------------------------------------------------------------------------------------------------------------*/
