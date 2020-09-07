#pragma once
/*-------------------------------------------------------------------------------------------------------------------*/
#include <stdbool.h>
#include "ctimer.h"
#include "process.h"
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    bool locked;
    const char* name;
    struct ctimer timer;
    clock_time_t duration;
    struct process* p;
} timed_unlock_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void timed_unlock_global_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
void timed_unlock_init(timed_unlock_t* l, const char* name, clock_time_t duration);
bool timed_unlock_is_locked(const timed_unlock_t* l);
void timed_unlock_lock(timed_unlock_t* l);
void timed_unlock_unlock(timed_unlock_t* l);
void timed_unlock_restart_timer(timed_unlock_t* l);
/*-------------------------------------------------------------------------------------------------------------------*/
extern process_event_t pe_timed_unlock_unlocked;
/*-------------------------------------------------------------------------------------------------------------------*/
