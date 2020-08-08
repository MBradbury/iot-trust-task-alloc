#include "timed-unlock.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "timed-lock"
#define LOG_LEVEL LOG_LEVEL_WARN
/*-------------------------------------------------------------------------------------------------------------------*/
static void timed_unlock_callack(void* data)
{
    timed_unlock_t* l = (timed_unlock_t*)data;

    timed_unlock_unlock(l);

    LOG_WARN("Unlocked %p[%s] after %lu ticks (%lu secs)\n", l, l->name, l->duration, l->duration / CLOCK_SECOND);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void timed_unlock_init(timed_unlock_t* l, const char* name, clock_time_t duration)
{
    l->locked = false;
    l->name = name;
    l->duration = duration;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool timed_unlock_is_locked(const timed_unlock_t* l)
{
    return l->locked;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void timed_unlock_lock(timed_unlock_t* l)
{
    l->locked = true;
    ctimer_set(&l->timer, l->duration, timed_unlock_callack, l);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void timed_unlock_unlock(timed_unlock_t* l)
{
    l->locked = false;
    ctimer_stop(&l->timer);
}
/*-------------------------------------------------------------------------------------------------------------------*/
