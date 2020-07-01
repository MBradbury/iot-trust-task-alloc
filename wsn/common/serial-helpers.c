#include "serial-helpers.h"
#include <string.h>
/*-------------------------------------------------------------------------------------------------------------------*/
bool
match_action(const char* data, const char* data_end, const char* action)
{
    size_t action_len = strlen(action);
    return data_end - data >= action_len &&
           strncmp(action, data, action_len) == 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
