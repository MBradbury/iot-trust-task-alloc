#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
/*-------------------------------------------------------------------------------------------------------------------*/
bool match_action(const char* data, const char* data_end, const char* action);
/*-------------------------------------------------------------------------------------------------------------------*/
int hex2bytes(const char* data, const char* data_end, uint8_t* buffer, size_t buffer_len);
/*-------------------------------------------------------------------------------------------------------------------*/
