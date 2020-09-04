#pragma once

#include <stdint.h>
#include <sys/types.h>

ssize_t base16_decode(const char* source, uint8_t* buff, ssize_t length);
