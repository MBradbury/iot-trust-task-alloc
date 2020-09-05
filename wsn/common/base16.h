#pragma once

#include <stdint.h>
#include <sys/types.h>

ssize_t base16_decode(const char* source, uint8_t* buf, ssize_t length);
ssize_t base16_decode_length(const char* source, size_t source_len, uint8_t* buf, ssize_t length);
