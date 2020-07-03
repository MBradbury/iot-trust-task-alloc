/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

// from: http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.h

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool base64_encode(const uint8_t* src, size_t len, char* out, size_t* out_len);
bool base64_decode(const char* source, size_t len, uint8_t* out, size_t* out_len);
