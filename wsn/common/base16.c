#include "base16.h"
#include <string.h>
// From: https://stackoverflow.com/questions/3408706/hexadecimal-string-to-byte-array-in-c
/*-------------------------------------------------------------------------------------------------------------------*/
static int hex_char(char c)
{
    if ('0' <= c && c <= '9') return (c - '0');
    if ('A' <= c && c <= 'F') return (c - 'A' + 10);
    if ('a' <= c && c <= 'f') return (c - 'a' + 10);
    return -1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
ssize_t base16_decode(const char* source, uint8_t* buf, ssize_t length)
{
    return base16_decode_length(source, strlen(source), buf, length);
}
/*-------------------------------------------------------------------------------------------------------------------*/
ssize_t base16_decode_length(const char* source, size_t source_len, uint8_t* buf, ssize_t length)
{
    ssize_t result = 0;
    if (!source || !buf || length <= 0) return -2;

    // Length needs to be a multiple of 2
    if ((source_len % 2) != 0) return -6;

    const char* const source_end = source + source_len;

    // Needs to be atleast 2 remaining characters
    while ((source_end - source) >= 2)
    {
        int nib1 = hex_char(*source++);
        if (nib1 < 0) return -3;
        int nib2 = hex_char(*source++);
        if (nib2 < 0) return -4;

        uint8_t bin = ((0xF & (uint8_t)nib1) << 4) | (0xF & (uint8_t)nib2);

        if (length-- <= 0) return -5;
        *buf++ = bin;
        ++result;
    }
    return result;
}
/*-------------------------------------------------------------------------------------------------------------------*/
