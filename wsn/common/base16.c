#include "base16.h"
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
ssize_t base16_decode(const char* source, uint8_t* buff, ssize_t length)
{
    ssize_t result = 0;
    if (!source || !buff || length <= 0) return -2;

    while (*source)
    {
        int nib1 = hex_char(*source++);
        if (nib1 < 0) return -3;
        int nib2 = hex_char(*source++);
        if (nib2 < 0) return -4;

        uint8_t bin = ((0xF & (uint8_t)nib1) << 4) | (0xF & (uint8_t)nib2);

        if (length-- <= 0) return -5;
        *buff++ = bin;
        ++result;
    }
    return result;
}
/*-------------------------------------------------------------------------------------------------------------------*/
