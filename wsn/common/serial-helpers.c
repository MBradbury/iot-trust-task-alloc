#include "serial-helpers.h"
#include <string.h>
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "serial-help"
#define LOG_LEVEL LOG_LEVEL_ERR
/*-------------------------------------------------------------------------------------------------------------------*/
bool
match_action(const char* data, const char* data_end, const char* action)
{
    size_t action_len = strlen(action);
    return data_end - data >= action_len &&
           strncmp(action, data, action_len) == 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
// From: https://stackoverflow.com/questions/18267803/how-to-correctly-convert-a-hex-string-to-byte-array-in-c
static uint8_t hex2char(char c)
{
    if ('0' <= c && c <= '9') return (uint8_t)(c - '0');
    if ('A' <= c && c <= 'F') return (uint8_t)(c - 'A' + 10);
    if ('a' <= c && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return 0xFF;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int hex2bytes(const char* data, const char* data_end, uint8_t* buffer, size_t buffer_len)
{
    if ((data_end - data) % 2 != 0)
    {
        LOG_ERR("hex2bytes: data length is not even (len=%d)\n", data_end - data);
        return 0;
    }

    if (buffer_len == 0)
    {
        LOG_ERR("hex2bytes: buffer_len == 0\n");
        return 0;
    }

    size_t written = 0;

    while (data != data_end)
    {
        if (buffer_len == 0)
        {
            return 0;
        }

        uint8_t msn = hex2char(*data++);
        if (msn == 0xFF) return 0;
        uint8_t lsn = hex2char(*data++);
        if (lsn == 0xFF) return 0;
        uint8_t bin = (msn << 4) + lsn;

        *buffer++ = bin;
        buffer_len--;
        written++;
    }

    return written;
}
/*-------------------------------------------------------------------------------------------------------------------*/
