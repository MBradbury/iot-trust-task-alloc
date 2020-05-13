#include "crypto-support.h"

#include "random.h"
/*-------------------------------------------------------------------------------------------------------------------*/
bool
crypto_fill_random(uint8_t* buffer, size_t len)
{
    if (buffer == NULL)
    {
        return false;
    }

    for (int i = 0; i < len; ++i)
    {
        buffer[i] = random_rand() & 0xff;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static inline uint32_t dtls_uint32_to_int(const unsigned char *field)
{
  return ((uint32_t)field[0] << 24)
       | ((uint32_t)field[1] << 16)
       | ((uint32_t)field[2] << 8 )
       | ((uint32_t)field[3]      );
}
/*-------------------------------------------------------------------------------------------------------------------*/
void dtls_ec_key_to_uint32(const uint8_t* key, size_t key_size, uint32_t* result) {
  int i;

  for (i = (key_size / sizeof(uint32_t)) - 1; i >= 0 ; i--) {
    *result = dtls_uint32_to_int(&key[i * sizeof(uint32_t)]);
    result++;
  }
}
/*-------------------------------------------------------------------------------------------------------------------*/