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
