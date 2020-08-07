#include "random-helpers.h"

#include "os/lib/random.h"

// See: https://stackoverflow.com/questions/11758809/what-is-the-optimal-algorithm-for-generating-an-unbiased-random-integer-within-a

uint16_t random_in_range(uint16_t min, uint16_t max)
{
    return min + (random_rand() % (uint16_t)(max - min + 1));
}

uint16_t random_in_range_unbiased(uint16_t min, uint16_t max)
{
    const uint16_t n = max - min + 1;
    const uint16_t remainder = RANDOM_RAND_MAX % n;
    uint16_t x;
    do
    {
        x = random_rand();
    } while (x >= RANDOM_RAND_MAX - remainder);
    return min + x % n;
}
