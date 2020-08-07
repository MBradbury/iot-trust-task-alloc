#pragma once

#include <stdint.h>

// Inclusive and biased
uint16_t random_in_range(uint16_t min, uint16_t max);

// Inclusive and unbiased, but slower
uint16_t random_in_range_unbiased(uint16_t min, uint16_t max);
