#pragma once

#include "nanocbor-helper.h"

#include <stdint.h>

/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct beta_dist {
    uint32_t alpha; // Number of 'good' events
    uint32_t beta;  // number of 'bad' events
} beta_dist_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_init(beta_dist_t* dist, uint32_t alpha, uint32_t beta);
void beta_dist_print(const beta_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/
float beta_dist_expected(const beta_dist_t* dist);
float beta_dist_variance(const beta_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_add_good(beta_dist_t* dist);
void beta_dist_add_bad(beta_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_combine(const beta_dist_t* a, const beta_dist_t* b, beta_dist_t* out);
/*-------------------------------------------------------------------------------------------------------------------*/
int beta_dist_serialise(nanocbor_encoder_t* enc, const beta_dist_t* dist);
int beta_dist_deserialise(nanocbor_value_t* dec, beta_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------------------------------------------------*/
// Used to record information about continious events
typedef struct gaussian_dist {
    float mean;
    float variance;

    // Need to keep a count of the number of values used to calculate the mean and variance.
    // This facilitates performing incremental updates without needing to store all previous values.
    uint32_t count;
} gaussian_dist_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void gaussian_dist_init(gaussian_dist_t* dist, float mean, float variance);
void gaussian_dist_print(const gaussian_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/
void gaussian_dist_update(gaussian_dist_t* dist, float value);
/*-------------------------------------------------------------------------------------------------------------------*/
int gaussian_dist_serialise(nanocbor_encoder_t* enc, const gaussian_dist_t* dist);
int gaussian_dist_deserialise(nanocbor_value_t* dec, gaussian_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/

/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct poisson_dist {
    uint32_t lambda; // The expected rate of occurances over some time period
} poisson_dist_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_dist_init(poisson_dist_t* dist, uint32_t lambda);
void poisson_dist_print(const poisson_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/
uint32_t poisson_dist_expected(const poisson_dist_t* dist);
uint32_t poisson_dist_variance(const poisson_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/
int poisson_dist_serialise(nanocbor_encoder_t* enc, const poisson_dist_t* dist);
int poisson_dist_deserialise(nanocbor_value_t* dec, poisson_dist_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct poisson_observation {
    uint32_t observations; // The number of occurances over some time period
} poisson_observation_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_observation_init(poisson_observation_t* obs);
void poisson_observation_print(const poisson_observation_t* obs);
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_observation_add(poisson_observation_t* obs);
void poisson_observation_reset(poisson_observation_t* obs);
/*-------------------------------------------------------------------------------------------------------------------*/
int poisson_observation_serialise(nanocbor_encoder_t* enc, const poisson_observation_t* dist);
int poisson_observation_deserialise(nanocbor_value_t* dec, poisson_observation_t* dist);
/*-------------------------------------------------------------------------------------------------------------------*/

#define dist_print(x) _Generic((x), \
    const beta_dist_t*:             beta_dist_print, \
    const gaussian_dist_t*:         gaussian_dist_print, \
    const poisson_dist_t*:          poisson_dist_print, \
    const poisson_observation_t*:   poisson_observation_print)(x)

#define dist_serialise(enc, x) _Generic((x), \
    const beta_dist_t*:             beta_dist_serialise, \
    const gaussian_dist_t*:         gaussian_dist_serialise, \
    const poisson_dist_t*:          poisson_dist_serialise, \
    const poisson_observation_t*:   poisson_observation_serialise)(enc, x)

#define dist_deserialise(dec, x) _Generic((x), \
    beta_dist_t*:             beta_dist_deserialise, \
    gaussian_dist_t*:         gaussian_dist_deserialise, \
    poisson_dist_t*:          poisson_dist_deserialise, \
    poisson_observation_t*:   poisson_observation_deserialise)(dec, x)
