#include "distributions.h"
#include <assert.h>
#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_init(beta_dist_t* dist, uint32_t alpha, uint32_t beta)
{
    assert(alpha > 0);
    assert(beta > 0);

    dist->alpha = alpha;
    dist->beta = beta;
}
/*-------------------------------------------------------------------------------------------------------------------*/
float beta_dist_expected(const beta_dist_t* dist)
{
    return (dist->alpha) / (dist->alpha + dist->beta);
}
/*-------------------------------------------------------------------------------------------------------------------*/
float beta_dist_variance(const beta_dist_t* dist)
{
    return (dist->alpha * dist->beta) /
           (((dist->alpha + dist->beta) * (dist->alpha + dist->beta)) + (dist->alpha + dist->beta + 1.0f));
}
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_add_good(beta_dist_t* dist)
{
    dist->alpha += 1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_add_bad(beta_dist_t* dist)
{
    dist->beta += 1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_print(const beta_dist_t* dist)
{
    printf("Beta(alpha=%"PRIu32",beta=%"PRIu32")", dist->alpha, dist->beta);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void gaussian_dist_init(gaussian_dist_t* dist, float mean, float variance)
{
    dist->mean = mean;
    dist->variance = variance;

    dist->count = 1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void gaussian_dist_update(gaussian_dist_t* dist, float value)
{
    const uint32_t new_count = dist->count + 1;

    const float new_mean = dist->mean + (value - dist->mean) / new_count;

    // https://math.stackexchange.com/questions/102978/incremental-computation-of-standard-deviation
    const float new_variance = (dist->variance * ((new_count - 2.0f) / (new_count - 1.0f))) +
                               ((value - dist->mean) * (value - dist->mean)) / new_count;


    dist->mean = new_mean;
    dist->variance = new_variance;

    dist->count = new_count;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void gaussian_dist_print(const gaussian_dist_t* dist)
{
    printf("N(mean=%f,var=%f,n=%"PRIu32")", dist->mean, dist->variance, dist->count);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_dist_init(poisson_dist_t* dist, uint32_t lambda)
{
    dist->lambda = lambda;
}
/*-------------------------------------------------------------------------------------------------------------------*/
uint32_t poisson_dist_expected(const poisson_dist_t* dist)
{
    return dist->lambda;
}
/*-------------------------------------------------------------------------------------------------------------------*/
uint32_t poisson_dist_variance(const poisson_dist_t* dist)
{
    return dist->lambda;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_dist_print(const poisson_dist_t* dist)
{
    printf("Poisson(lambda=%"PRIu32")", dist->lambda);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_observation_init(poisson_observation_t* obs)
{
    obs->observations = 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_observation_add(poisson_observation_t* obs)
{
    obs->observations += 1;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_observation_reset(poisson_observation_t* obs)
{
    obs->observations = 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void poisson_observation_print(const poisson_observation_t* obs)
{
    printf("PoissonObs(%"PRIu32")", obs->observations);
}
/*-------------------------------------------------------------------------------------------------------------------*/
