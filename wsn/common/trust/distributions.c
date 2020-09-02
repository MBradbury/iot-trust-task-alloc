#include "distributions.h"
#include <assert.h>
#include <stdio.h>
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-dist"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
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
    const float a = dist->alpha;
    const float b = dist->beta;

    return a / (a + b);
}
/*-------------------------------------------------------------------------------------------------------------------*/
float beta_dist_variance(const beta_dist_t* dist)
{
    const float a = dist->alpha;
    const float b = dist->beta;

    return (a * b) / (((a + b) * (a + b)) + (a + b + 1.0f));
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
void beta_dist_combine(const beta_dist_t* a, const beta_dist_t* b, beta_dist_t* out)
{
    if (b == NULL)
    {
        *out = *a;
    }
    else
    {
        // Minus 1 here to remove the initialisation to (1, 1)
        out->alpha = a->alpha - 1 + b->alpha;
        out->beta = a->beta - 1 + b->beta;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void beta_dist_print(const beta_dist_t* dist)
{
    printf("Beta(alpha=%"PRIu32",beta=%"PRIu32")", dist->alpha, dist->beta);
}
/*-------------------------------------------------------------------------------------------------------------------*/
int beta_dist_serialise(nanocbor_encoder_t* enc, const beta_dist_t* dist)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 2));
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, dist->alpha));
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, dist->beta));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int beta_dist_deserialise(nanocbor_value_t* dec, beta_dist_t* dist)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &dist->alpha));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &dist->beta));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
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
int gaussian_dist_serialise(nanocbor_encoder_t* enc, const gaussian_dist_t* dist)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 3));
    NANOCBOR_CHECK(nanocbor_fmt_float(enc, dist->mean));
    NANOCBOR_CHECK(nanocbor_fmt_float(enc, dist->variance));
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, dist->count));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int gaussian_dist_deserialise(nanocbor_value_t* dec, gaussian_dist_t* dist)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));
    NANOCBOR_CHECK(nanocbor_get_float(&arr, &dist->mean));
    NANOCBOR_CHECK(nanocbor_get_float(&arr, &dist->variance));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &dist->count));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
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
int poisson_dist_serialise(nanocbor_encoder_t* enc, const poisson_dist_t* dist)
{
    //NANOCBOR_CHECK(nanocbor_fmt_array(enc, 1));
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, dist->lambda));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int poisson_dist_deserialise(nanocbor_value_t* dec, poisson_dist_t* dist)
{
    //nanocbor_value_t arr;
    //NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));
    NANOCBOR_CHECK(nanocbor_get_uint32(dec, &dist->lambda)); //&arr

    /*if (!nanocbor_at_end(arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);*/

    return NANOCBOR_OK;
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
int poisson_observation_serialise(nanocbor_encoder_t* enc, const poisson_observation_t* dist)
{
    //NANOCBOR_CHECK(nanocbor_fmt_array(enc, 1));
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, dist->observations));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int poisson_observation_deserialise(nanocbor_value_t* dec, poisson_observation_t* dist)
{
    //nanocbor_value_t arr;
    //NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));
    NANOCBOR_CHECK(nanocbor_get_uint32(dec, &dist->observations)); // &arr

    /*if (!nanocbor_at_end(arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);*/

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
