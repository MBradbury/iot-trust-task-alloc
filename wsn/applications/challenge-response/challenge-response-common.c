#include "challenge-response.h"

#include "nanocbor-helper.h"

#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "A-" CHALLENGE_RESPONSE_APPLICATION_NAME
#ifdef APP_CHALLENGE_RESPONSE_LOG_LEVEL
#define LOG_LEVEL APP_CHALLENGE_RESPONSE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_fmt_challenge(uint8_t* buf, size_t buf_len, const challenge_t* c)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buf, buf_len);

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 3));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, c->difficulty));
    NANOCBOR_CHECK(nanocbor_put_bstr(&enc, c->data, sizeof(c->data)));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, c->max_duration_secs));

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
int nanocbor_get_challenge_response(const uint8_t* buf, size_t buf_len, challenge_response_t* cr)
{
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, buf, buf_len);

    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&dec, &arr));

    const uint8_t* data;
    size_t len;
    NANOCBOR_CHECK(nanocbor_get_bstr(&arr, &data, &len));

    if (len > sizeof(cr->data_prefix))
    {
        return NANOCBOR_ERR_OVERFLOW;
    }

    cr->data_length = len;
    cr->data_prefix = data;

    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &cr->duration_secs));

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_at_end 1\n");
        return -1;
    }

    nanocbor_leave_container(&dec, &arr);

    if (!nanocbor_at_end(&dec))
    {
        LOG_ERR("!nanocbor_at_end 2\n");
        return -1;
    }

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
