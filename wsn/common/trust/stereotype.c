#include "stereotype.h"

#include "os/sys/log.h"

#include "device-classes.h"

#include "nanocbor-helper.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-comm"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_stereotype_tags(nanocbor_encoder_t* enc, const stereotype_tags_t* tags)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 1));
    NANOCBOR_CHECK(nanocbor_fmt_uint(enc, tags->device_class));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_stereotype_tags(nanocbor_value_t* dec, stereotype_tags_t* tags)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    uint32_t device_class;
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &device_class));
    if (device_class < DEVICE_CLASS_MINIMUM || device_class > DEVICE_CLASS_MAXIMUM)
    {
        LOG_ERR("Invalid device class %" PRIu32 "\n", device_class);
        return -1;
    }
    tags->device_class = (uint8_t)device_class;

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_leave_container\n");
        return -1;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
