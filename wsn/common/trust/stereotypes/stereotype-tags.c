#include "stereotype-tags.h"

#include "os/sys/log.h"

#include "device-classes.h"

#include "nanocbor-helper.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "stereotype"
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

    NANOCBOR_CHECK(nanocbor_get_uint8(&arr, &tags->device_class));
    if (tags->device_class < DEVICE_CLASS_MINIMUM || tags->device_class > DEVICE_CLASS_MAXIMUM)
    {
        LOG_ERR("Invalid device class %" PRIu8 "\n", tags->device_class);
        return -1;
    }

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_at_end\n");
        return -1;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool stereotype_tags_equal(const stereotype_tags_t* a, const stereotype_tags_t* b)
{
    return a->device_class == b->device_class;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void stereotype_tags_print(const stereotype_tags_t* tags)
{
    printf("StereotypeTags(device_class=%" PRIu8 ")", tags->device_class);
}
/*-------------------------------------------------------------------------------------------------------------------*/
