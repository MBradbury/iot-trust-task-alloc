#include "applications.h"
#include "keystore.h"

#include "os/sys/log.h"
#include "os/lib/assert.h"

#include "nanocbor-helper.h"

#ifdef WITH_OSCORE
#include "oscore.h"
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "apps"
#ifdef APP_MONITORING_LOG_LEVEL
#define LOG_LEVEL APP_MONITORING_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
struct process* find_process_with_name(const char* name)
{
	for (struct process* iter = PROCESS_LIST(); iter != NULL; iter = iter->next)
	{
		if (strcmp(iter->name, name) == 0)
		{
			return iter;
		}
	}

	return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
struct process* find_process_for_capability(const edge_capability_t* cap)
{
    return find_process_with_name(cap->name);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void post_to_capability_process(const edge_capability_t* cap, process_event_t pe, void* data)
{
    struct process* proc = find_process_for_capability(cap);
    if (proc != NULL)
    {
        // Need to call process_post_synch instead of process_post, as we cannot be sure that
        // data will still be alive by the time the asynchronus post is called
        process_post_synch(proc, pe, data);
    }
    else
    {
        LOG_INFO("Failed to find a process running the application (%s)\n", cap->name);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_add_common(edge_resource_t* edge)
{
    // pin keys for this edge node
    public_key_item_t* key = keystore_find_addr(&edge->ep.ipaddr);

    if (key)
    {
        /*LOG_DBG("Pinning ");
        LOG_DBG_6ADDR(&edge->ep.ipaddr);
        LOG_DBG_("'s keys\n");

        keystore_pin(key);*/
    }
    else
    {
        LOG_WARN("Cannot create pin ");
        LOG_DBG_6ADDR(&edge->ep.ipaddr);
        LOG_DBG_("'s keys. Requesting public key...\n");
        // Ideally this point has been reached after:
        // 1. The client has received an announce from the edge that contained its certificate
        // 2. The client received an announce and requested a public key from the PKI
        // If we have got here and still don't have a public key, then we need to try requesting it now:
        request_public_key(&edge->ep.ipaddr);

        // TODO: When receiving this public key, we need to pin it and possibly do OSCORE things
        // to it, based on the code in the other branch
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_remove_common(edge_resource_t* edge)
{
    /*LOG_DBG("Removing context and unpinning ");
    LOG_DBG_6ADDR(&edge->ep.ipaddr);
    LOG_DBG_("'s keys\n");

    // unpin keys for this edge node
    public_key_item_t* key = keystore_find_addr(&edge->ep.ipaddr);

    // The key should never be NULL here
    assert(key != NULL);

    keystore_unpin(key);*/
}
/*-------------------------------------------------------------------------------------------------------------------*/
void application_stats_init(application_stats_t* application_stats)
{
    application_stats->mean = 0;
    application_stats->minimum = 0;
    application_stats->maximum = 0;
    application_stats->variance = 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int application_stats_serialise(const application_stats_t* application_stats, uint8_t* buffer, size_t len)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buffer, len);

    NANOCBOR_CHECK(nanocbor_fmt_array(&enc, 4));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, application_stats->mean));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, application_stats->maximum));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, application_stats->minimum));
    NANOCBOR_CHECK(nanocbor_fmt_uint(&enc, application_stats->variance));

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
int application_stats_nil_serialise(uint8_t* buffer, size_t len)
{
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, buffer, len);

    NANOCBOR_CHECK(nanocbor_fmt_null(&enc));

    return nanocbor_encoded_len(&enc);
}
/*-------------------------------------------------------------------------------------------------------------------*/
int application_stats_deserialise(nanocbor_value_t* dec, application_stats_t* application_stats)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &application_stats->mean));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &application_stats->maximum));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &application_stats->minimum));
    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &application_stats->variance));

    if (!nanocbor_at_end(&arr))
    {
        LOG_ERR("!nanocbor_at_end\n");
        return -1;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
