#include "applications.h"
#include "keystore.h"

#include "os/sys/log.h"
#include "os/lib/assert.h"

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
void edge_capability_add_common(edge_resource_t* edge, const char* uri)
{
    LOG_DBG("Creating context and pinning %s's keys\n", edge->name);

    // pin keys for this edge node
    public_key_item_t* key = keystore_find(&edge->ep.ipaddr);

    // TODO: set this up properly so the key cannot be NULL here
    // TODO: send public key in announce or attach at root server
    assert(key != NULL);

    keystore_pin(key);

#ifdef WITH_OSCORE
    oscore_ep_ctx_set_association(&edge->ep, uri, &key->context);
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_remove_common(edge_resource_t* edge, const char* uri)
{
    LOG_DBG("Removing context and unpinning %s's keys\n", edge->name);

#ifdef WITH_OSCORE
    oscore_remove_ep_ctx(&edge->ep, uri);
#endif

    // unpin keys for this edge node
    public_key_item_t* key = keystore_find(&edge->ep.ipaddr);

    // The key should never be NULL here
    assert(key != NULL);

    keystore_unpin(key);
}
/*-------------------------------------------------------------------------------------------------------------------*/
