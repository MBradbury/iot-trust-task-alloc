#include "keystore.h"

#include "lib/memb.h"
#include "lib/list.h"
#include "os/sys/log.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "keystore"
#ifdef KEYSTORE_LOG_LEVEL
#define LOG_LEVEL KEYSTORE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(public_keys_memb, public_key_item_t, PUBLIC_KEYSTORE_SIZE);
LIST(public_keys);
/*-------------------------------------------------------------------------------------------------------------------*/
void
keystore_init(void)
{
    memb_init(&public_keys_memb);
    list_init(public_keys);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
keystore_evict(keystore_eviction_policy_t evict)
{
    public_key_item_t* found = list_head(public_keys);
    if (!found)
    {
        return false;
    }

    switch (evict)
    {
    case EVICT_NONE:
        return false;

    case EVICT_OLDEST: {
        for (public_key_item_t* iter = list_item_next(found); iter != NULL; iter = list_item_next(iter))
        {
            if (iter->age > found->age)
            {
                found = iter;
            }
        }
    } break;

    default:
        LOG_WARN("Unknown eviction policy %u\n", evict);
        return false;
    }

    list_remove(public_keys, found);
    memb_free(&public_keys_memb, found);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t*
keystore_add(const uip_ip6addr_t* addr, const ecdsa_secp256r1_pubkey_t* pubkey, keystore_eviction_policy_t evict)
{
    public_key_item_t* item = memb_alloc(&public_keys_memb);
    if (!item)
    {
        if (keystore_evict(evict))
        {
            item = memb_alloc(&public_keys_memb);
            if (!item)
            {
                return NULL;
            }
        }
        else
        {
            return NULL;
        }
    }

    uip_ipaddr_copy(&item->addr, addr);
    memcpy(&item->pubkey, pubkey, sizeof(ecdsa_secp256r1_pubkey_t));
    item->age = clock_time();

    return item;
}
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t*
keystore_find(const uip_ip6addr_t* addr)
{
    for (public_key_item_t* iter = list_head(public_keys); iter != NULL; iter = list_item_next(iter))
    {
        if (uip_ip6addr_cmp(&iter->addr, addr) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
