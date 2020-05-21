#include "keystore.h"

#include "lib/memb.h"
#include "lib/list.h"
#include "os/sys/log.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-callback-api.h"

#include "crypto-support.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "keystore"
#ifdef KEYSTORE_LOG_LEVEL
#define LOG_LEVEL KEYSTORE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(keystore, "keystore");
/*-------------------------------------------------------------------------------------------------------------------*/
static process_event_t pe_verify_signature;
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(public_keys_memb, public_key_item_t, PUBLIC_KEYSTORE_SIZE);
LIST(public_keys);
/*-------------------------------------------------------------------------------------------------------------------*/
extern coap_endpoint_t server_ep;
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
            if (iter->age > found->age) // TODO: check for clock overflow
            {
                found = iter;
            }
        }
    } break;

    default:
        LOG_WARN("Unknown eviction policy %u\n", evict);
        return false;
    }

    LOG_DBG("Evicting ");
    uiplib_ipaddr_print(&found->addr);
    LOG_DBG_(" from the keystore.\n");

    list_remove(public_keys, found);
    memb_free(&public_keys_memb, found);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
uip_ip6addr_normalise(const uip_ip6addr_t* in, uip_ip6addr_t* out)
{
    uip_ipaddr_copy(out, in);

    // Check addr is a link-local (fe80::) address
    // and if so, normalise it to the global address (fd00::)
    if (uip_is_addr_linklocal(out))
    {
        out->u8[0] = 0xFD;
        out->u8[1] = 0x00;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t*
keystore_add(const uip_ip6addr_t* addr, const ecdsa_secp256r1_pubkey_t* pubkey, keystore_eviction_policy_t evict)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    public_key_item_t* item = keystore_find(&norm_addr);
    if (item)
    {
        return item;
    }

    item = memb_alloc(&public_keys_memb);
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

    uip_ipaddr_copy(&item->addr, &norm_addr);
    memcpy(&item->pubkey, pubkey, sizeof(ecdsa_secp256r1_pubkey_t));
    item->age = clock_time();

    return item;
}
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t*
keystore_find(const uip_ip6addr_t* addr)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    for (public_key_item_t* iter = list_head(public_keys); iter != NULL; iter = list_item_next(iter))
    {
        if (uip_ip6addr_cmp(&iter->addr, &norm_addr))
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
const ecdsa_secp256r1_pubkey_t* keystore_find_pubkey(const uip_ip6addr_t* addr)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    if (uip_ip6addr_cmp(&norm_addr, &server_ep.ipaddr))
    {
        return &root_key;
    }

    public_key_item_t* item = keystore_find(&norm_addr);
    if (!item)
    {
        return NULL;
    }

    return &item->pubkey;
}
/*-------------------------------------------------------------------------------------------------------------------*/
// 16 bytes for ipv6 address
// 2*32 for the public key
// 2*32 for the signature
static uint8_t req_resp[sizeof(uip_ip6addr_t) + DTLS_EC_KEY_SIZE*2 + DTLS_EC_KEY_SIZE*2];
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uip_ip6addr_t local_addr;
static bool in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
static void
request_public_key_callback(coap_callback_request_state_t* callback_state)
{
    //LOG_DBG("request_public_key_callback %d\n", in_use);
    /*if (!in_use)
    {
        return;
    }*/

    switch (callback_state->state.status)
    {
    case COAP_REQUEST_STATUS_RESPONSE:
    {
        coap_message_t* response = callback_state->state.response;

        LOG_DBG("Message req pk complete with code (%d) (len=%d)\n",
            response->code, response->payload_len);

        const uint8_t* payload = NULL;
        const int req_resp_len = coap_get_payload(response, &payload);

        if (req_resp_len == sizeof(req_resp))
        {
            memcpy(req_resp, payload, req_resp_len);
        }
        else
        {
            LOG_ERR("req_resp is too small for %d\n", req_resp_len);
            in_use = false;
        }
    } break;

    case COAP_REQUEST_STATUS_MORE:
    {
        LOG_ERR("Unhandled COAP_REQUEST_STATUS_MORE\n");
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        // Not truely finished yet here, need to wait for signature verification
        if (in_use)
        {
            process_post(&keystore, pe_verify_signature, req_resp);
        }
    } break;

    case COAP_REQUEST_STATUS_TIMEOUT:
    {
        LOG_ERR("Failed to send message due to timeout\n");
        in_use = false;
    } break;

    case COAP_REQUEST_STATUS_BLOCK_ERROR:
    {
        LOG_ERR("Failed to send message due to block error\n");
        in_use = false;
    } break;

    default:
    {
        LOG_ERR("Failed to send message with status %d\n", callback_state->state.status);
        in_use = false;
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool request_public_key(const uip_ip6addr_t* addr)
{
    if (in_use)
    {
        LOG_WARN("Already requesting a public key, cannot request another.\n");
        return false;
    }

    in_use = true;

    int ret;

    LOG_DBG("Generating public key request\n");

    coap_init_message(&msg, COAP_TYPE_CON, COAP_GET, 0);

    ret = coap_set_header_uri_path(&msg, "key");
    if (ret <= 0)
    {
        LOG_DBG("coap_set_header_uri_path failed %d\n", ret);
        return false;
    }

    uip_ipaddr_copy(&local_addr, addr);

    coap_set_payload(&msg, &local_addr.u8, sizeof(local_addr));

    ret = coap_send_request(&coap_callback, &server_ep, &msg, &request_public_key_callback);
    if (ret)
    {
        LOG_DBG("coap_send_request req pk done\n");
    }
    else
    {
        LOG_ERR("coap_send_request req pk failed %d\n", ret);
        in_use = false;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
keystore_init(void)
{
    memb_init(&public_keys_memb);
    list_init(public_keys);

    pe_verify_signature = process_alloc_event();

    in_use = false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(keystore, ev, data)
{
    PROCESS_BEGIN();

    keystore_init();

    LOG_DBG("Keystore process started, waiting for keys to verify and add...\n");

    while (1)
    {
        PROCESS_WAIT_EVENT();

        if (ev == pe_verify_signature)
        {
            // Parse contents of req_resp:
            // First 16 bytes are the IP Address
            // Next 64 bytes are the raw public key (x, y)
            // Next 64 bytes are the raw digital signature of the root server (r, s)
            LOG_DBG("Received public key for ");
            uiplib_ipaddr_print((const uip_ip6addr_t*)req_resp);
            LOG_DBG_(", verifying message...\n");

            static verify_state_t state;
            state.process = &keystore;
            PT_SPAWN(&keystore.pt, &state.pt, ecc_verify(&state, &root_key, req_resp, sizeof(req_resp)));

            if (state.ecc_verify_state.result == PKA_STATUS_SUCCESS)
            {
                const uip_ip6addr_t* addr = (const uip_ip6addr_t*)req_resp;
                const ecdsa_secp256r1_pubkey_t* pubkey = (const ecdsa_secp256r1_pubkey_t*)(req_resp + sizeof(uip_ip6addr_t));

                public_key_item_t* item = keystore_add(addr, pubkey, EVICT_OLDEST);
                if (item)
                {
                    LOG_DBG("Sucessfully added public key for ");
                    uiplib_ipaddr_print((const uip_ip6addr_t*)req_resp);
                    LOG_DBG_("\n");
                }
                else
                {
                    LOG_ERR("Failed to add public key for ");
                    uiplib_ipaddr_print((const uip_ip6addr_t*)req_resp);
                    LOG_ERR_("\n");
                }
            }

            in_use = false;
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
