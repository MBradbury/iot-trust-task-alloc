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
public_key_item_t*
keystore_add(const uip_ip6addr_t* addr, const ecdsa_secp256r1_pubkey_t* pubkey, keystore_eviction_policy_t evict)
{
    // TODO: check addr is a global (fd00::) address

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
    // TODO: detect if using link-local (fe80::) addresses and convert to being global (fd00::) addresses

    for (public_key_item_t* iter = list_head(public_keys); iter != NULL; iter = list_item_next(iter))
    {
        if (uip_ip6addr_cmp(&iter->addr, addr))
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
const ecdsa_secp256r1_pubkey_t* keystore_find_pubkey(const uip_ip6addr_t* addr)
{
    // TODO: detect if using link-local (fe80::) addresses and convert to being global (fd00::) addresses

    uip_ip6addr_t root;
    if (uiplib_ipaddrconv(MQTT_CLIENT_CONF_BROKER_IP_ADDR, &root))
    {
        if (uip_ip6addr_cmp(addr, &root))
        {
            return &root_key;
        }
    }
    else
    {
        LOG_WARN("Failed to parse root IP address '" MQTT_CLIENT_CONF_BROKER_IP_ADDR "'\n");
    }

    public_key_item_t* item = keystore_find(addr);
    if (!item)
    {
        return NULL;
    }

    return &item->pubkey;
}
/*-------------------------------------------------------------------------------------------------------------------*/
extern coap_endpoint_t server_ep;

static uint8_t req_resp[16 + 64 + 64]; // 16 bytes for ipv6 address, 2*32 for the public key, 2*32 for the signature
static int req_resp_len;

static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uip_ip6addr_t local_addr;
static bool in_use;

static void
request_public_key_callback(coap_callback_request_state_t* callback_state)
{
    LOG_DBG("request_public_key_callback %d\n", in_use);

    if (!in_use)
    {
        return;
    }

    coap_message_t* response = callback_state->state.response;

    if (callback_state->state.status == COAP_REQUEST_STATUS_RESPONSE)
    {
        LOG_DBG("Message req pk complete with code (%d) (len=%d)\n",
            response->code, response->payload_len);

        const uint8_t* payload = NULL;
        req_resp_len = coap_get_payload(response, &payload);

        if (req_resp_len <= sizeof(req_resp))
        {
            memcpy(req_resp, payload, req_resp_len);

            process_post(&keystore, pe_verify_signature, req_resp);
        }
        else
        {
            LOG_ERR("req_resp is too small for %d\n", req_resp_len);
        }
    }
    else if (callback_state->state.status == COAP_REQUEST_STATUS_FINISHED)
    {
        // Not finished yet here, need to wait for signature verification
    }
    else
    {
        if (callback_state->state.status == COAP_REQUEST_STATUS_TIMEOUT)
        {
            LOG_ERR("Failed to send message with status %d (timeout)\n", callback_state->state.status);
        }
        else
        {
            LOG_ERR("Failed to send message with status %d\n", callback_state->state.status);
        }

        in_use = false;
    }
}

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
            PT_SPAWN(&keystore.pt, &state.pt, ecc_verify(&state, &root_key, req_resp, req_resp_len));

            if (state.ecc_verify_state.result == PKA_STATUS_SUCCESS)
            {
                public_key_item_t* item = keystore_add(
                    (const uip_ip6addr_t*)req_resp,
                    (const ecdsa_secp256r1_pubkey_t*)(req_resp+16),
                    EVICT_OLDEST);
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
                    LOG_ERR("\n");
                }
            }

            in_use = false;
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
