#include "keystore.h"

#include "os/lib/assert.h"
#include "os/lib/memb.h"
#include "os/lib/list.h"
#include "os/sys/log.h"
#include "os/net/ipv6/uiplib.h"

#include "coap.h"
#include "coap-callback-api.h"

#include "crypto-support.h"
#include "keystore-oscore.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "keystore"
#ifdef KEYSTORE_LOG_LEVEL
#define LOG_LEVEL KEYSTORE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS(keystore_req, "keystore_req");
PROCESS(keystore_unver, "keystore_unver");
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
            // Do not evict pinned keys as they are in use
            if (keystore_is_pinned(iter))
            {
                continue;
            }

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

    // Do not evict the first item in the list if not other suitable items found
    if (keystore_is_pinned(found))
    {
        return false;
    }

    LOG_DBG("Evicting ");
    LOG_DBG_6ADDR(&found->addr);
    LOG_DBG_(" from the keystore.\n");

#ifdef WITH_OSCORE
    oscore_free_ctx(&found->context);
#endif

    list_remove(public_keys, found);

    memset(found, 0, sizeof(*found));

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
    item->pin_count = 0;

    list_push(public_keys, item);

    return item;
}
/*-------------------------------------------------------------------------------------------------------------------*/
// 2*32 for the public key
// 2*32 for the signature
static uint8_t add_unverified_buffer[DTLS_EC_KEY_SIZE*2 + DTLS_EC_KEY_SIZE*2];
static bool add_unverified_buffer_in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t*
keystore_add_unverified(const uip_ip6addr_t* addr, const ecdsa_secp256r1_pubkey_t* pubkey, const ecdsa_secp256r1_sig_t* sig)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    public_key_item_t* item = keystore_find(&norm_addr);
    if (item)
    {
        return item;
    }

    if (add_unverified_buffer_in_use)
    {
        LOG_WARN("keystore_add_unverified: buffer in use\n");
        return NULL;
    }

    item = memb_alloc(&public_keys_memb);
    if (!item)
    {
        LOG_ERR("keystore_add_unverified: out of memory\n");
        return NULL;
    }

    LOG_DBG("Queuing unverified key for ");
    LOG_DBG_6ADDR(addr);
    LOG_DBG_(" to be verified\n");

    uip_ipaddr_copy(&item->addr, &norm_addr);
    memcpy(&item->pubkey, pubkey, sizeof(ecdsa_secp256r1_pubkey_t));
    item->age = clock_time();
    item->pin_count = 0;

    memcpy(add_unverified_buffer + DTLS_EC_KEY_SIZE*0, pubkey, DTLS_EC_KEY_SIZE*2);
    memcpy(add_unverified_buffer + DTLS_EC_KEY_SIZE*2, sig,    DTLS_EC_KEY_SIZE*2);

    if (!queue_message_to_verify(&keystore_unver, item, add_unverified_buffer, sizeof(add_unverified_buffer), &root_key))
    {
        LOG_ERR("keystore_add_unverified: enqueue failed\n");
        memb_free(&public_keys_memb, item);
        return NULL;
    }

    add_unverified_buffer_in_use = true;

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
void keystore_pin(public_key_item_t* item)
{
    item->pin_count += 1;

    LOG_DBG("Key ");
    LOG_DBG_6ADDR(&item->addr);
    LOG_DBG_(" pin count=%u (+)\n", item->pin_count);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_unpin(public_key_item_t* item)
{
    assert(item->pin_count > 0);

    item->pin_count -= 1;

    LOG_DBG("Key ");
    LOG_DBG_6ADDR(&item->addr);
    LOG_DBG_(" pin count=%u (-)\n", item->pin_count);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool keystore_is_pinned(const public_key_item_t* item)
{
    return item->pin_count > 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
// 16 bytes for ipv6 address
// 2*32 for the public key
// 2*32 for the signature
static uint8_t req_resp[sizeof(uip_ip6addr_t) + DTLS_EC_KEY_SIZE*2 + DTLS_EC_KEY_SIZE*2];
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uint8_t key_req_payload[sizeof(uip_ip6addr_t) + DTLS_EC_KEY_SIZE*2];
static bool in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
static void request_public_key_callback(coap_callback_request_state_t* callback_state);
/*-------------------------------------------------------------------------------------------------------------------*/
bool request_public_key(const uip_ip6addr_t* addr)
{
    if (keystore_find(addr) != NULL)
    {
        //LOG_DBG("Already have this public key, do not need to request it.\n");
        return false;
    }

    if (in_use)
    {
        LOG_WARN("Already requesting a public key for ");
        LOG_WARN_6ADDR((const uip_ip6addr_t*)key_req_payload);
        LOG_WARN_(" cannot request another for ");
        LOG_WARN_6ADDR(addr);
        LOG_WARN_("\n");
        return false;
    }

    LOG_DBG("Generating public key request for ");
    LOG_DBG_6ADDR(addr);
    LOG_DBG_("\n");

    coap_init_message(&msg, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(&msg, "key");
    coap_set_header_content_format(&msg, APPLICATION_OCTET_STREAM);

    coap_set_random_token(&msg);

    memcpy(key_req_payload, addr, sizeof(*addr));

    if (!queue_message_to_sign(&keystore_req, NULL, key_req_payload, sizeof(key_req_payload), sizeof(*addr)))
    {
        LOG_ERR("request_public_key: Unable to sign message\n");
        return false;
    }

    in_use = true;

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void request_public_key_continued(void* data)
{
    messages_to_sign_entry_t* entry = (messages_to_sign_entry_t*)data;

    // If the message was signed successfully, then we need to inform coap
    // of the extra data that needsa to be sent.
    if (entry->result == PKA_STATUS_SUCCESS)
    {
        int payload_len = entry->message_len + DTLS_EC_KEY_SIZE*2;
        int coap_payload_len = coap_set_payload(&msg, key_req_payload, payload_len);
        if (coap_payload_len < payload_len)
        {
            LOG_WARN("Messaged length truncated to = %d\n", coap_payload_len);
            in_use = false;
        }
        else
        {
            int ret = coap_send_request(&coap_callback, &server_ep, &msg, &request_public_key_callback);
            if (ret)
            {
                LOG_DBG("coap_send_request req pk done\n");
            }
            else
            {
                LOG_ERR("coap_send_request req pk failed %d\n", ret);
                in_use = false;
            }
        }
    }
    else
    {
        LOG_ERR("Sign of pk req failed %d\n", entry->result);
        in_use = false;
    }

    queue_message_to_sign_done(entry);
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
request_public_key_callback(coap_callback_request_state_t* callback_state)
{
    switch (callback_state->state.status)
    {
    case COAP_REQUEST_STATUS_RESPONSE:
    {
        coap_message_t* response = callback_state->state.response;

        LOG_INFO("Message req pk complete with code (%d) (len=%d)\n",
            response->code, response->payload_len);

        const uint8_t* payload = NULL;
        const int req_resp_len = coap_get_payload(response, &payload);

        if (response->code != CONTENT_2_05)
        {
            LOG_ERR("Failed to request public key from key server '%.*s' (%d)\n",
                req_resp_len, (const char*)payload, response->code);
            in_use = false;
        }
        else
        {
            if (req_resp_len == sizeof(req_resp))
            {
                memcpy(req_resp, payload, req_resp_len);
            }
            else
            {
                LOG_ERR("req_resp is not the expected length %d != %d\n", req_resp_len, sizeof(req_resp));
                in_use = false;
            }
        }
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        // Not truely finished yet here, need to wait for signature verification
        if (in_use)
        {
            LOG_DBG("Queuing public key request ");
            LOG_DBG_6ADDR((const uip_ip6addr_t*)req_resp);
            LOG_DBG_(" response to be verified\n");
            if (!queue_message_to_verify(&keystore_req, NULL, req_resp, sizeof(req_resp), &root_key))
            {
                LOG_ERR("request_public_key_callback: enqueue failed\n");
                in_use = false;
            }
        }
    } break;

    default:
    {
        LOG_ERR("Failed to send message due to %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        in_use = false;
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static public_key_item_t*
request_public_key_callback_continued(messages_to_verify_entry_t* entry)
{
    // Parse contents of req_resp:
    // First 16 bytes are the IP Address
    // Next 64 bytes are the raw public key (x, y)
    // Next 64 bytes are the raw digital signature of the root server (r, s)
    const uip_ip6addr_t* addr = (const uip_ip6addr_t*)entry->message;
    const ecdsa_secp256r1_pubkey_t* pubkey = 
        (const ecdsa_secp256r1_pubkey_t*)(entry->message + sizeof(uip_ip6addr_t));

    public_key_item_t* item = NULL;

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        item = keystore_add(addr, pubkey, EVICT_OLDEST);
        if (item)
        {
            LOG_INFO("Sucessfully added public key for ");
            LOG_DBG_6ADDR(addr);
            LOG_INFO_(" [new]\n");
        }
        else
        {
            LOG_ERR("Failed to add public key for ");
            LOG_ERR_6ADDR(addr);
            LOG_ERR_(" (out of memory) [new]\n");
        }
    }
    else
    {
        LOG_ERR("Failed to add public key for ");
        LOG_ERR_6ADDR(addr);
        LOG_ERR_(" (sig verification failed) [new]\n");
    }

    queue_message_to_verify_done(entry);

    in_use = false;

    return item;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static public_key_item_t*
keystore_add_unverified_continued(messages_to_verify_entry_t* entry)
{
    public_key_item_t* item = (public_key_item_t*)entry->data;

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        LOG_INFO("Sucessfully verfied public key for ");
        LOG_INFO_6ADDR(&item->addr);
        LOG_INFO_(" [unver]\n");

        list_push(public_keys, item);
    }
    else
    {
        LOG_ERR("Failed to verfiy public key for ");
        LOG_ERR_6ADDR(&item->addr);
        LOG_ERR_(" (sig verification failed) [unver]\n");

        memb_free(&public_keys_memb, item);

        item = NULL;
    }

    queue_message_to_verify_done(entry);

    add_unverified_buffer_in_use = false;

    return item;
}
/*-------------------------------------------------------------------------------------------------------------------*/
#define OSCORE_ID_LEN 6
/*-------------------------------------------------------------------------------------------------------------------*/
static void
generate_shared_secret(public_key_item_t* item, uint8_t* shared_secret)
{
    LOG_INFO("Generated shared secret with ");
    LOG_INFO_6ADDR(&item->addr);
    LOG_INFO_(" value=");
    LOG_INFO_BYTES(shared_secret, DTLS_EC_KEY_SIZE);
    LOG_INFO_("\n");

    // Set the shared secret
    memcpy(item->shared_secret, shared_secret, DTLS_EC_KEY_SIZE);

#ifdef WITH_OSCORE
    // Take the lower OSCORE_ID_LEN bytes as the ids
    const uint8_t* sender_id = &linkaddr_node_addr.u8[LINKADDR_SIZE - OSCORE_ID_LEN];
    const uint8_t* receiver_id = &item->addr.u8[16 - OSCORE_ID_LEN];

    oscore_derive_ctx(&item->context,
        shared_secret, DTLS_EC_KEY_SIZE,
        NULL, 0, //master_salt, sizeof(master_salt), // optional master salt
        COSE_Algorithm_AES_CCM_16_64_128,
        sender_id, OSCORE_ID_LEN, // Sender ID
        receiver_id, OSCORE_ID_LEN, // Receiver ID
        NULL, 0, // optional ID context
        OSCORE_DEFAULT_REPLAY_WINDOW);

    LOG_DBG("Created oscore context with: ");
    LOG_DBG_("\n\tSender ID   : ");
    LOG_DBG_BYTES(sender_id, OSCORE_ID_LEN);
    LOG_DBG_("\n\tSender Key  : ");
    LOG_DBG_BYTES(item->context.sender_context.sender_key, CONTEXT_KEY_LEN);
    LOG_DBG_("\n\tReceiver ID : ");
    LOG_DBG_BYTES(receiver_id, OSCORE_ID_LEN);
    LOG_DBG_("\n\tReceiver Key: ");
    LOG_DBG_BYTES(item->context.recipient_context.recipient_key, CONTEXT_KEY_LEN);
    LOG_DBG_("\n");
#endif
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
keystore_init(void)
{
    crypto_support_init();

    memb_init(&public_keys_memb);
    list_init(public_keys);

    in_use = false;
    add_unverified_buffer_in_use = false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(keystore_req, ev, data)
{
    // This process processes events for keys that were requested

    PROCESS_BEGIN();

#ifdef BUILD_NUMBER
    LOG_INFO("BUILD NUMBER = %u\n", BUILD_NUMBER);
#endif

    keystore_init();

    while (1)
    {
        PROCESS_WAIT_EVENT();

        // Sign key request
        if (ev == pe_message_signed)
        {
            request_public_key_continued(data);
        }

        // Verify key response
        if (ev == pe_message_verified)
        {
            static public_key_item_t* item;
            messages_to_verify_entry_t* entry = (messages_to_verify_entry_t*)data;
            assert(entry->data == NULL);
            //LOG_INFO("Processing pe_message_verified for request_public_key_callback_continued\n");
            item = request_public_key_callback_continued(entry);

            if (item)
            {
                keystore_pin(item);

                static ecdh2_state_t state;
                state.process = &keystore_req;
                PROCESS_PT_SPAWN(&state.pt, ecdh2(&state, &item->pubkey));

                if (state.ecc_multiply_state.result == PKA_STATUS_SUCCESS)
                {
                    generate_shared_secret(item, state.shared_secret);
                }
                else
                {
                    LOG_ERR("Failed to generate shared secret with error %d\n",
                        state.ecc_multiply_state.result);
                }

                keystore_unpin(item);
            }
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(keystore_unver, ev, data)
{
    // This process processes events for keys that were unsolicitied
    PROCESS_BEGIN();

    while (1)
    {
        PROCESS_WAIT_EVENT();

        // Verify key response
        if (ev == pe_message_verified)
        {
            static public_key_item_t* item;
            messages_to_verify_entry_t* entry = (messages_to_verify_entry_t*)data;
            assert(entry->data != NULL);
            //LOG_INFO("Processing pe_message_verified for keystore_add_unverified_continued\n");
            item = keystore_add_unverified_continued(entry);

            if (item)
            {
                keystore_pin(item);

                static ecdh2_state_t state;
                state.process = &keystore_unver;
                PROCESS_PT_SPAWN(&state.pt, ecdh2(&state, &item->pubkey));

                if (state.ecc_multiply_state.result == PKA_STATUS_SUCCESS)
                {
                    generate_shared_secret(item, state.shared_secret);
                }
                else
                {
                    LOG_ERR("Failed to generate shared secret with error %d\n",
                        state.ecc_multiply_state.result);
                }

                keystore_unpin(item);
            }
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef WITH_OSCORE
void oscore_missing_security_context(const coap_endpoint_t *src)
{
    LOG_DBG("Missing OSCORE security context, requesting public key...\n");
    // If the OSCORE security context was missing, we
    // need to request the public key of the sender in order to
    // process their further messages.
    request_public_key(&src->ipaddr);
}
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
