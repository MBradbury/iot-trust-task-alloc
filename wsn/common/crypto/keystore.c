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
#include "timed-unlock.h"
#include "root-endpoint.h"

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
    LOG_DBG_BYTES(&found->cert.subject, EUI64_LENGTH);
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
keystore_add(const uip_ip6addr_t* addr, const certificate_t* cert, keystore_eviction_policy_t evict)
{
    public_key_item_t* item = keystore_find_addr(addr);
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

    item->cert = *cert;

    item->age = clock_time();
    item->pin_count = 0;

    list_push(public_keys, item);

    return item;
}
/*-------------------------------------------------------------------------------------------------------------------*/
// 2*32 for the public key
// 2*32 for the signature
static uint8_t add_unverified_buffer[CERTIFICATE_CBOR_LENGTH + DTLS_EC_SIG_SIZE];
static bool add_unverified_buffer_in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t*
keystore_add_unverified(const uip_ip6addr_t* addr, const certificate_t* cert)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    public_key_item_t* item = keystore_find_addr(&norm_addr);
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

    item->cert = *cert;

    item->age = clock_time();
    item->pin_count = 0;

    const size_t available_space = sizeof(add_unverified_buffer) - DTLS_EC_SIG_SIZE;

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, add_unverified_buffer, available_space);
    certificate_encode_tbs(&enc, cert);

    size_t encoded_length = nanocbor_encoded_len(&enc);

    if (encoded_length > available_space)
    {
        LOG_ERR("keystore_add_unverified: encode failed %zu > %zu\n", encoded_length, available_space);
        memb_free(&public_keys_memb, item);
        return NULL;
    }

    // Put the signature at the end
    memcpy(&add_unverified_buffer[encoded_length], &cert->signature, DTLS_EC_SIG_SIZE);

    if (!queue_message_to_verify(&keystore_unver, item,
                                 add_unverified_buffer, encoded_length + DTLS_EC_SIG_SIZE,
                                 &root_cert.public_key))
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
keystore_find(const uint8_t* eui64)
{
    for (public_key_item_t* iter = list_head(public_keys); iter != NULL; iter = list_item_next(iter))
    {
        if (memcmp(&iter->cert.subject, eui64, EUI64_LENGTH) == 0)
        {
            return iter;
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------------------*/
public_key_item_t*
keystore_find_addr(const uip_ip6addr_t* addr)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    uint8_t eui64[EUI64_LENGTH];
    eui64_from_ipaddr(&norm_addr, eui64);

    return keystore_find(eui64);
}
/*-------------------------------------------------------------------------------------------------------------------*/
const ecdsa_secp256r1_pubkey_t* keystore_find_pubkey(const uip_ip6addr_t* addr)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    if (uip_ip6addr_cmp(&norm_addr, &root_ep.ipaddr))
    {
        return &root_cert.public_key;
    }

    public_key_item_t* item = keystore_find_addr(&norm_addr);
    if (!item)
    {
        return NULL;
    }

    return &item->cert.public_key;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_pin(public_key_item_t* item)
{
    item->pin_count += 1;

    LOG_DBG("Key ");
    LOG_INFO_BYTES(&item->cert.subject, EUI64_LENGTH);
    LOG_DBG_(" pin count=%u (+)\n", item->pin_count);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_unpin(public_key_item_t* item)
{
    assert(item->pin_count > 0);

    item->pin_count -= 1;

    LOG_DBG("Key ");
    LOG_INFO_BYTES(&item->cert.subject, EUI64_LENGTH);
    LOG_DBG_(" pin count=%u (-)\n", item->pin_count);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool keystore_is_pinned(const public_key_item_t* item)
{
    return item->pin_count > 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static uint8_t req_resp[CERTIFICATE_CBOR_LENGTH + DTLS_EC_SIG_SIZE];
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uint8_t key_req_payload[sizeof(uip_ip6addr_t) + DTLS_EC_SIG_SIZE];
static timed_unlock_t in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
static void request_public_key_callback(coap_callback_request_state_t* callback_state);
/*-------------------------------------------------------------------------------------------------------------------*/
bool request_public_key(const uip_ip6addr_t* addr)
{
    if (keystore_find_addr(addr) != NULL)
    {
        //LOG_DBG("Already have this public key, do not need to request it.\n");
        return false;
    }

    if (timed_unlock_is_locked(&in_use))
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

    timed_unlock_lock(&in_use);

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
        int payload_len = entry->message_len + DTLS_EC_SIG_SIZE;
        int coap_payload_len = coap_set_payload(&msg, key_req_payload, payload_len);
        if (coap_payload_len < payload_len)
        {
            LOG_WARN("Messaged length truncated to = %d\n", coap_payload_len);
            timed_unlock_unlock(&in_use);
        }
        else
        {
            int ret = coap_send_request(&coap_callback, &root_ep, &msg, &request_public_key_callback);
            if (ret)
            {
                LOG_DBG("coap_send_request req pk done\n");
            }
            else
            {
                LOG_ERR("coap_send_request req pk failed %d\n", ret);
                timed_unlock_unlock(&in_use);
            }
        }
    }
    else
    {
        LOG_ERR("Sign of pk req failed %d\n", entry->result);
        timed_unlock_unlock(&in_use);
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
            timed_unlock_unlock(&in_use);
        }
        else
        {
            if (req_resp_len <= sizeof(req_resp))
            {
                memcpy(req_resp, payload, req_resp_len);

                LOG_DBG("Queuing public key request response to be verified\n");
                if (!queue_message_to_verify(&keystore_req, NULL, req_resp, req_resp_len, &root_cert.public_key))
                {
                    LOG_ERR("request_public_key_callback: enqueue failed\n");
                    timed_unlock_unlock(&in_use);
                }
            }
            else
            {
                LOG_ERR("req_resp is not the expected length %d > %d\n", req_resp_len, sizeof(req_resp));
                timed_unlock_unlock(&in_use);
            }
        }
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        // Not truely finished yet here, need to wait for signature verification
    } break;

    default:
    {
        LOG_ERR("Failed to send message due to %s(%d)\n",
            coap_request_status_to_string(callback_state->state.status), callback_state->state.status);
        timed_unlock_unlock(&in_use);
    } break;
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static public_key_item_t*
request_public_key_callback_continued(messages_to_verify_entry_t* entry)
{
    public_key_item_t* item = NULL;

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        nanocbor_value_t dec;
        nanocbor_decoder_init(&dec, entry->message, entry->message_len - DTLS_EC_SIG_SIZE);

        certificate_t cert;
        int ret = certificate_decode(&dec, &cert);
        if (ret != NANOCBOR_OK)
        {
            LOG_ERR("Failed to decode certificate\n");
            return NULL;
        }

        uip_ip6addr_t ipaddr;
        eui64_to_ipaddr(cert.subject, &ipaddr);

        item = keystore_add(&ipaddr, &cert, EVICT_OLDEST);
        if (item)
        {
            LOG_INFO("Sucessfully added public key for ");
            LOG_DBG_BYTES(cert.subject, EUI64_LENGTH);
            LOG_INFO_(" [new]\n");
        }
        else
        {
            LOG_ERR("Failed to add public key for ");
            LOG_DBG_BYTES(cert.subject, EUI64_LENGTH);
            LOG_ERR_(" (out of memory) [new]\n");
        }
    }
    else
    {
        LOG_ERR("Failed to add public key (sig verification failed) [new]\n");
    }

    queue_message_to_verify_done(entry);

    timed_unlock_unlock(&in_use);

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
        LOG_INFO_BYTES(&item->cert.subject, EUI64_LENGTH);
        LOG_INFO_(" [unver]\n");

        list_push(public_keys, item);
    }
    else
    {
        LOG_ERR("Failed to verfiy public key for ");
        LOG_INFO_BYTES(&item->cert.subject, EUI64_LENGTH);
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
generate_shared_secret(public_key_item_t* item, const uint8_t* shared_secret)
{
    LOG_INFO("Generated shared secret with ");
    LOG_INFO_BYTES(&item->cert.subject, EUI64_LENGTH);
    LOG_INFO_(" value=");
    LOG_INFO_BYTES(shared_secret, DTLS_EC_KEY_SIZE);
    LOG_INFO_("\n");

    // Set the shared secret
    memcpy(item->shared_secret, shared_secret, DTLS_EC_KEY_SIZE);

#ifdef WITH_OSCORE
    // Take the lower OSCORE_ID_LEN bytes as the ids
    const uint8_t* sender_id = &our_cert.subject[EUI64_LENGTH - OSCORE_ID_LEN];
    const uint8_t* receiver_id = &item->cert.subject[EUI64_LENGTH - OSCORE_ID_LEN];

    oscore_derive_ctx(&item->context,
        shared_secret, DTLS_EC_KEY_SIZE,
        NULL, 0, //master_salt, sizeof(master_salt), // optional master salt
        COSE_Algorithm_AES_CCM_16_64_128, //COSE_ALGO_AESCCM_16_64_128,
        sender_id, OSCORE_ID_LEN, // Sender ID
        receiver_id, OSCORE_ID_LEN, // Receiver ID
        NULL, 0); // optional ID context

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

    timed_unlock_init(&in_use, "keystore", (1 * 60 * CLOCK_SECOND));
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
            static public_key_item_t* pkitem;
            messages_to_verify_entry_t* entry = (messages_to_verify_entry_t*)data;
            assert(entry->data == NULL);
            //LOG_INFO("Processing pe_message_verified for request_public_key_callback_continued\n");
            pkitem = request_public_key_callback_continued(entry);

            if (pkitem)
            {
                keystore_pin(pkitem);

                static ecdh2_state_t ecdh2_req_state;
                ecdh2_req_state.process = &keystore_req;
                PROCESS_PT_SPAWN(&ecdh2_req_state.pt, ecdh2(&ecdh2_req_state, &pkitem->cert.public_key));

                if (ecdh2_req_state.ecc_multiply_state.result == PKA_STATUS_SUCCESS)
                {
                    generate_shared_secret(pkitem, ecdh2_req_state.shared_secret);
                }
                else
                {
                    LOG_ERR("Failed to generate shared secret with error %d\n",
                        ecdh2_req_state.ecc_multiply_state.result);
                }

                keystore_unpin(pkitem);
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
            static public_key_item_t* pkitem;
            messages_to_verify_entry_t* entry = (messages_to_verify_entry_t*)data;
            assert(entry->data != NULL);
            //LOG_INFO("Processing pe_message_verified for keystore_add_unverified_continued\n");
            pkitem = keystore_add_unverified_continued(entry);

            if (pkitem)
            {
                keystore_pin(pkitem);

                static ecdh2_state_t ecdh2_unver_state;
                ecdh2_unver_state.process = &keystore_unver;
                PROCESS_PT_SPAWN(&ecdh2_unver_state.pt, ecdh2(&ecdh2_unver_state, &pkitem->cert.public_key));

                if (ecdh2_unver_state.ecc_multiply_state.result == PKA_STATUS_SUCCESS)
                {
                    generate_shared_secret(pkitem, ecdh2_unver_state.shared_secret);
                }
                else
                {
                    LOG_ERR("Failed to generate shared secret with error %d\n",
                        ecdh2_unver_state.ecc_multiply_state.result);
                }

                keystore_unpin(pkitem);
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
