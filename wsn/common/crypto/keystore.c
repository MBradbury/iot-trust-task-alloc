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
PROCESS(keystore_add_verifier, "keystore_add_verifier"); // Processes verifying the certificate
/*-------------------------------------------------------------------------------------------------------------------*/
MEMB(public_keys_memb, public_key_item_t, PUBLIC_KEYSTORE_SIZE);
LIST(public_keys);
LIST(public_keys_to_verify);
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
static public_key_item_t*
keystore_find_in_list(const uint8_t* eui64, list_t l)
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
keystore_find(const uint8_t* eui64)
{
    return keystore_find_in_list(eui64, public_keys);
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
    public_key_item_t* item = keystore_find_addr(addr);
    if (!item)
    {
        return NULL;
    }

    return &item->cert.public_key;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool keystore_certificate_contains_tags(const stereotype_tags_t* tags)
{
    // Check the certificates that have been verified and are waiting to be verified

    for (public_key_item_t* iter = list_head(public_keys); iter != NULL; iter = list_item_next(iter))
    {
        if (stereotype_tags_equal(tags, &iter->cert.tags))
        {
            return true;
        }
    }

    for (public_key_item_t* iter = list_head(public_keys_to_verify); iter != NULL; iter = list_item_next(iter))
    {
        if (stereotype_tags_equal(tags, &iter->cert.tags))
        {
            return true;
        }
    }

    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_pin(public_key_item_t* item)
{
    item->pin_count += 1;

    LOG_DBG("Key ");
    LOG_DBG_BYTES(&item->cert.subject, EUI64_LENGTH);
    LOG_DBG_(" pin count=%u (+)\n", item->pin_count);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void keystore_unpin(public_key_item_t* item)
{
    assert(item->pin_count > 0);

    item->pin_count -= 1;

    LOG_DBG("Key ");
    LOG_DBG_BYTES(&item->cert.subject, EUI64_LENGTH);
    LOG_DBG_(" pin count=%u (-)\n", item->pin_count);
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool keystore_is_pinned(const public_key_item_t* item)
{
    return item->pin_count > 0;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
keystore_free_up_space(void)
{
    // We need to try to free up space for a new certificate.

    for (public_key_item_t* iter = list_head(public_keys); iter != NULL; iter = list_item_next(iter))
    {
        // 1. Must never evict the item for the root
        if (memcmp(iter->cert.subject, root_cert.subject, EUI64_LENGTH) == 0)
        {
            continue;
        }

        // 2. If a certificate is pinned, then it is in use and cannot be freed
        if (keystore_is_pinned(iter))
        {
            continue;
        }

        // TODO: Consider removing specific certificates (e.g., LRU)
        // (see: https://en.wikipedia.org/wiki/Cache_replacement_policies)
        if (keystore_remove(iter))
        {
            return true;
        }
    }

    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool
keystore_add(const certificate_t* cert)
{
    // Check if this certificate is already present
    public_key_item_t* item = keystore_find(cert->subject);
    if (item)
    {
        return true;
    }

    // Check if this certificate is queued to be verified
    item = keystore_find_in_list(cert->subject, public_keys_to_verify);
    if (item)
    {
        // Poll to ensure that the process is making progress with the certificates to verify
        process_poll(&keystore_add_verifier);
        return true;
    }

    // No item has this certificate so allocate memory for it
    item = memb_alloc(&public_keys_memb);
    if (!item)
    {
        LOG_WARN("keystore_add: out of memory (1st) for ");
        LOG_WARN_BYTES(cert->subject, EUI64_LENGTH);
        LOG_WARN_("\n");

        if (!keystore_free_up_space())
        {
            LOG_ERR("Failed to free space for the certificate ");
            LOG_ERR_BYTES(cert->subject, EUI64_LENGTH);
            LOG_ERR_("\n");
            return false;
        }
        else
        {
            item = memb_alloc(&public_keys_memb);
            if (item == NULL)
            {
                LOG_WARN("keystore_add: out of memory (2nd) for ");
                LOG_WARN_BYTES(cert->subject, EUI64_LENGTH);
                LOG_WARN_("\n");
                return false;
            }
            else
            {
                LOG_INFO("Successfully found memory for the certificate ");
                LOG_INFO_BYTES(cert->subject, EUI64_LENGTH);
                LOG_INFO_("\n");
            }
        }
    }

    LOG_DBG("Queuing unverified key for ");
    LOG_DBG_BYTES(cert->subject, EUI64_LENGTH);
    LOG_DBG_(" to be verified\n");

    item->cert = *cert;

    //item->age = clock_time();
    item->pin_count = 0;

    list_add(public_keys_to_verify, item);

    process_poll(&keystore_add_verifier);

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
bool keystore_remove(public_key_item_t* item)
{
    // Cannot remove if pinned (is in use)
    if (keystore_is_pinned(item))
    {
        return false;
    }

    // Cannot remove if this is the root item
    if (memcmp(item->cert.subject, root_cert.subject, EUI64_LENGTH) == 0)
    {
        return false;
    }

    LOG_INFO("keystore_remove: Attempting to remove certificate for ");
    LOG_INFO_BYTES(item->cert.subject, EUI64_LENGTH);
    LOG_INFO_("\n");

    // Can only remove from the verified public keys list
    // Cannot remove from the unverified public keys list
    const bool removed = list_remove(public_keys, item);
    if (!removed)
    {
        return false;
    }

    const bool freed = memb_free(&public_keys_memb, item);

    LOG_INFO("keystore_remove: Removed certificate for ");
    LOG_INFO_BYTES(item->cert.subject, EUI64_LENGTH);
    LOG_INFO_(" (freed=%d)\n", freed);

    return freed;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static coap_message_t msg;
static coap_callback_request_state_t coap_callback;
static uint8_t key_req_payload[sizeof(uip_ip6addr_t)];
static timed_unlock_t in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
static void request_public_key_callback(coap_callback_request_state_t* callback_state);
/*-------------------------------------------------------------------------------------------------------------------*/
bool request_public_key(const uip_ip6addr_t* addr)
{
    uip_ip6addr_t norm_addr;
    uip_ip6addr_normalise(addr, &norm_addr);

    uint8_t eui64[EUI64_LENGTH];
    eui64_from_ipaddr(&norm_addr, eui64);

    // Check if we have the key and have verified it
    if (keystore_find(eui64) != NULL)
    {
        LOG_DBG("Already have the public key for ");
        LOG_DBG_6ADDR(addr);
        LOG_DBG_(", do not need to request it.\n");
        return false;
    }

    // Check if we have the key and are in the process of verifying
    if (keystore_find_in_list(eui64, public_keys_to_verify) != NULL)
    {
        LOG_DBG("Already processing the public key for ");
        LOG_DBG_6ADDR(addr);
        LOG_DBG_(", do not need to request it.\n");

        // Poll to ensure that the process is making progress with the certificates to verify
        process_poll(&keystore_add_verifier);

        return false;
    }

    // Check if we are already requesting a key
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

    memcpy(key_req_payload, addr, sizeof(*addr));

    coap_init_message(&msg, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(&msg, "key");
    coap_set_header_content_format(&msg, APPLICATION_OCTET_STREAM);
    coap_set_payload(&msg, key_req_payload, sizeof(*addr));

#if defined(WITH_OSCORE) && defined(AIOCOAP_SUPPORTS_OSCORE)
    coap_set_random_token(&msg);
    keystore_protect_coap_with_oscore(&msg, &root_ep);
#endif

    int ret = coap_send_request(&coap_callback, &root_ep, &msg, &request_public_key_callback);
    if (ret)
    {
        LOG_DBG("coap_send_request req pk done\n");
        timed_unlock_lock(&in_use);
    }
    else
    {
        LOG_ERR("coap_send_request req pk failed %d\n", ret);
    }
    
    return ret != 0;
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
        }
        else
        {
            nanocbor_value_t dec;
            nanocbor_decoder_init(&dec, payload, req_resp_len);

            certificate_t cert;
            int ret = certificate_decode(&dec, &cert);
            if (ret == NANOCBOR_OK)
            {
                if (keystore_add(&cert))
                {
                    LOG_INFO("Sucessfully added public key for ");
                    LOG_DBG_BYTES(cert.subject, EUI64_LENGTH);
                    LOG_INFO_("\n");
                }
                else
                {
                    LOG_ERR("Failed to add public key for ");
                    LOG_ERR_BYTES(cert.subject, EUI64_LENGTH);
                    LOG_ERR_(" (out of memory)\n");
                }
            }
            else
            {
                LOG_ERR("Failed to decode certificate\n");
            }
        }
    } break;

    case COAP_REQUEST_STATUS_FINISHED:
    {
        // Not truely finished yet here, need to wait for signature verification
        // But we are finished with sending and receiving a message
        timed_unlock_unlock(&in_use);
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
static uint8_t add_buffer[TBS_CERTIFICATE_CBOR_LENGTH + DTLS_EC_SIG_SIZE];
static bool add_buffer_in_use;
/*-------------------------------------------------------------------------------------------------------------------*/
static void
keystore_add_start(void)
{
    // Don't start adding a queued certificate to verify if we are already doing work
    if (add_buffer_in_use)
    {
        return;
    }

    public_key_item_t* item = list_head(public_keys_to_verify);
    if (!item)
    {
        // Nothing to do, if there are no certificates queued to be verified
        return;
    }

    const size_t available_space = sizeof(add_buffer) - DTLS_EC_SIG_SIZE;

    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, add_buffer, available_space);
    int encode_ret = certificate_encode_tbs(&enc, &item->cert);

    size_t encoded_length = nanocbor_encoded_len(&enc);

    if (encode_ret != NANOCBOR_OK || encoded_length > available_space)
    {
        LOG_ERR("keystore_add: encode failed %zu > %zu for ", encoded_length, available_space);
        LOG_ERR_BYTES(item->cert.subject, EUI64_LENGTH);
        LOG_ERR_("\n");

        list_remove(public_keys_to_verify, item);
        memb_free(&public_keys_memb, item);
        return;
    }

    // Put the signature at the end
    memcpy(&add_buffer[encoded_length], &item->cert.signature, DTLS_EC_SIG_SIZE);

    if (!queue_message_to_verify(&keystore_add_verifier, item,
                                 add_buffer, encoded_length + DTLS_EC_SIG_SIZE,
                                 &root_cert.public_key))
    {
        LOG_ERR("keystore_add: enqueue failed for ");
        LOG_ERR_BYTES(item->cert.subject, EUI64_LENGTH);
        LOG_ERR_("\n");

        list_remove(public_keys_to_verify, item);
        memb_free(&public_keys_memb, item);
        return;
    }

    add_buffer_in_use = true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static public_key_item_t*
keystore_add_continued(messages_to_verify_entry_t* entry)
{
    public_key_item_t* item = (public_key_item_t*)entry->data;

    list_remove(public_keys_to_verify, item);

    if (entry->result == PKA_STATUS_SUCCESS)
    {
        LOG_INFO("Sucessfully verfied public key for ");
        LOG_INFO_BYTES(item->cert.subject, EUI64_LENGTH);
        LOG_INFO_("\n");

        list_push(public_keys, item);
    }
    else
    {
        LOG_ERR("Failed to verfiy public key for ");
        LOG_INFO_BYTES(item->cert.subject, EUI64_LENGTH);
        LOG_ERR_(" (sig verification failed)\n");

        memb_free(&public_keys_memb, item);

        item = NULL;
    }

    queue_message_to_verify_done(entry);

    add_buffer_in_use = false;

    return item;
}
/*-------------------------------------------------------------------------------------------------------------------*/
// TODO: this should be OSCORE_SENDER_ID_MAX_LEN(COSE_algorithm_AES_CCM_16_64_128_IV_LEN)
#define OSCORE_ID_LEN 6
/*-------------------------------------------------------------------------------------------------------------------*/
static void
generate_shared_secret(public_key_item_t* item, const uint8_t* shared_secret, size_t shared_secret_len)
{
    LOG_INFO("Generated shared secret with ");
    LOG_INFO_BYTES(item->cert.subject, EUI64_LENGTH);
    LOG_INFO_(" value=");
    LOG_INFO_BYTES(shared_secret, shared_secret_len);
    LOG_INFO_("\n");

#ifdef WITH_OSCORE
    // Take the lower OSCORE_ID_LEN bytes as the ids
    const uint8_t* sender_id = &our_cert.subject[EUI64_LENGTH - OSCORE_ID_LEN];
    const uint8_t* receiver_id = &item->cert.subject[EUI64_LENGTH - OSCORE_ID_LEN];

    // The master salt might have been provided as a compile time option
    // if so define it and use it to derive the context
#ifdef OSCORE_MASTER_SALT
    const uint8_t master_salt[] = OSCORE_MASTER_SALT;
    const uint8_t master_salt_len = sizeof(master_salt);
#else
    const uint8_t* master_salt = NULL;
    const uint8_t master_salt_len = 0;
#endif

    // Same for the ID context
#ifdef OSCORE_ID_CONTEXT
    const uint8_t id_context[] = OSCORE_ID_CONTEXT;
    const uint8_t id_context_len = sizeof(id_context);
#else
    const uint8_t* id_context = NULL;
    const uint8_t id_context_len = 0;
#endif

#ifdef WITH_GROUPCOM
    static const uint8_t gid[] = {0x1};
#endif

    oscore_derive_ctx(&item->context,
        // The shared secret between these two nodes
        shared_secret, shared_secret_len,

        // optional master salt
        master_salt, master_salt_len,

        // Algorithm
        COSE_Algorithm_AES_CCM_16_64_128,

        // Sender ID
        sender_id, OSCORE_ID_LEN,

        // Receiver ID
        receiver_id, OSCORE_ID_LEN,

        // optional ID context
        id_context, id_context_len

#ifdef WITH_GROUPCOM
        , gid
#endif
    );

#ifdef WITH_GROUPCOM
    // Set public keys
    oscore_add_group_keys(&item->context,
        // Our public key
        (const uint8_t*)&our_cert.public_key,

        // Our private key
        (const uint8_t*)&our_privkey,

        // Their public key
        (const uint8_t*)&item->cert.public_key,

        // secp256r1/ NIST P-256
        COSE_Algorithm_ES256,
        COSE_Elliptic_Curve_P256
    );
#endif

    LOG_DBG("Created oscore context with: ");
    LOG_DBG_("\n\tSender ID   : ");
    LOG_DBG_BYTES(sender_id, OSCORE_ID_LEN);
    LOG_DBG_("\n\tSender Key  : ");
    LOG_DBG_BYTES(item->context.sender_context.sender_key, CONTEXT_KEY_LEN);
    LOG_DBG_("\n\tReceiver ID : ");
    LOG_DBG_BYTES(receiver_id, OSCORE_ID_LEN);
    LOG_DBG_("\n\tReceiver Key: ");
    LOG_DBG_BYTES(item->context.recipient_context.recipient_key, CONTEXT_KEY_LEN);
    LOG_DBG_("\n\tCommon IV: ");
    LOG_DBG_BYTES(item->context.common_iv, CONTEXT_INIT_VECT_LEN);
#ifdef OSCORE_MASTER_SALT
    LOG_DBG_("\n\tMaster Salt: ");
    LOG_DBG_BYTES(master_salt, master_salt_len);
#endif
#ifdef OSCORE_ID_CONTEXT
    LOG_DBG_("\n\tID Context: ");
    LOG_DBG_BYTES(id_context, id_context_len);
#endif
    LOG_DBG_("\n");

#endif /* WITH_OSCORE */
}
/*-------------------------------------------------------------------------------------------------------------------*/
static bool
keystore_init(void)
{
    crypto_support_init();

    memb_init(&public_keys_memb);
    list_init(public_keys);
    list_init(public_keys_to_verify);

    timed_unlock_init(&in_use, "keystore", (1 * 60 * CLOCK_SECOND));
    add_buffer_in_use = false;

    // Need to add the root certificate to the keystore in order to
    // generate the shared secret with it
    if (!keystore_add(&root_cert))
    {
        LOG_ERR("Adding the root certificate to the keystore failed\n");
        return false;
    }

    return true;
}
/*-------------------------------------------------------------------------------------------------------------------*/
PROCESS_THREAD(keystore_add_verifier, ev, data)
{
    // This process processes events for keys that were unsolicitied
    PROCESS_BEGIN();

    if (!keystore_init())
    {
        PROCESS_EXIT();
    }

    while (1)
    {
        PROCESS_WAIT_EVENT();

        // Need to consider verifying certificate
        if (ev == PROCESS_EVENT_POLL)
        {
            keystore_add_start();
        }

        // Verify key response
        if (ev == pe_message_verified)
        {
            static public_key_item_t* pkitem;
            messages_to_verify_entry_t* entry = (messages_to_verify_entry_t*)data;
            assert(entry != NULL);
            assert(entry->data != NULL);
            //LOG_INFO("Processing pe_message_verified for keystore_add_continued\n");
            pkitem = keystore_add_continued(entry);

            // Generated a shared secret if this step succeeded
            if (pkitem)
            {
                keystore_pin(pkitem);

                static ecdh2_state_t ecdh2_unver_state;
                ecdh2_unver_state.ecc_multiply_state.process = &keystore_add_verifier;
                PROCESS_PT_SPAWN(&ecdh2_unver_state.pt, ecdh2(&ecdh2_unver_state, &pkitem->cert.public_key));

                if (ECDH_GET_RESULT(ecdh2_unver_state) == PKA_STATUS_SUCCESS)
                {
                    generate_shared_secret(pkitem,
                        ecdh2_unver_state.shared_secret, sizeof(ecdh2_unver_state.shared_secret));
                }
                else
                {
                    LOG_ERR("Failed to generate shared secret with error %d\n",
                        ECDH_GET_RESULT(ecdh2_unver_state));
                }

                keystore_unpin(pkitem);
            }

            // Poll ourselves to potentially verify another message
            process_poll(&keystore_add_verifier);
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef WITH_OSCORE
void oscore_missing_security_context(const coap_endpoint_t *src)
{
    LOG_INFO("Missing OSCORE security context, requesting public key for ");
    LOG_INFO_6ADDR(&src->ipaddr);
    LOG_INFO_("\n");
    // If the OSCORE security context was missing, we
    // need to request the public key of the sender in order to
    // process their further messages.
    request_public_key(&src->ipaddr);
}
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
