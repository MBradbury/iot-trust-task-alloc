#include "trust-common.h"
#include "edge-info.h"

#include "contiki.h"
#include "os/sys/log.h"
#include "os/lib/json/jsonparse.h"
#include "os/net/ipv6/uip-ds6.h"
#include "os/net/ipv6/uiplib.h"

#include "dev/sha256.h"

#include <stdio.h>
#include <ctype.h>

#include "applications.h"
#include "trust-common.h"
#include "crypto-support.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-common"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
const char *topics_to_suscribe[TOPICS_TO_SUBSCRIBE_LEN] = {
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_ANNOUNCE,
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_ADD,
    MQTT_EDGE_NAMESPACE "/+/" MQTT_EDGE_ACTION_CAPABILITY "/+/" MQTT_EDGE_ACTION_CAPABILITY_REMOVE,
};
/*-------------------------------------------------------------------------------------------------------------------*/
process_event_t pe_edge_capability_add;
process_event_t pe_edge_capability_remove;
/*-------------------------------------------------------------------------------------------------------------------*/
static bool is_our_addr(const uip_ip6addr_t* addr)
{
    for (int i = 0; i < UIP_DS6_ADDR_NB; i++)
    {
        uint8_t state = uip_ds6_if.addr_list[i].state;

        if (uip_ds6_if.addr_list[i].isused &&
            (state == ADDR_TENTATIVE || state == ADDR_PREFERRED) &&
            uip_ip6addr_cmp(addr, &uip_ds6_if.addr_list[i].ipaddr)
            )
        {
            return true;
        }
    }
    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_publish_announce_handler(const char *topic, const char* topic_end,
                              const uint8_t *chunk, uint16_t chunk_len,
                              const char* topic_identity)
{
    struct jsonparse_state state;
    jsonparse_setup(&state, (const char*)chunk, chunk_len);

    int next;

    if ((next = jsonparse_next(&state)) != '{')
    {
        LOG_ERR("jsonparse_next 1 (next=%d)\n", next);
        return;
    }

    if ((next = jsonparse_next(&state)) != JSON_TYPE_PAIR_NAME)
    {
        LOG_ERR("jsonparse_next 2 (next=%d)\n", next);
        return;
    }

    if (jsonparse_strcmp_value(&state, "addr") != 0)
    {
        LOG_ERR("jsonparse_next 3\n");
        return;
    }

    if ((next = jsonparse_next(&state)) != '"')
    {
        LOG_ERR("jsonparse_next 4 (next=%d)\n", next);
        return;
    }

    char ip_addr_buf[UIPLIB_IPV6_MAX_STR_LEN];
    jsonparse_copy_value(&state, ip_addr_buf, sizeof(ip_addr_buf));

    uip_ipaddr_t ip_addr;
    uiplib_ip6addrconv(ip_addr_buf, &ip_addr);

    if (jsonparse_next(&state) != '}')
    {
        LOG_ERR("jsonparse_next 5\n");
        return;
    }

    edge_resource_t* edge_resource = edge_info_add(ip_addr, topic_identity);
    if (edge_resource != NULL)
    {
        LOG_DBG("Received announce for %s with address %s\n", topic_identity, ip_addr_buf);
    }
    else
    {
        LOG_ERR("Failed to allocate edge resource\n");
    }

    // We should connect to the Edge resource that has announced themselves here
    // This means that if we are using DTLS, the handshake has already been performed,
    // so we will be ready to communicate tasks to them and receive responses.
    // This should only be done if another edge resource has been announced other
    // then ourselves.
    if (!is_our_addr(&ip_addr))
    {
        coap_endpoint_t ep;
        edge_info_get_server_endpoint(edge_resource, &ep, false);

        LOG_DBG("Connecting to CoAP endpoint ");
        coap_endpoint_log(&ep);
        LOG_DBG_("\n");

        // TODO: delays this by a random amount to space out connects
        coap_endpoint_connect(&ep);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void
mqtt_publish_capability_handler(const char *topic, const char* topic_end,
                                const uint8_t *chunk, uint16_t chunk_len,
                                const char* topic_identity)
{
    edge_resource_t* edge = edge_info_find_ident(topic_identity);
    if (edge == NULL)
    {
        LOG_ERR("Failed to find edge with identity %s\n", topic_identity);
        return;
    }

    // Format of topic is now in "/%s/add"

    if (*topic != '/')
    {
        LOG_ERR("Bad sep\n");
        return;
    }

    topic += 1;

    const char* next_slash = strchr(topic, '/');
    if (next_slash == NULL)
    {
        LOG_ERR("Bad sep\n");
        return;
    }

    // Check that capability name isn't too long
    ptrdiff_t distance = next_slash - topic;
    if (distance <= 0 || distance > EDGE_CAPABILITY_NAME_LEN)
    {
        LOG_ERR("Bad cap name\n");
        return;
    }

    // Parse capability name
    char capability_name[EDGE_CAPABILITY_NAME_LEN+1];
    strncpy(capability_name, topic, distance);
    capability_name[distance] = '\0';

    topic = next_slash + 1;

    if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_ADD, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_ADD)) == 0)
    {
        edge_capability_t* capability = edge_info_capability_add(edge, capability_name);
        if (capability == NULL)
        {
            LOG_ERR("Failed to create capability (%s) for edge with identity %s\n", capability_name, topic_identity);
            return;
        }

        struct jsonparse_state state;
        jsonparse_setup(&state, (const char*)chunk, chunk_len);

        int next;

        if ((next = jsonparse_next(&state)) != '{')
        {
            LOG_ERR("jsonparse_next 1 (next=%d)\n", next);
            return;
        }

        if ((next = jsonparse_next(&state)) != '}')
        {
            LOG_ERR("jsonparse_next 2 (next=%d)\n", next);
            return;
        }

        LOG_DBG("Added capability (%s) for edge with identity %s\n", capability_name, topic_identity);

        // We have at least one Edge resource to support this application, so we need to inform the process
        struct process* proc = find_process_with_name(capability_name);
        if (proc != NULL)
        {
            process_post(proc, pe_edge_capability_add, edge);
        }
        else
        {
            LOG_DBG("Failed to find a process running the application (%s)\n", capability_name);
        }
    }
    else if (strncmp(MQTT_EDGE_ACTION_CAPABILITY_REMOVE, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY_ADD)) == 0)
    {
        // TODO
        LOG_ERR("Not implemented (%.*s)\n", topic_end - topic, topic);
    }
    else
    {
        LOG_ERR("Unknown cap action (%.*s)\n", topic_end - topic, topic);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
mqtt_publish_handler(const char *topic, const char* topic_end, const uint8_t *chunk, uint16_t chunk_len)
{
    LOG_DBG("Pub Handler: topic='%.*s' (len=%u), chunk_len=%u\n", topic_end - topic, topic, topic_end - topic, chunk_len);

    int ret;

    // First check that we are in the right namespace
    ret = strncmp(MQTT_EDGE_NAMESPACE, topic, MQTT_EDGE_NAMESPACE_LEN);
    if (ret != 0)
    {
        LOG_ERR("Initial prefix does not match " MQTT_EDGE_NAMESPACE "\n");
        return;
    }

    // Consume MQTT_EDGE_NAMESPACE_LEN
    topic += MQTT_EDGE_NAMESPACE_LEN;

    if ((topic_end - topic) < 2 + MQTT_IDENTITY_LEN || *topic != '/')
    {
        LOG_ERR("Topic does not contain identity\n");
        return;
    }

    // Consume '/'
    topic += 1;

    // Check that the identiy is hex
    for (int i = 0; i != MQTT_IDENTITY_LEN; ++i)
    {
        if (!isxdigit(topic[i]))
        {
            LOG_ERR("Topic identity is in an invalid format (char %u = %c)\n", i, topic[i]);
            return;
        }
    }

    char topic_identity[MQTT_IDENTITY_LEN + 1];
    strncpy(topic_identity, topic, MQTT_IDENTITY_LEN);
    *(topic_identity + MQTT_IDENTITY_LEN) = '\0';

    topic += MQTT_IDENTITY_LEN;

    if (*topic != '/')
    {
        LOG_ERR("Bad sep\n");
        return;
    }

    topic += 1;

    if (strncmp(MQTT_EDGE_ACTION_ANNOUNCE, topic, strlen(MQTT_EDGE_ACTION_ANNOUNCE)) == 0)
    {
        topic += strlen(MQTT_EDGE_ACTION_ANNOUNCE);

        mqtt_publish_announce_handler(topic, topic_end, chunk, chunk_len, topic_identity);
    }
    else if (strncmp(MQTT_EDGE_ACTION_CAPABILITY, topic, strlen(MQTT_EDGE_ACTION_CAPABILITY)) == 0)
    {
        topic += strlen(MQTT_EDGE_ACTION_CAPABILITY);

        mqtt_publish_capability_handler(topic, topic_end, chunk, chunk_len, topic_identity);
    }
    else
    {
        LOG_ERR("Unknown topic '%.*s'\n", topic_end - topic, topic);
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
int serialise_trust(void* trust_info, uint8_t* buffer, size_t buffer_len)
{
    uint32_t time_secs = clock_seconds();

    int len = snprintf((char*)buffer, buffer_len,
        "{"
            "\"name\":\"serialised-trust\","
            "\"time\":%" PRIu32
        "}",
        time_secs
    );
    if (len < 0 || len >= buffer_len)
    {
        return -1;
    }

    // Include NUL byte
    len += 1;

    return len;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int deserialise_trust(void* trust_info, const uint8_t* buffer, size_t buffer_len)
{
    return false;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static void sha256_hash(const uint8_t* buffer, size_t len, uint8_t* hash)
{
    sha256_state_t sha256_state;
    rtimer_clock_t time;

    LOG_DBG("Starting sha256()...\n");
    time = RTIMER_NOW();
    crypto_enable();
    sha256_init(&sha256_state);
    sha256_process(&sha256_state, buffer, len);
    sha256_done(&sha256_state, hash);
    crypto_disable();
    time = RTIMER_NOW() - time;
    LOG_DBG("sha256(), %" PRIu32 " us\n", (uint32_t)((uint64_t)time * 1000000 / RTIMER_SECOND));
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(sign_trust(sign_trust_state_t* state, uint8_t* buffer, size_t buffer_len, size_t msg_len))
{
    PT_BEGIN(&state->pt);

    state->sig_len = 0;

    sha256_hash(buffer, msg_len, (uint8_t*)state->ecc_sign_state.hash);

    state->ecc_sign_state.process = state->process;
    state->ecc_sign_state.curve_info = &nist_p_256;

    // Set secret key from our private key
    dtls_ec_key_to_uint32(our_key.priv_key, DTLS_EC_KEY_SIZE, state->ecc_sign_state.secret);

    crypto_fill_random((uint8_t*)state->ecc_sign_state.k_e, DTLS_EC_KEY_SIZE);

    LOG_DBG("Starting ecc_dsa_sign()...\n");
    state->time = RTIMER_NOW();
    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_sign_state.pt, ecc_dsa_sign(&state->ecc_sign_state));
    pka_disable();
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecc_dsa_sign(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));

    if (state->ecc_sign_state.result != PKA_STATUS_SUCCESS)
    {
        LOG_ERR("Failed to sign message with %d\n", state->ecc_sign_state.result);
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Message sign success!\n");

    // Add signature into the message
    memcpy(buffer + msg_len,                        state->ecc_sign_state.point_r.x,   sizeof(uint32_t) * 8);
    memcpy(buffer + msg_len + sizeof(uint32_t) * 8, state->ecc_sign_state.signature_s, sizeof(uint32_t) * 8);

    state->sig_len = sizeof(uint32_t) * 8 * 2;

#if 1
    static verify_trust_state_t test;
    test.process = state->process;
    PT_SPAWN(&state->pt, &test.pt, verify_trust(&test, buffer, msg_len + state->sig_len));
#endif

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
PT_THREAD(verify_trust(verify_trust_state_t* state, const uint8_t* buffer, size_t buffer_len))
{
    PT_BEGIN(&state->pt);

    // Extract signature
    if (buffer_len < sizeof(uint32_t) * 8 * 2)
    {
        LOG_ERR("No signature\n");
        PT_EXIT(&state->pt);
    }

    const uint8_t* sig_r = buffer + buffer_len - sizeof(uint32_t) * 8 * 2;
    const uint8_t* sig_s = buffer + buffer_len - sizeof(uint32_t) * 8;

    // Extract signature from buffer
    memcpy(state->ecc_verify_state.signature_r, sig_r, sizeof(uint32_t) * 8);
    memcpy(state->ecc_verify_state.signature_s, sig_s, sizeof(uint32_t) * 8);

    size_t msg_len = buffer_len - sizeof(uint32_t) * 8 * 2;

    sha256_hash(buffer, msg_len, (uint8_t*)state->ecc_verify_state.hash);

    state->ecc_verify_state.process = state->process;
    state->ecc_verify_state.curve_info = &nist_p_256;

    // TODO: get public key from key store
    dtls_ec_key_to_uint32(our_key.pub_key.x, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.x);
    dtls_ec_key_to_uint32(our_key.pub_key.y, DTLS_EC_KEY_SIZE, state->ecc_verify_state.public.y);

    state->time = RTIMER_NOW();
    pka_enable();
    PT_SPAWN(&state->pt, &state->ecc_verify_state.pt, ecc_dsa_verify(&state->ecc_verify_state));
    pka_disable();
    state->time = RTIMER_NOW() - state->time;
    LOG_DBG("ecc_dsa_verify(), %" PRIu32 " ms\n", (uint32_t)((uint64_t)state->time * 1000 / RTIMER_SECOND));

    if (state->ecc_verify_state.result != PKA_STATUS_SUCCESS)
    {
        if (state->ecc_verify_state.result == PKA_STATUS_SIGNATURE_INVALID)
        {
            LOG_ERR("Failed to verify message with PKA_STATUS_SIGNATURE_INVALID\n");
        }
        else
        {
            LOG_ERR("Failed to verify message with %d\n", state->ecc_verify_state.result);
        }
        
        PT_EXIT(&state->pt);
    }

    LOG_DBG("Message verify success!\n");

    PT_END(&state->pt);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void
trust_common_init(void)
{
    pe_edge_capability_add = process_alloc_event();
    pe_edge_capability_remove = process_alloc_event();

    crypto_init();
    crypto_disable();
}
/*-------------------------------------------------------------------------------------------------------------------*/
