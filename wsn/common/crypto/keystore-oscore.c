#include "keystore-oscore.h"
#include "keystore.h"
#include "oscore.h"
#include "crypto-support.h"

#include "os/sys/log.h"

/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "keystore"
#ifdef KEYSTORE_LOG_LEVEL
#define LOG_LEVEL KEYSTORE_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
void coap_set_random_token(coap_message_t* request)
{
    // See: https://tools.ietf.org/html/rfc7252#section-5.3.
    // Given this is a 64-bit random token and we are sending few messages
    // the probability of a collision is fairly low (~10 in 18 quintillion),
    // not taking into account bias in the PRNG.

    crypto_fill_random(request->token, COAP_TOKEN_LEN);
    request->token_len = COAP_TOKEN_LEN;
}
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef WITH_OSCORE
bool keystore_protect_coap_with_oscore(coap_message_t* request, const coap_endpoint_t* ep)
{
    public_key_item_t* pubkeyitem = keystore_find(&ep->ipaddr);
    if (pubkeyitem)
    {
        coap_set_oscore(request, &pubkeyitem->context);
    }
    else
    {
        LOG_WARN("Failed to find oscore context for ");
        LOG_WARN_6ADDR(&ep->ipaddr);
        LOG_WARN_(", request will not be protected.\n");
    }

    return pubkeyitem != NULL;
}
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
