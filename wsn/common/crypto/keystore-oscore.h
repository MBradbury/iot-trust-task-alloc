#pragma once

#include <stdbool.h>

#include "coap.h"
#include "coap-endpoint.h"
/*-------------------------------------------------------------------------------------------------------------------*/
void coap_set_random_token(coap_message_t* request);
/*-------------------------------------------------------------------------------------------------------------------*/
#ifdef WITH_OSCORE
bool keystore_protect_coap_with_oscore(coap_message_t* request, const coap_endpoint_t* ep);
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
