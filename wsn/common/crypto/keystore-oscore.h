#pragma once

#include <stdbool.h>

#include "coap.h"
#include "coap-endpoint.h"

#ifdef WITH_OSCORE
bool keystore_protect_coap_with_oscore(coap_message_t* request, const coap_endpoint_t* ep);
#endif
