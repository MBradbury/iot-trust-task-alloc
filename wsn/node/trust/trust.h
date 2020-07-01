#pragma once

#include "edge-info.h"

#include "keys.h"

#define TRUST_COAP_URI "trust"
#define MAX_TRUST_PAYLOAD (COAP_MAX_CHUNK_SIZE - DTLS_EC_SIG_SIZE)
