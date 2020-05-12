#pragma once

#include "edge-info.h"

#define TRUST_COAP_URI "trust"
#define MAX_TRUST_PAYLOAD 128 + (sizeof(uint32_t) * 8 * 2)

edge_resource_t* choose_edge(const char* capability_name);
