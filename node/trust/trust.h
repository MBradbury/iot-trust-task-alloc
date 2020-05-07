#pragma once

#include "edge-info.h"

#define TRUST_COAP_URI "trust"
#define MAX_TRUST_PAYLOAD 128

edge_resource_t* choose_edge(const char* capability_name);
