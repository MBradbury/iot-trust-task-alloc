#pragma once

#include "edge-info.h"

#define TRUST_COAP_URI "trust"

edge_resource_t* choose_edge(const char* capability_name);
