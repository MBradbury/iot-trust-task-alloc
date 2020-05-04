#pragma once

#include "contiki.h"

#ifdef APPLICATION_MONITORING
#include "monitoring.h"
#endif

struct process* find_process_with_name(const char* name);
