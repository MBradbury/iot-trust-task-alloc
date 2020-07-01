#pragma once

#define ROUTING_APPLICATION_NAME "routing"
#define ROUTING_APPLICATION_URI "routing"

#define ROUTING_SUBMIT_TASK "submit-task:route-req:"

void init_trust_weights_routing(void);

typedef struct {
    float latitude;
    float longitude;
} coordinate_t;
