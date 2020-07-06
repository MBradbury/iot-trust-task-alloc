#pragma once

#define ROUTING_APPLICATION_NAME "routing"
#define ROUTING_APPLICATION_URI "routing"

#define ROUTING_SUBMIT_TASK "submit-task:route-req:"

void init_trust_weights_routing(void);

typedef struct {
    float latitude;
    float longitude;
} coordinate_t;

typedef enum {
    ROUTING_SUCCESS = 0,
    ROUTING_NO_ROUTE = 1,
    ROUTING_GAVE_UP = 2,
    ROUTING_UNKNOWN_ERROR = 3,
    ROUTING_PARSING_ERROR = 4,
} pyroutelib3_status_t;
