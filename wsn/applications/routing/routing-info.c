#include "routing.h"
#include "trust-models.h"

static const trust_weight_t weights[] = {
    { TRUST_METRIC_TASK_SUBMISSION, 1.0f/3.0f },
    { TRUST_METRIC_TASK_RESULT,     1.0f/3.0f },
    { TRUST_METRIC_RESULT_QUALITY,  1.0f/3.0f },

    // If the trust model uses reputation, only assign up to
    // this much of the total trust value from reputation
    { TRUST_CONF_REPUTATION_WEIGHT, 0.25f     }
};

static trust_weights_t weights_info = {
    .application_name = ROUTING_APPLICATION_NAME,
    .weights = weights,
    .num = sizeof(weights)/sizeof(*weights)
};

void init_trust_weights_routing(void)
{
    trust_weights_add(&weights_info);
}
