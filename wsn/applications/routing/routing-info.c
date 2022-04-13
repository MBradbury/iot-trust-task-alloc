#include "routing.h"
#include "trust-models.h"

static const trust_weight_t weights[] = {
#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    { TRUST_METRIC_TASK_SUBMISSION, 1.0f/4.0f },
    { TRUST_METRIC_TASK_RESULT,     1.0f/4.0f },
    { TRUST_METRIC_RESULT_QUALITY,  1.0f/4.0f },
    { TRUST_METRIC_THROUGHPUT,      1.0f/4.0f },
#else
    { TRUST_METRIC_TASK_SUBMISSION, 1.0f/3.0f },
    { TRUST_METRIC_TASK_RESULT,     1.0f/3.0f },
    { TRUST_METRIC_RESULT_QUALITY,  1.0f/3.0f },
#endif

    // If the trust model uses reputation, only assign up to
    // this much of the total trust value from reputation
    { TRUST_CONF_REPUTATION_WEIGHT, 0.25f     }
};

static trust_weights_t weights_info = {
    .application_name = ROUTING_APPLICATION_NAME,
    .weights = weights,
    .num = sizeof(weights)/sizeof(*weights)
};

#ifdef APPLICATIONS_MONITOR_THROUGHPUT
static trust_throughput_threshold_t threshold_info = {
    .application_name = ROUTING_APPLICATION_NAME,
    .in_threshold = 425,
    .out_threshold = 75
};
#endif

void init_trust_weights_routing(void)
{
    trust_weights_add(&weights_info);

#ifdef APPLICATIONS_MONITOR_THROUGHPUT
    trust_throughput_thresholds_add(&threshold_info);
#endif
}
