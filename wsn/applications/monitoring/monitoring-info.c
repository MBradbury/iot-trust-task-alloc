#include "trust-models.h"

const trust_weight_t trust_weights[] = {
    { TRUST_METRIC_TASK_SUBMISSION, 1.0f },
};
const uint8_t trust_weights_len = sizeof(trust_weights)/sizeof(*trust_weights);
