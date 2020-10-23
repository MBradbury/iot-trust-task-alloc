#pragma once

#include "interaction-history.h"

#include "nanocbor-helper.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define HMM_NUM_STATES 2
#define HMM_NUM_OBSERVATIONS 4
/*-------------------------------------------------------------------------------------------------------------------*/
// Hidden states: Is the edge node trustworthy (behaving well) or untrustworthy (behaving badly)
typedef enum {
    HMM_STATE_EDGE_TRUSTWORTHY = 0,
    HMM_STATE_EDGE_UNTRUSTWORTHY = 1
} hmm_states_t;

// Observations: What interactions have been observed
#if HMM_NUM_OBSERVATIONS == 4
typedef enum {
    HMM_OBS_TASK_SUBMISSION_ACK_TIMEDOUT = 0,
    HMM_OBS_TASK_RESPONSE_TIMEDOUT = 1,
    HMM_OBS_TASK_RESULT_QUALITY_INCORRECT = 2,
    HMM_OBS_TASK_RESULT_QUALITY_CORRECT = 3
} hmm_observations_t;

#elif HMM_NUM_OBSERVATIONS == 2
typedef enum {
    HMM_OBS_TASK_SUBMISSION_ACK_TIMEDOUT = 0,
    HMM_OBS_TASK_RESPONSE_TIMEDOUT = 0,
    HMM_OBS_TASK_RESULT_QUALITY_INCORRECT = 0,
    HMM_OBS_TASK_RESULT_QUALITY_CORRECT = 1
} hmm_observations_t;

#else
#error "Bad number of observations"

#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// TODO: see https://github.com/hmmlearn/hmmlearn/blob/master/lib/hmmlearn
/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct {
    // The initial probability distribution over the states
    // The probability of starting in a state s
    // Also called pi : S -> [0,1]
    float initial[HMM_NUM_STATES];

    // The state transition matrix
    // The probability of transitioning from a state s to s'
    // Also called A : S * S -> [0,1]
    float trans[HMM_NUM_STATES][HMM_NUM_STATES];

    // The observation emission matrix
    // The probability of observing o when in state s
    // Also called B : S * O -> [0,1]
    float emission[HMM_NUM_STATES][HMM_NUM_OBSERVATIONS];

} hmm_t;
/*-------------------------------------------------------------------------------------------------------------------*/
#define HMM_CBOR_MAX_SIZE ( \
    (1) + \
    (1) + HMM_NUM_STATES * sizeof(float) + \
    (1) + HMM_NUM_STATES * ((1) + HMM_NUM_STATES * sizeof(float)) + \
    (1) + HMM_NUM_STATES * ((1) + HMM_NUM_OBSERVATIONS * sizeof(float)) \
)
/*-------------------------------------------------------------------------------------------------------------------*/
void hmm_init_default(hmm_t* hmm);
/*-------------------------------------------------------------------------------------------------------------------*/
void hmm_update(hmm_t* hmm, hmm_observations_t ob, bool first);
float hmm_one_observation_probability(const hmm_t* hmm, hmm_observations_t ob);
float hmm_observation_probability(const hmm_t* hmm, hmm_observations_t ob, const interaction_history_t* prev_obs);
/*-------------------------------------------------------------------------------------------------------------------*/
int hmm_serialise(nanocbor_encoder_t* enc, const hmm_t* hmm);
int hmm_deserialise(nanocbor_value_t* dec, hmm_t* hmm);
/*-------------------------------------------------------------------------------------------------------------------*/
void hmm_print(const hmm_t* hmm);
/*-------------------------------------------------------------------------------------------------------------------*/
