#include "hmm.h"
#include "assert.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "trust-comm"
#ifdef TRUST_MODEL_LOG_LEVEL
#define LOG_LEVEL TRUST_MODEL_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
// Possibly useful: https://www.codeproject.com/articles/69647/hidden-markov-models-in-c
// https://github.com/sukhoy/nanohmm/blob/master/nanohmm.c
/*-------------------------------------------------------------------------------------------------------------------*/
#define PR_GOOD_GIVEN_TRUSTWORTHY 0.9f
#define PR_BAD_GIVEN_UNTRUSTWORTHY 0.9f
#define NUM_BAD_OBSERVATIONS (HMM_NUM_OBSERVATIONS - 1)
/*-------------------------------------------------------------------------------------------------------------------*/
void hmm_init_default(hmm_t* hmm)
{
    hmm->initial[HMM_STATE_EDGE_TRUSTWORTHY] = 0.8f;
    hmm->initial[HMM_STATE_EDGE_UNTRUSTWORTHY] = 0.2f;

    hmm->trans[HMM_STATE_EDGE_TRUSTWORTHY][HMM_STATE_EDGE_TRUSTWORTHY] = 0.8f;
    hmm->trans[HMM_STATE_EDGE_TRUSTWORTHY][HMM_STATE_EDGE_UNTRUSTWORTHY] = 0.2f;
    hmm->trans[HMM_STATE_EDGE_UNTRUSTWORTHY][HMM_STATE_EDGE_TRUSTWORTHY] = 0.8f;
    hmm->trans[HMM_STATE_EDGE_UNTRUSTWORTHY][HMM_STATE_EDGE_UNTRUSTWORTHY] = 0.2f;

    for (uint8_t i = 0; i != HMM_NUM_STATES; ++i)
    {
        for (uint8_t j = 0; j != HMM_NUM_OBSERVATIONS; ++j)
        {
            const bool good_state = i == HMM_STATE_EDGE_TRUSTWORTHY;
            const bool good_obs = j == HMM_OBS_TASK_RESULT_QUALITY_CORRECT;

            if (good_state)
            {
                if (good_obs)
                {
                    hmm->emission[i][j] = PR_GOOD_GIVEN_TRUSTWORTHY;
                }
                else
                {
                    hmm->emission[i][j] = (1.0f - PR_GOOD_GIVEN_TRUSTWORTHY) / NUM_BAD_OBSERVATIONS;
                }
            }
            else
            {
                if (good_obs)
                {
                    hmm->emission[i][j] = (1.0f - PR_BAD_GIVEN_UNTRUSTWORTHY);
                }
                else
                {
                    hmm->emission[i][j] = PR_BAD_GIVEN_UNTRUSTWORTHY / NUM_BAD_OBSERVATIONS;
                }
            }
        }
    }
}
/*-------------------------------------------------------------------------------------------------------------------*/
float hmm_observation_probability(const hmm_t* hmm, hmm_observations_t ob, const interaction_history_t* prev_obs)
{
    // Use the forward algorithm to solve
    // Based on pseudocode from: https://web.stanford.edu/~jurafsky/slp3/A.pdf

    float alpha[HMM_NUM_STATES][INTERACTION_HISTORY_SIZE+1];

    const uint8_t* obs = interaction_history_iter(prev_obs);
    assert(obs != NULL);

    // Initialisation
    for (uint8_t i = 0; i != HMM_NUM_STATES; ++i)
    {
        alpha[i][0] = hmm->initial[i] * hmm->emission[i][*obs];
    }

    // Recursion
    uint8_t t;
    for (t = 1; t < prev_obs->count; ++t)
    {
        obs = interaction_history_next(prev_obs, obs);
        assert(obs != NULL);

        for (uint8_t s1 = 0; s1 != HMM_NUM_STATES; ++s1)
        {
            alpha[s1][t] = 0.0f;

            for (uint8_t s2 = 0; s2 != HMM_NUM_STATES; ++s2)
            {
                // TODO: check order for s2 and s1

                alpha[s1][t] += alpha[s2][t-1] * hmm->trans[s2][s1] * hmm->emission[s1][*obs];
            }
        }
    }

    // Treat the additional observation as a member of the history list
    t = prev_obs->count;

    for (uint8_t s1 = 0; s1 != HMM_NUM_STATES; ++s1)
    {
        alpha[s1][t] = 0.0f;

        for (uint8_t s2 = 0; s2 != HMM_NUM_STATES; ++s2)
        {
            // TODO: check order for s2 and s1

            alpha[s1][t] += alpha[s2][t-1] * hmm->trans[s2][s1] * hmm->emission[s1][ob];
        }
    }

    // Termination
    float result = 0.0f;

    for (uint8_t s = 0; s != HMM_NUM_STATES; ++s)
    {
        result += alpha[s][t];
    }

    return result;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int hmm_serialise(nanocbor_encoder_t* enc, const hmm_t* hmm)
{
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, 3));

    // initial
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, HMM_NUM_STATES));
    for (int i = 0; i != HMM_NUM_STATES; ++i)
    {
        NANOCBOR_CHECK(nanocbor_fmt_float(enc, hmm->initial[i]));
    }

    // trans
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, HMM_NUM_STATES));
    for (int i = 0; i != HMM_NUM_STATES; ++i)
    {
        NANOCBOR_CHECK(nanocbor_fmt_array(enc, HMM_NUM_STATES));
        for (int j = 0; j != HMM_NUM_STATES; ++j)
        {
            NANOCBOR_CHECK(nanocbor_fmt_float(enc, hmm->trans[i][j]));
        }
    }

    // emission
    NANOCBOR_CHECK(nanocbor_fmt_array(enc, HMM_NUM_STATES));
    for (int i = 0; i != HMM_NUM_STATES; ++i)
    {
        NANOCBOR_CHECK(nanocbor_fmt_array(enc, HMM_NUM_OBSERVATIONS));
        for (int j = 0; j != HMM_NUM_OBSERVATIONS; ++j)
        {
            NANOCBOR_CHECK(nanocbor_fmt_float(enc, hmm->emission[i][j]));
        }
    }

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int hmm_deserialise(nanocbor_value_t* dec, hmm_t* hmm)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    // initial
    nanocbor_value_t sub_arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&arr, &sub_arr));
    for (int i = 0; i != HMM_NUM_STATES; ++i)
    {
        NANOCBOR_CHECK(nanocbor_get_float(&arr, &hmm->initial[i]));
    }

    if (!nanocbor_at_end(&sub_arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(&arr, &sub_arr);


    // trans
    NANOCBOR_CHECK(nanocbor_enter_array(&arr, &sub_arr));
    for (int i = 0; i != HMM_NUM_STATES; ++i)
    {
        nanocbor_value_t sub_arr2;
        NANOCBOR_CHECK(nanocbor_enter_array(&sub_arr, &sub_arr2));

        for (int j = 0; j != HMM_NUM_STATES; ++j)
        {
            NANOCBOR_CHECK(nanocbor_get_float(&arr, &hmm->trans[i][j]));
        }

        if (!nanocbor_at_end(&sub_arr2))
        {
            return NANOCBOR_ERR_END;
        }

        nanocbor_leave_container(&sub_arr, &sub_arr2);
    }

    if (!nanocbor_at_end(&sub_arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(&arr, &sub_arr);



    // emission
    NANOCBOR_CHECK(nanocbor_enter_array(&arr, &sub_arr));
    for (int i = 0; i != HMM_NUM_STATES; ++i)
    {
        nanocbor_value_t sub_arr2;
        NANOCBOR_CHECK(nanocbor_enter_array(&sub_arr, &sub_arr2));

        for (int j = 0; j != HMM_NUM_OBSERVATIONS; ++j)
        {
            NANOCBOR_CHECK(nanocbor_get_float(&arr, &hmm->emission[i][j]));
        }

        if (!nanocbor_at_end(&sub_arr2))
        {
            return NANOCBOR_ERR_END;
        }

        nanocbor_leave_container(&sub_arr, &sub_arr2);
    }

    if (!nanocbor_at_end(&sub_arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(&arr, &sub_arr);



    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
void hmm_print(const hmm_t* hmm)
{
    printf("HMM(pi=[");
    for (uint8_t i = 0; i != HMM_NUM_STATES; ++i)
    {
        printf("%f, ", hmm->initial[i]);
    }
    printf("],A=[");
    for (uint8_t i = 0; i != HMM_NUM_STATES; ++i)
    {
        printf("[");
        for (uint8_t j = 0; j != HMM_NUM_STATES; ++j)
        {
            printf("%f, ", hmm->trans[i][j]);
        }
        printf("],");
    }
    printf("],B=[");
    for (uint8_t i = 0; i != HMM_NUM_STATES; ++i)
    {
        printf("[");
        for (uint8_t j = 0; j != HMM_NUM_OBSERVATIONS; ++j)
        {
            printf("%f, ", hmm->emission[i][j]);
        }
        printf("],");
    }
    printf("]");
}
/*-------------------------------------------------------------------------------------------------------------------*/
