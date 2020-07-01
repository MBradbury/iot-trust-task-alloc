#include "trust-model.h"
#include <stdio.h>
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_init(edge_resource_tm_t* tm)
{
    beta_dist_init(&tm->task_submission, 1, 1);
    beta_dist_init(&tm->task_result, 1, 1);

    poisson_observation_init(&tm->announce);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_resource_tm_print(const edge_resource_tm_t* tm)
{
    printf("EdgeResourceTM(TaskSub=");
    dist_print(&tm->task_submission);
    printf(",TaskRes=");
    dist_print(&tm->task_result);
    printf(",Announce=");
    dist_print(&tm->announce);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_init(edge_capability_tm_t* tm, float expected_latency_mean, float expected_latency_variance)
{
    beta_dist_init(&tm->result_quality, 1, 1);
    gaussian_dist_init(&tm->latency, expected_latency_mean, expected_latency_variance);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void edge_capability_tm_print(const edge_capability_tm_t* tm)
{
    printf("EdgeResourceTM(ResQual=");
    dist_print(&tm->result_quality);
    printf(",Latency=");
    dist_print(&tm->latency);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_init(peer_tm_t* tm)
{
    beta_dist_init(&tm->task_observation, 1, 1);
}
/*-------------------------------------------------------------------------------------------------------------------*/
void peer_tm_print(const peer_tm_t* tm)
{
    printf("EdgeResourceTM(TaskObserve=");
    dist_print(&tm->task_observation);
    printf(")");
}
/*-------------------------------------------------------------------------------------------------------------------*/
