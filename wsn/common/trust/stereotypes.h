#pragma once

#include "stereotype-tags.h"
#include "trust-model.h"

// This should be the maximum number of tag combinations
// Likely to get big, so try to keep small
#ifndef MAX_NUM_STEREOTYPES
#define MAX_NUM_STEREOTYPES 5
#endif

/*-------------------------------------------------------------------------------------------------------------------*/
typedef struct edge_stereotype {
    struct edge_stereotype* next;

    stereotype_tags_t tags;

    edge_resource_tm_t edge_tm;

    // TODO: Could consider edge capability stereotypes,
    // for now focus on the edge stereotypes only.

} edge_stereotype_t;
/*-------------------------------------------------------------------------------------------------------------------*/
void stereotypes_init(void);
/*-------------------------------------------------------------------------------------------------------------------*/
bool stereotypes_request(const stereotype_tags_t* tags);
/*-------------------------------------------------------------------------------------------------------------------*/
edge_stereotype_t* edge_stereotype_find(const stereotype_tags_t* tags);
/*-------------------------------------------------------------------------------------------------------------------*/
bool edge_stereotype_remove(edge_stereotype_t* stereotype);
/*-------------------------------------------------------------------------------------------------------------------*/
