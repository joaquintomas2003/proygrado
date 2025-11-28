#ifndef EVENT_RING_WORKER_H
#define EVENT_RING_WORKER_H

#include "nfp.h"
#include "nfp_cpp.h"
#include "nfp_nffw.h"
#include "nfp-common/nfp_resid.h"

typedef struct {
    int ring_start;
    int ring_end;
    struct nfp_cpp_area **area_rings;
    struct nfp_cpp_area **area_ring_metas;
    int debug_flag;
} thread_arg_t;

void *event_ring_worker(void *arg);

#endif