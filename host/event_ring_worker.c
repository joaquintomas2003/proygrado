#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>

#include "event_ring_worker.h"
#include "ring_defs.h"

extern volatile int stop;

void *event_ring_worker(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    int ring = targ->ring_index;
    printf("Hi from thread for ring %d\n", ring + 1);
    while (!stop) {
        ring_meta current_ring_meta;
        memset(&current_ring_meta, 0, sizeof(ring_meta));

        if (nfp_cpp_area_read(targ->area_ring_meta, 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
            fprintf(stderr, "Error: Failed to read ring meta for ring %d\n", ring + 1);
            break;
        }

        /* Do procces here */
    }
    printf("Exiting thread for ring %d\n", ring + 1);
    return NULL;
}