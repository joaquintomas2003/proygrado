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
    int ring           = targ->ring_index;
    int debug_flag     = targ->debug_flag;

    unsigned long long loop_iteration = 0;
    if (debug_flag) printf("\n---- Debug mode is active - detailed output enabled ----\n\n");

    while (!stop) {
        ring_meta current_ring_meta;
        memset(&current_ring_meta, 0, sizeof(ring_meta));

        if (nfp_cpp_area_read(targ->area_ring_meta, 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
            fprintf(stderr, "Error: Failed to read ring meta for ring %d\n", ring + 1);
            break;
        }
        uint32_t wp   = current_ring_meta.write_pointer;
        uint32_t rp   = current_ring_meta.read_pointer;
        uint32_t full = current_ring_meta.full;

        if (debug_flag) printf("Ring %d - WP: %u, RP: %u, Full: %u\n", ring + 1, wp, rp, full);

        int j = 0;

        for (j = 0; j < BATCH_SIZE; j++) {
            /* ring empty? */
            if (rp == wp && !full) break;

            event_record current_ring_entry;
            uint64_t offset_event_record = (uint64_t)rp * sizeof(event_record);
            if (nfp_cpp_area_read(targ->area_ring, offset_event_record, &current_ring_entry, sizeof(event_record)) < 0) {
                fprintf(stderr, "Error: Failed to read event record from ring buffer %d.\n", ring + 1);
                return NULL;
            }

            if (!event_spooler_enqueue(&current_ring_entry)) {
                /* If stop is set while waiting, break gracefully */
                break;
            }

            if (debug_flag) {
                printf("\n===== EVENT RECORD [%u] =====\n", rp);
                printf("Switch ID      : %u\n", current_ring_entry.switch_id);
                printf("Value          : %u\n", current_ring_entry.value);
                printf("Event Bitmap   : %u\n", current_ring_entry.event_bitmap);
                uint32_t ts_high = current_ring_entry.event_ts_high;
                uint32_t ts_low  = current_ring_entry.event_ts_low;
                uint64_t event_timestamp = ((uint64_t)ts_high << 32) | ts_low;
                printf("Event TS : %lu\n", event_timestamp);
                printf("==============================\n");
            }
            rp = (rp + 1) & (RING_SIZE - 1);
            if (debug_flag) usleep(200000);
        }
        /* Advance read pointer if we consumed anything */
        if (j > 0) {
            if (full) full = 0;
            current_ring_meta.write_pointer = wp;
            current_ring_meta.read_pointer  = rp;
            current_ring_meta.full          = full;
            if (nfp_cpp_area_write(targ->area_ring_meta, 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
                fprintf(stderr, "Error: Failed to write updated ring meta for ring %d (%s)\n", ring + 1, strerror(errno));
                stop = 1;
                return NULL;
            }
        }
        if (debug_flag && j != 0) printf("  Processed %d entries from ring %d in iteration %llu\n\n", j, ring + 1, loop_iteration);
        if (debug_flag) usleep(1000000);
        loop_iteration++;
    }
    return NULL;
}