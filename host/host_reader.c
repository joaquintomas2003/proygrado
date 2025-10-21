#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <signal.h>

#include "nfp.h"
#include "nfp_cpp.h"
#include "nfp_nffw.h"
#include "nfp-common/nfp_resid.h"

#include "ring_defs.h"
#include "event_ring_worker.h"
#include "spooler.h"
#include "event_spooler.h"

volatile int stop = 0;
int debug = 0;

static void interrupt_handler(int dummy) {
    (void)dummy;
    stop = 1;
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "D")) != -1) {
        switch (opt) {
            case 'D': debug = 1; break;
            default:
                fprintf(stderr, "Usage: %s [-D]    Enable debug mode (shows detailed output)\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    signal(SIGINT, interrupt_handler);

    /* ---- Spooler startup (queue + spool thread) ---- */
    spooler_init();
    spooler_start();
    event_spooler_init();
    event_spooler_start();

    struct nfp_device *h_nfp = NULL;
    struct nfp_cpp *h_cpp = NULL;
    const struct nfp_rtsym *rtsym_ring_buffer_G = NULL;
    const struct nfp_rtsym *rtsym_ring_G = NULL;
    const struct nfp_rtsym *rtsym_ring_buffer_I = NULL;
    const struct nfp_rtsym *rtsym_ring_I = NULL;

    struct nfp_cpp_area *area_rings_G[NUM_RINGS];
    struct nfp_cpp_area *area_ring_metas_G[NUM_RINGS];
    struct nfp_cpp_area *area_rings_I[NUM_RINGS];
    struct nfp_cpp_area *area_ring_metas_I[NUM_RINGS];

    memset(area_rings_G, 0, sizeof(area_rings_G));
    memset(area_ring_metas_G, 0, sizeof(area_ring_metas_G));
    memset(area_rings_I, 0, sizeof(area_rings_I));
    memset(area_ring_metas_I, 0, sizeof(area_ring_metas_I));

    int ret = 0;

    /* 1. Open NFP device and get CPP handle */
    h_nfp = nfp_device_open(0);
    if (!h_nfp) {
        fprintf(stderr, "Error: Failed to open NFP device (%s)\n", strerror(errno));
        ret = 1;
        goto exit_spooler_stop;
    }

    h_cpp = nfp_device_cpp(h_nfp);
    if (!h_cpp) {
        fprintf(stderr, "Error: Failed to get CPP handle (%s)\n", strerror(errno));
        ret = 1;
        goto exit_cleanup_nfp_device;
    }

    /* 2. Look up runtime symbols */
    rtsym_ring_buffer_G = nfp_rtsym_lookup(h_nfp, "_ring_buffer_G");
    if (!rtsym_ring_buffer_G) { fprintf(stderr, "Error: Could not find 'ring_buffer_G' (%s)\n", strerror(errno)); ret = 1; goto exit_cleanup_nfp_device; }

    rtsym_ring_buffer_I = nfp_rtsym_lookup(h_nfp, "_ring_buffer_I");
    if (!rtsym_ring_buffer_I) { fprintf(stderr, "Error: Could not find 'ring_buffer_I' (%s)\n", strerror(errno)); ret = 1; goto exit_cleanup_nfp_device; }

    rtsym_ring_G = nfp_rtsym_lookup(h_nfp, "_ring_G");
    if (!rtsym_ring_G) { fprintf(stderr, "Error: Could not find 'ring_G' (%s)\n", strerror(errno)); ret = 1; goto exit_cleanup_nfp_device; }

    rtsym_ring_I = nfp_rtsym_lookup(h_nfp, "_ring_I");
    if (!rtsym_ring_I) { fprintf(stderr, "Error: Could not find 'ring_I' (%s)\n", strerror(errno)); ret = 1; goto exit_cleanup_nfp_device; }

    /* 3. Allocate CPP areas */
    for (int i = 0; i < NUM_RINGS; i++) {
        /* G rings */
        uint64_t off_rb_g  = rtsym_ring_buffer_G->addr + ((uint64_t)i * sizeof(ring_list));
        uint32_t cpp_rb_g  = NFP_CPP_ISLAND_ID(rtsym_ring_buffer_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_buffer_G->domain);
        area_rings_G[i]    = nfp_cpp_area_alloc_acquire(h_cpp, cpp_rb_g, off_rb_g, sizeof(ring_list));
        if (!area_rings_G[i]) { fprintf(stderr, "Error: CPP area for ring buffer G %d\n", i+1); ret = 1; goto exit_cleanup_areas; }

        /* I rings */
        uint64_t off_rb_i  = rtsym_ring_buffer_I->addr + ((uint64_t)i * sizeof(event_ring_list));
        uint32_t cpp_rb_i  = NFP_CPP_ISLAND_ID(rtsym_ring_buffer_I->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_buffer_I->domain);
        area_rings_I[i]    = nfp_cpp_area_alloc_acquire(h_cpp, cpp_rb_i, off_rb_i, sizeof(event_ring_list));
        if (!area_rings_I[i]) { fprintf(stderr, "Error: CPP area for ring buffer I %d\n", i+1); ret = 1; goto exit_cleanup_areas; }

        /* G ring metas */
        uint64_t off_meta_g = rtsym_ring_G->addr + ((uint64_t)i * sizeof(ring_meta));
        uint32_t cpp_meta_g = NFP_CPP_ISLAND_ID(rtsym_ring_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_G->domain);
        area_ring_metas_G[i]= nfp_cpp_area_alloc_acquire(h_cpp, cpp_meta_g, off_meta_g, sizeof(ring_meta));
        if (!area_ring_metas_G[i]) { fprintf(stderr, "Error: CPP area for ring meta G %d\n", i+1); ret = 1; goto exit_cleanup_areas; }

        /* I ring metas */
        uint64_t off_meta_i = rtsym_ring_I->addr + ((uint64_t)i * sizeof(ring_meta));
        uint32_t cpp_meta_i = NFP_CPP_ISLAND_ID(rtsym_ring_I->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_I->domain);
        area_ring_metas_I[i]= nfp_cpp_area_alloc_acquire(h_cpp, cpp_meta_i, off_meta_i, sizeof(ring_meta));
        if (!area_ring_metas_I[i]) { fprintf(stderr, "Error: CPP area for ring meta I %d\n", i+1); ret = 1; goto exit_cleanup_areas; }
    }

    /* 4. Start event-ring workers (I rings) */
    pthread_t threads_ring_I[NUM_RINGS];
    thread_arg_t args[NUM_RINGS];
    for (int i = 0; i < NUM_RINGS; i++) {
        args[i].ring_index = i;
        args[i].area_ring = area_rings_I[i];
        args[i].area_ring_meta = area_ring_metas_I[i];
        args[i].debug_flag = debug;

        if (pthread_create(&threads_ring_I[i], NULL, event_ring_worker, &args[i]) != 0) {
            perror("pthread_create failed");
            ret = 1;
            goto exit_cleanup_areas;
        }
    }

    /*********************** MAIN DRAIN LOOP *************************/
    printf("Starting to read all Ring buffers\n");
    if (debug) printf("\n---- Debug mode is active - detailed output enabled ----\n\n");

    unsigned long long loop_iteration = 0;
    while (!stop) {
        for (int i = 0; i < NUM_RINGS; i++) {
            ring_meta current_ring_meta;
            memset(&current_ring_meta, 0, sizeof(ring_meta));

            if (nfp_cpp_area_read(area_ring_metas_G[i], 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
                fprintf(stderr, "Error: Failed to read ring meta for ring %d in loop (%s)\n", i + 1, strerror(errno));
                ret = 1;
                goto exit_join_I_workers;
            }

            uint32_t wp = current_ring_meta.write_pointer;
            uint32_t rp = current_ring_meta.read_pointer;
            uint32_t full = current_ring_meta.full;

            if (debug) {
                printf("Ring %d - WP: %u, RP: %u, Full: %u\n", i + 1, wp, rp, full);
            }

            int j = 0;
            for (j = 0; j < BATCH_SIZE; j++) {
                /* ring empty? */
                if (rp == wp && !full) break;

                bucket_entry current_ring_entry;
                uint64_t offset_bucket_entry = (uint64_t)rp * sizeof(bucket_entry);
                if (nfp_cpp_area_read(area_rings_G[i], offset_bucket_entry, &current_ring_entry, sizeof(bucket_entry)) < 0) {
                    fprintf(stderr, "Error: Failed to read bucket entry from ring buffer %d.\n", i + 1);
                    ret = 1;
                    goto exit_join_I_workers;
                }

                if (!spooler_enqueue(&current_ring_entry)) {
                    /* If stop is set while waiting, break gracefully */
                    break;
                }

                if (debug) {
                    printf("\n================ BUCKET ENTRY [%u] ================\n", rp);

                    printf("Key Flow: [%u, %u, %u, %u]\n",
                        current_ring_entry.key[0],
                        current_ring_entry.key[1],
                        current_ring_entry.key[2],
                        current_ring_entry.key[3]);

                    printf("First Packet Timestamp: %lu ns\n",
                        ((uint64_t)current_ring_entry.first_packet_ts_high << 32) | current_ring_entry.first_packet_ts_low);

                    printf("Last Update Timestamp : %lu ns\n",
                        ((uint64_t)current_ring_entry.last_update_ts_high << 32)  | current_ring_entry.last_update_ts_low);

                    printf("Packet Count          : %u\n", current_ring_entry.packet_count);

                    // uint16_t request_id = current_ring_entry.request_meta & 0xFFFF;
                    // uint8_t  is_response = (current_ring_entry.request_meta >> 16) & 0x1;

                    // printf("Request Meta          : 0x%08X (request_id=%u, is_response=%u)\n",
                    //     current_ring_entry.request_meta, request_id, is_response);

                    printf("Node Count            : %u\n", current_ring_entry.int_metric_info_value.node_count);

                    printf("\n-- Latest Metrics --\n");
                    for (uint32_t n = 0; n < current_ring_entry.int_metric_info_value.node_count; n++) {
                        printf("  Node[%u]: id=%u, hop_latency=%u, queue_occupancy=%u, egress_tx=%u\n",
                            n,
                            current_ring_entry.int_metric_info_value.latest[n].node_id,
                            current_ring_entry.int_metric_info_value.latest[n].hop_latency,
                            current_ring_entry.int_metric_info_value.latest[n].queue_occupancy,
                            current_ring_entry.int_metric_info_value.latest[n].egress_interface_tx);
                    }

                    printf("\n-- Average Metrics --\n");
                    for (uint32_t n = 0; n < current_ring_entry.int_metric_info_value.node_count; n++) {
                        printf("  Node[%u]: id=%u, hop_latency=%u, queue_occupancy=%u, egress_tx=%u\n",
                            n,
                            current_ring_entry.int_metric_info_value.average[n].node_id,
                            current_ring_entry.int_metric_info_value.average[n].hop_latency,
                            current_ring_entry.int_metric_info_value.average[n].queue_occupancy,
                            current_ring_entry.int_metric_info_value.average[n].egress_interface_tx);
                    }

                    printf("====================================================\n\n");
                }

                rp = (rp + 1) & (RING_SIZE - 1);
                if (debug) usleep(200000);
            }

            /* Advance read pointer if we consumed anything */
            if (j > 0) {
                if (full) full = 0;
                current_ring_meta.write_pointer = wp;
                current_ring_meta.read_pointer  = rp;
                current_ring_meta.full          = full;
                if (nfp_cpp_area_write(area_ring_metas_G[i], 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
                    fprintf(stderr, "Error: Failed to write updated ring meta for ring %d (%s)\n", i + 1, strerror(errno));
                    ret = 1;
                    goto exit_join_I_workers;
                }
            }

            if (debug && j != 0) printf("  Processed %d entries from ring %d in iteration %llu\n\n", j, i + 1, loop_iteration);
        }

        if (debug) usleep(200000);
        loop_iteration++;
    }
    /*****************************************************************/

exit_join_I_workers:
    for (int i = 0; i < NUM_RINGS; i++) {
        pthread_join(threads_ring_I[i], NULL);
    }

exit_cleanup_areas:
    for (int i = 0; i < NUM_RINGS; i++) {
        if (area_ring_metas_G[i]) { nfp_cpp_area_release_free(area_ring_metas_G[i]); }
        if (area_rings_G[i])      { nfp_cpp_area_release_free(area_rings_G[i]); }
        if (area_ring_metas_I[i]) { nfp_cpp_area_release_free(area_ring_metas_I[i]); }
        if (area_rings_I[i])      { nfp_cpp_area_release_free(area_rings_I[i]); }
    }

exit_cleanup_nfp_device:
    if (h_nfp) { nfp_device_close(h_nfp); }

exit_spooler_stop:
    spooler_stop();

    return ret;
}
