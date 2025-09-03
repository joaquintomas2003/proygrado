#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>
#include <pthread.h>
#include <getopt.h>

#include "nfp.h"
#include "nfp_cpp.h"
#include "nfp_nffw.h"
#include "nfp-common/nfp_resid.h"

#include "ring_defs.h"
#include "event_ring_worker.h"

volatile int stop = 0;
int debug = 0;

void interrupt_handler(int dummy) {
    (void)dummy;
    stop = 1;
}

uint32_t hash_me_crc32(const uint32_t key[4]) {
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)key, 4*4);
    return (uint32_t)(crc & (FLOWCACHE_ROWS - 1));
}

int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "D")) != -1) {
        switch (opt) {
            case 'D':
                debug = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-D]    Enable debug mode (shows detailed output)\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

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

    bucket_list *int_flowcache = malloc(FLOWCACHE_ROWS * sizeof(bucket_list));
    memset(int_flowcache, 0, sizeof(int_flowcache));

    uint32_t hash_key[4];
    volatile uint32_t hash_value;

    signal(SIGINT, interrupt_handler);

    int ret = 0;

    /* 1. Open NFP device and get CPP handle */
    h_nfp = nfp_device_open(0);
    if (!h_nfp) {
        fprintf(stderr, "Error: Failed to open NFP device (%s)\n", strerror(errno));
        return 1;
    }

    h_cpp = nfp_device_cpp(h_nfp);
    if (!h_cpp) {
        fprintf(stderr, "Error: Failed to get CPP handle (%s)\n", strerror(errno));
        ret = 1;
        goto exit_cleanup_nfp_device;
    }

    /* 2. Look up the runtime symbol for ring_buffer_G and ring_buffer_I */
    rtsym_ring_buffer_G = nfp_rtsym_lookup(h_nfp, "_ring_buffer_G");
    if (!rtsym_ring_buffer_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_buffer_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit_cleanup_nfp_device;
    }

    rtsym_ring_buffer_I = nfp_rtsym_lookup(h_nfp, "_ring_buffer_I");
    if (!rtsym_ring_buffer_I) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_buffer_I' (%s)\n", strerror(errno));
        ret = 1;
        goto exit_cleanup_nfp_device;
    }

    /* 2.5. Look up the runtime symbol for ring_G and ring_I */
    rtsym_ring_G = nfp_rtsym_lookup(h_nfp, "_ring_G");
    if (!rtsym_ring_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit_cleanup_nfp_device;
    }

    rtsym_ring_I = nfp_rtsym_lookup(h_nfp, "_ring_I");
    if (!rtsym_ring_I) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_I' (%s)\n", strerror(errno));
        ret = 1;
        goto exit_cleanup_nfp_device;
    }

    /* 3. Allocate and acquire CPP areas for all rings and their metadata */
    for (int i = 0; i < NUM_RINGS; i++) {
        /* General rings */
        uint64_t offset_ring_buffer_target = rtsym_ring_buffer_G->addr + ((uint64_t)i * sizeof(ring_list));
        uint32_t cpp_id_ring_buffer = NFP_CPP_ISLAND_ID(rtsym_ring_buffer_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_buffer_G->domain);

        area_rings_G[i] = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_buffer, offset_ring_buffer_target, sizeof(ring_list));
        if (!area_rings_G[i]) {
            fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring buffer G %d (%s)\n", i + 1, strerror(errno));
            ret = 1;
            goto exit_cleanup_areas;
        }

        /* Event rings */
        offset_ring_buffer_target = rtsym_ring_buffer_I->addr + ((uint64_t)i * sizeof(event_ring_list));
        cpp_id_ring_buffer = NFP_CPP_ISLAND_ID(rtsym_ring_buffer_I->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_buffer_I->domain);

        area_rings_I[i] = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_buffer, offset_ring_buffer_target, sizeof(event_ring_list));
        if (!area_rings_I[i]) {
            fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring buffer I %d (%s)\n", i + 1, strerror(errno));
            ret = 1;
            goto exit_cleanup_areas;
        }

        /*** Rings metadata ***/

         /* General rings */
        uint64_t offset_ring_meta_target = rtsym_ring_G->addr + ((uint64_t)i * sizeof(ring_meta));
        uint32_t cpp_id_ring_meta = NFP_CPP_ISLAND_ID(rtsym_ring_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_G->domain);

        area_ring_metas_G[i] = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_meta, offset_ring_meta_target, sizeof(ring_meta));
        if (!area_ring_metas_G[i]) {
            fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring meta G %d (%s)\n", i + 1, strerror(errno));
            ret = 1;
            goto exit_cleanup_areas;
        }

        /* Event rings*/
        offset_ring_meta_target = rtsym_ring_I->addr + ((uint64_t)i * sizeof(event_ring_list));
        cpp_id_ring_meta = NFP_CPP_ISLAND_ID(rtsym_ring_I->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_I->domain);

        area_ring_metas_I[i] = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_meta, offset_ring_meta_target, sizeof(event_ring_list));
        if (!area_ring_metas_I[i]) {
            fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring meta I %d (%s)\n", i + 1, strerror(errno));
            ret = 1;
            goto exit_cleanup_areas;
        }
    }

    pthread_t threads_ring_I[NUM_RINGS];
    thread_arg_t args[NUM_RINGS];
    for (int i = 0; i < NUM_RINGS; i++) {
        args[i].ring_index = i;
        args[i].area_ring = area_rings_I[i];
        args[i].area_ring_meta = area_ring_metas_I[i];

        if (pthread_create(&threads_ring_I[i], NULL, event_ring_worker, &args[i]) != 0) {
            perror("pthread_create failed");
            ret = 1;
            goto exit_cleanup_areas;
        }
    }
    /**************************************************************************************************************************/

    printf("Starting to read all Ring buffers\n");
    if (debug) printf("\n----Debug mode is active - detailed output enabled----\n\n");

    unsigned long long loop_iteration = 0;
    while (!stop) {
        for (int i = 0; i < NUM_RINGS; i++) {
            ring_meta current_ring_meta;
            memset(&current_ring_meta, 0, sizeof(ring_meta));

            if (nfp_cpp_area_read(area_ring_metas_G[i], 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
                fprintf(stderr, "Error: Failed to read ring meta for ring %d in loop (%s)\n", i + 1, strerror(errno));
                ret = 1;
                goto exit_cleanup_areas;
            }

            uint32_t wp = current_ring_meta.write_pointer;
            uint32_t rp = current_ring_meta.read_pointer;
            uint32_t full = current_ring_meta.full;
            if (debug) {
                printf("Ring %d - WP: %u, RP: %u, Full: %u\n", i + 1, wp, rp, full);
            }
            int j = 0;
            for (j = 0; j < BATCH_SIZE; j++) {

                /* Contrl if ring is empty */
                if (rp == wp && !full) { break; }

                bucket_entry current_ring_entry;
                uint64_t offset_bucket_entry = (uint64_t)rp * sizeof(bucket_entry);
                if (nfp_cpp_area_read(area_rings_G[i], offset_bucket_entry, &current_ring_entry, sizeof(bucket_entry)) < 0) {
                    fprintf(stderr, "Error: Failed to read bucket entry from ring buffer %d.\n",
                            i + 1, offset_bucket_entry, strerror(errno));
                    ret = 1;
                    goto exit_cleanup_areas;
                }

                hash_key[0] = current_ring_entry.key[0];
                hash_key[1] = current_ring_entry.key[1];
                hash_key[2] = current_ring_entry.key[2];
                hash_key[3] = current_ring_entry.key[3];
                hash_value = hash_me_crc32(hash_key);

                if (debug) {
                    printf("  Entry[%u] Key Flow: [%u, %u, %u, %u]\n", rp,
                            current_ring_entry.key[0],
                            current_ring_entry.key[1],
                            current_ring_entry.key[2],
                            current_ring_entry.key[3]);
                }

                /* Linear probing */
                int k = 0;
                while (int_flowcache[hash_value + k].entry[0].packet_count != 0) {
                    k++;
                }
                memcpy(&int_flowcache[hash_value + k].entry[0], &current_ring_entry, sizeof(bucket_entry));
                if (debug) {
                    printf("  Hop Latency: %u | Queue Occupancy: %u\n\n", 
                            int_flowcache[hash_value + k].entry[0].int_metric_info_value.average[0].hop_latency,
                            int_flowcache[hash_value + k].entry[0].int_metric_info_value.average[0].queue_occupancy);
                }
                rp = (rp + 1) & (RING_SIZE - 1);

                if (debug) usleep(1000000); // Sleep for 1s
            }
            if (j > 0) {
                if (full) { full = 0; }
                current_ring_meta.read_pointer = rp;
                current_ring_meta.full = full;
                if (nfp_cpp_area_write(area_ring_metas_G[i], 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
                    fprintf(stderr, "Error: Failed to write updated ring meta for ring %d (%s)\n", i + 1, strerror(errno));
                    ret = 1;
                    goto exit_cleanup_areas;
                }
            }
            if (debug) printf("  Processed %d entries from ring %d in iteration %llu\n\n", j, i + 1, loop_iteration);
        }
        if (debug) usleep(3000000); // Sleep for 3s
    }

    for (int i = 0; i < NUM_RINGS; i++) {
        pthread_join(threads_ring_I[i], NULL);
    }

exit_cleanup_areas:
    for (int i = 0; i < NUM_RINGS; i++) {
        if (area_ring_metas_G[i]) { nfp_cpp_area_release_free(area_ring_metas_G[i]); }
        if (area_rings_G[i]) { nfp_cpp_area_release_free(area_rings_G[i]); }
    }

exit_cleanup_nfp_device:
    if (h_nfp) { nfp_device_close(h_nfp); }
    return ret;
}