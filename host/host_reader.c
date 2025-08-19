#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "nfp.h"
#include "nfp_cpp.h"
#include "nfp_nffw.h"
#include "nfp-common/nfp_resid.h"

#define MAX_INT_NODES 5
#define NUM_RINGS 8
#define RING_SIZE (1 << 16) // 65536

typedef struct int_metric_sample {
    uint32_t node_id;
    uint32_t hop_latency;
    uint32_t queue_occupancy;
    uint32_t egress_interface_tx;
} int_metric_sample;

typedef struct int_metric_info {
    int_metric_sample latest[MAX_INT_NODES];
    int_metric_sample average[MAX_INT_NODES];
    uint32_t node_count;
} int_metric_info;

// Explicit padding to match NFP's default layout, based on the NFP compiler's default padding rules:
// - 4-byte padding is needed after 'packet_count' to align 'last_update_timestamp' (uint64_t) to an 8-byte boundary.
// - 4-byte tail padding is needed at the end to make the total structure size 200 bytes.
typedef struct bucket_entry {
    uint32_t key[4];                       // 16 bytes
    uint32_t packet_count;                 // 4 bytes (Total 20 bytes so far)
    uint32_t _padding1;
    uint64_t last_update_timestamp;        // 8 bytes (Total 20 + 4 + 8 = 32 bytes so far)
    int_metric_info int_metric_info_value; // 164 bytes (Total 32 + 164 = 196 bytes so far)
    uint32_t _padding2;                    // Tail padding to make total size 200 bytes (196 -> 200)
} bucket_entry;

typedef struct ring_list {
    struct bucket_entry entry[RING_SIZE];
} ring_list;

typedef struct ring_meta {
    uint32_t write_pointer;
    uint32_t read_pointer;
    uint32_t full;
    uint32_t _padding1; // Padding to ensure 16-byte alignment
} ring_meta;

int main(int argc, char *argv[]) {
    struct nfp_device *h_nfp = NULL;
    struct nfp_cpp *h_cpp = NULL;
    const struct nfp_rtsym *rtsym_ring_buffer_G = NULL;
    const struct nfp_rtsym *rtsym_ring_G = NULL;
    struct nfp_cpp_area *area_ring = NULL;
    struct nfp_cpp_area *area_ring_meta = NULL;
    struct bucket_entry *ring_entry = 0;

    int ret = 0;

    int TARGET_RING_INDEX = 0;

    if (argc > 1) {
        TARGET_RING_INDEX = atoi(argv[1]) - 1;
        if (TARGET_RING_INDEX < 0 || TARGET_RING_INDEX >= NUM_RINGS) {
            fprintf(stderr, "Error: Target Ring Number must be between 0 < n < 9\n");
            return 1;
        }
    }

    // 1. Open NFP device and get CPP handle
    h_nfp = nfp_device_open(0);
    if (!h_nfp) {
        fprintf(stderr, "Error: Failed to open NFP device (%s)\n", strerror(errno));
        return 1;
    }

    h_cpp = nfp_device_cpp(h_nfp); // Get CPP handle
    if (!h_cpp) {
        fprintf(stderr, "Error: Failed to get CPP handle (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }

    // 2. Look up the runtime symbol for ring_buffer_G
    rtsym_ring_buffer_G = nfp_rtsym_lookup(h_nfp, "_ring_buffer_G");
    if (!rtsym_ring_buffer_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_buffer_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }

    printf("Found symbol 'ring_buffer_G': Address=0x%llx, Size=%llu bytes, Target=%d, Domain=%d\n",
           rtsym_ring_buffer_G->addr, rtsym_ring_buffer_G->size, rtsym_ring_buffer_G->target, rtsym_ring_buffer_G->domain);

    // 2.5. Look up the runtime symbol for ring_G
    rtsym_ring_G = nfp_rtsym_lookup(h_nfp, "_ring_G");
    if (!rtsym_ring_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }

    printf("Found symbol 'ring_G': Address=0x%llx, Size=%llu bytes, Target=%d, Domain=%d\n",
           rtsym_ring_G->addr, rtsym_ring_G->size, rtsym_ring_G->target, rtsym_ring_G->domain);

    // 3. Calculate the specific offset for target ring and construct the CPP ID
    uint64_t offset_ring_buffer_target = rtsym_ring_buffer_G->addr + (TARGET_RING_INDEX * sizeof(ring_list));
    uint32_t cpp_id = NFP_CPP_ISLAND_ID(rtsym_ring_buffer_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_buffer_G->domain);

    printf("\nTargeting Ring Number: %d (0-indexed: %d)\n", TARGET_RING_INDEX + 1, TARGET_RING_INDEX);
    printf("Calculated Offset for Ring Buffer %d: 0x%llx\n", TARGET_RING_INDEX + 1, offset_ring_buffer_target);
    printf("Size of Ring Buffer %d: %zu bytes\n", TARGET_RING_INDEX + 1, sizeof(ring_list));
    printf("Constructed CPP ID for Ring Buffer %d: 0x%x (Target: %u, Island: %u)\n",
           TARGET_RING_INDEX + 1,
           cpp_id,
           NFP_CPP_ID_TARGET_of(cpp_id), // Extract target from CPP ID
           NFP_CPP_ID_ISLAND_of(cpp_id)); // Extract island from CPP ID

    // Calculate offset and CPP ID for the target ring_meta
    uint64_t offset_ring_meta_target = rtsym_ring_G->addr + (TARGET_RING_INDEX * sizeof(ring_meta));
    uint32_t cpp_id_ring_meta_target = NFP_CPP_ISLAND_ID(rtsym_ring_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_G->domain);

    printf("Calculated Offset for Ring Meta %d: 0x%llx\n", TARGET_RING_INDEX + 1, offset_ring_meta_target);
    printf("Size of Ring Meta %d: %zu bytes\n", TARGET_RING_INDEX + 1, sizeof(ring_meta));
    printf("Constructed CPP ID for Ring Meta %d: 0x%x (Target: %u, Island: %u)\n",
           TARGET_RING_INDEX + 1,
           cpp_id_ring_meta_target,
           NFP_CPP_ID_TARGET_of(cpp_id_ring_meta_target),
           NFP_CPP_ID_ISLAND_of(cpp_id_ring_meta_target));

    // 4. Allocate and acquire the CPP area for ring_buffer_G
    area_ring = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id, offset_ring_buffer_target, sizeof(ring_list));
    if (!area_ring) {
        fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring buffer %d (%s)\n", TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto exit;
    }
    printf("Successfully allocated and acquired CPP area for ring buffer %d.\n", TARGET_RING_INDEX + 1);

    // Allocate and acquire the CPP area for ring_meta_G
    area_ring_meta = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_meta_target, offset_ring_meta_target, sizeof(ring_meta));
    if (!area_ring_meta) {
        fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring meta %d (%s)\n", TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto free_area_ring_buffer; // Jump to cleanup area_ring if this fails
    }
    printf("Successfully allocated and acquired CPP area for ring meta %d.\n", TARGET_RING_INDEX + 1);

    /**************************************************************************************************************************/

    printf("\nStarting to read ring buffer %d in a loop.\n", TARGET_RING_INDEX + 1);

    unsigned long long loop_iteration = 0;
    while (1) {
        ring_meta current_ring_meta;
        if (nfp_cpp_area_read(area_ring_meta, 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
            fprintf(stderr, "Error: Failed to read ring meta in loop (%s)\n", strerror(errno));
            break;
        }

        uint32_t wp = current_ring_meta.write_pointer;
        uint32_t rp = current_ring_meta.read_pointer;
        uint32_t f = current_ring_meta.full;

        // Check if the ring is empty
        if (rp == wp && f == 0) {
            printf("\nRing %d is currently empty (WP=%u, RP=%u, Full=%u). Waiting for new data...\n",
                   TARGET_RING_INDEX + 1, wp, rp, f);
            usleep(1000000); // Sleep for 1ms before checking again
            continue;
        }

        // The ring has data
        printf("\nIteration %llu: (WP=%u, RP=%u, Full=%u)\n", loop_iteration++, wp, rp, f);

        bucket_entry current_ring_entry;
        uint64_t offset_bucket_entry = (uint64_t)rp * sizeof(bucket_entry);

        // Read the specific bucket_entry from NFP using nfp_cpp_area_read
        if (nfp_cpp_area_read(area_ring, offset_bucket_entry, &current_ring_entry, sizeof(bucket_entry)) < 0) {
            fprintf(stderr, "Error: Failed to read bucket entry from ring buffer %d at offset 0x%llx (%s)\n",
                    TARGET_RING_INDEX + 1, offset_bucket_entry, strerror(errno));
            break;
        }

        uint32_t entry_packet_count = current_ring_entry.packet_count;
        uint64_t entry_last_update_timestamp = current_ring_entry.last_update_timestamp;
        uint32_t entry_node_count = current_ring_entry.int_metric_info_value.node_count;

        printf(" Read Entry[RP=%u]: PacketCount=%u, Last Update Timestamp=%llu, NodeCount=%u\n",
               rp, entry_packet_count, entry_last_update_timestamp, entry_node_count);

        printf(" Entry[%u] Key Flow: [%u, %u, %u, %u]\n", rp,
                current_ring_entry.key[0],
                current_ring_entry.key[1],
                current_ring_entry.key[2],
                current_ring_entry.key[3]);

        // Advance the read_pointer
        rp = (rp + 1) & (RING_SIZE - 1);
        if (f == 1 && rp == wp) {
            f = 0;
        } else if (f == 1 && rp != wp) {
            f = 0;
        }

        // Write back the updated read_pointer and full flag to ring_meta
        current_ring_meta.read_pointer = rp;
        current_ring_meta.full = f;
        if (nfp_cpp_area_write(area_ring_meta, 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
            fprintf(stderr, "Error: Failed to write updated ring meta (%s)\n", strerror(errno));
            break;
        }

        printf(" Updated ring_meta: RP=%u, Full=%u.\n", current_ring_meta.read_pointer, current_ring_meta.full);
        usleep(200000); // Sleep for 200ms before attempting to read the next entry
    }

free_area_meta:
    // 5. Release and free the CPP area for ring_meta
    if (area_ring_meta) {
        nfp_cpp_area_release_free(area_ring_meta);
        printf("Released and freed CPP area for ring meta %d.\n", TARGET_RING_INDEX + 1);
    }

free_area_ring_buffer:
    // 6. Release and free the CPP area for ring_buffer_G
    if (area_ring) {
        nfp_cpp_area_release_free(area_ring);
        printf("Released and freed CPP area for ring buffer %d.\n", TARGET_RING_INDEX + 1);
    }

exit:
    if (h_nfp) {
        nfp_device_close(h_nfp);
        printf("Closed NFP device.\n");
    }

    return ret;
}