#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> // For usleep
#include <time.h>   // For clock_gettime (optional, for timing if needed)

// Include necessary NFP headers
#include "nfp.h"
#include "nfp_cpp.h"
#include "nfp_nffw.h"
#include "nfp-common/nfp_resid.h"

// Re-declare relevant structures and defines from main.txt for size calculation
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

typedef struct bucket_entry {
    uint32_t key[4]; // Added key[4] as per main.txt [1]
    uint32_t packet_count;
    uint64_t last_update_timestamp;
    int_metric_info int_metric_info_value;
} bucket_entry;

typedef struct ring_list {
    struct bucket_entry entry[RING_SIZE];
} ring_list;

// NEW: Define ring_meta structure from main.txt [1, 2]
typedef struct ring_meta {
    uint32_t write_pointer;
    uint32_t read_pointer;
    uint32_t full;
} ring_meta;

int main() {
    struct nfp_device *h_nfp = NULL;
    struct nfp_cpp *h_cpp = NULL;
    const struct nfp_rtsym *rtsym_ring_buffer_G = NULL;
    const struct nfp_rtsym *rtsym_ring_G = NULL; // NEW: Symbol for ring_G
    struct nfp_cpp_area *area_ring_7 = NULL;
    struct nfp_cpp_area *area_ring_meta_7 = NULL; // NEW: CPP area for ring_meta

    int ret = 0;

    // Calculate sizes based on definitions in main.txt
    const size_t SIZEOF_INT_METRIC_SAMPLE = sizeof(uint32_t) * 4; // 16 bytes
    const size_t SIZEOF_INT_METRIC_INFO = (2 * MAX_INT_NODES * SIZEOF_INT_METRIC_SAMPLE) + sizeof(uint32_t); // 164 bytes
    // Corrected SIZEOF_BUCKET_ENTRY to account for key[4] (4 uint32_t) and packet_count (1 uint32_t) + timestamp (1 uint64_t) + metric_info [1]
    const size_t SIZEOF_BUCKET_ENTRY = (sizeof(uint32_t) * 4) + sizeof(uint32_t) + sizeof(uint64_t) + SIZEOF_INT_METRIC_INFO; // 4*4 + 4 + 8 + 164 = 192 bytes
    const size_t SIZEOF_RING_LIST_ONE_RING = RING_SIZE * SIZEOF_BUCKET_ENTRY; // 65536 * 192 bytes

    // User requested ring number 7, which is index 6 in a 0-indexed array
    const int TARGET_RING_INDEX = 6; // MODIFIED: Changed from 1 to 6 as per request for "ring buffer 7"

    // 1. Open NFP device and get CPP handle
    h_nfp = nfp_device_open(0); // Open NFP device 0
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
    rtsym_ring_buffer_G = nfp_rtsym_lookup(h_nfp, "_ring_buffer_G"); // Lookup symbol
    if (!rtsym_ring_buffer_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_buffer_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }
    printf("Found symbol 'ring_buffer_G': Address=0x%llx, Size=%llu bytes, Target=%d, Domain=%d\n",
           rtsym_ring_buffer_G->addr, rtsym_ring_buffer_G->size, rtsym_ring_buffer_G->target, rtsym_ring_buffer_G->domain);

    // NEW: 2.5. Look up the runtime symbol for ring_G
    rtsym_ring_G = nfp_rtsym_lookup(h_nfp, "_ring_G");
    if (!rtsym_ring_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }
    printf("Found symbol 'ring_G': Address=0x%llx, Size=%llu bytes, Target=%d, Domain=%d\n",
           rtsym_ring_G->addr, rtsym_ring_G->size, rtsym_ring_G->target, rtsym_ring_G->domain);


    // 3. Determine chip family for correct CPP ID construction (e.g., NFP6000 for __emem)
    uint32_t model_id = nfp_cpp_model(h_cpp); // Get model ID
    int chip_family = NFP_CPP_MODEL_FAMILY_of(model_id); // Get chip family

    if (chip_family != NFP_CHIP_FAMILY_NFP6000) { // Check for NFP6000
        fprintf(stderr, "Error: __emem (external memory) access typically applies to NFP6000 devices. Detected chip family: 0x%x. Proceeding with NFP6000 assumptions.\n", chip_family);
        // Depending on your specific NFP device, the 'target' and 'domain' (island ID)
        // from the rtsym might vary. For NFP6000, __emem usually maps to MU (target 7)
        // in a specific EMEM island (e.g., 24 for EMEM0).
    }

    // 4. Calculate the specific offset for target ring and construct the CPP ID
    uint64_t offset_ring_buffer_target = rtsym_ring_buffer_G->addr + (TARGET_RING_INDEX * SIZEOF_RING_LIST_ONE_RING);
    size_t size_ring_buffer_target = SIZEOF_RING_LIST_ONE_RING;
    // NFP_CPP_ACTION_RW (value 32) is the wildcard for read/write actions
    uint32_t cpp_id_ring_buffer_target = NFP_CPP_ISLAND_ID(rtsym_ring_buffer_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_buffer_G->domain); // Pack CPP ID components

    printf("\nTargeting Ring Number: %d (0-indexed: %d)\n", TARGET_RING_INDEX + 1, TARGET_RING_INDEX);
    printf("Calculated Offset for Ring Buffer %d: 0x%llx\n", TARGET_RING_INDEX + 1, offset_ring_buffer_target);
    printf("Size of Ring Buffer %d: %zu bytes\n", TARGET_RING_INDEX + 1, size_ring_buffer_target);
    printf("Constructed CPP ID for Ring Buffer %d: 0x%x (Target: %u, Island: %u)\n",
           TARGET_RING_INDEX + 1,
           cpp_id_ring_buffer_target,
           NFP_CPP_ID_TARGET_of(cpp_id_ring_buffer_target), // Extract target from CPP ID
           NFP_CPP_ID_ISLAND_of(cpp_id_ring_buffer_target)); // Extract island from CPP ID

    // NEW: Calculate offset and CPP ID for the target ring_meta
    uint64_t offset_ring_meta_target = rtsym_ring_G->addr + (TARGET_RING_INDEX * sizeof(ring_meta));
    size_t size_ring_meta_target = sizeof(ring_meta);
    uint32_t cpp_id_ring_meta_target = NFP_CPP_ISLAND_ID(rtsym_ring_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_G->domain);

    printf("Calculated Offset for Ring Meta %d: 0x%llx\n", TARGET_RING_INDEX + 1, offset_ring_meta_target);
    printf("Size of Ring Meta %d: %zu bytes\n", TARGET_RING_INDEX + 1, size_ring_meta_target);
    printf("Constructed CPP ID for Ring Meta %d: 0x%x (Target: %u, Island: %u)\n",
           TARGET_RING_INDEX + 1,
           cpp_id_ring_meta_target,
           NFP_CPP_ID_TARGET_of(cpp_id_ring_meta_target),
           NFP_CPP_ID_ISLAND_of(cpp_id_ring_meta_target));

    // 5. Allocate and acquire the CPP area for ring_buffer_G (original ring_7)
    area_ring_7 = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_buffer_target, offset_ring_buffer_target, size_ring_buffer_target);
    if (!area_ring_7) {
        fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring buffer %d (%s)\n", TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto exit;
    }
    printf("Successfully allocated and acquired CPP area for ring buffer %d.\n", TARGET_RING_INDEX + 1);

    // NEW: Allocate and acquire the CPP area for ring_meta_G
    area_ring_meta_7 = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_meta_target, offset_ring_meta_target, size_ring_meta_target);
    if (!area_ring_meta_7) {
        fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring meta %d (%s)\n", TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto free_area_ring_buffer; // Jump to cleanup area_ring_7 if this fails
    }
    printf("Successfully allocated and acquired CPP area for ring meta %d.\n", TARGET_RING_INDEX + 1);

    // 6. Read data from the acquired CPP areas
    // Option A: Map the area and access directly
    volatile ring_list *mapped_ring_7_data = (volatile ring_list *)nfp_cpp_area_mapped(area_ring_7);
    if (!mapped_ring_7_data) {
        fprintf(stderr, "Error: Failed to get mapped area for ring buffer %d (%s)\n", TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto free_area_meta; // Jump to cleanup for both areas
    }

    volatile ring_meta *mapped_ring_meta_data = (volatile ring_meta *)nfp_cpp_area_mapped(area_ring_meta_7); // NEW: Map ring_meta area
    if (!mapped_ring_meta_data) {
        fprintf(stderr, "Error: Failed to get mapped area for ring meta %d (%s)\n", TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto free_area_meta; // Jump to cleanup for both areas
    }

    printf("\nStarting to read ring buffer %d in a loop. Press Ctrl+C to stop.\n", TARGET_RING_INDEX + 1);
    int loop_iteration = 0;
    while (1) {
        uint32_t current_wp = mapped_ring_meta_data->write_pointer;
        uint32_t current_rp = mapped_ring_meta_data->read_pointer;
        uint32_t current_full = mapped_ring_meta_data->full;

        // Condition to check if the ring is empty: read_pointer equals write_pointer AND it's not full [5, 6]
        if (current_rp == current_wp && current_full == 0) {
            printf("\nRing %d is currently empty (WP=%u, RP=%u, Full=%u). Waiting for new data...\n",
                   TARGET_RING_INDEX + 1, current_wp, current_rp, current_full);
            usleep(5000000); // Sleep for 500ms before checking again
            continue;
        }

        // The ring has data
        printf("\nIteration %d: Reading entry at index %u (WP=%u, RP=%u, Full=%u)\n",
               loop_iteration++, current_rp, current_wp, current_full);

        // Access the bucket_entry at the current read_pointer
        if (RING_SIZE > 0) {
            // Read packet_count and last_update_timestamp from the entry
            uint32_t entry_packet_count = mapped_ring_7_data->entry[current_rp].packet_count;
            uint64_t entry_last_update_timestamp = mapped_ring_7_data->entry[current_rp].last_update_timestamp;
            uint32_t entry_node_count = mapped_ring_7_data->entry[current_rp].int_metric_info_value.node_count;

            printf("  Entry[%u] Key: %u, %u, %u, %u\n", current_rp,
                   mapped_ring_7_data->entry[current_rp].key,
                   mapped_ring_7_data->entry[current_rp].key[7],
                   mapped_ring_7_data->entry[current_rp].key[8],
                   mapped_ring_7_data->entry[current_rp].key[3]);
            printf("  Entry[%u] Packet Count: %u\n", current_rp, entry_packet_count);
            printf("  Entry[%u] Last Update Timestamp: %llu\n", current_rp, entry_last_update_timestamp);
            printf("  Entry[%u] Node Count: %u\n", current_rp, entry_node_count);

            if (entry_node_count > 0 && entry_node_count <= MAX_INT_NODES) { // MAX_INT_NODES is 5 [6, 7]
                printf("  Entry[%u] Number of nodes present: %u\n", current_rp, entry_node_count);

                // Loop through each node to access its 'latest' and 'average' metrics
                for (int k = 0; k < entry_node_count; ++k) { // Iterate up to 'node_count' to get all active nodes
                    printf("    --- Node %d Metrics ---\n", k);

                    // Accessing every entry of 'latest' metrics [1, 2]
                    uint32_t latest_node_id = mapped_ring_7_data->entry[current_rp].int_metric_info_value.latest[k].node_id; // Corrected: Added [k]
                    uint32_t latest_hop_latency = mapped_ring_7_data->entry[current_rp].int_metric_info_value.latest[k].hop_latency; // Corrected: Added [k]
                    uint32_t latest_queue_occupancy = mapped_ring_7_data->entry[current_rp].int_metric_info_value.latest[k].queue_occupancy; // Corrected: Added [k]
                    uint32_t latest_egress_tx = mapped_ring_7_data->entry[current_rp].int_metric_info_value.latest[k].egress_interface_tx; // Corrected: Added [k]

                    printf("      Latest - Node ID: %u, Hop Latency: %u, Queue Occupancy: %u, Egress TX: %u\n",
                        latest_node_id, latest_hop_latency, latest_queue_occupancy, latest_egress_tx);

                    // Accessing every entry of 'average' metrics [1, 2]
                    uint32_t average_node_id = mapped_ring_7_data->entry[current_rp].int_metric_info_value.average[k].node_id; // Corrected: Added [k]
                    uint32_t average_hop_latency = mapped_ring_7_data->entry[current_rp].int_metric_info_value.average[k].hop_latency; // Corrected: Added [k]
                    uint32_t average_queue_occupancy = mapped_ring_7_data->entry[current_rp].int_metric_info_value.average[k].queue_occupancy; // Corrected: Added [k]
                    uint32_t average_egress_tx = mapped_ring_7_data->entry[current_rp].int_metric_info_value.average[k].egress_interface_tx; // Corrected: Added [k]

                    printf("      Average - Node ID: %u, Hop Latency: %u, Queue Occupancy: %u, Egress TX: %u\n",
                        average_node_id, average_hop_latency, average_queue_occupancy, average_egress_tx);
                }
            } else {
                printf("  Entry[%u] No or invalid nodes present in metric info (node_count: %u).\n", current_rp, entry_node_count);
            }

            // Advance the read_pointer
            current_rp = (current_rp + 1) & (RING_SIZE - 1);

            // Update the 'full' flag: if ring was full and read_pointer moves, it's no longer full.
            // If read_pointer now equals write_pointer, the ring becomes empty.
            if (current_full == 1 && current_rp == current_wp) {
                current_full = 0; // Ring was full, now empty
                printf("  Ring %d was full, now became empty after this read.\n", TARGET_RING_INDEX + 1);
            } else if (current_full == 1 && current_rp != current_wp) {
                current_full = 0; // Ring was full, but still has data left
                printf("  Ring %d was full, now partially read.\n", TARGET_RING_INDEX + 1);
            }
            // No action needed if current_full was already 0.

            // Write back the updated read_pointer and full flag to ring_meta
            mapped_ring_meta_data->read_pointer = current_rp;
            mapped_ring_meta_data->full = current_full;
            printf("  Updated ring_meta: RP=%u, Full=%u.\n", mapped_ring_meta_data->read_pointer, mapped_ring_meta_data->full);

        } else {
            printf("Ring size is zero, no entries to read. Exiting loop.\n");
            break; // Exit loop if RING_SIZE is 0
        }

        usleep(1000000); // Sleep for 100ms before attempting to read the next entry
    }

free_area_meta: // NEW label for cleanup of ring_meta area
    // 7. Release and free the CPP area for ring_meta
    if (area_ring_meta_7) {
        nfp_cpp_area_release_free(area_ring_meta_7);
        printf("Released and freed CPP area for ring meta %d.\n", TARGET_RING_INDEX + 1);
    }

free_area_ring_buffer: // Original free_area label, renamed for clarity
    // 7. Release and free the CPP area for ring_buffer_G
    if (area_ring_7) {
        nfp_cpp_area_release_free(area_ring_7);
        printf("Released and freed CPP area for ring buffer %d.\n", TARGET_RING_INDEX + 1);
    }

exit:
    // Close NFP device handle
    if (h_nfp) {
        nfp_device_close(h_nfp); // Close device
        printf("Closed NFP device.\n");
    }

    return ret;
}