// host_reader.c
// Read Netronome ring buffers and push each entry to a Redis Stream.
// Build:
//   gcc host_reader.c -o host_reader \
//     -I/opt/netronome/include \
//     -L/opt/netronome/lib \
//     -lnfp -lhiredis
//
// Run:
//   ./host_reader [RING_INDEX 1..8]
//
// Environment (optional):
//   REDIS_HOST, REDIS_PORT, REDIS_PASSWORD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include <hiredis/hiredis.h>

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

// Explicit padding to match NFP's default layout
typedef struct bucket_entry {
    uint32_t key[4];                       // 16 bytes
    uint32_t packet_count;                 // 4 bytes (Total 20 bytes so far)
    uint32_t _padding1;
    uint64_t last_update_timestamp;        // 8 bytes (Total 32 bytes so far)
    int_metric_info int_metric_info_value; // 164 bytes (Total 196 bytes so far)
    uint32_t _padding2;                    // Tail padding to make total size 200 bytes
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

/* ---------------- Redis helpers ---------------- */

static void get_redis_cfg(const char **host_out, int *port_out, const char **pass_out) {
    const char *h = getenv("REDIS_HOST");
    const char *p = getenv("REDIS_PORT");
    const char *pw = getenv("REDIS_PASSWORD");
    if (!h || !*h) h = "127.0.0.1";
    int port = 6379;
    if (p && *p) {
        int tmp = atoi(p);
        if (tmp > 0) port = tmp;
    }
    *host_out = h;
    *port_out = port;
    *pass_out = (pw && *pw) ? pw : NULL;
}

static redisContext* redis_connect_with_retry(int timeout_ms) {
    const char *host, *password;
    int port;
    get_redis_cfg(&host, &port, &password);

    struct timeval tv = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000
    };

    redisContext* c = redisConnectWithTimeout(host, port, tv);
    if (c == NULL) {
        fprintf(stderr, "Redis connect returned NULL\n");
        return NULL;
    }
    if (c->err) {
        fprintf(stderr, "Redis connect error: %s\n", c->errstr);
        return c;
    }

    if (password) {
        redisReply *r = redisCommand(c, "AUTH %s", password);
        if (!r) {
            fprintf(stderr, "Redis AUTH: no reply, will mark as error\n");
            c->err = 1;
            return c;
        }
        if (r->type == REDIS_REPLY_ERROR) {
            fprintf(stderr, "Redis AUTH error: %s\n", r->str);
            freeReplyObject(r);
            c->err = 1;
            return c;
        }
        freeReplyObject(r);
    }

    return c;
}

static int xadd_bucket_entry(redisContext **ctx_ptr,
                             const char *stream_prefix,
                             int ring_idx,
                             uint32_t rp,
                             const struct bucket_entry *e) {
    if (!*ctx_ptr || (*ctx_ptr)->err) {
        if (*ctx_ptr) { redisFree(*ctx_ptr); *ctx_ptr = NULL; }
        *ctx_ptr = redis_connect_with_retry(500);
        if (!*ctx_ptr || (*ctx_ptr)->err) {
            fprintf(stderr, "Redis connect failed: %s\n", *ctx_ptr ? (*ctx_ptr)->errstr : "no ctx");
            return -1;
        }
    }

    char stream[64];
    snprintf(stream, sizeof(stream), "%s:%d", stream_prefix, ring_idx);

    /* Stream fields — flatten latest[0..4]. Adjust MAXLEN as needed. */
    redisReply *reply = redisCommand(
        *ctx_ptr,
        "XADD %s MAXLEN ~ %d * "
        "ring %d rp %u "
        "key0 %u key1 %u key2 %u key3 %u "
        "packet_count %u last_ts %llu node_count %u "
        "n0_id %u n0_hl %u n0_q %u n0_tx %u "
        "n1_id %u n1_hl %u n1_q %u n1_tx %u "
        "n2_id %u n2_hl %u n2_q %u n2_tx %u "
        "n3_id %u n3_hl %u n3_q %u n3_tx %u "
        "n4_id %u n4_hl %u n4_q %u n4_tx %u",
        stream, 100000,
        ring_idx, rp,
        e->key[0], e->key[1], e->key[2], e->key[3],
        e->packet_count, (unsigned long long)e->last_update_timestamp, e->int_metric_info_value.node_count,
        /* n0 */
        e->int_metric_info_value.latest[0].node_id,
        e->int_metric_info_value.latest[0].hop_latency,
        e->int_metric_info_value.latest[0].queue_occupancy,
        e->int_metric_info_value.latest[0].egress_interface_tx,
        /* n1 */
        e->int_metric_info_value.latest[1].node_id,
        e->int_metric_info_value.latest[1].hop_latency,
        e->int_metric_info_value.latest[1].queue_occupancy,
        e->int_metric_info_value.latest[1].egress_interface_tx,
        /* n2 */
        e->int_metric_info_value.latest[2].node_id,
        e->int_metric_info_value.latest[2].hop_latency,
        e->int_metric_info_value.latest[2].queue_occupancy,
        e->int_metric_info_value.latest[2].egress_interface_tx,
        /* n3 */
        e->int_metric_info_value.latest[3].node_id,
        e->int_metric_info_value.latest[3].hop_latency,
        e->int_metric_info_value.latest[3].queue_occupancy,
        e->int_metric_info_value.latest[3].egress_interface_tx,
        /* n4 */
        e->int_metric_info_value.latest[4].node_id,
        e->int_metric_info_value.latest[4].hop_latency,
        e->int_metric_info_value.latest[4].queue_occupancy,
        e->int_metric_info_value.latest[4].egress_interface_tx
    );

    if (!reply) {
        fprintf(stderr, "XADD failed (no reply). Will reconnect next time.\n");
        (*ctx_ptr)->err = 1;  // force reconnect
        return -1;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        fprintf(stderr, "XADD error: %s\n", reply->str);
        freeReplyObject(reply);
        return -1;
    }
    /* reply->str holds the generated entry ID like "1724352520000-0" */
    freeReplyObject(reply);
    return 0;
}

/* ---------------- Main Program ---------------- */

int main(int argc, char *argv[]) {
    struct nfp_device *h_nfp = NULL;
    struct nfp_cpp *h_cpp = NULL;
    const struct nfp_rtsym *rtsym_ring_buffer_G = NULL;
    const struct nfp_rtsym *rtsym_ring_G = NULL;
    struct nfp_cpp_area *area_ring = NULL;
    struct nfp_cpp_area *area_ring_meta = NULL;

    int ret = 0;
    int TARGET_RING_INDEX = 0;

    if (argc > 1) {
        TARGET_RING_INDEX = atoi(argv[1]) - 1;
        if (TARGET_RING_INDEX < 0 || TARGET_RING_INDEX >= NUM_RINGS) {
            fprintf(stderr, "Error: Target Ring Number must be between 0 < n < 9\n");
            return 1;
        }
    }

    /* Connect to Redis (non-fatal if unavailable; we’ll retry) */
    redisContext *redis = redis_connect_with_retry(500);
    if (!redis || redis->err) {
        fprintf(stderr, "Warning: Redis not available now, will keep trying while running.\n");
    }

    /* 1. Open NFP device and get CPP handle */
    h_nfp = nfp_device_open(0);
    if (!h_nfp) {
        fprintf(stderr, "Error: Failed to open NFP device (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }

    h_cpp = nfp_device_cpp(h_nfp);
    if (!h_cpp) {
        fprintf(stderr, "Error: Failed to get CPP handle (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }

    /* 2. Look up runtime symbols */
    rtsym_ring_buffer_G = nfp_rtsym_lookup(h_nfp, "_ring_buffer_G");
    if (!rtsym_ring_buffer_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_buffer_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }

    printf("Found symbol 'ring_buffer_G': Address=0x%llx, Size=%llu bytes, Target=%d, Domain=%d\n",
           (unsigned long long)rtsym_ring_buffer_G->addr,
           (unsigned long long)rtsym_ring_buffer_G->size,
           rtsym_ring_buffer_G->target, rtsym_ring_buffer_G->domain);

    rtsym_ring_G = nfp_rtsym_lookup(h_nfp, "_ring_G");
    if (!rtsym_ring_G) {
        fprintf(stderr, "Error: Could not find runtime symbol 'ring_G' (%s)\n", strerror(errno));
        ret = 1;
        goto exit;
    }

    printf("Found symbol 'ring_G': Address=0x%llx, Size=%llu bytes, Target=%d, Domain=%d\n",
           (unsigned long long)rtsym_ring_G->addr,
           (unsigned long long)rtsym_ring_G->size,
           rtsym_ring_G->target, rtsym_ring_G->domain);

    /* 3. Calculate offsets and CPP IDs */
    uint64_t offset_ring_buffer_target = rtsym_ring_buffer_G->addr + (uint64_t)TARGET_RING_INDEX * sizeof(ring_list);
    uint32_t cpp_id = NFP_CPP_ISLAND_ID(rtsym_ring_buffer_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_buffer_G->domain);

    printf("\nTargeting Ring Number: %d (0-indexed: %d)\n", TARGET_RING_INDEX + 1, TARGET_RING_INDEX);
    printf("Calculated Offset for Ring Buffer %d: 0x%llx\n", TARGET_RING_INDEX + 1, (unsigned long long)offset_ring_buffer_target);
    printf("Size of Ring Buffer %d: %zu bytes\n", TARGET_RING_INDEX + 1, sizeof(ring_list));
    printf("Constructed CPP ID for Ring Buffer %d: 0x%x (Target: %u, Island: %u)\n",
           TARGET_RING_INDEX + 1,
           cpp_id,
           NFP_CPP_ID_TARGET_of(cpp_id),
           NFP_CPP_ID_ISLAND_of(cpp_id));

    uint64_t offset_ring_meta_target = rtsym_ring_G->addr + (uint64_t)TARGET_RING_INDEX * sizeof(ring_meta);
    uint32_t cpp_id_ring_meta_target = NFP_CPP_ISLAND_ID(rtsym_ring_G->target, NFP_CPP_ACTION_RW, 0, rtsym_ring_G->domain);

    printf("Calculated Offset for Ring Meta %d: 0x%llx\n", TARGET_RING_INDEX + 1, (unsigned long long)offset_ring_meta_target);
    printf("Size of Ring Meta %d: %zu bytes\n", TARGET_RING_INDEX + 1, sizeof(ring_meta));
    printf("Constructed CPP ID for Ring Meta %d: 0x%x (Target: %u, Island: %u)\n",
           TARGET_RING_INDEX + 1,
           cpp_id_ring_meta_target,
           NFP_CPP_ID_TARGET_of(cpp_id_ring_meta_target),
           NFP_CPP_ID_ISLAND_of(cpp_id_ring_meta_target));

    /* 4. Acquire CPP areas */
    area_ring = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id, offset_ring_buffer_target, sizeof(ring_list));
    if (!area_ring) {
        fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring buffer %d (%s)\n",
                TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto exit;
    }
    printf("Successfully allocated and acquired CPP area for ring buffer %d.\n", TARGET_RING_INDEX + 1);

    area_ring_meta = nfp_cpp_area_alloc_acquire(h_cpp, cpp_id_ring_meta_target, offset_ring_meta_target, sizeof(ring_meta));
    if (!area_ring_meta) {
        fprintf(stderr, "Error: Failed to allocate and acquire CPP area for ring meta %d (%s)\n",
                TARGET_RING_INDEX + 1, strerror(errno));
        ret = 1;
        goto free_area_ring_buffer;
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

        /* Check if the ring is empty */
        if (rp == wp && f == 0) {
            printf("\nRing %d is currently empty (WP=%u, RP=%u, Full=%u). Waiting for new data...\n",
                   TARGET_RING_INDEX + 1, wp, rp, f);
            usleep(1000000); // Sleep for ~1s before checking again
            continue;
        }

        /* The ring has data */
        printf("\nIteration %llu: (WP=%u, RP=%u, Full=%u)\n", loop_iteration++, wp, rp, f);

        bucket_entry current_ring_entry;
        uint64_t offset_bucket_entry = (uint64_t)rp * sizeof(bucket_entry);

        /* Read the specific bucket_entry from NFP */
        if (nfp_cpp_area_read(area_ring, offset_bucket_entry, &current_ring_entry, sizeof(bucket_entry)) < 0) {
            fprintf(stderr, "Error: Failed to read bucket entry from ring buffer %d at offset 0x%llx (%s)\n",
                    TARGET_RING_INDEX + 1, (unsigned long long)offset_bucket_entry, strerror(errno));
            break;
        }

        uint32_t entry_packet_count = current_ring_entry.packet_count;
        uint64_t entry_last_update_timestamp = current_ring_entry.last_update_timestamp;
        uint32_t entry_node_count = current_ring_entry.int_metric_info_value.node_count;

        printf(" Read Entry[RP=%u]: PacketCount=%u, Last Update Timestamp=%llu, NodeCount=%u\n",
               rp, entry_packet_count, (unsigned long long)entry_last_update_timestamp, entry_node_count);

        printf(" Entry[%u] Key Flow: [%u, %u, %u, %u]\n", rp,
               current_ring_entry.key[0],
               current_ring_entry.key[1],
               current_ring_entry.key[2],
               current_ring_entry.key[3]);

        /* --- Push to Redis Stream --- */
        if (xadd_bucket_entry(&redis, "int:ring", TARGET_RING_INDEX, rp, &current_ring_entry) == 0) {
            printf(" Pushed to Redis stream int:ring:%d\n", TARGET_RING_INDEX);
        } else {
            fprintf(stderr, " Failed to push to Redis (will retry later).\n");
        }

        /* Advance the read_pointer */
        rp = (rp + 1) & (RING_SIZE - 1);
        if (f == 1 && rp == wp) {
            f = 0;
        } else if (f == 1 && rp != wp) {
            f = 0;
        }

        /* Write back the updated read_pointer and full flag to ring_meta */
        current_ring_meta.read_pointer = rp;
        current_ring_meta.full = f;
        if (nfp_cpp_area_write(area_ring_meta, 0, &current_ring_meta, sizeof(ring_meta)) < 0) {
            fprintf(stderr, "Error: Failed to write updated ring meta (%s)\n", strerror(errno));
            break;
        }

        printf(" Updated ring_meta: RP=%u, Full=%u.\n", current_ring_meta.read_pointer, current_ring_meta.full);
        usleep(200000); // Sleep for ~200ms before attempting to read the next entry
    }

free_area_meta:
    if (area_ring_meta) {
        nfp_cpp_area_release_free(area_ring_meta);
        printf("Released and freed CPP area for ring meta %d.\n", TARGET_RING_INDEX + 1);
    }

free_area_ring_buffer:
    if (area_ring) {
        nfp_cpp_area_release_free(area_ring);
        printf("Released and freed CPP area for ring buffer %d.\n", TARGET_RING_INDEX + 1);
    }

exit:
    if (h_nfp) {
        nfp_device_close(h_nfp);
        printf("Closed NFP device.\n");
    }
    if (redis) {
        redisFree(redis);
    }
    return ret;
}
