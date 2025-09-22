#include <nfp.h>
#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>

#define FLOWCACHE_ROWS (1 << 18)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define IP_PROTO_UDP 0x11
#define IP_PROTO_TCP 0x6
#define NUM_RINGS 8
#define RING_SIZE (1 << 16)
#define AGE_THRESHOLD_NS (1000000000ULL)  /* 1 second for testing */

typedef struct int_metric_sample {
  uint32_t node_id; /* Node ID */
  // uint32_t ingress_and_egress_interface_id; /* Level 1 ingress interface ID */
  uint32_t hop_latency; /* Hop latency */
  uint32_t queue_occupancy; /* Queue occupancy */
  // uint64_t ingress_timestamp; /* Ingress timestamp */
  // uint64_t egress_timestamp; /* Egress timestamp */
  // uint16_t level2_ingress_interface_id; /* Level 2 ingress interface ID */
  // uint16_t level2_egress_interface_id; /* Level 2 egress interface ID */
  uint32_t egress_interface_tx; /* Egress interface transmission */
  // uint32_t buffer_occupancy; /* Buffer occupancy */
} int_metric_sample;

typedef struct int_metric_info {
  int_metric_sample latest[MAX_INT_NODES];
  int_metric_sample average[MAX_INT_NODES];
  uint32_t node_count;
} int_metric_info;

typedef struct bucket_entry {
  uint32_t key[4]; /* ipv4.src_addr, ipv4.dst_addr, (src_port << 16) | dst_port, ipv4.protocol */
  uint32_t packet_count;
  uint64_t last_update_timestamp; /* Timestamp in nanoseconds */
  int_metric_info int_metric_info_value;
} bucket_entry;

typedef struct bucket_list {
  struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;

typedef struct ring_list {
  struct bucket_entry entry[RING_SIZE];
} ring_list;

typedef struct event_record {
  uint32_t switch_id;     /* per-switch id, or 0xFFFFFFFF for E2E */
  uint32_t value;         /* metric value or delta */
  uint32_t event_bitmap;  /* encodes type & metric */
  uint32_t ts_low32;      /* truncated timestamp (lower 32 bits) */
} event_record;

typedef struct event_ring_list {
  struct event_record entry[RING_SIZE];
} event_ring_list;

typedef struct ring_meta {
  uint32_t write_pointer;
  uint32_t read_pointer;
  uint32_t full;
} ring_meta;

__export __emem bucket_list int_flowcache[FLOWCACHE_ROWS];
__export __emem ring_list ring_buffer_G[NUM_RINGS];
__export __emem ring_meta ring_G[NUM_RINGS];

void evict_stale_entries(uint64_t current_time, uint64_t threshold_ns) {
    __xrw ring_meta ring_meta_read;
    __addr40 __emem bucket_entry *entry;
    __addr40 __emem ring_meta *ring_info;
    __addr40 __emem ring_entry *r_entry;
    uint32_t wp, rp, f;
    uint32_t i, j, ring_index;
    uint64_t last_ts;
    uint32_t zero = 0;
    uint32_t key_reset[4] = {0};

    for (i = 0; i < FLOWCACHE_ROWS; i++) {
        for (j = 0; j < BUCKET_SIZE; j++) {
            entry = &int_flowcache[i].entry[j];

            mem_read_atomic(&last_ts, &entry->last_update_timestamp, sizeof(last_ts));

            if (entry->packet_count != 0 && (current_time - last_ts) > threshold_ns) {
                // Determine ring index
                ring_index = i & (NUM_RINGS - 1);
                ring_info = &ring_G[ring_index];

                mem_read_atomic(&ring_meta_read, ring_info, sizeof(ring_meta_read));
                wp = ring_meta_read.write_pointer;
                rp = ring_meta_read.read_pointer;
                f  = ring_meta_read.full;

                if (f == 0) {
                    r_entry = &ring_buffer_G[ring_index].entry[wp];

                    // Copy key and metadata to ring buffer
                    mem_write_atomic(entry->key, &r_entry->key, sizeof(entry->key));
                    mem_write_atomic(&entry->packet_count, &r_entry->packet_count, sizeof(entry->packet_count));
                    mem_write_atomic(&entry->last_update_timestamp, &r_entry->last_update_timestamp, sizeof(entry->last_update_timestamp));
                    mem_write_atomic(&entry->int_metric_info_value.node_count,
                                     &r_entry->int_metric_info_value.node_count,
                                     sizeof(entry->int_metric_info_value.node_count));

                    // Copy per-node data
                    for (uint32_t k = 0; k < entry->int_metric_info_value.node_count && k < MAX_INT_NODES; k++) {
                        mem_write_atomic(&entry->int_metric_info_value.latest[k],
                                         &r_entry->int_metric_info_value.latest[k],
                                         sizeof(entry->int_metric_info_value.latest[k]));
                        mem_write_atomic(&entry->int_metric_info_value.average[k],
                                         &r_entry->int_metric_info_value.average[k],
                                         sizeof(entry->int_metric_info_value.average[k]));
                    }

                    // Advance write pointer
                    wp = (wp + 1) & (RING_SIZE - 1);
                    if (wp == rp) f = 1;

                    // Free the bucket
                    mem_write_atomic(&zero, &entry->packet_count, sizeof(zero));
                    mem_write_atomic(&key_reset, &entry->key, sizeof(key_reset));

                    // Update ring metadata
                    ring_meta_read.write_pointer = wp;
                    ring_meta_read.full = f;
                    mem_write_atomic(&ring_meta_read, ring_info, sizeof(ring_meta_read));
                }
            }
        }
    }
}

void main(void)
{
}
