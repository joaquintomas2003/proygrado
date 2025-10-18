#ifndef RING_DEFS_H
#define RING_DEFS_H

#include <stdint.h>

#define FLOWCACHE_ROWS (1 << 10)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define NUM_RINGS 8
#define RING_SIZE (1 << 16)
#define BATCH_SIZE 10

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

/* 8-byte padding is needed to match NFP's compiler default padding rules */
typedef struct bucket_entry {
    uint32_t key[4];
    uint64_t first_packet_timestamp;
    uint64_t last_update_timestamp;
    int_metric_info int_metric_info_value;
    uint32_t packet_count;
    uint32_t request_meta; // bits 0–15: request_id, bit 16: is_response, bits 17–31: reserved
    uint32_t _padding;
} bucket_entry;

typedef struct bucket_list {
    struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;

typedef struct ring_list {
    struct bucket_entry entry[RING_SIZE];
} ring_list;

typedef struct ring_meta {
    uint32_t write_pointer;
    uint32_t read_pointer;
    uint32_t full;
    uint32_t _padding;
} ring_meta;

typedef struct event_record {
    uint32_t switch_id;
    uint32_t value;
    uint32_t event_bitmap;
    uint32_t ts_low32;
} event_record;

typedef struct event_ring_list {
    struct event_record entry[RING_SIZE];
} event_ring_list;

#endif
