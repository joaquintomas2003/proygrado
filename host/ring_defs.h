#ifndef RING_DEFS_H
#define RING_DEFS_H

#include <stdint.h>

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
} int_metric_info;

typedef struct bucket_header_io {
    uint32_t key[4];
    uint32_t node_count;
    uint32_t packet_count;
    uint32_t request_meta;
    uint32_t _padding;
    uint64_t first_packet_ts;
    uint64_t last_update_ts;
} bucket_header_io;

/* 8-byte padding is needed to match NFP's compiler default padding rules */
typedef struct bucket_entry {
    bucket_header_io header;
    int_metric_info int_metric_info_value;
} bucket_entry;

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
    uint32_t _padding1;
    uint32_t event_ts_high;
    uint32_t event_ts_low;
    uint64_t _padding2;
} event_record;

typedef struct event_ring_list {
    struct event_record entry[RING_SIZE];
} event_ring_list;

#endif