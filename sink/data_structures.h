#include <stdint.h>

#define FLOWCACHE_ROWS (1 << 10)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define IP_PROTO_UDP 0x11
#define IP_PROTO_TCP 0x6
#define NUM_RINGS 8
#define RING_SIZE (1 << 16)

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
