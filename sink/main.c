#include <nfp.h>
#include <stdint.h>
#include <nfp/me.h>
#include <pif_common.h>
#include <nfp/mem_atomic.h>
#include <nfp/mem_ring.h>
#include <pif_plugin.h>
#include <std/hash.h>
#include <memory.h>

#define FLOWCACHE_ROWS (1 << 18)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define IP_PROTO_UDP = 0x11;
#define IP_PROTO_TCP = 0x6;

typedef struct int_metric_sample {
  uint32_t node_id; /* Node ID */
  uint16_t ingress_interface_id; /* Level 1 ingress interface ID */
  uint16_t egress_interface_id; /* Level 1 egress interface ID */
  uint32_t hop_latency; /* Hop latency */
  uint32_t queue_occupancy; /* Queue occupancy */
  uint64_t ingress_timestamp; /* Ingress timestamp */
  uint64_t egress_timestamp; /* Egress timestamp */
  uint16_t level2_ingress_interface_id; /* Level 2 ingress interface ID */
  uint16_t level2_egress_interface_id; /* Level 2 egress interface ID */
  uint32_t egress_interface_tx; /* Egress interface transmission */
  uint32_t buffer_occupancy; /* Buffer occupancy */
} int_metric_sample;

typedef struct int_metric_info {
  int_metric_sample latest[MAX_INT_NODES];
  int_metric_sample average[MAX_INT_NODES];
  uint32_t node_count;
} int_metric_info;

typedef struct bucket_entry {
  uint32_t key[4]; /* ipv4.src_addr, ipv4.dst_addr, (src_port << 16) | dst_port, ipv4.protocol */
  uint32_t packet_count;
  uint32_t last_update_timestamp; /* Timestamp in nanoseconds */
  int_metric_info int_metric_info_value;
} bucket_entry;

typedef struct bucket_list {
  struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;

__export __emem bucket_list int_flowcache[FLOWCACHE_ROWS];
