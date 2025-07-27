#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <std/hash.h>

#define FLOWCACHE_ROWS (1 << 18)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define IP_PROTO_UDP 0x11
#define IP_PROTO_TCP 0x6

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

__export __emem bucket_list int_flowcache[FLOWCACHE_ROWS];

static __inline int _get_hash_key(EXTRACTED_HEADERS_T *headers, uint32_t hash_key[4]) {
  uint32_t src_port;
  uint32_t dst_port;

  PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
  PIF_PLUGIN_udp_T *udp = pif_plugin_hdr_get_udp(headers);
  PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);

  if (ipv4->protocol == IP_PROTO_UDP) {
    src_port = udp->src_port;
    dst_port = udp->dst_port;
  } else if (ipv4->protocol == IP_PROTO_TCP) {
    src_port = tcp->src_port;
    dst_port = tcp->dst_port;
  } else {
    return -1;
  }

  hash_key[0] = ipv4->src_addr;
  hash_key[1] = ipv4->dst_addr;
  hash_key[2] = (src_port << 16) | dst_port;
  hash_key[3] = ipv4->protocol;

  return 0;
}

// Writes a sample from node metadata to a given destination in the entry
static __inline void _write_node_sample(__xwrite int_metric_sample *sample,
                                        __addr40 void *dest,
                                        void *node_metadata_ptr) {
  uint32_t *base = (uint32_t *)node_metadata_ptr;

  sample->node_id = base[0];             // node_id
  sample->hop_latency = base[1];         // hop_latency
  sample->queue_occupancy = base[2];     // queue_occupancy
  sample->egress_interface_tx = base[3]; // egress_interface_tx

  mem_write_atomic(sample, dest, sizeof(*sample));
}

int pif_plugin_save_in_hash(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
  // Declare the bucket entry variables
  __addr40 __emem bucket_entry *entry = 0;
  __xrw int_metric_sample avg_sample;
  __xrw uint32_t nodes_present;
  __xrw uint32_t pkt_cnt;
  __xrw uint64_t ingress_timestamp;
  __xwrite int_metric_sample sample;
  int i, k;
  uint32_t hash_key[4];
  void *node_metadata_ptrs[MAX_INT_NODES];
  volatile uint32_t hash_value;

  // Declare the metadata variables
  __lmem struct pif_header_scalars *scalars;
  __lmem struct pif_header_ingress__bitmap *bitmap;
  __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;

  // Get the hash key from the 5-tuple
  if (_get_hash_key(headers, hash_key) < 0) {
    return PIF_PLUGIN_RETURN_FORWARD;
  }

  // Calculate the hash value using CRC32
  hash_value = hash_me_crc32((void *) hash_key, sizeof(hash_key), 1);
  hash_value &= (FLOWCACHE_ROWS - 1);
  bitmap = (__lmem struct pif_header_ingress__bitmap *) (headers + PIF_PARREP_ingress__bitmap_OFF_LW);
  scalars = (__lmem struct pif_header_scalars *) (headers + PIF_PARREP_scalars_OFF_LW);
  intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (headers + PIF_PARREP_intrinsic_metadata_OFF_LW);

  // Search for an existing entry in the bucket
  for (i = 0; i < BUCKET_SIZE; i++) {
    entry = &int_flowcache[hash_value].entry[i];

    if (entry->packet_count == 0 ||
        (entry->key[0] == hash_key[0] &&
         entry->key[1] == hash_key[1] &&
         entry->key[2] == hash_key[2] &&
         entry->key[3] == hash_key[3])) {
      break;
    }
  }

  // If we reached the end of the bucket without finding a match
  if (i == BUCKET_SIZE) {
    return PIF_PLUGIN_RETURN_FORWARD;
  }

  // Metadata pointers for nodes
  node_metadata_ptrs[0] = headers + PIF_PARREP_ingress__node1_metadata_OFF_LW;
  node_metadata_ptrs[1] = headers + PIF_PARREP_ingress__node2_metadata_OFF_LW;
  node_metadata_ptrs[2] = headers + PIF_PARREP_ingress__node3_metadata_OFF_LW;
  node_metadata_ptrs[3] = headers + PIF_PARREP_ingress__node4_metadata_OFF_LW;
  node_metadata_ptrs[4] = headers + PIF_PARREP_ingress__node5_metadata_OFF_LW;

  // Save the last update timestamp
  ingress_timestamp = ((uint64_t) (intrinsic_metadata->ingress_global_timestamp) << 32) | intrinsic_metadata->__ingress_global_timestamp_1;
  mem_write_atomic(&ingress_timestamp, &entry->last_update_timestamp, sizeof(ingress_timestamp));

  // Increment the packet count
  mem_incr32(&entry->packet_count);

  if (entry->packet_count == 1) {
    // New entry: initialize
    __xwrite uint32_t key_wr[4] = {hash_key[0], hash_key[1], hash_key[2], hash_key[3]};
    mem_write_atomic(key_wr, entry->key, sizeof(key_wr));

    // Save node count
    nodes_present = scalars->metadata__nodes_present;
    mem_write_atomic(&nodes_present, &entry->int_metric_info_value.node_count, sizeof(nodes_present));

    for (k = 0; k < nodes_present && k < MAX_INT_NODES; k++) {
      void *node_metadata = (__lmem void *)node_metadata_ptrs[k];
      _write_node_sample(&sample, (__addr40 void *)&entry->int_metric_info_value.latest[k], node_metadata);
      _write_node_sample(&sample, (__addr40 void *)&entry->int_metric_info_value.average[k], node_metadata); // initialize average = latest
    }

  } else {
    // Existing entry: update
    mem_read_atomic(&nodes_present, &entry->int_metric_info_value.node_count, sizeof(nodes_present));

    for (k = 0; k < nodes_present && k < MAX_INT_NODES; k++) {
      void *node_metadata = (__lmem void *)node_metadata_ptrs[k];

      // Read new sample from node metadata
      uint32_t *base = (uint32_t *)node_metadata;
      uint32_t new_node_id = base[0];
      uint32_t new_hop_latency = base[1];
      uint32_t new_queue_occupancy = base[2];
      uint32_t new_egress_interface_tx = base[3];

      // Update latest
      sample.node_id = new_node_id;
      sample.hop_latency = new_hop_latency;
      sample.queue_occupancy = new_queue_occupancy;
      sample.egress_interface_tx = new_egress_interface_tx;

      mem_write_atomic(&sample, &entry->int_metric_info_value.latest[k], sizeof(sample));

      // Read current average
      mem_read_atomic(&avg_sample, &entry->int_metric_info_value.average[k], sizeof(avg_sample));

      // Compute new average using integer division
      avg_sample.node_id = new_node_id; // Keep latest node_id
      avg_sample.hop_latency = (avg_sample.hop_latency * (pkt_cnt - 1) + new_hop_latency) / pkt_cnt;
      avg_sample.queue_occupancy = (avg_sample.queue_occupancy * (pkt_cnt - 1) + new_queue_occupancy) / pkt_cnt;
      avg_sample.egress_interface_tx = (avg_sample.egress_interface_tx * (pkt_cnt - 1) + new_egress_interface_tx) / pkt_cnt;

      mem_write_atomic(&avg_sample, &entry->int_metric_info_value.average[k], sizeof(avg_sample));
    }
  }

  return PIF_PLUGIN_RETURN_FORWARD;
}
