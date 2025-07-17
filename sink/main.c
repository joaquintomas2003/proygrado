#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <std/hash.h>

#define FLOWCACHE_ROWS (1 << 18)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define IP_PROTO_UDP = 0x11;
#define IP_PROTO_TCP = 0x6;

typedef struct int_metric_sample {
  uint32_t node_id; /* Node ID */
  uint32_t ingress_and_egress_interface_id; /* Level 1 ingress interface ID */
  uint32_t hop_latency; /* Hop latency */
  uint32_t queue_occupancy; /* Queue occupancy */
  uint64_t ingress_timestamp; /* Ingress timestamp */
  uint64_t egress_timestamp; /* Egress timestamp */
  /* uint16_t level2_ingress_interface_id; /1* Level 2 ingress interface ID *1/ */
  /* uint16_t level2_egress_interface_id; /1* Level 2 egress interface ID *1/ */
  /* uint32_t egress_interface_tx; /1* Egress interface transmission *1/ */
  /* uint32_t buffer_occupancy; /1* Buffer occupancy *1/ */
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

static __inline int _get_hash_key(EXTRACTED_HEADERS_T *headers, uint32_t hash_key[4]) {
  uint32_t src_port;
  uint32_t dst_port;

  PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
  PIF_PLUGIN_udp_T *udp = pif_plugin_hdr_get_udp(headers);
  PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);

  if (ipv4->protocol == 17) {  // IP_PROTO_UDP
    src_port = udp->src_port;
    dst_port = udp->dst_port;
  } else if (ipv4->protocol == 6) {  // IP_PROTO_TCP
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

int pif_plugin_save_in_hash(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
  // Declare the bucket entry variables
  __addr40 __emem bucket_entry *entry = 0;
  __xrw uint32_t pkt_cnt;
  __xwrite int_metric_sample sample;
  __xwrite uint32_t node_count_wr;
  int i, k;
  uint32_t hash_key[4];
  uint32_t nodes_present;
  volatile uint32_t hash_value;

  // Declare the metadata variables
  __lmem struct pif_header_scalars *scalars;
  __lmem struct pif_header_ingress__bitmap *bitmap;
  __lmem struct pif_header_ingress__node1_metadata *node1_metadata;
  __lmem struct pif_header_ingress__node2_metadata *node2_metadata;
  __lmem struct pif_header_ingress__node3_metadata *node3_metadata;
  __lmem struct pif_header_ingress__node4_metadata *node4_metadata;
  __lmem struct pif_header_ingress__node5_metadata *node5_metadata;

  // Get the hash key from the 5-tuple
  if (_get_hash_key(headers, hash_key) < 0) {
    return PIF_PLUGIN_RETURN_FORWARD;
  }

  // Calculate the hash value using CRC32
  hash_value = hash_me_crc32((void *) hash_key, sizeof(hash_key), 1);
  hash_value &= (FLOWCACHE_ROWS - 1);
  bitmap = (__lmem struct pif_header_ingress__bitmap *) (headers + PIF_PARREP_ingress__bitmap_OFF_LW);
  scalars = (__lmem struct pif_header_scalars *) (headers + PIF_PARREP_scalars_OFF_LW);

  // Search for an existing entry in the bucket
  for (i = 0; i < BUCKET_SIZE; i++) {
    entry = &int_flowcache[hash_value].entry[i];

    if (entry->packet_count == 0 ||
        (entry->key[0] == hash_key[0] &&
         entry->key[1] == hash_key[1] &&
         entry->key[2] == hash_key[2] &&
         entry->key[3] == hash_key[3])) {
      // TODO: handle the case where the entry needs to be updated
      break;
    }
  }

  // If we reached the end of the bucket without finding a match
  if (i == BUCKET_SIZE) {
    return PIF_PLUGIN_RETURN_FORWARD;
  }

  // If we found an empty bucket initialize the entry
  if (entry->packet_count == 0) {
    __xwrite uint32_t key_wr[4] = {hash_key[0], hash_key[1], hash_key[2], hash_key[3]};

    // Save the key in the entry
    mem_write_atomic(key_wr, entry->key, sizeof(key_wr));

    // Increment the packet count
    mem_test_add(&pkt_cnt, &entry->packet_count, sizeof(pkt_cnt));

    nodes_present = scalars->metadata__nodes_present;

    if (nodes_present > 0) {
      node1_metadata = (__lmem struct pif_header_ingress__node1_metadata *) (headers + PIF_PARREP_ingress__node1_metadata_OFF_LW);
      sample.node_id = node1_metadata->node_id;
      sample.ingress_and_egress_interface_id = (((uint32_t) node1_metadata->level1_ingress_interface_id) << 16) | node1_metadata->level1_egress_interface_id;
      sample.hop_latency = node1_metadata->hop_latency;
      sample.queue_occupancy = node1_metadata->queue_occupancy;
      sample.ingress_timestamp = (((uint64_t)node1_metadata->ingress_timestamp) << 32) | node1_metadata->__ingress_timestamp_1;
      sample.egress_timestamp = (((uint64_t)node1_metadata->egress_timestamp) << 32) | node1_metadata->__egress_timestamp_1;
      /* sample.level2_ingress_interface_id = node1_metadata->level2_ingress_interface_id; */
      /* sample.level2_egress_interface_id = node1_metadata->level2_egress_interface_id; */
      /* sample.egress_interface_tx = node1_metadata->egress_interface_tx; */
      /* sample.buffer_occupancy = node1_metadata->buffer_occupancy; */

      mem_write_atomic(&sample, &entry->int_metric_info_value.latest[0], sizeof(sample));
    }

    if (nodes_present > 1) {
      node2_metadata = (__lmem struct pif_header_ingress__node2_metadata *) (headers + PIF_PARREP_ingress__node2_metadata_OFF_LW);

      sample.node_id = node2_metadata->node_id;
      sample.ingress_and_egress_interface_id = (((uint32_t) node2_metadata->level1_ingress_interface_id) << 16) | node2_metadata->level1_egress_interface_id;
      sample.hop_latency = node2_metadata->hop_latency;
      sample.queue_occupancy = node2_metadata->queue_occupancy;
      sample.ingress_timestamp = (((uint64_t)node2_metadata->ingress_timestamp) << 32) | node2_metadata->__ingress_timestamp_1;
      sample.egress_timestamp = (((uint64_t)node2_metadata->egress_timestamp) << 32) | node2_metadata->__egress_timestamp_1;
      /* sample.level2_ingress_interface_id = node2_metadata->level2_ingress_interface_id; */
      /* sample.level2_egress_interface_id = node2_metadata->level2_egress_interface_id; */
      /* sample.egress_interface_tx = node2_metadata->egress_interface_tx; */
      /* sample.buffer_occupancy = node2_metadata->buffer_occupancy; */

      mem_write_atomic(&sample, &entry->int_metric_info_value.latest[1], sizeof(sample));
    }

    if (nodes_present > 2) {
      node3_metadata = (__lmem struct pif_header_ingress__node3_metadata *) (headers + PIF_PARREP_ingress__node3_metadata_OFF_LW);

      sample.node_id = node3_metadata->node_id;
      sample.ingress_and_egress_interface_id = (((uint32_t) node3_metadata->level1_ingress_interface_id) << 16) | node3_metadata->level1_egress_interface_id;
      sample.hop_latency = node3_metadata->hop_latency;
      sample.queue_occupancy = node3_metadata->queue_occupancy;
      sample.ingress_timestamp = (((uint64_t)node3_metadata->ingress_timestamp) << 32) | node3_metadata->__ingress_timestamp_1;
      sample.egress_timestamp = (((uint64_t)node3_metadata->egress_timestamp) << 32) | node3_metadata->__egress_timestamp_1;
      /* sample.level2_ingress_interface_id = node3_metadata->level2_ingress_interface_id; */
      /* sample.level2_egress_interface_id = node3_metadata->level2_egress_interface_id; */
      /* sample.egress_interface_tx = node3_metadata->egress_interface_tx; */
      /* sample.buffer_occupancy = node3_metadata->buffer_occupancy; */

      mem_write_atomic(&sample, &entry->int_metric_info_value.latest[2], sizeof(sample));
    }

    if (nodes_present > 3) {
      node4_metadata = (__lmem struct pif_header_ingress__node4_metadata *) (headers + PIF_PARREP_ingress__node4_metadata_OFF_LW);

      sample.node_id = node4_metadata->node_id;
      sample.ingress_and_egress_interface_id = (((uint32_t) node4_metadata->level1_ingress_interface_id) << 16) | node4_metadata->level1_egress_interface_id;
      sample.hop_latency = node4_metadata->hop_latency;
      sample.queue_occupancy = node4_metadata->queue_occupancy;
      sample.ingress_timestamp = (((uint64_t)node4_metadata->ingress_timestamp) << 32) | node4_metadata->__ingress_timestamp_1;
      sample.egress_timestamp = (((uint64_t)node4_metadata->egress_timestamp) << 32) | node4_metadata->__egress_timestamp_1;
      /* sample.level2_ingress_interface_id = node4_metadata->level2_ingress_interface_id; */
      /* sample.level2_egress_interface_id = node4_metadata->level2_egress_interface_id; */
      /* sample.egress_interface_tx = node4_metadata->egress_interface_tx; */
      /* sample.buffer_occupancy = node4_metadata->buffer_occupancy; */

      mem_write_atomic(&sample, &entry->int_metric_info_value.latest[3], sizeof(sample));
    }

    if (nodes_present > 4) {
      node5_metadata = (__lmem struct pif_header_ingress__node5_metadata *) (headers + PIF_PARREP_ingress__node5_metadata_OFF_LW);

      sample.node_id = node5_metadata->node_id;
      sample.ingress_and_egress_interface_id = (((uint32_t) node5_metadata->level1_ingress_interface_id) << 16) | node5_metadata->level1_egress_interface_id;
      sample.hop_latency = node5_metadata->hop_latency;
      sample.queue_occupancy = node5_metadata->queue_occupancy;
      sample.ingress_timestamp = (((uint64_t)node5_metadata->ingress_timestamp) << 32) | node5_metadata->__ingress_timestamp_1;
      sample.egress_timestamp = (((uint64_t)node5_metadata->egress_timestamp) << 32) | node5_metadata->__egress_timestamp_1;
      /* sample.level2_ingress_interface_id = node5_metadata->level2_ingress_interface_id; */
      /* sample.level2_egress_interface_id = node5_metadata->level2_egress_interface_id; */
      /* sample.egress_interface_tx = node5_metadata->egress_interface_tx; */
      /* sample.buffer_occupancy = node5_metadata->buffer_occupancy; */

      mem_write_atomic(&sample, &entry->int_metric_info_value.latest[4], sizeof(sample));
    }
  }

  return PIF_PLUGIN_RETURN_FORWARD;
}
