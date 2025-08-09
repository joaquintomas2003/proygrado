#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <std/hash.h>

#define FLOWCACHE_ROWS (1 << 18)
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

typedef struct ring_meta {
  uint32_t write_pointer;
  uint32_t read_pointer;
  uint32_t full;
} ring_meta;

__export __emem bucket_list int_flowcache[FLOWCACHE_ROWS];

__export __emem ring_list ring_buffer_G[NUM_RINGS];
__export __emem ring_meta ring_G[NUM_RINGS];

static __inline int _get_hash_key(EXTRACTED_HEADERS_T *headers, uint32_t hash_key[4]) {
  uint32_t src_port;
  uint32_t dst_port;

  PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
  PIF_PLUGIN_udp_T *udp = pif_plugin_hdr_get_udp(headers);
  PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
  PIF_PLUGIN_intl4_shim_T *int_shim = pif_plugin_hdr_get_intl4_shim(headers);

  if (int_shim->npt == 1){
    uint32_t first_word = int_shim->first_word_of_udp_port;
    uint32_t second_word = int_shim->reserved;

    src_port = udp->src_port;
    dst_port = (first_word << 8) | second_word;
  } else if (int_shim->npt == 2 && int_shim->reserved == IP_PROTO_TCP){
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
  __xrw uint64_t ingress_timestamp;
  __xwrite int_metric_sample sample;
  int i, k;
  uint32_t hash_key[4];
  void *node_metadata_ptrs[MAX_INT_NODES];
  volatile uint32_t hash_value;

  __xrw uint64_t timestamp = 0xFFFFFFFFFFFFFFFF;
  uint32_t wp, rp, f;
  uint32_t ring_index;
  __xwrite uint32_t zero = 0;
  __xwrite uint32_t key_reset[4] = {0, 0, 0, 0};
  __addr40 __emem bucket_entry *lru_entry = 0;
  __addr40 __emem bucket_entry *ring_entry = 0;
  __addr40 __emem ring_meta *ring_info;
  __xrw    ring_meta ring_meta_read;
  __xwrite uint32_t key_lru[4];
  __xwrite uint32_t packet_count_lru;

  // Declare the metadata variables
  __lmem struct pif_header_scalars *scalars;
  __lmem struct pif_header_ingress__bitmap *bitmap;
  __lmem struct pif_header_intrinsic_metadata *intrinsic_metadata;
  __lmem struct pif_header_ingress__node1_metadata *node;

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
    /* Keep track of the LRU bucket */
    if (timestamp > entry->last_update_timestamp) {
      timestamp = entry->last_update_timestamp;
      lru_entry = entry;
    }
  }

  // If we reached the end of the bucket without finding a match
  if (i == BUCKET_SIZE) {
    ring_index = hash_value & (NUM_RINGS - 1);
    ring_info = &ring_G[ring_index];

    mem_read_atomic(&ring_meta_read, ring_info, sizeof(ring_meta_read));
    wp = ring_meta_read.write_pointer;
    rp = ring_meta_read.read_pointer;
    f  = ring_meta_read.full;

    if (f == 0) {
      nodes_present = lru_entry->int_metric_info_value.node_count;
      ring_entry = &ring_buffer_G[ring_index].entry[wp];

      key_lru[0] = lru_entry->key[0];
      key_lru[1] = lru_entry->key[1];
      key_lru[2] = lru_entry->key[2];
      key_lru[3] = lru_entry->key[3];
      packet_count_lru = lru_entry->packet_count;

      mem_write_atomic(key_lru, &ring_entry->key, sizeof(key_lru));
      mem_write_atomic(&packet_count_lru, &ring_entry->packet_count, sizeof(packet_count_lru));
      mem_write_atomic(&timestamp, &ring_entry->last_update_timestamp, sizeof(timestamp));
      mem_write_atomic(&nodes_present, &ring_entry->int_metric_info_value.node_count, sizeof(nodes_present));
      
      for (k = 0; k < nodes_present && k < MAX_INT_NODES; k++) {

        sample.node_id = lru_entry->int_metric_info_value.latest[k].node_id;
        sample.hop_latency = lru_entry->int_metric_info_value.latest[k].hop_latency;
        sample.queue_occupancy = lru_entry->int_metric_info_value.latest[k].queue_occupancy;
        sample.egress_interface_tx = lru_entry->int_metric_info_value.latest[k].egress_interface_tx;
        mem_write_atomic(&sample, &ring_entry->int_metric_info_value.latest[k], sizeof(sample));

        sample.node_id = lru_entry->int_metric_info_value.average[k].node_id;
        sample.hop_latency = lru_entry->int_metric_info_value.average[k].hop_latency;
        sample.queue_occupancy = lru_entry->int_metric_info_value.average[k].queue_occupancy;
        sample.egress_interface_tx = lru_entry->int_metric_info_value.average[k].egress_interface_tx;
        mem_write_atomic(&sample, &ring_entry->int_metric_info_value.average[k], sizeof(sample));
      }
      wp = (wp + 1) & (RING_SIZE - 1);
      if(wp == rp){
          f = 1;
      }
      /* Free the bucket on the hash table */
      mem_write_atomic(&zero, &lru_entry->packet_count, sizeof(zero));
      mem_write_atomic(&key_reset, &lru_entry->key, sizeof(key_reset));
      /* We were on the last bucket, now we are on the free'd bucket*/
      entry = lru_entry;

    } else {
      return PIF_PLUGIN_RETURN_FORWARD;
    }
    ring_meta_read.write_pointer = wp;
    ring_meta_read.full          = f;
    ring_meta_read.read_pointer  = rp;
    mem_write_atomic(&ring_meta_read, ring_info, sizeof(ring_meta_read));
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

  nodes_present = scalars->metadata__nodes_present;

  // If this is the first packet for this flow, initialize the entry
  if (entry->packet_count == 1) {
    __xwrite uint32_t key_wr[4] = {hash_key[0], hash_key[1], hash_key[2], hash_key[3]};
    mem_write_atomic(key_wr, entry->key, sizeof(key_wr));
    mem_write_atomic(&nodes_present, &entry->int_metric_info_value.node_count, sizeof(nodes_present));
  }

  for (k = 0; k < nodes_present && k < MAX_INT_NODES; k++) {
    node = (__lmem struct pif_header_ingress__node1_metadata *)node_metadata_ptrs[k];

    // Write latest sample
    sample.node_id = node->node_id;
    sample.hop_latency = node->hop_latency;
    sample.queue_occupancy = node->queue_occupancy;
    sample.egress_interface_tx = node->egress_interface_tx;
    mem_write_atomic(&sample, &entry->int_metric_info_value.latest[k], sizeof(sample));

    if (entry->packet_count > 1) {
      mem_read_atomic(&avg_sample, &entry->int_metric_info_value.average[k], sizeof(avg_sample));

      avg_sample.node_id = node->node_id;
      avg_sample.hop_latency = (avg_sample.hop_latency * (entry->packet_count - 1) + node->hop_latency) / entry->packet_count;
      avg_sample.queue_occupancy = (avg_sample.queue_occupancy * (entry->packet_count - 1) + node->queue_occupancy) / entry->packet_count;
      avg_sample.egress_interface_tx = (avg_sample.egress_interface_tx * (entry->packet_count - 1) + node->egress_interface_tx) / entry->packet_count;

      mem_write_atomic(&avg_sample, &entry->int_metric_info_value.average[k], sizeof(avg_sample));
    } else {
      mem_write_atomic(&sample, &entry->int_metric_info_value.average[k], sizeof(sample));
    }
  }

  return PIF_PLUGIN_RETURN_FORWARD;
}
