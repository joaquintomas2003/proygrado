#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <std/hash.h>
#include "time_utils.h"
#include "data_structures.h"

static __inline int _get_hash_key(EXTRACTED_HEADERS_T *headers, uint32_t hash_key[4]) {
  uint32_t src_port;
  uint32_t dst_port;
  uint32_t proto;

  PIF_PLUGIN_ipv4_T *ipv4 = pif_plugin_hdr_get_ipv4(headers);
  PIF_PLUGIN_udp_T *udp = pif_plugin_hdr_get_udp(headers);
  PIF_PLUGIN_tcp_T *tcp = pif_plugin_hdr_get_tcp(headers);
  PIF_PLUGIN_intl4_shim_T *int_shim = pif_plugin_hdr_get_intl4_shim(headers);

  if (int_shim->npt == 1){
    uint32_t first_word = int_shim->first_word_of_udp_port;
    uint32_t second_word = int_shim->reserved;

    src_port = udp->src_port;
    dst_port = (first_word << 8) | second_word;
    proto = ipv4->protocol;
  } else if (int_shim->npt == 2 && int_shim->reserved == IP_PROTO_TCP){
    src_port = tcp->src_port;
    dst_port = tcp->dst_port;
    proto = int_shim->reserved;
  } else {
    return -1;
  }

  hash_key[0] = ipv4->src_addr;
  hash_key[1] = ipv4->dst_addr;
  hash_key[2] = (src_port << 16) | dst_port;
  hash_key[3] = proto;

  return 0;
}

static __inline int _push_event_to_RI(uint32_t ring_index,
                                      uint32_t switch_id,
                                      uint32_t value,
                                      uint32_t event_bitmap,
                                      uint32_t ts_low32) {
  __addr40 __emem ring_meta *ri_meta;
  __addr40 __emem event_record *slot;
  uint32_t wp, rp, f;
  __xrw ring_meta md_buf; /* [0]=wp, [1]=rp, [2]=full */
  __xwrite uint32_t wr0[4];

  semaphore_down(&ring_buffer_sem_I[ring_index]);
  ri_meta = &ring_I[ring_index];

  mem_read_atomic(&md_buf, ri_meta, sizeof(md_buf));
  wp = md_buf.write_pointer;
  rp = md_buf.read_pointer;
  f  = md_buf.full;

  if (f) return -1; /* full */

  slot = &ring_buffer_I[ring_index].entry[md_buf.write_pointer];

  wr0[0] = switch_id;
  wr0[1] = value;
  wr0[2] = event_bitmap;
  wr0[3] = ts_low32;
  mem_write_atomic(wr0, slot, sizeof(wr0));

  wp = (wp + 1) & (RING_SIZE - 1);
  if (wp == rp) f = 1;

  md_buf.write_pointer = wp;
  md_buf.read_pointer = rp;
  md_buf.full = f;

  mem_write_atomic(&md_buf, ri_meta, sizeof(md_buf));
  semaphore_up(&ring_buffer_sem_I[ring_index]);
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

static __inline int _absdiff(uint32_t a, uint32_t b) {
  return (a > b) ? (a - b) : (b - a);
}

int pif_plugin_save_in_hash(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
  // Declare the bucket entry variables
  __addr40 __emem bucket_entry *entry = 0;
  __xrw int_metric_sample avg_sample;
  __xrw uint32_t nodes_present;
  __xrw uint64_t update_timestamp;
  __xwrite int_metric_sample sample;
  int i, k;
  uint32_t hash_key[4];
  void *node_metadata_ptrs[MAX_INT_NODES];
  volatile uint32_t hash_value;

  __xrw uint64_t timestamp;
  uint64_t min_ts = 0xFFFFFFFFFFFFFFFFULL;
  uint64_t aged_ts;
  uint32_t evict_selected = 0;
  uint32_t wp, rp, f;
  uint32_t ring_index;
  __xwrite uint32_t zero = 0;
  __xwrite uint32_t key_reset[4] = {0, 0, 0, 0};
  __addr40 __emem bucket_entry *victim_entry = 0;
  __addr40 __emem bucket_entry *ring_entry = 0;
  __addr40 __emem ring_meta *ring_info;
  __xrw    ring_meta ring_meta_read;
  __xwrite uint32_t key_lru[4];
  __xwrite uint32_t packet_count_lru;
  __xwrite uint64_t first_packet_timestamp_lru;

  __xrw int_metric_sample prev_latest;
  uint32_t e2e_prev_hop = 0, e2e_curr_hop = 0;
  uint32_t absdiff;
  uint32_t metric_id;
  uint32_t ring_index_ev;
  uint32_t hop_latency;

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
  ring_index_ev = hash_value & (NUM_RINGS - 1);
  bitmap = (__lmem struct pif_header_ingress__bitmap *) (headers + PIF_PARREP_ingress__bitmap_OFF_LW);
  scalars = (__lmem struct pif_header_scalars *) (headers + PIF_PARREP_scalars_OFF_LW);
  intrinsic_metadata = (__lmem struct pif_header_intrinsic_metadata *) (headers + PIF_PARREP_intrinsic_metadata_OFF_LW);

  semaphore_down(&global_semaphores[hash_value]);
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
    /* Check for aged entries */
    if (get_time_diff_ns(entry->last_update_timestamp) > AGE_THRESHOLD_NS) {
        aged_ts = get_time_diff_ns(entry->last_update_timestamp);
        victim_entry = entry;
        evict_selected = 1;
        break;
    }
    /* Keep track of the LRU bucket in case of no aged entries */
    if (entry->last_update_timestamp < min_ts) {
        min_ts = entry->last_update_timestamp;
        victim_entry = entry;
    }
  }
  if (evict_selected) timestamp = aged_ts;
  else timestamp = min_ts;

  // If we reached the end of the bucket without finding a match
  if (i == BUCKET_SIZE || evict_selected) {
    ring_index = hash_value & (NUM_RINGS - 1);
    semaphore_down(&ring_buffer_sem_G[ring_index]);
      ring_info = &ring_G[ring_index];

      mem_read_atomic(&ring_meta_read, ring_info, sizeof(ring_meta_read));
      wp = ring_meta_read.write_pointer;
      rp = ring_meta_read.read_pointer;
      f  = ring_meta_read.full;

      if (f == 0) {
        nodes_present = victim_entry->int_metric_info_value.node_count;
        ring_entry = &ring_buffer_G[ring_index].entry[wp];

        key_lru[0] = victim_entry->key[0];
        key_lru[1] = victim_entry->key[1];
        key_lru[2] = victim_entry->key[2];
        key_lru[3] = victim_entry->key[3];
        packet_count_lru = victim_entry->packet_count;
        first_packet_timestamp_lru = victim_entry->first_packet_timestamp;

        mem_write_atomic(key_lru, &ring_entry->key, sizeof(key_lru));
        mem_write_atomic(&packet_count_lru, &ring_entry->packet_count, sizeof(packet_count_lru));
        mem_write_atomic(&first_packet_timestamp_lru, &ring_entry->first_packet_timestamp, sizeof(first_packet_timestamp_lru));
        mem_write_atomic(&timestamp, &ring_entry->last_update_timestamp, sizeof(timestamp));
        mem_write_atomic(&nodes_present, &ring_entry->int_metric_info_value.node_count, sizeof(nodes_present));

        for (k = 0; k < nodes_present && k < MAX_INT_NODES; k++) {
          sample.node_id = victim_entry->int_metric_info_value.latest[k].node_id;
          sample.hop_latency = victim_entry->int_metric_info_value.latest[k].hop_latency;
          sample.queue_occupancy = victim_entry->int_metric_info_value.latest[k].queue_occupancy;
          sample.egress_interface_tx = victim_entry->int_metric_info_value.latest[k].egress_interface_tx;
          mem_write_atomic(&sample, &ring_entry->int_metric_info_value.latest[k], sizeof(sample));

          sample.node_id = victim_entry->int_metric_info_value.average[k].node_id;
          sample.hop_latency = victim_entry->int_metric_info_value.average[k].hop_latency;
          sample.queue_occupancy = victim_entry->int_metric_info_value.average[k].queue_occupancy;
          sample.egress_interface_tx = victim_entry->int_metric_info_value.average[k].egress_interface_tx;
          mem_write_atomic(&sample, &ring_entry->int_metric_info_value.average[k], sizeof(sample));
        }
        wp = (wp + 1) & (RING_SIZE - 1);
        if(wp == rp){
            f = 1;
        }
        /* Free the bucket on the hash table */
        mem_write_atomic(&zero, &victim_entry->packet_count, sizeof(zero));
        mem_write_atomic(&key_reset, &victim_entry->key, sizeof(key_reset));
        /* We were on the last bucket, now we are on the free'd bucket*/
        entry = victim_entry;

      } else {
        return PIF_PLUGIN_RETURN_FORWARD;
      }
      ring_meta_read.write_pointer = wp;
      ring_meta_read.full          = f;
      ring_meta_read.read_pointer  = rp;
      mem_write_atomic(&ring_meta_read, ring_info, sizeof(ring_meta_read));
    semaphore_up(&ring_buffer_sem_G[ring_index]);
  }

  // Metadata pointers for nodes
  node_metadata_ptrs[0] = headers + PIF_PARREP_ingress__node1_metadata_OFF_LW;
  node_metadata_ptrs[1] = headers + PIF_PARREP_ingress__node2_metadata_OFF_LW;
  node_metadata_ptrs[2] = headers + PIF_PARREP_ingress__node3_metadata_OFF_LW;
  node_metadata_ptrs[3] = headers + PIF_PARREP_ingress__node4_metadata_OFF_LW;
  node_metadata_ptrs[4] = headers + PIF_PARREP_ingress__node5_metadata_OFF_LW;

  // Save the last update timestamp
  update_timestamp = ticks_to_ns(me_tsc_read());
  mem_write_atomic(&update_timestamp, &entry->last_update_timestamp, sizeof(update_timestamp));

  // Increment the packet count
  mem_incr32(&entry->packet_count);

  nodes_present = scalars->metadata__nodes_present;

  // If this is the first packet for this flow, initialize the entry
  if (entry->packet_count == 1) {
    __xwrite uint32_t key_wr[4] = {hash_key[0], hash_key[1], hash_key[2], hash_key[3]};
    mem_write_atomic(key_wr, entry->key, sizeof(key_wr));
    mem_write_atomic(&nodes_present, &entry->int_metric_info_value.node_count, sizeof(nodes_present));

    // Set the first packet timestamp
    mem_write_atomic(&update_timestamp, &entry->first_packet_timestamp, sizeof(update_timestamp));
  }

  for (k = 0; k < nodes_present && k < MAX_INT_NODES; k++) {
    node = (__lmem struct pif_header_ingress__node1_metadata *)node_metadata_ptrs[k];

    /* NOTE: We control C-events when there is more than one packet */
    /* === Per-switch T-events on HOP === */
    metric_id = METRIC_HOP;
    hop_latency = node->hop_latency;

    if (hop_latency >= THR_T_SWITCH[0]) {
      _push_event_to_RI(ring_index_ev,
                        node->node_id,
                        hop_latency,
                        EVENT_T_SWITCH | metric_id,
                        (uint32_t)update_timestamp);
    }

    /* === Maintain end-to-end current hop sum as we go === */
    e2e_curr_hop += hop_latency;

    /* Write latest sample */
    sample.node_id             = node->node_id;
    sample.hop_latency         = hop_latency;
    sample.queue_occupancy     = node->queue_occupancy;
    sample.egress_interface_tx = node->egress_interface_tx;

    if (entry->packet_count > 1) {

      /* Read previous latest BEFORE overwriting, for C-events */
      mem_read_atomic(&prev_latest, &entry->int_metric_info_value.latest[k], sizeof(prev_latest));

      /* Build the previous end-to-end hop sum before we overwrite latest[] */
      e2e_prev_hop += prev_latest.hop_latency;

      /* === Per-switch C-events on HOP === */
      absdiff = _absdiff(hop_latency, prev_latest.hop_latency);
      if (absdiff >= THR_C_SWITCH[0]) {
        _push_event_to_RI(ring_index_ev,
                          node->node_id,
                          absdiff,
                          EVENT_C_SWITCH | metric_id,
                          (uint32_t)update_timestamp);
      }
      mem_read_atomic(&avg_sample, &entry->int_metric_info_value.average[k], sizeof(avg_sample));

      avg_sample.node_id             = node->node_id;
      avg_sample.hop_latency         = (avg_sample.hop_latency         * (entry->packet_count - 1) + hop_latency)               / entry->packet_count;
      avg_sample.queue_occupancy     = (avg_sample.queue_occupancy     * (entry->packet_count - 1) + node->queue_occupancy)     / entry->packet_count;
      avg_sample.egress_interface_tx = (avg_sample.egress_interface_tx * (entry->packet_count - 1) + node->egress_interface_tx) / entry->packet_count;

      mem_write_atomic(&avg_sample, &entry->int_metric_info_value.average[k], sizeof(avg_sample));
    } else {
      mem_write_atomic(&sample, &entry->int_metric_info_value.average[k], sizeof(sample));

      /* This way, we wont trigger a C-event e2e */
      e2e_prev_hop = e2e_curr_hop;
    }
    /* We can write after the IF without problem */
    mem_write_atomic(&sample, &entry->int_metric_info_value.latest[k], sizeof(sample));
  }
  semaphore_up(&global_semaphores[hash_value]);

  /* === End-to-end hop-latency events (T/C) === */
  if (e2e_curr_hop >= THR_T_E2E[0]) {
    _push_event_to_RI(ring_index_ev,
                      E2E_SWITCH_ID,
                      e2e_curr_hop,
                      EVENT_T_E2E | METRIC_HOP,
                      (uint32_t)update_timestamp);
  }
  absdiff = _absdiff(e2e_curr_hop, e2e_prev_hop);
  if (absdiff >= THR_C_E2E[0]) {
    _push_event_to_RI(ring_index_ev,
                      E2E_SWITCH_ID,
                      absdiff,
                      EVENT_C_E2E | METRIC_HOP,
                      (uint32_t)update_timestamp);
  }

  return PIF_PLUGIN_RETURN_FORWARD;
}