#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>

#define FLOWCACHE_ROWS (1 << 18)
#define BUCKET_SIZE    12
#define MAX_INT_NODES  5
#define IP_PROTO_UDP = 0x11;
#define IP_PROTO_TCP = 0x6;

typedef struct int_metric_sample {
  uint32_t data[12];
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

int pif_plugin_save_hash(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
  uint32_t hash_key[4];
  volatile uint32_t hash_value;
  __addr40 __emem bucket_entry *entry;
  int i;
  __xrw uint32_t pkt_cnt;
  __xwrite int_metric_info tmp_b_info;
  int k;

  if (_get_hash_key(headers, hash_key) < 0) {
    return -1;
  }

  hash_value = hash_me_crc32((void *) hash_key, sizeof(hash_key), 1);
  hash_value &= (FLOWCACHE_ROWS - 1);

  entry = 0;

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

  if (i == BUCKET_SIZE) {
    return -1;
  }

  if (entry->packet_count == 0) {
    __xwrite uint32_t key_wr[4] = {hash_key[0], hash_key[1], hash_key[2], hash_key[3]};
    mem_write_atomic(key_wr, entry->key, sizeof(key_wr));
  }

  pkt_cnt = 1;
  mem_test_add(&pkt_cnt, &entry->packet_count, sizeof(pkt_cnt));

  PIF_PLUGIN_stack_element_t *node1_elem;
  PIF_PLUGIN_stack_element_t *node2_elem;
  PIF_PLUGIN_stack_element_t *node3_elem;
  PIF_PLUGIN_stack_element_t *node4_elem;
  PIF_PLUGIN_stack_element_t *node5_elem;

  for (k = 0; k < 12; k++) {
    node1_elem = pif_plugin_hdr_get_node1_metadata(headers, k);
    node2_elem = pif_plugin_hdr_get_node2_metadata(headers, k);
    node3_elem = pif_plugin_hdr_get_node3_metadata(headers, k);
    node4_elem = pif_plugin_hdr_get_node4_metadata(headers, k);
    node5_elem = pif_plugin_hdr_get_node5_metadata(headers, k);

    tmp_b_info.latest[0].data[k] = node1_elem->data;
    tmp_b_info.latest[1].data[k] = node2_elem->data;
    tmp_b_info.latest[2].data[k] = node3_elem->data;
    tmp_b_info.latest[3].data[k] = node4_elem->data;
    tmp_b_info.latest[4].data[k] = node5_elem->data;
  }

  mem_write_atomic(&tmp_b_info, &entry->int_metric_info_value, sizeof(tmp_b_info));

  return 0;
}
