#include <nfp.h>
#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include "time_utils.h"
#include "data_structures.h"

#define AGE_THRESHOLD_NS (30000000000)  /* 30 seconds */

__export __emem bucket_list int_flowcache[FLOWCACHE_ROWS];
__export __emem ring_list ring_buffer_G[NUM_RINGS];
__export __emem ring_meta ring_G[NUM_RINGS];

unsigned long long get_time_diff_ns(uint64_t last)
{
    uint64_t ts;
    unsigned long long elapsed_ns;

    ts = me_tsc_read();

    elapsed_ns = ticks_to_ns(ts) - last;

    return elapsed_ns;
}

void evict_stale_entries(uint64_t threshold_ns) {
    __xrw ring_meta ring_meta_read;
    __volatile __addr40 __emem bucket_entry *entry;
    __volatile __addr40 __emem ring_meta *ring_info;
    __volatile __addr40 __emem bucket_entry *r_entry;
    uint32_t wp, rp, f;
    uint32_t i, j, ring_index;
    uint64_t last_ts;
    __xrw uint64_t last_ts_xrw;
    uint32_t zero = 0;
    uint32_t key_reset[4] = {0};
    uint32_t k;
    uint64_t current_time;

    for (i = 0; i < FLOWCACHE_ROWS; i++) {
        current_time = me_tsc_read();
        for (j = 0; j < BUCKET_SIZE; j++) {
            entry = &int_flowcache[i].entry[j];
            last_ts = entry->last_update_timestamp;

            if (entry->packet_count != 0 && get_time_diff_ns(last_ts) > threshold_ns) {
                // Determine ring index
                ring_index = i & (NUM_RINGS - 1);
                ring_info = &ring_G[ring_index];

                mem_read_atomic(&ring_meta_read, (__mem void *)ring_info, sizeof(ring_meta_read));
                wp = ring_meta_read.write_pointer;
                rp = ring_meta_read.read_pointer;
                f  = ring_meta_read.full;

                if (f == 0) {
                  // Get ring entry pointer
                  r_entry = &ring_buffer_G[ring_index].entry[wp];

                  // Copy key
                  {
                    __xrw uint32_t key[4];
                    int key_index;
                    for (key_index = 0; key_index < 4; key_index++) {
                        key[key_index] = entry->key[key_index];
                    }
                    mem_write_atomic(&key, (__mem void *)&r_entry->key, sizeof(key));
                  }

                  // Copy packet_count
                  {
                    __xrw uint32_t pkt_cnt_buf;
                    pkt_cnt_buf = entry->packet_count;
                    mem_write_atomic(&pkt_cnt_buf, (__mem void *)&r_entry->packet_count, sizeof(pkt_cnt_buf));
                  }

                  // Copy last_update_timestamp
                  {
                    __xrw uint64_t ts_buf;
                    ts_buf = entry->last_update_timestamp;
                    mem_write_atomic(&ts_buf, (__mem void *)&r_entry->last_update_timestamp, sizeof(ts_buf));
                  }

                  // Copy int_metric_info_value.node_count
                  {
                    __xrw uint32_t node_cnt_buf;
                    node_cnt_buf = entry->int_metric_info_value.node_count;
                    mem_write_atomic(&node_cnt_buf,
                        (__mem void *)&r_entry->int_metric_info_value.node_count,
                        sizeof(node_cnt_buf));
                  }

                    // Copy per-node data
                    for (k = 0; k < entry->int_metric_info_value.node_count && k < MAX_INT_NODES; k++) {
                      __xrw int_metric_sample tmp_latest;
                      __xrw int_metric_sample tmp_avg;

                      // Copy latest[k]
                      tmp_latest = entry->int_metric_info_value.latest[k];
                      mem_write_atomic(&tmp_latest,
                          (__mem void *)&r_entry->int_metric_info_value.latest[k],
                          sizeof(tmp_latest));

                      // Copy average[k]
                      tmp_avg = entry->int_metric_info_value.average[k];
                      mem_write_atomic(&tmp_avg,
                          (__mem void *)&r_entry->int_metric_info_value.average[k],
                          sizeof(tmp_avg));
                    }

                    // Advance write pointer
                    wp = (wp + 1) & (RING_SIZE - 1);
                    if (wp == rp) f = 1;

                    // Free the bucket
                    {
                      __xrw uint32_t zero_xrw = 0;
                      mem_write_atomic(&zero_xrw,
                          (__mem void *)&entry->packet_count,
                          sizeof(zero_xrw));
                    }

                    {
                      __xrw uint32_t key_reset_xrw[4] = {0};
                      mem_write_atomic(&key_reset_xrw,
                          (__mem void *)&entry->key,
                          sizeof(key_reset_xrw));
                    }

                    // Update ring metadata
                    ring_meta_read.write_pointer = wp;
                    ring_meta_read.full = f;
                    mem_write_atomic(&ring_meta_read,
                        (__mem void *)ring_info,
                        sizeof(ring_meta_read));
                }
            }
        }
    }
}

__export __mem40 uint32_t timers = 0;

void main(void)
{
    // Only one thread launches the periodic eviction timer
    if (ctx() == 0 && timers == 0) {
        timers++;

        while (1) {
            // Call the eviction routine
            evict_stale_entries(AGE_THRESHOLD_NS);
        }
    }
}
