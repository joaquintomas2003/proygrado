#include "time_utils.h"

/* From nfp-hwinfo: me.speed=633 */
#define ME_FREQ_MHZ      633

/* Each tick = 16 cycles. (cycles per tick x 1000) */
#define NS_PER_TICK   (16 * 1000ULL)

uint64_t ticks_to_ns(uint64_t ticks) {
  return (ticks * NS_PER_TICK) / ME_FREQ_MHZ;
}

unsigned long long get_time_diff_ns(uint64_t last) {
    uint64_t ts;
    unsigned long long elapsed_ns;

    ts = me_tsc_read();

    elapsed_ns = ticks_to_ns(ts) - last;

    return elapsed_ns;
}