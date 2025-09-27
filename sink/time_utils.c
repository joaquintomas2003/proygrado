#include "time_utils.h"

/* From nfp-hwinfo: me.speed=633 */
#define ME_FREQ_MHZ      633

/* Each tick = 16 cycles. (cycles per tick x 1000) */
#define NS_PER_TICK   (16 * 1000ULL)

uint64_t ticks_to_ns(uint64_t ticks) {
  return (ticks * NS_PER_TICK) / ME_FREQ_MHZ;
}
