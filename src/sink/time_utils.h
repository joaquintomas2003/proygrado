#ifndef TIME_UTILS_H
#define TIME_UTILS_H

#include <stdint.h>
#include <nfp/me.h>

#define AGE_THRESHOLD_NS (30000000000)  /* 30 seconds */

unsigned long long get_time_diff_ns(uint64_t last);
uint64_t ticks_to_ns(uint64_t ticks);

#endif