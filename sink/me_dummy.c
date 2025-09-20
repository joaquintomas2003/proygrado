#include <stdint.h>
#include <nfp.h>
#include <nfp/mem_atomic.h>
#include <nfp/me.h>

/* exported variables in EMEM so host/tools/other MEs can inspect/modify */
__export __mem40 uint32_t latch = 0xFF;         /* wake/trigger latch */
__export __mem40 uint32_t timers = 0;           /* single-timer guard */
__export __mem40 uint32_t dummy_counter = 0;    /* counter to confirm ME runs */

/* how long to sleep between increments (ms) */
#define INCREMENT_MS 1000

/* timer thread */
void timer_thread()
{
  __xrw uint32_t xfer = 0xFF;
  __xrw uint32_t tmp = 0;
  int i;

  while (1) {
    // increase the counter
    mem_read_atomic(&tmp, &dummy_counter, sizeof(tmp));
    tmp++;
    mem_write_atomic(&tmp, &dummy_counter, sizeof(tmp));
  }
}

/* main: ensure only one thread across MEs becomes the timer thread (ctx==0 && timers==0) */
void main()
{
  if (ctx() == 0 && timers == 0) {
    /* claim the single-timer role */
    timers++;
    timer_thread(); /* does not return */
  }
}
