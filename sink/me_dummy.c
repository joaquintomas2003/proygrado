#include <stdint.h>
#include <nfp.h>
#include <nfp/mem_atomic.h>
#include <nfp/me.h>

/* exported variables in EMEM so host/tools/other MEs can inspect/modify */
__export __mem40 volatile uint32_t latch = 0xFF;         /* wake/trigger latch */
__export __mem40 volatile uint32_t timers = 0;           /* single-timer guard */
__export __mem40 volatile uint32_t dummy_counter = 0;    /* counter to confirm ME runs */

/* how long to sleep between increments (ms) */
#define INCREMENT_MS 1000

/* timer thread */
void timer_thread()
{
  __xrw uint32_t xfer = 0xFF;
  __xrw uint32_t tmp;
  int i;

  while (1) {
    /* Grab the latch value (test-set).  If it's 0xFF we go to the sleep/scan loop. */
    mem_test_set(&xfer, (__mem40 void *)&latch, sizeof(xfer));
    while (xfer == 0xFF) {
      /* Periodic background work: increment the exported counter atomically. */
      mem_incr32((__mem40 void *)&dummy_counter);

      /* Yield a bit so we don't busy spin (match behavior in your template). */
      sleep(INCREMENT_MS);

      /* re-check latch value */
      mem_test_set(&xfer, (__mem40 void *)&latch, sizeof(xfer));
    }

    /* If latch was cleared (someone triggered us), do a short immediate burst of work. */
    for (i = 0; i < 8; i++) {
      mem_incr32((__mem40 void *)&dummy_counter);
    }

    /* Release the latch (clear the test-set) so others waiting can be notified. */
    tmp = 0xFF;
    mem_test_clr(&tmp, (__mem40 void *)&latch, sizeof(tmp));
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
