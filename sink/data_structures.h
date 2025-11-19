#include <stdint.h>

#define FLOWCACHE_ROWS (1 << 18)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define IP_PROTO_UDP 0x11
#define IP_PROTO_TCP 0x6
#define NUM_RINGS 8
#define RING_SIZE (1 << 17)

#define x1 1                        //2^0
#define x2 x1, x1                   //2^1
#define x4 x2, x2                   //2^2
#define x8 x4, x4                   //2^3

/* Event type bits */
#define EVENT_T_SWITCH  (1u << 0)
#define EVENT_C_SWITCH  (1u << 1)
#define EVENT_T_E2E     (1u << 2)
#define EVENT_C_E2E     (1u << 3)

/* Metric id (packed in bits [8..15]) */
#define METRIC_HOP     (0u << 8)
#define METRIC_QUEUE   (1u << 8)
#define METRIC_EGRESS  (2u << 8)

/* Special switch_id for end-to-end events */
#define E2E_SWITCH_ID  0xFFFFFFFF

/* Number of metrics to be monitorized */
#define NUM_METRICS 1

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
  uint64_t first_packet_timestamp; /* Timestamp in nanoseconds */
  uint64_t last_update_timestamp; /* Timestamp in nanoseconds */
  int_metric_info int_metric_info_value;
  uint32_t packet_count;
  uint32_t request_meta; // bits 0–15: request_id, bit 16: is_response, bits 17–31: reserved
  uint32_t _padding2;
} bucket_entry;

typedef struct bucket_list {
  struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;

typedef struct ring_list {
  struct bucket_entry entry[RING_SIZE];
} ring_list;

typedef struct event_record {
  uint32_t switch_id;       /* per-switch id, or 0xFFFFFFFF for E2E */
  uint32_t value;           /* metric value or delta */
  uint32_t event_bitmap;    /* encodes type & metric */
  uint64_t event_timestamp; /* timestamp of the event */
  uint64_t _padding;
} event_record;

typedef struct event_ring_list {
  struct event_record entry[RING_SIZE];
} event_ring_list;

typedef struct ring_meta {
  uint32_t read_pointer;
  uint32_t write_pointer;
  uint32_t full;
  uint32_t _padding;
} ring_meta;

__export __emem uint32_t THR_T_SWITCH[NUM_METRICS] = {700};
__export __emem uint32_t THR_C_SWITCH[NUM_METRICS] = {300};
__export __emem uint32_t THR_T_E2E[NUM_METRICS]    = {3500};
__export __emem uint32_t THR_C_E2E[NUM_METRICS]    = {900};

__export __emem bucket_list int_flowcache[FLOWCACHE_ROWS];

__export __emem ring_list ring_buffer_G[NUM_RINGS];
__export __emem ring_meta ring_G[NUM_RINGS];

__export __emem event_ring_list ring_buffer_I[NUM_RINGS];
__export __emem ring_meta ring_I[NUM_RINGS];

volatile __emem __export uint32_t global_semaphores[FLOWCACHE_ROWS];
volatile __emem __export uint32_t ring_buffer_sem_G[NUM_RINGS] = {x8};
volatile __emem __export uint32_t ring_buffer_sem_I[NUM_RINGS] = {x8};

#define NUM_ISLANDS      5
#define BASE_ISLAND      32
#define MEs_PER_ISLAND   12
#define THREADS_PER_ME   4
#define NUM_THREADS      (NUM_ISLANDS * MEs_PER_ISLAND * THREADS_PER_ME)  // 240

typedef struct latency_record {
  uint32_t value;
  uint32_t _padding1;
  uint32_t _padding2;
  uint32_t _padding3;
} latency_record;


volatile __export __emem latency_record latency_array[NUM_THREADS] = {0ULL};

volatile __addr40 __emem __export uint64_t ts_evict_inicio = 0;
volatile __addr40 __emem __export uint64_t ts_evict_fin = 0;

volatile __addr40 __emem __export uint64_t ts_inicio = 0;
volatile __addr40 __emem __export uint64_t ts_fin = 0;
volatile __addr40 __emem __export uint64_t latency = 0xFFFFFFFFFFFFFFFFULL;


static __forceinline uint32_t get_global_thread_id(void)
{
    /* Extract island and ME from encoded _ME() */
    uint32_t me_raw = _ME();

    uint32_t island =  me_raw >> 4;          // 32..36
    uint32_t me     = (me_raw & 0xF) - 4;    // 0..11

    /* Compact thread ID: __ctx() = 0,2,4,6 → 0..3 */
    uint32_t thread = __ctx() >> 1;          // 0..3

    /* Produce unique contiguous thread index */
    uint32_t global_thread_id =
        (island - BASE_ISLAND) * (MEs_PER_ISLAND * THREADS_PER_ME) +
        me                       * THREADS_PER_ME +
        thread;

    return global_thread_id;                 // 0..239
}

static __inline void semaphore_down(volatile __declspec(mem addr40) void * addr) {
  unsigned int addr_hi, addr_lo;
  __declspec(read_write_reg) int xfer;
  SIGNAL_PAIR my_signal_pair;
  addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
  addr_lo = (unsigned long long int)addr & 0xffffffff;
  do {
      xfer = 1;
      __asm {
      mem[test_subsat, xfer, addr_hi, <<8, addr_lo, 1],\
          sig_done[my_signal_pair];
      ctx_arb[my_signal_pair]
      }
      sleep(500);
  } while (xfer == 0);
}

static __inline void semaphore_up(volatile __declspec(mem addr40) void * addr) {
  unsigned int addr_hi, addr_lo;
  __declspec(read_write_reg) int xfer;
  addr_hi = ((unsigned long long int)addr >> 8) & 0xff000000;
  addr_lo = (unsigned long long int)addr & 0xffffffff;
  __asm {
    mem[incr, --, addr_hi, <<8, addr_lo, 1];
  }
}