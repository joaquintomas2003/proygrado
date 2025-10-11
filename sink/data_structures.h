#include <stdint.h>

#define FLOWCACHE_ROWS (1 << 10)
#define BUCKET_SIZE 12
#define MAX_INT_NODES 5
#define IP_PROTO_UDP 0x11
#define IP_PROTO_TCP 0x6
#define NUM_RINGS 8
#define RING_SIZE (1 << 16)

#define x1 1                        //2^0
#define x2 x1, x1                   //2^1
#define x4 x2, x2                   //2^2
#define x8 x4, x4                   //2^3
#define x16 x8, x8                  //2^4
#define x32 x16, x16                //2^5
#define x64 x32, x32                //2^6
#define x128 x64, x64               //2^7
#define x256 x128, x128             //2^8
#define x512 x256, x256             //2^9
#define x1024 x512, x512            //2^10
#define x2048 x1024, x1024          //2^11
#define x4096 x2048, x2048          //2^12
#define x8192 x4096, x4096          //2^13
#define x16384 x8192, x8192         //2^14
#define x32768 x16384, x16384       //2^15
#define x655356 x32768, x32768      //2^16
#define x1310712 x655356, x655356   //2^17
#define x2621424 x1310712, x1310712 //2^18

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
  uint64_t _padding2;
} bucket_entry;

typedef struct bucket_list {
  struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;

typedef struct ring_list {
  struct bucket_entry entry[RING_SIZE];
} ring_list;

typedef struct event_record {
  uint32_t switch_id;     /* per-switch id, or 0xFFFFFFFF for E2E */
  uint32_t value;         /* metric value or delta */
  uint32_t event_bitmap;  /* encodes type & metric */
  uint32_t ts_low32;      /* truncated timestamp (lower 32 bits) */
} event_record;

typedef struct event_ring_list {
  struct event_record entry[RING_SIZE];
} event_ring_list;

typedef struct ring_meta {
  uint32_t write_pointer;
  uint32_t read_pointer;
  uint32_t full;
  uint32_t _padding;
} ring_meta;

__export __emem uint32_t THR_T_SWITCH[3] = {0, 0, 0};
__export __emem uint32_t THR_C_SWITCH[3] = {0, 0, 0};
__export __emem uint32_t THR_T_E2E[3] = {0, 0, 0};
__export __emem uint32_t THR_C_E2E[3] = {0, 0, 0};

__export __emem bucket_list int_flowcache[FLOWCACHE_ROWS];

__export __emem ring_list ring_buffer_G[NUM_RINGS];
__export __emem ring_meta ring_G[NUM_RINGS];

__export __emem event_ring_list ring_buffer_I[NUM_RINGS];
__export __emem ring_meta ring_I[NUM_RINGS];

volatile __emem __export uint32_t global_semaphores[FLOWCACHE_ROWS] = {x1024};
volatile __emem __export uint32_t ring_buffer_sem_G[NUM_RINGS] = {x8};
volatile __emem __export uint32_t ring_buffer_sem_I[NUM_RINGS] = {x8};

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
