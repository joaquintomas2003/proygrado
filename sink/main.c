#include <nfp.h>
#include <stdint.h>
#include <nfp/me.h>
#include <pif_common.h>
#include <nfp/mem_atomic.h>
#include <nfp/mem_ring.h>
#include <pif_plugin.h>
#include <std/hash.h>
#include <memory.h>

#define TABLE_SIZE (524888*12)
#define BUCKET_SIZE (48)

volatile __export __emem uint32_t  conns_array[TABLE_SIZE][BUCKET_SIZE];
