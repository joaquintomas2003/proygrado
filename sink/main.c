#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <stdint.h>

#define RING_BUFFER_SIZE 1024

// Ring buffer in EMEM (visible to host)
__export __emem uint64_t ring_buffer[RING_BUFFER_SIZE];

// Write index in EMEM (shared with host for reading)
__export __emem uint32_t ring_index = 0;

int pif_plugin_write_to_ring(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
    __xrw uint32_t idx;
    __xwrite uint64_t constant = 0xdeadbeefdeadbeef;

    // Get current index and increment it atomically
    mem_test_add(&idx, &ring_index, sizeof(idx));
    idx %= RING_BUFFER_SIZE;

    // Write the constant into the buffer at index
    mem_write_atomic(&constant, &ring_buffer[idx], sizeof(constant));

    return PIF_PLUGIN_RETURN_FORWARD;
}
