#pragma once
#include <stddef.h>
#include <stdint.h>
#include "ring_defs.h"

/**
 * The spooler is responsible for:
 *  - Draining bucket_entry items from a bounded queue.
 *  - Writing them as plain NDJSON (one document per line).
 *  - Rotating files when they reach a max size, doc count,
 *    or age threshold (age checked even when idle).
 *  - Renaming files from .ndjson.open → .ndjson for durability and
 *    safe handoff to Filebeat/Logstash (empty segments are unlinked).
 */

#define QUEUE_CAPACITY (1u << 20) /* ~1M entries */

void spooler_init(void);
void spooler_start(void);
void spooler_stop(void);

/* Producer side API: enqueue a new entry */
int spooler_enqueue(const bucket_entry *e);
