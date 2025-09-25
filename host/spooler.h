#pragma once
#include <stddef.h>
#include <stdint.h>
#include "ring_defs.h"

/**
 * The spooler is responsible for:
 *  - Draining bucket_entry items from a bounded queue.
 *  - Writing them as plain NDJSON in Elasticsearch Bulk format
 *    (action line + document line).
 *  - Rotating files when they reach a max size, doc count,
 *    or age threshold.
 *  - Renaming files from .open → .ready for durability and
 *    safe handoff to Filebeat/Logstash.
 */

#define QUEUE_CAPACITY (1u << 20) /* ~1M entries */

void spooler_init(void);
void spooler_start(void);
void spooler_stop(void);

/* Producer side API: enqueue a new entry */
int spooler_enqueue(const bucket_entry *e);
