// spooler.c
//
// Spooler = lock-free-ish producer/consumer with a bounded queue.
// Producers (your ring readers) call spooler_enqueue(bucket_entry*).
// A single background thread pops entries and appends them as **one JSON
// document per line** into a rolling ".ndjson.open" file, which is atomically
// renamed to ".ndjson" on rotation/close. Filebeat tails only the closed files.
//
// Each document includes:
//   - @timestamp               : host wall-clock (ISO8601, UTC)
//   - host.name                : hostname
//   - flow.key[]               : 4x u32 key (numeric array)
//   - flow.packet_count        : packet_count
//   - flow.first_packet_ts     : NIC raw timestamp (ns)
//   - flow.last_update_ts      : NIC raw timestamp (ns)
//   - int.node_count           : # INT nodes
//   - int.latest[] / average[] : arrays of {node_id, hop_latency, queue_occupancy, egress_interface_tx}
//   - int.request_metadata     : 16 bits request id + 1 bit is_response + 7 bits reserved
//
// Notes:
//   - No Bulk action lines; NDJSON is compatible with Filebeat filestream+ndjson parser.
//   - SEG_MAX_AGE_MS defaults to 10s to avoid sub-1KB segments at low traffic.
//   - On shutdown, we drain the queue before closing/renaming the final segment.
//   - Age-based rotation now works even when idle (thread wakes periodically).
//   - Age uses CLOCK_MONOTONIC to avoid NTP jumps affecting rotation.

#include "spooler.h"
#include "ring_defs.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>     // gethostname, fsync, unlink
#include <time.h>       // clock_gettime, gmtime_r
#include <sys/stat.h>   // mkdir, stat
#include <limits.h>     // PATH_MAX

#define SPOOL_DIR         "/var/spool/int"
#define SEG_MAX_BYTES     (128u * 1024u * 1024u) /* 128 MB */
#define SEG_MAX_DOCS      500000u
#define SEG_MAX_AGE_MS    10000u                  /* 10s: avoids tiny segments */
#define HOSTNAME_MAX_LEN  128
#define POP_IDLE_TICK_MS  500u                    /* Wake to check age while idle */

extern volatile int stop;
uint64_t system_ts = 0;

/* ---------------- Queue ---------------- */
typedef struct {
    bucket_entry *buf;
    size_t cap, head, tail, size;
    pthread_mutex_t mu;
    pthread_cond_t  not_empty, not_full;
} bucket_queue;

static bucket_queue g_q;

/* ---------------- Spooler ---------------- */
typedef struct {
    FILE  *fp;
    char   path_open[PATH_MAX];
    char   path_ready[PATH_MAX];
    size_t bytes;
    size_t docs;
    uint64_t opened_ms;   // monotonic ms when this segment was opened
    char hostname[HOSTNAME_MAX_LEN];
    uint64_t seq;
} spooler_t;

static spooler_t g_spooler;
static pthread_t g_thread;

/* ---------------- Helpers ---------------- */
static inline uint64_t now_ms_mono(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void now_iso8601(char *out, size_t outlen) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    time_t secs = ts.tv_sec; struct tm tm; gmtime_r(&secs, &tm);
    int ms = (int)(ts.tv_nsec / 1000000);
    snprintf(out, outlen, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static void ts_to_iso8601(uint64_t ts_ns, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    time_t secs = ts_ns / 1000000000ull;
    long nsec   = ts_ns % 1000000000ull;
    int ms      = (int)(nsec / 1000000);
    struct tm tm;
    gmtime_r(&secs, &tm);
    snprintf(out, outlen, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static void q_init(bucket_queue *q, size_t cap) {
    q->buf = (bucket_entry*)calloc(cap, sizeof(bucket_entry));
    if (!q->buf) { perror("calloc queue"); exit(1); }
    q->cap = cap; q->head = q->tail = q->size = 0;
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

static int q_push(bucket_queue *q, const bucket_entry *e) {
    pthread_mutex_lock(&q->mu);
    while (q->size == q->cap && !stop)
        pthread_cond_wait(&q->not_full, &q->mu);
    if (stop) { pthread_mutex_unlock(&q->mu); return 0; }
    q->buf[q->tail] = *e;
    q->tail = (q->tail + 1) % q->cap; q->size++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mu);
    return 1;
}

/* Timed pop: returns 1 on item; 0 on (stop && drained); -1 on idle timeout */
static int q_pop_timeout(bucket_queue *q, bucket_entry *out, uint64_t timeout_ms) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t add_ns = (timeout_ms % 1000ull) * 1000000ull + ts.tv_nsec;
    ts.tv_sec  += (time_t)(timeout_ms / 1000ull) + (time_t)(add_ns / 1000000000ull);
    ts.tv_nsec  = (long)(add_ns % 1000000000ull);

    pthread_mutex_lock(&q->mu);
    while (q->size == 0 && !stop) {
        int rc = pthread_cond_timedwait(&q->not_empty, &q->mu, &ts);
        if (rc == ETIMEDOUT) { pthread_mutex_unlock(&q->mu); return -1; } // idle tick
    }
    if (q->size == 0 && stop) { pthread_mutex_unlock(&q->mu); return 0; }  // drain complete
    *out = q->buf[q->head];
    q->head = (q->head + 1) % q->cap; q->size--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mu);
    return 1; // got item
}

/* Spooler file ops */
static int ensure_spool_dir(void) {
    struct stat st;
    if (stat(SPOOL_DIR, &st) == 0) return 0;
    if (mkdir(SPOOL_DIR, 0755) == 0) return 0;
    perror("mkdir spool dir");
    return -1;
}

static void spooler_open(spooler_t *s) {
    if (ensure_spool_dir() != 0) exit(1);
    char tsbuf[32];
    time_t t = time(NULL); struct tm tm; gmtime_r(&t, &tm);
    strftime(tsbuf, sizeof tsbuf, "%Y%m%dT%H%M%SZ", &tm);

    snprintf(s->path_open, sizeof s->path_open,
             SPOOL_DIR "/host=%s.ts=%s.seq=%06llu.ndjson.open",
             s->hostname, tsbuf, (unsigned long long)(s->seq++));
    /* strip ".open" for final */
    snprintf(s->path_ready, sizeof s->path_ready, "%.*s",
             (int)(strlen(s->path_open) - 5), s->path_open);

    s->fp = fopen(s->path_open, "ab");
    if (!s->fp) { perror("fopen spool"); exit(1); }

    s->bytes = 0;
    s->docs  = 0;
    s->opened_ms = now_ms_mono();
}

static void spooler_close(spooler_t *s) {
    if (!s->fp) return;
    fflush(s->fp);
    fsync(fileno(s->fp));
    if (fclose(s->fp) != 0) perror("fclose spool");
    s->fp = NULL;

    if (s->docs == 0) {
        /* Don't produce empty .ndjson files; clean up the temp */
        if (unlink(s->path_open) != 0) {
            perror("unlink empty spool segment");
        }
    } else {
        if (rename(s->path_open, s->path_ready) != 0) {
            perror("rename spool segment");
        }
    }
}

static void spooler_rotate_if_needed(spooler_t *s) {
    uint64_t age = now_ms_mono() - s->opened_ms;
    /* Guard age with docs>0 to avoid churn during long idle periods */
    if (s->bytes >= SEG_MAX_BYTES ||
        s->docs  >= SEG_MAX_DOCS  ||
        (age >= SEG_MAX_AGE_MS && s->docs > 0)) {
        spooler_close(s);
        spooler_open(s);
    }
}

/* Helper: write an array of int_metric_sample as compact JSON */
static size_t write_int_samples_json(FILE *fp, const int_metric_sample *arr, uint32_t count) {
    size_t n = 0;
    if (count > MAX_INT_NODES) count = MAX_INT_NODES;
    n += fputc('[', fp) != EOF ? 1 : 0;
    for (uint32_t i = 0; i < count; i++) {
        if (i) n += fputc(',', fp) != EOF ? 1 : 0;
        n += fprintf(fp,
            "{\"node_id\":%u,\"hop_latency\":%u,\"queue_occupancy\":%u,\"egress_interface_tx\":%u}",
            arr[i].node_id,
            arr[i].hop_latency,
            arr[i].queue_occupancy,
            arr[i].egress_interface_tx
        );
    }
    n += fputc(']', fp) != EOF ? 1 : 0;
    return n;
}

/* Write ONE NDJSON doc per call (no Bulk action line). */
static void write_doc_ndjson(FILE *fp, const bucket_entry *e,
                             const char *hostname, size_t *bytes_accum, size_t *docs_accum) {
    char ts_now[48]; now_iso8601(ts_now, sizeof ts_now);

    uint64_t first_packet_ts = (((uint64_t)e->first_packet_ts_high << 32) | e->first_packet_ts_low) + system_ts;
    uint64_t last_update_ts  = (((uint64_t)e->last_update_ts_high  << 32) | e->last_update_ts_low)  + system_ts;
    uint64_t completion_time_ms = (last_update_ts - first_packet_ts) / 1000000ull;

    char first_ts_system[48]; char last_ts_system[48]; char completion_ts_system[48];
    ts_to_iso8601(first_packet_ts, first_ts_system, sizeof first_ts_system);
    ts_to_iso8601(last_update_ts, last_ts_system, sizeof last_ts_system);

    uint32_t n = e->int_metric_info_value.node_count;
    if (n > MAX_INT_NODES) n = MAX_INT_NODES;

    size_t wrote = 0;
    wrote += fprintf(fp,
        "{"
          "\"@timestamp\":\"%s\","
          "\"host\":{\"name\":\"%s\"},"
          "\"flow\":{"
            "\"key\":[%u,%u,%u,%u],"
            "\"packet_count\":%u,"
            "\"completion_time\":%u,"
            "\"first_packet_ts\":\"%s\","
            "\"last_update_ts\":\"%s\""
          "},"
          "\"int\":{"
            "\"request_metadata\":%u,"
            "\"node_count\":%u,"
            "\"latest\":",
        ts_now, hostname,
        e->key[0], e->key[1], e->key[2], e->key[3],
        e->packet_count,
        completion_time_ms,
        first_ts_system,
        last_ts_system,
        e->request_meta,
        n
    );

    wrote += write_int_samples_json(fp, e->int_metric_info_value.latest,  n);
    wrote += fprintf(fp, ",\"average\":");
    wrote += write_int_samples_json(fp, e->int_metric_info_value.average, n);
    wrote += fprintf(fp, "}}\n");

    fflush(fp);
    *bytes_accum += wrote;
    *docs_accum  += 1;
}

/* Spooler thread: drain until q_pop_timeout returns 0 (i.e., stop && empty) */
static void* spooler_thread(void *arg) {
    (void)arg;
    spooler_open(&g_spooler);

    bucket_entry e;
    for (;;) {
        int rc = q_pop_timeout(&g_q, &e, POP_IDLE_TICK_MS);
        if (rc == 1) {
            write_doc_ndjson(g_spooler.fp, &e, g_spooler.hostname, &g_spooler.bytes, &g_spooler.docs);
            spooler_rotate_if_needed(&g_spooler);
        } else if (rc == 0) {
            /* stop signaled AND queue drained */
            break;
        } else { /* rc == -1: idle timeout */
            spooler_rotate_if_needed(&g_spooler); /* age-based rotation while idle */
        }
    }

    spooler_close(&g_spooler);
    return NULL;
}

/* ---------------- Public API ---------------- */
void spooler_init(void) {
    q_init(&g_q, QUEUE_CAPACITY);
    if (gethostname(g_spooler.hostname, sizeof g_spooler.hostname) != 0)
        strncpy(g_spooler.hostname, "unknown", sizeof g_spooler.hostname);
    g_spooler.hostname[sizeof g_spooler.hostname - 1] = '\0';
    g_spooler.seq = 0;
    FILE *fp = popen("cat /home/smartlab/.local/share/p4_load_timestamp", "r");
        if (fp) {
            if (fscanf(fp, "%llu", &system_ts) != 1) system_ts = 0;
            pclose(fp);
        }
}

void spooler_start(void) {
    if (pthread_create(&g_thread, NULL, spooler_thread, NULL) != 0) {
        perror("pthread_create spooler");
        exit(1);
    }
}

void spooler_stop(void) {
    /* Wake any waiters so the thread can observe 'stop' and drain/exit. */
    pthread_mutex_lock(&g_q.mu);
    pthread_cond_broadcast(&g_q.not_empty);
    pthread_cond_broadcast(&g_q.not_full);
    pthread_mutex_unlock(&g_q.mu);
    pthread_join(g_thread, NULL);
}

int spooler_enqueue(const bucket_entry *e) {
    return q_push(&g_q, e);
}
