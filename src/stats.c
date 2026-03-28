#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "stats.h"

#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

volatile uint64_t stats_sieved = 0;
volatile uint64_t stats_tested = 0;
volatile uint64_t stats_gaps = 0;
volatile uint64_t stats_pairs = 0;
volatile uint64_t stats_blocks = 0;
volatile uint64_t stats_submits = 0;
volatile uint64_t stats_success = 0;
volatile uint64_t stats_crt_windows = 0;
volatile uint64_t stats_primes_found = 0;
uint64_t stats_start_ms = 0;
volatile double g_mining_target = 20.0;
volatile double stats_best_merit = 0.0;
volatile uint64_t stats_best_gap = 0;
volatile uint64_t stats_last_gap = 0;
volatile uint64_t stats_last_qual_gap = 0;
volatile uint64_t stats_crt_consumer_windows = 0;
volatile uint64_t stats_crt_consumer_last_gap = 0;
volatile uint64_t stats_crt_consumer_last_qual_gap = 0;
volatile uint64_t stats_crt_consumer_best_gap = 0;
volatile uint64_t stats_gpu_flushes = 0;
volatile uint64_t stats_gpu_batched = 0;
volatile uint64_t stats_crt_tmpl_hits = 0;
volatile uint64_t stats_false_gaps = 0;
volatile uint64_t stats_partial_sieve_auto_windows = 0;
volatile uint64_t stats_partial_sieve_auto_activations = 0;
volatile uint64_t stats_partial_sieve_auto_adjusts = 0;
volatile uint64_t stats_partial_sieve_auto_limit_last = 0;
volatile uint64_t stats_partial_sieve_auto_limit_sum = 0;
volatile uint64_t stats_partial_sieve_auto_limit_samples = 0;
volatile uint64_t stats_adaptive_presieve_skipped = 0;
volatile uint64_t stats_crt_heap_push_ok = 0;
volatile uint64_t stats_crt_heap_push_replace = 0;
volatile uint64_t stats_crt_heap_push_drop = 0;
volatile uint64_t stats_crt_heap_pop_ok = 0;
volatile uint64_t stats_crt_heap_pop_empty = 0;
volatile uint64_t stats_crt_heap_waits = 0;
volatile uint64_t stats_crt_heap_hwm = 0;
volatile uint64_t stats_crt_stale_drop = 0;

struct rate_ring_slot rate_ring[RATE_RING_SLOTS];
int rate_ring_idx = 0;
int rate_ring_full = 0;

#define STATS_INTERVAL_MS 5000

static _Atomic int stats_thread_running = 0;
static pthread_t stats_thread;
static void (*stats_tick_fn)(void) = NULL;

static void *stats_thread_fn(void *arg) {
	(void)arg;
	while (stats_thread_running) {
		struct timespec ts = {
			STATS_INTERVAL_MS / 1000,
			(long)(STATS_INTERVAL_MS % 1000) * 1000000L
		};
		nanosleep(&ts, NULL);
		if (stats_thread_running && stats_tick_fn)
			stats_tick_fn();
	}
	return NULL;
}

void start_stats_thread(void (*tick_fn)(void)) {
	stats_tick_fn = tick_fn;
	stats_thread_running = 1;
	if (pthread_create(&stats_thread, NULL, stats_thread_fn, NULL) != 0)
		stats_thread_running = 0;
}

void stop_stats_thread(void) {
	if (!stats_thread_running) return;
	stats_thread_running = 0;
	pthread_join(stats_thread, NULL);
}

bool stats_thread_is_running(void) {
	return stats_thread_running != 0;
}
