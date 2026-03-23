#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <stdbool.h>

/* Shared mining/statistics state.
 * Defined in stats.c and consumed by main.c and mining routines. */
extern volatile uint64_t stats_sieved;
extern volatile uint64_t stats_tested;
extern volatile uint64_t stats_gaps;
extern volatile uint64_t stats_pairs;
extern volatile uint64_t stats_blocks;
extern volatile uint64_t stats_submits;
extern volatile uint64_t stats_success;
extern volatile uint64_t stats_crt_windows;
extern volatile uint64_t stats_primes_found;
extern uint64_t stats_start_ms;
extern volatile double g_mining_target;
extern volatile double stats_best_merit;
extern volatile uint64_t stats_best_gap;
extern volatile uint64_t stats_gpu_flushes;
extern volatile uint64_t stats_gpu_batched;
extern volatile uint64_t stats_crt_tmpl_hits;  /* times per-nonce CRT template was applied */

/* Rolling-window state used by print_stats(). */
#define RATE_RING_SLOTS 6
struct rate_ring_slot {
    uint64_t pairs;
    uint64_t ms;
};

extern struct rate_ring_slot rate_ring[RATE_RING_SLOTS];
extern int rate_ring_idx;
extern int rate_ring_full;

/* Periodic stats thread control. */
void start_stats_thread(void (*tick_fn)(void));
void stop_stats_thread(void);
bool stats_thread_is_running(void);

#endif /* STATS_H */
