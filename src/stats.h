/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

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
extern volatile uint64_t stats_last_gap;
extern volatile uint64_t stats_last_qual_gap;
extern volatile uint64_t stats_crt_consumer_windows;
extern volatile uint64_t stats_crt_consumer_last_gap;
extern volatile uint64_t stats_crt_consumer_last_qual_gap;
extern volatile uint64_t stats_crt_consumer_best_gap;
extern volatile uint64_t stats_gpu_flushes;
extern volatile uint64_t stats_gpu_batched;
extern volatile uint64_t stats_gpu_sieve_calls;
extern volatile uint64_t stats_gpu_sieve_primes;
extern volatile uint64_t stats_gpu_sieve_fallback;
extern volatile uint64_t stats_gpu_sieve_us_base_upload;
extern volatile uint64_t stats_gpu_sieve_us_zero;
extern volatile uint64_t stats_gpu_sieve_us_compute_k0;
extern volatile uint64_t stats_gpu_sieve_us_mark;
extern volatile uint64_t stats_gpu_sieve_us_compact;
extern volatile uint64_t stats_gpu_sieve_us_pack;
extern volatile uint64_t stats_gpu_sieve_us_bits_dl;
extern volatile uint64_t stats_gpu_sieve_us_merge;
extern volatile uint64_t stats_gpu_sieve_surv_calls;  /* calls that returned compact survivors */
extern volatile uint64_t stats_gpu_sieve_k0_inc_calls;   /* compute_k0 used incremental path */
extern volatile uint64_t stats_gpu_sieve_k0_full_calls;  /* compute_k0 used full recompute */
extern volatile uint64_t stats_gpu_sieve_k0_delta_preps; /* incremental calls that rebuilt d_delta_mod */
extern volatile uint64_t stats_crt_tmpl_hits;  /* times per-nonce CRT template was applied */
extern volatile uint64_t stats_false_gaps;     /* rejected as false after interior verification */
extern volatile uint64_t stats_partial_sieve_auto_windows;    /* windows evaluated by partial-sieve-auto */
extern volatile uint64_t stats_partial_sieve_auto_activations; /* threads that initialized auto limit */
extern volatile uint64_t stats_partial_sieve_auto_adjusts;    /* auto limit changes */
extern volatile uint64_t stats_partial_sieve_auto_limit_last;  /* last effective sieve-prime limit */
extern volatile uint64_t stats_partial_sieve_auto_limit_sum;   /* sum of effective sieve-prime limits */
extern volatile uint64_t stats_partial_sieve_auto_limit_samples;/* sampled windows for effective limit */
extern volatile uint64_t stats_adaptive_presieve_windows;      /* windows observed by adaptive-presieve */
extern volatile uint64_t stats_adaptive_presieve_skipped;      /* dense windows skipped by adaptive-presieve */
extern volatile uint64_t stats_noncrt_lane_pairs_total;        /* all adjacent non-CRT prime pairs observed */
extern volatile uint64_t stats_noncrt_lane_pairs_same;         /* p->q stays on same 6k lane (gap mod 6 == 0) */
extern volatile uint64_t stats_noncrt_lane_pairs_alt2;         /* lane alternation with +2 delta (5->1 lane) */
extern volatile uint64_t stats_noncrt_lane_pairs_alt4;         /* lane alternation with +4 delta (1->5 lane) */
extern volatile uint64_t stats_noncrt_lane_pairs_unexpected;   /* unexpected mod-6 transitions */
extern volatile uint64_t stats_noncrt_lane_qual_total;         /* qualifying non-CRT pairs (merit >= target) */
extern volatile uint64_t stats_noncrt_lane_qual_same;
extern volatile uint64_t stats_noncrt_lane_qual_alt2;
extern volatile uint64_t stats_noncrt_lane_qual_alt4;
extern volatile uint64_t stats_noncrt_lane_qual_unexpected;
extern volatile uint64_t stats_noncrt_onesided_intervals;      /* one-sided gate decisions in non-CRT bkscan */
extern volatile uint64_t stats_noncrt_onesided_skipped;        /* intervals skipped by give-up/go-next */
extern volatile uint64_t stats_noncrt_onesided_fullcheck;      /* intervals kept for full two-sided check */
extern volatile uint64_t stats_crt_heap_push_ok;
extern volatile uint64_t stats_crt_heap_push_replace;
extern volatile uint64_t stats_crt_heap_push_drop;
extern volatile uint64_t stats_crt_heap_pop_ok;
extern volatile uint64_t stats_crt_heap_pop_empty;
extern volatile uint64_t stats_crt_heap_waits;
extern volatile uint64_t stats_crt_heap_hwm;
extern volatile uint64_t stats_crt_stale_drop;

/* Phase 1 CRT runtime telemetry. */
extern volatile uint64_t stats_crt_solver_mono_cpu_tests;
extern volatile uint64_t stats_crt_solver_mono_gpu_tests;
extern volatile uint64_t stats_crt_solver_consumer_cpu_tests;
extern volatile uint64_t stats_crt_solver_consumer_gpu_tests;
extern volatile uint64_t stats_crt_solver_prod_windows_generated;
extern volatile uint64_t stats_crt_solver_prod_windows_enqueued;
extern volatile uint64_t stats_crt_solver_prod_prefilter_span_drop;
extern volatile uint64_t stats_crt_solver_prod_prefilter_density_drop;
extern volatile uint64_t stats_crt_gpu_accum_flush_count;
extern volatile uint64_t stats_crt_gpu_accum_flush_ms;
extern volatile uint64_t stats_crt_gpu_accum_collect_count;
extern volatile uint64_t stats_crt_gpu_accum_collect_ms;
extern volatile uint64_t stats_crt_gpu_accum_batch_le_512;
extern volatile uint64_t stats_crt_gpu_accum_batch_le_1024;
extern volatile uint64_t stats_crt_gpu_accum_batch_le_2048;
extern volatile uint64_t stats_crt_gpu_accum_batch_le_4096;
extern volatile uint64_t stats_crt_gpu_accum_batch_gt_4096;
extern volatile uint64_t stats_crt_cuda_fb_no_accum;
extern volatile uint64_t stats_crt_cuda_fb_limb_mismatch;
extern volatile uint64_t stats_crt_cuda_fb_add_fail;

/* Cramér-model score stats (CRT paths only). */
extern volatile uint64_t stats_cramer_scored;       /* windows whose score was computed */
extern volatile uint64_t stats_cramer_skipped;      /* windows skipped by span<needed_gap (monolithic) */
extern volatile uint64_t stats_cramer_heap_skip;    /* windows skipped by score<=worst (producer) */
/* score sum stored as scaled integer (×1e9) to avoid atomic double */
extern volatile uint64_t stats_cramer_score_sum_e9; /* sum of cramer_score×1e9 */

/* PGT trend telemetry (log-only; does not affect mining decisions). */
extern volatile uint64_t stats_pgt_records_total;       /* observed global best-gap updates */
extern volatile uint64_t stats_pgt_records_above_trend; /* updates where gap exceeded k=1 trend */
extern volatile uint64_t stats_pgt_records_above_cramer;/* updates where gap exceeded log^2 bound */
extern volatile uint64_t stats_pgt_records_above_submit;/* updates where gap exceeded submit threshold */
extern volatile uint64_t stats_pgt_last_gap;            /* last record gap seen by observer */
extern volatile uint64_t stats_pgt_last_trend_gap_e3;   /* last trend gap, scaled ×1000 */
extern volatile uint64_t stats_pgt_last_ratio_e3;       /* last gap/trend ratio, scaled ×1000 */
extern volatile uint64_t stats_pgt_last_submit_ratio_e3;/* last gap/(target*logbase), scaled ×1000 */

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
