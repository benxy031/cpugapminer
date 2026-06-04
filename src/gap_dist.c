/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* gap_dist.c — Hardy-Littlewood gap distribution accumulator.
 *
 * Tracks a histogram of prime gaps observed during mining and exposes a
 * snapshot for comparison against the theoretical relative frequencies
 * predicted by the Hardy-Littlewood twin-prime conjecture extension:
 *
 *   C_g / C_2  =  ∏_{p odd prime, p | g}  (p-1)/(p-2)
 *
 * This is the same asymptotic limit (λ → 0) as Holt's w_{g,1}(∞) model.
 * The full λ-dependent correction is small for typical mining ranges
 * (logbase >> GAP_DIST_MAX_GAP) and is applied by the caller at report time
 * using exp(-(g-2)/logbase).
 *
 * Implementation:
 *   - Relaxed atomic increments for all bucket accumulators: no mutex, no
 *     false sharing between threads (each bucket is its own cache line via
 *     the padded struct below), virtually zero hot-path overhead.
 *   - Snapshot via relaxed atomic loads — a small transient count skew is
 *     acceptable for a statistical health check.
 */

#include "gap_dist.h"

#include <math.h>
#include <stdint.h>
#include <string.h>

/* Avoid including <stdatomic.h> here; use __sync builtins which are
 * available in all GCC/Clang versions that this project targets. */

/* ── Precomputed C_g / C_2 for even gaps 2..GAP_DIST_MAX_GAP ─────────── */
/*
 * Index i → even gap g = 2*(i+1).
 * Formula: ∏_{p | g, p odd prime}  (p-1)/(p-2).
 * Odd prime factors of g (g ≤ 30):  only 3, 5, 7, 11, 13 can appear.
 *
 *  g= 2:  (none)           → 1
 *  g= 4:  (none)           → 1
 *  g= 6:  3                → 2
 *  g= 8:  (none)           → 1
 *  g=10:  5                → 4/3
 *  g=12:  3                → 2
 *  g=14:  7                → 6/5
 *  g=16:  (none)           → 1
 *  g=18:  3                → 2
 *  g=20:  5                → 4/3
 *  g=22:  11               → 10/9
 *  g=24:  3                → 2
 *  g=26:  13               → 12/11
 *  g=28:  7                → 6/5
 *  g=30:  3, 5             → 2 × 4/3 = 8/3
 */
static const double s_hl_ratio[GAP_DIST_NBUCKETS - 1] = {
    /* g= 2 */ 1.0,
    /* g= 4 */ 1.0,
    /* g= 6 */ 2.0,
    /* g= 8 */ 1.0,
    /* g=10 */ 4.0 / 3.0,
    /* g=12 */ 2.0,
    /* g=14 */ 6.0 / 5.0,
    /* g=16 */ 1.0,
    /* g=18 */ 2.0,
    /* g=20 */ 4.0 / 3.0,
    /* g=22 */ 10.0 / 9.0,
    /* g=24 */ 2.0,
    /* g=26 */ 12.0 / 11.0,
    /* g=28 */ 6.0 / 5.0,
    /* g=30 */ 8.0 / 3.0,
};

/* ── Bucket storage ───────────────────────────────────────────────────── */
/* Each bucket in its own cache line (64 bytes) to prevent false sharing
 * between mining threads that accumulate concurrently.                    */
typedef struct { volatile uint64_t n; char _pad[56]; } gap_bucket_t;

static gap_bucket_t s_buckets[GAP_DIST_NBUCKETS];
static volatile uint64_t s_total;

/* ── Public API ───────────────────────────────────────────────────────── */

void gap_dist_accumulate(const uint64_t *primes, size_t cnt)
{
    if (!primes || cnt < 2)
        return;

    for (size_t i = 0; i + 1 < cnt; i++) {
        uint64_t g = primes[i + 1] - primes[i];

        size_t bucket;
        if (g >= 2 && (g & 1) == 0 && g <= GAP_DIST_MAX_GAP)
            bucket = (size_t)(g / 2) - 1;          /* 0 .. GAP_DIST_NBUCKETS-2 */
        else
            bucket = (size_t)(GAP_DIST_NBUCKETS - 1);  /* overflow               */

        __sync_fetch_and_add(&s_buckets[bucket].n, 1);
        __sync_fetch_and_add(&s_total, 1);
    }
}

int gap_dist_snapshot(uint64_t counts_out[GAP_DIST_NBUCKETS],
                      uint64_t *total_out)
{
    uint64_t t = 0;
    for (int i = 0; i < GAP_DIST_NBUCKETS; i++) {
        uint64_t v = s_buckets[i].n;  /* volatile read — relaxed, acceptable */
        counts_out[i] = v;
        t += v;
    }
    if (total_out)
        *total_out = t;
    return (t > 0) ? 1 : 0;
}

double gap_dist_hl_ratio(int g)
{
    if (g < 2 || (g & 1) || g > GAP_DIST_MAX_GAP)
        return 1.0;
    return s_hl_ratio[(size_t)(g / 2) - 1];
}

/* Odd primes used for factoring in gap_dist_hl_ratio_large.
 * Covers all odd primes up to 37; beyond that (p-1)/(p-2) < 1.027
 * and the accumulated error from ignoring them is < 3% even for
 * highly composite gaps. */
static const uint32_t s_small_odd_primes[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
};
#define N_SMALL_ODD 11

double gap_dist_hl_ratio_large(uint64_t g)
{
    if (g < 2 || (g & 1))
        return 1.0;
    if (g <= (uint64_t)GAP_DIST_MAX_GAP)
        return gap_dist_hl_ratio((int)g);

    double r = 1.0;
    uint64_t rem = g;
    for (int i = 0; i < N_SMALL_ODD; i++) {
        uint32_t p = s_small_odd_primes[i];
        if (rem % p == 0) {
            r *= (double)(p - 1) / (double)(p - 2);
            /* Remove all factors of p (ratio depends only on distinct primes). */
            while (rem % p == 0)
                rem /= p;
        }
    }
    return r;
}

/* ── MR recommendation state ─────────────────────────────────────────── */
/* Number of consecutive print_stats intervals where avg ratio > threshold.
 * Declared volatile only to suppress optimisation of the static; it is only
 * ever written from print_stats (single-threaded context). */
static volatile int s_mr_trigger_count = 0;

int gap_dist_mr_recommendation(double logbase)
{
    if (logbase <= 1.0)
        return 0;

    uint64_t counts[GAP_DIST_NBUCKETS];
    uint64_t total;
    if (!gap_dist_snapshot(counts, &total) || total < 100000 || counts[0] < 500)
        return 0;

    /* Compute average ratio(observed/expected) for g=2..12 (buckets 0..5).
     * All buckets are normalised relative to g=2 (bucket 0 = reference),
     * so the logbase exponential factor nearly cancels for small gaps
     * (exp(-(g-2)/logbase) ≈ 1 for g ≤ 12 and logbase ≥ 100).            */
    double inv_lb = 1.0 / logbase;
    double ratio_sum = 0.0;
    int    ratio_cnt = 0;
    for (int gi = 0; gi <= 5; gi++) {         /* g = 2, 4, 6, 8, 10, 12    */
        int g = 2 * (gi + 1);
        double hl      = gap_dist_hl_ratio(g);
        double exp_cnt = (double)counts[0] * hl * exp(-(g - 2) * inv_lb);
        if (exp_cnt > 0.0) {
            ratio_sum += (double)counts[gi] / exp_cnt;
            ratio_cnt++;
        }
    }
    if (ratio_cnt == 0)
        return 0;

    double avg_ratio = ratio_sum / (double)ratio_cnt;

    /* Hysteresis: require 2 consecutive intervals above threshold before
     * recommending tightening, and reset counter when below threshold.    */
    if (avg_ratio > 1.20) {
        s_mr_trigger_count++;
        if (s_mr_trigger_count >= 2)
            return +1;
    } else {
        if (s_mr_trigger_count > 0)
            s_mr_trigger_count--;
    }
    return 0;
}
