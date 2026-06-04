/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* ── Hardy-Littlewood gap distribution check ─────────────────────────────────
 *
 * Accumulates observed prime-gap counts and compares them to the theoretical
 * relative frequencies predicted by the Hardy-Littlewood k-tuple conjecture
 * (equivalently, Holt's w_{g,1}(∞) asymptotic model):
 *
 *   Relative frequency of even gap g  ∝  C_g × exp(-g / log(x))
 *
 * where  C_g / C_2 = ∏_{p odd prime, p | g}  (p-1)/(p-2)
 *
 * This gives a primality-pipeline sanity check complementary to the mean-gap
 * test: if composites leak through (test too weak), small gaps are
 * over-represented; if real primes are rejected, small gaps are under-
 * represented.  These effects show up in the gap-distribution before
 * accumulating the gap-count needed for the mean-gap warning.
 *
 * Bucket layout (GAP_DIST_NBUCKETS buckets):
 *   bucket i  (0 ≤ i < GAP_DIST_NBUCKETS-1):  count of gaps equal to 2*(i+1)
 *   bucket GAP_DIST_NBUCKETS-1:               count of gaps > GAP_DIST_MAX_GAP
 *
 * Thread-safety: accumulation uses relaxed atomics — cheap and correct.
 */

/* Maximum even gap tracked individually.  Gaps larger than this fall into the
 * overflow bucket.  30 covers all gaps where C_g/C_2 has a notable structure
 * (including the high-ratio g=30 = 2·3·5 → 8/3 ≈ 2.67). */
#define GAP_DIST_MAX_GAP  30

/* Total number of buckets: one per even gap 2..GAP_DIST_MAX_GAP, plus overflow. */
#define GAP_DIST_NBUCKETS (GAP_DIST_MAX_GAP / 2 + 1)

/* Accumulate all consecutive prime gaps in a sorted array of primes.
 * Gaps that are odd or zero (e.g. duplicates, bad data) go to the overflow
 * bucket so they do not silently vanish from the total count.
 * Thread-safe; can be called from multiple mining threads simultaneously. */
void gap_dist_accumulate(const uint64_t *primes, size_t cnt);

/* Copy current bucket counts into caller-provided arrays.
 *   counts_out : array of length GAP_DIST_NBUCKETS — filled with bucket counts
 *   total_out  : total number of gaps observed (sum of all buckets)
 * Returns 1 if any gaps have been recorded, 0 if no data yet. */
int gap_dist_snapshot(uint64_t counts_out[GAP_DIST_NBUCKETS],
                      uint64_t *total_out);

/* Hardy-Littlewood correction factor C_g / C_2 for even gap g.
 * Equals the product of (p-1)/(p-2) over all odd primes p that divide g.
 * Returns 1.0 for g < 2, odd g, or g > GAP_DIST_MAX_GAP. */
double gap_dist_hl_ratio(int g);

/* Same as gap_dist_hl_ratio but works for any even g, including large gaps.
 * Factors out distinct odd prime divisors of g up to 37; beyond that the
 * correction is negligible (p=41 gives only a 2.6% factor).
 * Used by compute_cramer_score to weight the target gap probability. */
double gap_dist_hl_ratio_large(uint64_t g);

/* Primality-pipeline health check based on gap distribution shape.
 * Compares the observed small-gap frequencies (g=2..12) against the
 * HL asymptotic model and returns:
 *   +1  if composites are likely leaking through (avg ratio > 1.20 for
 *       two consecutive calls) — caller should tighten primality test
 *    0  no action needed
 * Uses internal 2-check hysteresis; thread-safe (called only from
 * single-threaded print_stats).
 *   logbase: weighted average log(x) from rgm_mean_gap_snapshot() */
int gap_dist_mr_recommendation(double logbase);
