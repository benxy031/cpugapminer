/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "gap_scan.h"

#define ONE_SIDED_FORCE_FULLCHECK_EVERY 16U
#define ONE_SIDED_FORCE_FULLCHECK_MIN_PROBE_STEPS 12U
#define ONE_SIDED_FORCE_FULLCHECK_MIN_EVERY 4U
#define ONE_SIDED_FORCE_FULLCHECK_MAX_EVERY 24U

/* Adapt one-sided cadence to local gate geometry and observed skip trend.
 * Narrow gate bands carry weaker signal, so force fullcheck more often. */
static inline unsigned one_sided_fullcheck_every_adaptive(
        size_t needed_gap,
        size_t one_sided_min_gap,
        const struct bkscan_result *res) {
    unsigned every = ONE_SIDED_FORCE_FULLCHECK_EVERY;
    size_t gate_band = 0;

    if (one_sided_min_gap > needed_gap)
        gate_band = one_sided_min_gap - needed_gap;

    if (needed_gap > 0) {
        if (gate_band <= (needed_gap >> 2))
            every = 4;
        else if (gate_band <= (needed_gap >> 1))
            every = 8;
        else if (gate_band <= needed_gap)
            every = 12;
        else
            every = 20;
    }

    if (res && res->one_sided_considered >= 32) {
        size_t considered = res->one_sided_considered;
        size_t skipped = res->one_sided_skipped;
        size_t skip_pct = (considered > 0)
            ? ((skipped * 100U) / considered)
            : 0U;

        if (skip_pct >= 85U && every > 6U)
            every -= 2U;
        else if (skip_pct <= 45U && every < 22U)
            every += 2U;
    }

    if (every < ONE_SIDED_FORCE_FULLCHECK_MIN_EVERY)
        every = ONE_SIDED_FORCE_FULLCHECK_MIN_EVERY;
    if (every > ONE_SIDED_FORCE_FULLCHECK_MAX_EVERY)
        every = ONE_SIDED_FORCE_FULLCHECK_MAX_EVERY;
    return every;
}

void backward_scan_segment(const uint64_t *pr, size_t lo, size_t hi,
                           size_t needed_gap, size_t one_sided_min_gap,
                           double logbase, double target,
                           gap_prime_test_fn prime_test,
                           gap_forward_scan_assist_fn forward_assist,
                           void *forward_assist_ctx,
                           struct bkscan_result *res)
{
    res->tested = 0;
    res->primes_found = 0;
    res->best_merit = 0.0;
    res->best_gap   = 0;
    res->first_prime = 0;
    res->last_prime  = 0;
    res->one_sided_considered = 0;
    res->one_sided_skipped = 0;
    res->one_sided_fullcheck = 0;
    res->one_sided_fullcheck_every_sum = 0;
    res->one_sided_fullcheck_every_min = 0;
    res->one_sided_fullcheck_every_max = 0;
    res->forward_parallel_hits = 0;
    res->qual_cnt    = 0;
    if (lo >= hi || !prime_test) return;

    /* Find first Fermat-prime in segment (forward scan) */
    size_t first_idx = hi;  /* sentinel: not found */
    for (size_t j = lo; j < hi; j++) {
        res->tested++;
        if (prime_test(pr[j])) {
            first_idx = j;
            res->primes_found++;
            res->first_prime = pr[j];
            res->last_prime  = pr[j];
            break;
        }
    }
    if (first_idx >= hi) return;

    uint64_t start_nAdd = pr[first_idx];
    size_t scan_from = first_idx;

    /* Main backward-scan loop */
    for (;;) {
        uint64_t target_pos = start_nAdd + needed_gap;

        /* Binary search: first index in pr[lo..hi-1] > target_pos */
        size_t bhi;
        { size_t l = scan_from + 1, h = hi;
          while (l < h) {
              size_t m = l + (h - l) / 2;
              if (pr[m] <= target_pos) l = m + 1;
              else h = m;
          }
          bhi = l; }

        if (one_sided_min_gap > 0) {
            size_t upper_idx = hi;
            uint64_t gate_pos = start_nAdd + one_sided_min_gap;
            size_t gate_hi = hi;
            int gate_found_upper = 0;
            int force_fullcheck = 0;
            size_t probe_steps = 0;

            /* Binary search: first index in pr[scan_from+1..hi-1] >= gate_pos */
            {
                size_t l = bhi, h = hi;
                while (l < h) {
                    size_t m = l + (h - l) / 2;
                    if (pr[m] < gate_pos)
                        l = m + 1;
                    else
                        h = m;
                }
                gate_hi = l;
            }

            /* One-sided gate probe:
               only search (target_pos, gate_pos) to decide skip/fullcheck.
               A full forward search to hi is deferred until strictly needed. */
            size_t j_gate = bhi;
            while (j_gate < gate_hi) {
                res->tested++;
                if (prime_test(pr[j_gate])) {
                    upper_idx = j_gate; /* first prime beyond target_pos and before gate */
                    gate_found_upper = 1;
                    probe_steps = j_gate - bhi;
                    break;
                }
                j_gate++;
            }

            if (gate_found_upper) {
                res->one_sided_considered++;
                unsigned fullcheck_every = one_sided_fullcheck_every_adaptive(
                    needed_gap, one_sided_min_gap, res);
                res->one_sided_fullcheck_every_sum += (uint64_t)fullcheck_every;
                if (res->one_sided_fullcheck_every_min == 0 ||
                    (size_t)fullcheck_every < res->one_sided_fullcheck_every_min) {
                    res->one_sided_fullcheck_every_min = (size_t)fullcheck_every;
                }
                if ((size_t)fullcheck_every > res->one_sided_fullcheck_every_max)
                    res->one_sided_fullcheck_every_max = (size_t)fullcheck_every;
                /* Hybrid mode: periodically force full two-sided verification
                   to reduce one-sided bias while keeping skip as default.
                   Also force when the upper-prime probe had to scan a long
                   stretch, because that window is sparse enough to justify
                   the extra work. */
                if (probe_steps < ONE_SIDED_FORCE_FULLCHECK_MIN_PROBE_STEPS &&
                    (res->one_sided_considered % (size_t)fullcheck_every) != 0) {
                    /* Give-up/go-next: weak first-side signal. */
                    res->one_sided_skipped++;
                    start_nAdd = pr[upper_idx];
                    scan_from = upper_idx;
                    res->primes_found++;
                    res->last_prime = pr[upper_idx];
                    continue;
                }
                force_fullcheck = 1;
            } else {
                res->one_sided_considered++;
            }

            res->one_sided_fullcheck++;

            /* Full two-sided check only for strong first-side intervals. */
            int found = 0;
            for (size_t j = bhi; j > scan_from + 1; ) {
                j--;
                res->tested++;
                if (prime_test(pr[j])) {
                    start_nAdd = pr[j];
                    scan_from = j;
                    res->primes_found++;
                    res->last_prime = pr[j];
                    found = 1;
                    break;
                }
            }

            if (!found) {
                /* Need the next prime right of target_pos only when no
                   backward-side prime exists (to finalize a real gap). */
                size_t j_next = j_gate;

                /* If a gate prime was already found and this iteration is in
                   forced fullcheck mode, reuse it directly and avoid retesting. */
                if (force_fullcheck && gate_found_upper) {
                    j_next = upper_idx;
                }

                while (j_next < hi) {
                    if (force_fullcheck && gate_found_upper && j_next == upper_idx)
                        break;
                    res->tested++;
                    if (prime_test(pr[j_next])) {
                        upper_idx = j_next;
                        break;
                    }
                    j_next++;
                }

                if (upper_idx >= hi) {
                    /* Backward interval (scan_from, target_pos] was already fully
                       checked in the full two-sided pass above.  No backward or
                       upper prime found => end of segment. */
                    break;
                }

                {
                    uint64_t gap = pr[upper_idx] - start_nAdd;
                    double merit = (double)gap / logbase;

                    if (merit > res->best_merit) {
                        res->best_merit = merit;
                        res->best_gap = gap;
                    }

                    if (merit >= target && res->qual_cnt < 64) {
                        res->qual_pairs[res->qual_cnt][0] = start_nAdd;
                        res->qual_pairs[res->qual_cnt][1] = pr[upper_idx];
                        res->qual_cnt++;
                    }
                }

                start_nAdd = pr[upper_idx];
                scan_from = upper_idx;
                res->primes_found++;
                res->last_prime = pr[upper_idx];
            }
        } else {
            /* Original full two-sided scan behavior. */
            int found = 0;
            for (size_t j = bhi; j > scan_from + 1; ) {
                j--;
                res->tested++;
                if (prime_test(pr[j])) {
                    start_nAdd = pr[j];
                    scan_from  = j;
                    res->primes_found++;
                    res->last_prime = pr[j];
                    found = 1;
                    break;
                }
            }

            if (!found) {
                int have_next = 0;
                size_t found_idx = hi;

                if (forward_assist) {
                    size_t assist_tested = 0;
                    if (forward_assist(forward_assist_ctx, pr, bhi, hi,
                                       prime_test, &found_idx, &assist_tested)) {
                        have_next = 1;
                        res->forward_parallel_hits++;
                    }
                    res->tested += assist_tested;
                } else {
                    for (size_t j = bhi; j < hi; j++) {
                        res->tested++;
                        if (prime_test(pr[j])) {
                            found_idx = j;
                            have_next = 1;
                            break;
                        }
                    }
                }

                if (have_next) {
                    uint64_t gap = pr[found_idx] - start_nAdd;
                    double merit = (double)gap / logbase;

                    if (merit > res->best_merit) {
                        res->best_merit = merit;
                        res->best_gap   = gap;
                    }

                    if (merit >= target && res->qual_cnt < 64) {
                        res->qual_pairs[res->qual_cnt][0] = start_nAdd;
                        res->qual_pairs[res->qual_cnt][1] = pr[found_idx];
                        res->qual_cnt++;
                    }

                    start_nAdd = pr[found_idx];
                    scan_from  = found_idx;
                    res->primes_found++;
                    res->last_prime = pr[found_idx];
                }
                if (!have_next) break; /* end of segment */
            }
        }
    }
}

int gap_has_interior_prime(uint64_t prev, uint64_t gap,
                           gap_prime_test_fn prime_test,
                           uint64_t *found_off)
{
    if (!prime_test || gap <= 2) return 0;
    for (uint64_t off = 2; off < gap; off += 2) {
        if (prime_test(prev + off)) {
            if (found_off) *found_off = off;
            return 1;
        }
    }
    return 0;
}
