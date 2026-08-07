/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef GAP_SCAN_H
#define GAP_SCAN_H

#include <stddef.h>
#include <stdint.h>

typedef int (*gap_prime_test_fn)(uint64_t offset);

/* Optional forward-scan assist: given [from, hi), find the SMALLEST index
 * whose candidate is prime (per prime_test). Implementations may split the
 * work across multiple threads. Must return the same answer a plain
 * sequential scan of [from, hi) would return (no false positives/negatives).
 * On return: *out_idx = found index (or hi if none found), *out_tested =
 * number of Fermat tests performed (added into res->tested by the caller).
 * Returns 1 if a prime was found, 0 otherwise. */
typedef int (*gap_forward_scan_assist_fn)(void *ctx, const uint64_t *pr,
                                          size_t from, size_t hi,
                                          gap_prime_test_fn prime_test,
                                          size_t *out_idx, size_t *out_tested);

/* Backward-scan result struct. */
struct bkscan_result {
    size_t   tested;             /* Fermat tests performed                   */
    size_t   primes_found;       /* primes discovered (jumps + 1)            */
    double   best_merit;         /* best verified gap merit seen             */
    uint64_t best_gap;           /* best verified gap size (qualifying path) */
    uint64_t first_prime;        /* first prime found in segment (0=none)    */
    uint64_t last_prime;         /* last prime found in segment  (0=none)    */
    size_t   one_sided_considered; /* intervals evaluated by one-sided gate   */
    size_t   one_sided_skipped;    /* intervals skipped (give-up/go-next)     */
    size_t   one_sided_fullcheck;  /* intervals that kept full two-sided scan */
    uint64_t one_sided_fullcheck_every_sum; /* sum of adaptive cadence values */
    size_t   one_sided_fullcheck_every_min; /* min adaptive cadence used */
    size_t   one_sided_fullcheck_every_max; /* max adaptive cadence used */
    size_t   forward_parallel_hits; /* forward gap-closing scans done via assist */
    uint64_t qual_pairs[64][2];  /* [start_nAdd, end_nAdd] qualifying pairs  */
    size_t   qual_cnt;           /* number of qualifying gaps found          */
};

/* Standalone backward-scan on a segment of pr[lo..hi-1].
 * Caller provides prime_test callback and merges results into global stats.
 * forward_assist/forward_assist_ctx are optional (pass NULL/NULL to keep the
 * plain sequential forward gap-closing scan); when set, they are only used
 * in the plain two-sided path (one_sided_min_gap == 0). */
void backward_scan_segment(const uint64_t *pr, size_t lo, size_t hi,
                           size_t needed_gap, size_t one_sided_min_gap,
                           double logbase, double target,
                           gap_prime_test_fn prime_test,
                           gap_forward_scan_assist_fn forward_assist,
                           void *forward_assist_ctx,
                           struct bkscan_result *res);

/* Returns 1 if any interior even offset in (0, gap) is prime-tested true.
 * If found_off is non-NULL, stores the first offset that tested prime. */
int gap_has_interior_prime(uint64_t prev, uint64_t gap,
                           gap_prime_test_fn prime_test,
                           uint64_t *found_off);

#endif /* GAP_SCAN_H */
