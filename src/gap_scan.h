#ifndef GAP_SCAN_H
#define GAP_SCAN_H

#include <stddef.h>
#include <stdint.h>

typedef int (*gap_prime_test_fn)(uint64_t offset);

/* Backward-scan result struct. */
struct bkscan_result {
    size_t   tested;             /* Fermat tests performed                   */
    size_t   primes_found;       /* primes discovered (jumps + 1)            */
    double   best_merit;         /* best verified gap merit seen             */
    uint64_t best_gap;           /* best verified gap size                   */
    uint64_t first_prime;        /* first prime found in segment (0=none)    */
    uint64_t last_prime;         /* last prime found in segment  (0=none)    */
    uint64_t qual_pairs[64][2];  /* [start_nAdd, end_nAdd] qualifying pairs  */
    size_t   qual_cnt;           /* number of qualifying gaps found          */
};

/* Standalone backward-scan on a segment of pr[lo..hi-1].
 * Caller provides prime_test callback and merges results into global stats. */
void backward_scan_segment(const uint64_t *pr, size_t lo, size_t hi,
                           size_t needed_gap, double logbase, double target,
                           gap_prime_test_fn prime_test,
                           struct bkscan_result *res);

/* Returns 1 if any interior even offset in (0, gap) is prime-tested true.
 * If found_off is non-NULL, stores the first offset that tested prime. */
int gap_has_interior_prime(uint64_t prev, uint64_t gap,
                           gap_prime_test_fn prime_test,
                           uint64_t *found_off);

#endif /* GAP_SCAN_H */
