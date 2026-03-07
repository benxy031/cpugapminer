#include "gap_scan.h"

void backward_scan_segment(const uint64_t *pr, size_t lo, size_t hi,
                           size_t needed_gap, double logbase, double target,
                           gap_prime_test_fn prime_test,
                           struct bkscan_result *res)
{
    res->tested = 0;
    res->primes_found = 0;
    res->best_merit = 0.0;
    res->best_gap   = 0;
    res->first_prime = 0;
    res->last_prime  = 0;
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

        /* Scan backward from bhi-1 toward scan_from+1 */
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
            /* No prime in [start, start+needed_gap]. Search forward for next. */
            int have_next = 0;
            for (size_t j = bhi; j < hi; j++) {
                res->tested++;
                if (prime_test(pr[j])) {
                    uint64_t gap = pr[j] - start_nAdd;
                    double merit = (double)gap / logbase;

                    if (merit > res->best_merit) {
                        res->best_merit = merit;
                        res->best_gap   = gap;
                    }

                    if (merit >= target && res->qual_cnt < 64) {
                        res->qual_pairs[res->qual_cnt][0] = start_nAdd;
                        res->qual_pairs[res->qual_cnt][1] = pr[j];
                        res->qual_cnt++;
                    }

                    start_nAdd = pr[j];
                    scan_from  = j;
                    res->primes_found++;
                    res->last_prime = pr[j];
                    have_next = 1;
                    break;
                }
            }
            if (!have_next) break; /* end of segment */
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
