#include "sieve_cache.h"

#include <stdlib.h>

uint64_t cli_sieve_prime_limit = 0;   /* computed from count; 0 = not yet set */
uint64_t cli_sieve_prime_count = DEFAULT_SIEVE_PRIME_COUNT;

uint64_t *small_primes_cache = NULL;
size_t small_primes_count = 0;
size_t small_primes_cap = 0;
pthread_once_t small_primes_once = PTHREAD_ONCE_INIT;

uint32_t td_extra_primes[TD_EXTRA_CNT];
int td_extra_count = 0;
pthread_once_t td_extra_once = PTHREAD_ONCE_INIT;

void populate_td_extra_primes(void) {
    /* Ensure the main sieve cache is ready. */
    pthread_once(&small_primes_once, populate_small_primes_cache);
    if (!small_primes_cache) return;

    /* Segmented sieve over [lo, hi) to find primes just above the sieve limit. */
    uint64_t lo = (uint64_t)cli_sieve_prime_limit + 1;
    if ((lo & 1) == 0) lo++; /* start on odd */
    /* A window of 200 000 odd numbers (~11 000 primes) is more than enough. */
    uint64_t hi = lo + 400000ULL; /* covers ~22 000 primes */
    size_t   sz = (hi - lo) / 2 + 1;
    uint8_t *sieve = (uint8_t *)calloc(sz, 1);
    if (!sieve) return;

    for (size_t idx = 1; idx < small_primes_count; idx++) {
        uint64_t p = small_primes_cache[idx];
        if (p * p > hi) break;
        /* first odd multiple of p >= lo */
        uint64_t rem = lo % p;
        uint64_t start = rem ? lo + (p - rem) : lo;
        if ((start & 1) == 0) start += p;
        for (uint64_t j = start; j < hi; j += 2 * p)
            sieve[(j - lo) / 2] = 1;
    }
    td_extra_count = 0;
    for (uint64_t n = lo; n < hi && td_extra_count < TD_EXTRA_CNT; n += 2)
        if (!sieve[(n - lo) / 2])
            td_extra_primes[td_extra_count++] = (uint32_t)n;
    free(sieve);
}

void populate_small_primes_cache(void) {
    /* Generate all primes up to cli_sieve_prime_limit (already set from
       COUNT via PNT upper bound before this function is called). */
    size_t maxp = (size_t)cli_sieve_prime_limit + 1;
    if (maxp < 100) maxp = 100;  /* sanity floor */
    unsigned char *is_small = calloc(maxp, 1);
    if (!is_small) { free(is_small); return; }
    small_primes_cap = 80000;
    small_primes_cache = malloc(sizeof(uint64_t) * small_primes_cap);
    if (!small_primes_cache) {
        free(is_small);
        small_primes_cache = NULL;
        small_primes_cap = 0;
        return;
    }
    small_primes_count = 0;
    /* include 2 so the cache can be used for primality tests */
    if (small_primes_count < small_primes_cap)
        small_primes_cache[small_primes_count++] = 2;
    for (uint64_t i = 3; i < maxp; i += 2) {
        if (!is_small[i]) {
            if (small_primes_count + 1 > small_primes_cap) {
                size_t ncap = small_primes_cap * 2;
                uint64_t *tmp = realloc(small_primes_cache,
                                        ncap * sizeof(uint64_t));
                if (tmp) {
                    small_primes_cache = tmp;
                    small_primes_cap = ncap;
                } else {
                    break;
                }
            }
            small_primes_cache[small_primes_count++] = i;
            if (i * i < maxp) {
                for (uint64_t j = i * i; j < maxp; j += 2 * i)
                    is_small[j] = 1;
            }
        }
    }
    free(is_small);
}
