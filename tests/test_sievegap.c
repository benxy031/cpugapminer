#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/sievegap.h"
#include "../src/uint256_utils.h"

static int is_prime_u64(uint64_t x) {
    if (x < 2)
        return 0;
    if ((x & 1ULL) == 0ULL)
        return x == 2;
    for (uint64_t d = 3; d * d <= x; d += 2) {
        if (x % d == 0)
            return 0;
    }
    return 1;
}

static size_t build_small_primes(uint64_t *out, size_t cap, uint64_t limit) {
    size_t n = 0;
    for (uint64_t v = 2; v <= limit; v++) {
        if (!is_prime_u64(v))
            continue;
        if (n >= cap)
            break;
        out[n++] = v;
    }
    return n;
}

static int naive_marked(uint64_t off,
                        const uint8_t *h256,
                        int shift,
                        const uint64_t *primes,
                        size_t n_primes,
                        uint64_t prime_limit) {
    for (size_t i = 1; i < n_primes; i++) {
        uint64_t p = primes[i];
        if (p > prime_limit)
            break;
        uint64_t base_mod = uint256_mod_small(h256, shift, p);
        if ((base_mod + (off % p)) % p == 0)
            return 1;
    }
    return 0;
}

static void assert_equal_survivors(const uint64_t *a,
                                   size_t an,
                                   const uint64_t *b,
                                   size_t bn,
                                   const char *label) {
    if (an != bn) {
        fprintf(stderr, "FAIL %s: count mismatch %zu != %zu\n", label, an, bn);
        exit(1);
    }
    for (size_t i = 0; i < an; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr, "FAIL %s: value mismatch at %zu (%llu != %llu)\n",
                    label,
                    i,
                    (unsigned long long)a[i],
                    (unsigned long long)b[i]);
            exit(1);
        }
    }
}

static void run_case(uint64_t L,
                     uint64_t R,
                     const uint8_t *h256,
                     int shift,
                     const uint64_t *primes,
                     size_t n_primes,
                     uint64_t prime_limit,
                     const uint64_t *base_mod) {
    size_t n_cached = 0;
    size_t n_uncached = 0;

    const uint64_t *cached = sievegap_run_range(L, R, &n_cached,
                                                h256, shift,
                                                primes, n_primes,
                                                prime_limit,
                                                base_mod, 1,
                                                1);
    const uint64_t *uncached = sievegap_run_range(L, R, &n_uncached,
                                                  h256, shift,
                                                  primes, n_primes,
                                                  prime_limit,
                                                  NULL, 0,
                                                  1);

    if (!cached || !uncached) {
        fprintf(stderr, "FAIL: sievegap returned NULL\n");
        exit(1);
    }

    assert_equal_survivors(cached, n_cached, uncached, n_uncached, "cached-vs-uncached");

    size_t n_ref = 0;
    for (uint64_t off = L | 1ULL; off < R; off += 2) {
        if (!naive_marked(off, h256, shift, primes, n_primes, prime_limit))
            n_ref++;
    }

    uint64_t *ref = (uint64_t *)malloc(n_ref * sizeof(uint64_t));
    if (!ref) {
        fprintf(stderr, "FAIL: out of memory\n");
        exit(1);
    }

    size_t w = 0;
    for (uint64_t off = L | 1ULL; off < R; off += 2) {
        if (!naive_marked(off, h256, shift, primes, n_primes, prime_limit))
            ref[w++] = off;
    }

    assert_equal_survivors(cached, n_cached, ref, n_ref, "sievegap-vs-naive");
    free(ref);
}

int main(void) {
    uint64_t small_primes[4096];
    size_t n_primes = build_small_primes(small_primes, 4096, 50000);
    if (n_primes < 100) {
        fprintf(stderr, "FAIL: could not build enough small primes\n");
        return 1;
    }

    uint8_t h256[32];
    for (int i = 0; i < 32; i++)
        h256[i] = (uint8_t)(i * 7 + 3);

    uint64_t *base_mod = (uint64_t *)malloc(n_primes * sizeof(uint64_t));
    if (!base_mod) {
        fprintf(stderr, "FAIL: out of memory\n");
        return 1;
    }

    const int shifts[] = {20, 29, 37};
    const uint64_t limits[] = {1000, 8000, 30000};
    const uint64_t windows[][2] = {
        {1, 20001},
        {19999, 88001},
        {333333, 401111},
        {700001, 801337}
    };

    for (size_t si = 0; si < sizeof(shifts) / sizeof(shifts[0]); si++) {
        int shift = shifts[si];
        for (size_t i = 0; i < n_primes; i++)
            base_mod[i] = uint256_mod_small(h256, shift, small_primes[i]);

        for (size_t li = 0; li < sizeof(limits) / sizeof(limits[0]); li++) {
            uint64_t limit = limits[li];
            for (size_t wi = 0; wi < sizeof(windows) / sizeof(windows[0]); wi++) {
                run_case(windows[wi][0], windows[wi][1],
                         h256, shift,
                         small_primes, n_primes,
                         limit,
                         base_mod);
            }
        }
    }

    sievegap_free_tls_buffers();
    free(base_mod);
    printf("All sievegap tests passed.\n");
    return 0;
}
