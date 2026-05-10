#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/sievegap.h"
#include "../src/uint256_utils.h"

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

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

static size_t baseline_gapminer_style(uint64_t L,
                                      uint64_t R,
                                      uint64_t prime_limit,
                                      const uint64_t *primes,
                                      size_t n_primes,
                                      const uint64_t *base_mod,
                                      uint64_t *out) {
    uint64_t seg_size = R - L;
    size_t bit_bytes = (size_t)((seg_size + 15ULL) >> 4);
    if (bit_bytes == 0)
        bit_bytes = 1;

    uint8_t *bits = (uint8_t *)calloc(bit_bytes, 1);
    if (!bits)
        return 0;

    for (size_t i = 1; i < n_primes; i++) {
        uint64_t p = primes[i];
        if (p > prime_limit)
            break;

        uint64_t l_mod_p = L % p;
        uint64_t rem = base_mod[i] + l_mod_p;
        if (rem >= p)
            rem -= p;

        uint64_t m = (rem == 0) ? L : (L + (p - rem));
        if ((m & 1ULL) == 0ULL)
            m += p;

        for (uint64_t x = m; x < R; x += (p << 1)) {
            uint64_t k = (x - L) >> 1;
            bits[k >> 3] |= (uint8_t)(1U << (k & 7U));
        }
    }

    uint64_t odd_count = (seg_size + 1ULL) >> 1;
    size_t n_out = 0;
    for (uint64_t k = 0; k < odd_count; k++) {
        if ((bits[k >> 3] & (uint8_t)(1U << (k & 7U))) == 0)
            out[n_out++] = L + (k << 1);
    }

    free(bits);
    return n_out;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [iters] [window_size] [sieve_limit]\n"
            "Defaults: iters=300 window_size=33554432 sieve_limit=500000\n",
            argv0);
}

int main(int argc, char **argv) {
    int iters = 300;
    uint64_t window_size = 33554432ULL;
    uint64_t sieve_limit = 500000ULL;

    if (argc > 1) {
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            usage(argv[0]);
            return 0;
        }
        iters = atoi(argv[1]);
    }
    if (argc > 2)
        window_size = strtoull(argv[2], NULL, 10);
    if (argc > 3)
        sieve_limit = strtoull(argv[3], NULL, 10);
    if (iters < 1)
        iters = 1;

    uint64_t *primes = (uint64_t *)malloc(2000000ULL * sizeof(uint64_t));
    if (!primes) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }
    size_t n_primes = build_small_primes(primes, 2000000ULL, sieve_limit + 1000ULL);

    uint8_t h256[32];
    for (int i = 0; i < 32; i++)
        h256[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 11 + 1));

    int shift = 20;
    uint64_t *base_mod = (uint64_t *)malloc(n_primes * sizeof(uint64_t));
    if (!base_mod) {
        fprintf(stderr, "allocation failed\n");
        free(primes);
        return 1;
    }
    for (size_t i = 0; i < n_primes; i++)
        base_mod[i] = uint256_mod_small(h256, shift, primes[i]);

    uint64_t *baseline_out = (uint64_t *)malloc((size_t)window_size * sizeof(uint64_t));
    if (!baseline_out) {
        fprintf(stderr, "allocation failed\n");
        free(base_mod);
        free(primes);
        return 1;
    }

    uint64_t L = 1;
    uint64_t R = L + window_size;

    size_t n_sievegap = 0;
    const uint64_t *sg = sievegap_run_range(L, R, &n_sievegap,
                                            h256, shift,
                                            primes, n_primes,
                                            sieve_limit,
                                            base_mod, 1,
                                            1);
    size_t n_baseline = baseline_gapminer_style(L, R, sieve_limit,
                                                primes, n_primes,
                                                base_mod,
                                                baseline_out);
    if (!sg || n_sievegap != n_baseline) {
        fprintf(stderr, "correctness mismatch: sievegap=%zu baseline=%zu\n",
                n_sievegap, n_baseline);
        free(baseline_out);
        free(base_mod);
        free(primes);
        return 2;
    }
    for (size_t i = 0; i < n_baseline; i++) {
        if (sg[i] != baseline_out[i]) {
            fprintf(stderr, "correctness mismatch at %zu (%llu != %llu)\n",
                    i,
                    (unsigned long long)sg[i],
                    (unsigned long long)baseline_out[i]);
            free(baseline_out);
            free(base_mod);
            free(primes);
            return 3;
        }
    }

    uint64_t t0 = now_ns();
    size_t sink_a = 0;
    for (int it = 0; it < iters; it++) {
        size_t n = 0;
        const uint64_t *tmp = sievegap_run_range(L, R, &n,
                                                 h256, shift,
                                                 primes, n_primes,
                                                 sieve_limit,
                                                 base_mod, 1,
                                                 1);
        if (!tmp) {
            fprintf(stderr, "sievegap returned NULL\n");
            free(baseline_out);
            free(base_mod);
            free(primes);
            return 4;
        }
        sink_a += n;
    }
    uint64_t t1 = now_ns();

    uint64_t t2 = now_ns();
    size_t sink_b = 0;
    for (int it = 0; it < iters; it++) {
        sink_b += baseline_gapminer_style(L, R, sieve_limit,
                                          primes, n_primes,
                                          base_mod,
                                          baseline_out);
    }
    uint64_t t3 = now_ns();

    double sievegap_ms = (double)(t1 - t0) / 1e6;
    double baseline_ms = (double)(t3 - t2) / 1e6;
    double speedup = baseline_ms / sievegap_ms;

    printf("bench_sievegap\n");
    printf("iters=%d window_size=%llu sieve_limit=%llu\n",
           iters,
           (unsigned long long)window_size,
           (unsigned long long)sieve_limit);
    printf("survivors=%zu\n", n_sievegap);
    printf("sievegap_total_ms=%.3f\n", sievegap_ms);
    printf("baseline_total_ms=%.3f\n", baseline_ms);
    printf("speedup=%.3fx\n", speedup);
    printf("sink_guard=%zu:%zu\n", sink_a, sink_b);

    sievegap_free_tls_buffers();
    free(baseline_out);
    free(base_mod);
    free(primes);
    return 0;
}
