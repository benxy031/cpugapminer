/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Microbenchmark for docs/CRT_LOW_SHIFT_PERFORMANCE_PLAN.md section 4:
 * measures whether replacing mpz_fdiv_ui(tls_base_mpz, p) with
 * uint256_mod_small(h256, shift, p) in the per-nonce residue setup
 * (set_base_bn's sieve-prime loop, crt_filter_init_residues) would
 * actually be faster, across the same shift ladder used for the
 * low-shift CRT investigation. Does NOT touch src/main.c; read-only
 * measurement to decide whether the swap is worth making.
 *
 * Usage: ./tests/bench_residue_setup [prime_count]
 *   prime_count defaults to 1000000 (representative of a mid/large
 *   sieve-primes count); pass e.g. 1000 to mimic the low-shift
 *   auto-profile default, or 2000000 for the SIEVE_PRIMES=2000000 case.
 */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <gmp.h>

#include "uint256_utils.h"

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Sieve of Eratosthenes up to `limit`; returns malloc'd array of primes,
   sets *out_count. Caller frees. */
static uint64_t *sieve_primes(uint64_t limit, size_t *out_count) {
    uint8_t *is_comp = calloc(limit + 1, 1);
    if (!is_comp) { *out_count = 0; return NULL; }
    for (uint64_t i = 2; i * i <= limit; i++) {
        if (is_comp[i]) continue;
        for (uint64_t j = i * i; j <= limit; j += i)
            is_comp[j] = 1;
    }
    size_t cnt = 0;
    for (uint64_t i = 2; i <= limit; i++)
        if (!is_comp[i]) cnt++;
    uint64_t *primes = malloc(cnt * sizeof(uint64_t));
    size_t k = 0;
    for (uint64_t i = 2; i <= limit; i++)
        if (!is_comp[i]) primes[k++] = i;
    free(is_comp);
    *out_count = cnt;
    return primes;
}

int main(int argc, char **argv) {
    size_t want_primes = (argc > 1) ? (size_t)strtoull(argv[1], NULL, 10) : 1000000;

    /* Fixed, non-trivial 256-bit hash (avoid all-zero which trivializes
       uint256_mod_small's reduction loop). */
    uint8_t h256[32];
    for (int i = 0; i < 32; i++) h256[i] = (uint8_t)(0x9e3779b1u * (i + 1) >> 3);

    /* Generate enough primes to cover want_primes; rough prime counting
       estimate limit = n * (ln n + ln ln n) for n >= 6, with margin. */
    double n = (double)want_primes;
    uint64_t limit = (n < 10) ? 30 : (uint64_t)(n * (log(n) + log(log(n))) * 1.15) + 100;
    size_t avail = 0;
    uint64_t *primes = sieve_primes(limit, &avail);
    if (!primes || avail < want_primes) {
        fprintf(stderr, "sieve failed to produce %zu primes (got %zu, limit %llu)\n",
                want_primes, avail, (unsigned long long)limit);
        return 1;
    }
    size_t n_primes = want_primes;

    int shifts[] = {64, 96, 128, 256, 384, 512, 768, 1001};
    size_t n_shifts = sizeof(shifts) / sizeof(shifts[0]);

    printf("bench_residue_setup: n_primes=%zu (max prime ~%llu)\n",
           n_primes, (unsigned long long)primes[n_primes - 1]);
    printf("%-8s %14s %14s %10s %14s %14s\n",
           "shift", "gmp_ms", "gmp_ns/call", "vs", "u256_ms", "u256_ns/call");

    mpz_t base;
    mpz_init(base);

    for (size_t si = 0; si < n_shifts; si++) {
        int shift = shifts[si];

        /* base = h256 << shift, same construction as set_base_bn(). */
        mpz_import(base, 32, 1, 1, 1, 0, h256);
        mpz_mul_2exp(base, base, (unsigned long)shift);

        volatile uint64_t sink = 0;

        double t0 = now_s();
        for (size_t i = 0; i < n_primes; i++)
            sink += mpz_fdiv_ui(base, (unsigned long)primes[i]);
        double t1 = now_s();
        double gmp_ms = (t1 - t0) * 1e3;
        double gmp_ns_call = (t1 - t0) * 1e9 / (double)n_primes;

        double t2 = now_s();
        for (size_t i = 0; i < n_primes; i++)
            sink += uint256_mod_small(h256, shift, primes[i]);
        double t3 = now_s();
        double u256_ms = (t3 - t2) * 1e3;
        double u256_ns_call = (t3 - t2) * 1e9 / (double)n_primes;

        printf("%-8d %14.3f %14.2f %10s %14.3f %14.2f\n",
               shift, gmp_ms, gmp_ns_call,
               (u256_ms < gmp_ms) ? "u256<gmp" : "gmp<u256",
               u256_ms, u256_ns_call);

        if (sink == 0xdeadbeefdeadbeefULL) printf("(unreachable)\n");
    }

    mpz_clear(base);
    free(primes);
    return 0;
}
