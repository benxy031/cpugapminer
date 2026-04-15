/*
 * bench_euler_vs_gmp.c
 *
 * Benchmarks euler_test_cpu_nlimbs() vs GMP mpz_powm (fast-euler style)
 * and fermat_test_cpu_nlimbs() vs GMP mpz_powm (fast-fermat style).
 *
 * Also cross-checks all three for agreement on the same candidates.
 *
 * Build:
 *   gcc -O3 -march=native -std=c11 -o bench_euler_vs_gmp \
 *       tests/bench_euler_vs_gmp.c src/primality_utils.c \
 *       -lgmp -lm && ./bench_euler_vs_gmp
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

#include "../src/primality_utils.h"

/* ── timing ────────────────────────────────────────────────────────────── */
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* ── GMP fast-euler (mirrors bn_candidate_is_prime / use_fast_euler) ─── */
static int gmp_fast_euler(mpz_t n)
{
    mpz_t nm1, d, res;
    mpz_init(nm1); mpz_init(d); mpz_init(res);

    mpz_sub_ui(nm1, n, 1);
    unsigned long s = mpz_scan1(nm1, 0);
    mpz_tdiv_q_2exp(d, nm1, s);

    mpz_t two; mpz_init_set_ui(two, 2);
    mpz_powm(res, two, d, n);

    int ok = 0;
    if (mpz_cmp_ui(res, 1) == 0 || mpz_cmp(res, nm1) == 0) {
        ok = 1;
    } else {
        for (unsigned long i = 1; i < s; i++) {
            mpz_mul(res, res, res);
            mpz_mod(res, res, n);
            if (mpz_cmp(res, nm1) == 0) { ok = 1; break; }
            if (mpz_cmp_ui(res, 1) == 0) break;
        }
    }

    mpz_clear(nm1); mpz_clear(d); mpz_clear(res); mpz_clear(two);
    return ok;
}

/* ── GMP fast-fermat ────────────────────────────────────────────────── */
static int gmp_fast_fermat(mpz_t n)
{
    mpz_t exp, res, two;
    mpz_init(exp); mpz_init(res); mpz_init_set_ui(two, 2);
    mpz_sub_ui(exp, n, 1);
    mpz_powm(res, two, exp, n);
    int ok = (mpz_cmp_ui(res, 1) == 0);
    mpz_clear(exp); mpz_clear(res); mpz_clear(two);
    return ok;
}

/* generate a random odd nlimbs-word candidate with exactly `bits` significant
 * bits — matching how Gapcoin candidates are formed: hash256 << shift + adder.
 * bits = 256 + shift + 1 (the +1 is because hash256 has its MSB set). */
static void rand_cand(uint64_t *c, int nl, int bits, uint64_t seed)
{
    /* xorshift64 — deterministic, reproducible */
    uint64_t x = seed ^ 0xdeadbeefcafeULL;
    for (int i = 0; i < nl; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        c[i] = x;
    }
    c[0] |= 1; /* ensure odd */

    /* Clamp top limb: keep only bits that are within `bits` total.
     * top limb index = nl-1, valid bits in top limb = bits - (nl-1)*64 */
    int top_bits = bits - (nl - 1) * 64; /* 1..64 */
    if (top_bits < 64) {
        uint64_t mask = (top_bits == 0) ? 0 : ((uint64_t)1 << top_bits) - 1;
        c[nl - 1] &= mask;
    }
    /* ensure top limb is non-zero (set the MSB of the valid region) */
    int msb_pos = (top_bits == 0 || top_bits == 64) ? 63 : top_bits - 1;
    c[nl - 1] |= (uint64_t)1 << msb_pos;
}

/* ── copy nlimbs uint64 array to mpz (little-endian) ─────────────────── */
static void u64_to_mpz(mpz_t z, const uint64_t *c, int nl)
{
    mpz_import(z, (size_t)nl, -1, 8, 0, 0, c);
}

/* ── run one shift benchmark ─────────────────────────────────────────── */
static void bench_shift(int shift, int iters)
{
    /* Actual Gapcoin candidate bit width: hash256 (256 bits) << shift,
     * so candidate = 256 + shift bits (top bit always set).             */
    int cand_bits = 256 + shift;
    int nlimbs    = (cand_bits + 63) / 64;
    if (nlimbs > FERMAT_CPU_MAX_LIMBS) {
        printf("shift=%-4d  nlimbs=%2d  SKIPPED (exceeds FERMAT_CPU_MAX_LIMBS=%d)\n",
               shift, nlimbs, FERMAT_CPU_MAX_LIMBS);
        return;
    }

    /* generate candidates */
    uint64_t (*cands)[FERMAT_CPU_MAX_LIMBS] =
        malloc((size_t)iters * sizeof(*cands));
    if (!cands) { fprintf(stderr, "OOM\n"); return; }

    for (int i = 0; i < iters; i++)
        rand_cand(cands[i], nlimbs, cand_bits,
                  (uint64_t)i * 6364136223846793005ULL + 1442695040888963407ULL);

    mpz_t z; mpz_init(z);

    /* ── correctness cross-check on first 512 candidates ─────────────── */
    int mismatches = 0;
    int check_n = iters < 512 ? iters : 512;
    for (int i = 0; i < check_n; i++) {
        u64_to_mpz(z, cands[i], nlimbs);

        int r_euler_cpu  = euler_test_cpu_nlimbs(cands[i], nlimbs);
        int r_fermat_cpu = fermat_test_cpu_nlimbs(cands[i], nlimbs);
        int r_gmp_euler  = gmp_fast_euler(z);
        int r_gmp_fermat = gmp_fast_fermat(z);

        /* euler_cpu vs gmp_euler */
        if (r_euler_cpu != r_gmp_euler) {
            mismatches++;
            if (mismatches <= 3)
                gmp_printf("  MISMATCH[euler]  i=%d  euler_cpu=%d gmp_euler=%d  n=%Zx\n",
                           i, r_euler_cpu, r_gmp_euler, z);
        }
        /* fermat_cpu vs gmp_fermat */
        if (r_fermat_cpu != r_gmp_fermat) {
            mismatches++;
            if (mismatches <= 3)
                gmp_printf("  MISMATCH[fermat] i=%d  fermat_cpu=%d gmp_fermat=%d  n=%Zx\n",
                           i, r_fermat_cpu, r_gmp_fermat, z);
        }
        /* euler_cpu vs fermat_cpu (must agree on primes; composites may differ) */
        if (r_euler_cpu && !r_fermat_cpu) {
            mismatches++;
            if (mismatches <= 3)
                gmp_printf("  MISMATCH[euler>fermat] i=%d  n=%Zx\n", i, z);
        }
    }

    /* ── benchmark euler_test_cpu_nlimbs ─────────────────────────────── */
    volatile int sink = 0;
    double t0 = now_sec();
    for (int i = 0; i < iters; i++)
        sink += euler_test_cpu_nlimbs(cands[i], nlimbs);
    double t_euler_cpu = now_sec() - t0;

    /* ── benchmark fermat_test_cpu_nlimbs ────────────────────────────── */
    t0 = now_sec();
    for (int i = 0; i < iters; i++)
        sink += fermat_test_cpu_nlimbs(cands[i], nlimbs);
    double t_fermat_cpu = now_sec() - t0;

    /* ── benchmark GMP fast-euler ────────────────────────────────────── */
    t0 = now_sec();
    for (int i = 0; i < iters; i++) {
        u64_to_mpz(z, cands[i], nlimbs);
        sink += gmp_fast_euler(z);
    }
    double t_gmp_euler = now_sec() - t0;

    /* ── benchmark GMP fast-fermat ───────────────────────────────────── */
    t0 = now_sec();
    for (int i = 0; i < iters; i++) {
        u64_to_mpz(z, cands[i], nlimbs);
        sink += gmp_fast_fermat(z);
    }
    double t_gmp_fermat = now_sec() - t0;

    (void)sink;

    double us_euler_cpu  = t_euler_cpu  * 1e6 / iters;
    double us_fermat_cpu = t_fermat_cpu * 1e6 / iters;
    double us_gmp_euler  = t_gmp_euler  * 1e6 / iters;
    double us_gmp_fermat = t_gmp_fermat * 1e6 / iters;

    /* speedup of euler_cpu vs gmp_euler */
    double speedup_e = us_gmp_euler / us_euler_cpu;
    double speedup_f = us_gmp_fermat / us_fermat_cpu;

    printf("shift=%-4d  bits=%-5d  nlimbs=%-2d  "
           "euler_cpu=%6.2fus  gmp_euler=%6.2fus  speedup=%5.2fx  |  "
           "fermat_cpu=%6.2fus  gmp_fermat=%6.2fus  speedup=%5.2fx  "
           "%s\n",
           shift, cand_bits, nlimbs,
           us_euler_cpu, us_gmp_euler, speedup_e,
           us_fermat_cpu, us_gmp_fermat, speedup_f,
           mismatches ? "*** MISMATCH ***" : "OK");

    mpz_clear(z);
    free(cands);
}

int main(void)
{
    printf("bench_euler_vs_gmp — euler_test_cpu_nlimbs vs GMP mpz_powm\n");
    printf("=============================================================\n");

    /* Representative shifts covering the full range */
    static const int shifts[] = {
        25, 28, 32, 40, 48, 54, 64, 68, 96,
        128, 192, 256, 384, 512, 640, 768, 896, 1024
    };
    int n_shifts = (int)(sizeof(shifts) / sizeof(shifts[0]));

    /* Fewer iterations for larger shifts to keep total time manageable */
    for (int si = 0; si < n_shifts; si++) {
        int s = shifts[si];
        int bits = 256 + s;
        /* scale iters inversely with bits^2 (Montgomery cost is O(bits^2)) */
        int iters = (int)(4000000.0 / ((double)bits * bits / (256.0 * 256.0)));
        if (iters < 200)  iters = 200;
        if (iters > 50000) iters = 50000;
        bench_shift(s, iters);
    }

    return 0;
}
