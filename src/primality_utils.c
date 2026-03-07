#include "primality_utils.h"

#include <stddef.h>

/* n_prime = -(n^{-1}) mod 2^64 for odd n. */
static inline uint64_t mont_ninv(uint64_t n) {
    uint64_t x = 1;
    x *= 2 - n * x;
    x *= 2 - n * x;
    x *= 2 - n * x;
    x *= 2 - n * x;
    x *= 2 - n * x;
    x *= 2 - n * x;
    return -x;
}

/* Montgomery product: a * b * R^{-1} mod n. */
static inline uint64_t mont_mul(uint64_t a, uint64_t b,
                                uint64_t n, uint64_t np) {
    __uint128_t ab = (__uint128_t)a * b;
    uint64_t ab_lo = (uint64_t)ab;
    uint64_t ab_hi = (uint64_t)(ab >> 64);
    uint64_t m = ab_lo * np;
    __uint128_t mn = (__uint128_t)m * n;
    uint64_t mn_lo = (uint64_t)mn;
    uint64_t mn_hi = (uint64_t)(mn >> 64);
    uint64_t carry = (ab_lo + mn_lo) < ab_lo ? 1u : 0u;
    uint64_t u = ab_hi + mn_hi + carry;
    return u >= n ? u - n : u;
}

/* R^2 mod n = 2^128 mod n. */
static inline uint64_t mont_R2(uint64_t n) {
    uint64_t r = (-(uint64_t)n) % n;
    return (uint64_t)(((__uint128_t)r * r) % n);
}

/* Strong (Miller-Rabin) pseudoprime test for base a modulo n. */
static int strong_mrt(uint64_t n, uint64_t a,
                      uint64_t np, uint64_t R2,
                      uint64_t d, int s) {
    uint64_t one_m = mont_mul(1, R2, n, np);
    uint64_t nm1_m = mont_mul(n - 1, R2, n, np);
    uint64_t b = mont_mul(a % n, R2, n, np);
    uint64_t x = one_m;
    uint64_t e = d;
    while (e) {
        if (e & 1) x = mont_mul(x, b, n, np);
        b = mont_mul(b, b, n, np);
        e >>= 1;
    }
    if (x == one_m || x == nm1_m) return 1;
    for (int r = 1; r < s; r++) {
        x = mont_mul(x, x, n, np);
        if (x == nm1_m) return 1;
    }
    return 0;
}

int primality_miller_rabin_u64(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if (!(n & 1) || n % 3 == 0) return 0;

    static const uint64_t small[] = {5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (size_t i = 0; i < sizeof(small) / sizeof(*small); ++i) {
        if (n == small[i]) return 1;
        if (n % small[i] == 0) return 0;
    }

    uint64_t d = n - 1;
    int s = 0;
    while (!(d & 1)) {
        d >>= 1;
        s++;
    }

    uint64_t np = mont_ninv(n);
    uint64_t R2 = mont_R2(n);
    static const uint64_t bases[] = {2, 325, 9375, 28178, 450775, 9780504, 1795265022};
    for (size_t i = 0; i < 7; i++) {
        uint64_t a = bases[i] % n;
        if (a == 0) continue;
        if (!strong_mrt(n, a, np, R2, d, s)) return 0;
    }
    return 1;
}

int primality_fast_fermat_u64(uint64_t n) {
    if (n < 4) return n >= 2;
    if (!(n & 1)) return 0;

    uint64_t d = n - 1;
    int s = 0;
    while (!(d & 1)) {
        d >>= 1;
        s++;
    }

    uint64_t np = mont_ninv(n);
    uint64_t R2 = mont_R2(n);
    if (!strong_mrt(n, 2, np, R2, d, s)) return 0;
    if (!strong_mrt(n, 3, np, R2, d, s)) return 0;

    return 1;
}
