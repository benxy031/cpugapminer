#include "primality_utils.h"

#include <stddef.h>
#include <string.h>
#if defined(__x86_64__) || defined(_M_X64)
#include <x86intrin.h>
#endif

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

/* ═══════════════════════════════════════════════════════════════════
 * Multi-limb CPU Fermat test: 2^(n-1) ≡ 1 (mod n)
 *
 * Implements CIOS (Coarsely Integrated Operand Scanning) Montgomery
 * multiplication using __uint128_t for 64×64→128 multiply-accumulate.
 * This mirrors the GPU kernel (fermat_kernel_t<AL> in gpu_fermat.cu)
 * but runs on CPU with dynamic limb count.
 *
 * Supports up to FERMAT_CPU_MAX_LIMBS × 64-bit candidates.
 * For Gapcoin shift 68: candidates are 324 bits → 6 limbs.
 *   active_limbs = ceil((256 + shift) / 64)
 * ═══════════════════════════════════════════════════════════════════ */

/* Multiply-accumulate: *acc += a × b + carry.  Returns high 64 bits. */
static inline uint64_t cpu_mac(uint64_t *acc, uint64_t a, uint64_t b,
                                uint64_t carry)
{
    unsigned __int128 p = (unsigned __int128)a * b + carry;
    uint64_t lo = (uint64_t)p;
    uint64_t hi = (uint64_t)(p >> 64);
#if defined(__x86_64__) || defined(_M_X64)
    unsigned long long out = 0;
    unsigned char c = _addcarry_u64(0,
                                    (unsigned long long)(*acc),
                                    (unsigned long long)lo,
                                    &out);
    *acc = (uint64_t)out;
    return hi + (uint64_t)c;
#else
    uint64_t prev = *acc;
    *acc = prev + lo;
    hi += (*acc < prev);
    return hi;
#endif
}

/* a >= b  (nl limbs, big-endian comparison) */
static inline int cpu_gte_n(const uint64_t *a, const uint64_t *b, int nl)
{
    for (int i = nl - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1; /* equal */
}

/* r = a − b  (nl limbs, unsigned, no overflow check) */
static inline void cpu_sub_n(uint64_t *r, const uint64_t *a,
                             const uint64_t *b, int nl)
{
    uint64_t borrow = 0;
    for (int i = 0; i < nl; i++) {
        uint64_t ai = a[i], bi = b[i];
        uint64_t d   = ai - bi;
        uint64_t b1  = (ai < bi);
        uint64_t d2  = d - borrow;
        uint64_t b2  = (d < borrow);
        r[i]   = d2;
        borrow = b1 + b2;
    }
}

/* a = 2a mod n  (modular doubling) */
static inline void cpu_moddbl_n(uint64_t *a, const uint64_t *n, int nl)
{
    uint64_t carry = 0;
    for (int i = 0; i < nl; i++) {
        uint64_t v = a[i];
        a[i]  = (v << 1) | carry;
        carry = v >> 63;
    }
    if (carry || cpu_gte_n(a, n, nl))
        cpu_sub_n(a, a, n, nl);
}

/* r = R mod n,  R = 2^(64*nl).
 * Finds topbit of n via __builtin_clzll, computes r = 2^topbit − n,
 * then doubles (64*nl − 1 − topbit) more times.  Same algorithm as
 * compute_rmodn_t<AL> in the CUDA kernel. */
static inline void cpu_rmodn_n(uint64_t *r, const uint64_t *n, int nl)
{
    /* nlimbs is significant-limb count; top limb is non-zero. */
    int top_limb = nl - 1;
    int top_bit_in_limb = 63 - __builtin_clzll(n[top_limb]);
    int topbit = top_limb * 64 + top_bit_in_limb;

    /* r = 2^topbit (single bit) */
    for (int i = 0; i < nl; i++) r[i] = 0;
    r[top_limb] = (uint64_t)1 << top_bit_in_limb;
    /* r = 2^topbit − n */
    cpu_sub_n(r, r, n, nl);
    /* double (64*nl − 1 − topbit) more times → r = R mod n */
    int remaining = 64 * nl - 1 - topbit;
    for (int i = 0; i < remaining; i++)
        cpu_moddbl_n(r, n, nl);
}

/* Montgomery multiplication: r = a · b · R⁻¹ mod n  (CIOS algorithm)
 * Requires n odd, 0 ≤ a, b < n < R = 2^(64*nl). */
static inline void cpu_montmul_n(uint64_t *r,
                                 const uint64_t *a,
                                 const uint64_t *b,
                                 const uint64_t *n,
                                 uint64_t ninv, int nl)
{
    uint64_t tbuf[2 * FERMAT_CPU_MAX_LIMBS + 4];
    for (int i = 0; i < 2 * nl + 4; i++) tbuf[i] = 0;
    uint64_t *t = tbuf;

    for (int i = 0; i < nl; i++) {
        uint64_t c = 0;
        for (int j = 0; j < nl; j++)
            c = cpu_mac(&t[j], a[i], b[j], c);
        uint64_t old = t[nl];
        t[nl] += c;
        t[nl + 1] += (t[nl] < old);

        uint64_t m = t[0] * ninv;
        c = 0;
        for (int j = 0; j < nl; j++)
            c = cpu_mac(&t[j], m, n[j], c);
        old = t[nl];
        t[nl] += c;
        t[nl + 1] += (t[nl] < old);

        /* Logical left-shift by one limb (drop t[0], append 0)
           without copying nl+1 words each iteration. */
        t++;
        t[nl + 1] = 0;
    }

    if (t[nl] || cpu_gte_n(t, n, nl))
        cpu_sub_n(r, t, n, nl);
    else
        for (int i = 0; i < nl; i++) r[i] = t[i];
}

#define DECL_MONTMUL_BUCKET(FN, MAXNL) \
static inline void FN(uint64_t *r, \
                      const uint64_t *a, \
                      const uint64_t *b, \
                      const uint64_t *n, \
                      uint64_t ninv, int nlimbs) \
{ \
    uint64_t tbuf[2 * (MAXNL) + 4]; \
    for (int i = 0; i < 2 * nlimbs + 4; i++) tbuf[i] = 0; \
    uint64_t *t = tbuf; \
    for (int i = 0; i < nlimbs; i++) { \
        uint64_t c = 0; \
        uint64_t ai = a[i]; \
        int j = 0; \
        for (; j + 3 < nlimbs; j += 4) { \
            c = cpu_mac(&t[j],     ai, b[j],     c); \
            c = cpu_mac(&t[j + 1], ai, b[j + 1], c); \
            c = cpu_mac(&t[j + 2], ai, b[j + 2], c); \
            c = cpu_mac(&t[j + 3], ai, b[j + 3], c); \
        } \
        for (; j < nlimbs; j++) \
            c = cpu_mac(&t[j], ai, b[j], c); \
        uint64_t old = t[nlimbs]; \
        t[nlimbs] += c; \
        t[nlimbs + 1] += (t[nlimbs] < old); \
        uint64_t m = t[0] * ninv; \
        c = 0; \
        j = 0; \
        for (; j + 3 < nlimbs; j += 4) { \
            c = cpu_mac(&t[j],     m, n[j],     c); \
            c = cpu_mac(&t[j + 1], m, n[j + 1], c); \
            c = cpu_mac(&t[j + 2], m, n[j + 2], c); \
            c = cpu_mac(&t[j + 3], m, n[j + 3], c); \
        } \
        for (; j < nlimbs; j++) \
            c = cpu_mac(&t[j], m, n[j], c); \
        old = t[nlimbs]; \
        t[nlimbs] += c; \
        t[nlimbs + 1] += (t[nlimbs] < old); \
        t++; \
        t[nlimbs + 1] = 0; \
    } \
    if (t[nlimbs] || cpu_gte_n(t, n, nlimbs)) \
        cpu_sub_n(r, t, n, nlimbs); \
    else \
        for (int i = 0; i < nlimbs; i++) r[i] = t[i]; \
}

DECL_MONTMUL_BUCKET(cpu_montmul_b4, 4)
DECL_MONTMUL_BUCKET(cpu_montmul_b8, 8)
DECL_MONTMUL_BUCKET(cpu_montmul_b12, 12)
DECL_MONTMUL_BUCKET(cpu_montmul_b20, 20)

static int fermat_u64_exact(uint64_t n)
{
    if (n < 4) return n >= 2;
    if ((n & 1) == 0) return 0;

    uint64_t e = n - 1;
    uint64_t acc = 1 % n;
    uint64_t base = 2 % n;
    while (e) {
        if (e & 1)
            acc = (uint64_t)(((__uint128_t)acc * base) % n);
        base = (uint64_t)(((__uint128_t)base * base) % n);
        e >>= 1;
    }
    return acc == 1;
}

/*
 * fermat_test_cpu_nlimbs — base-2 Fermat test for multi-limb integers.
 *
 * n     : little-endian array of nlimbs 64-bit words representing the
 *         candidate integer.  n[0] is the least-significant word.
 * nlimbs: number of significant 64-bit limbs (1 ≤ nlimbs ≤ FERMAT_CPU_MAX_LIMBS).
 *
 * Returns 1 if 2^(n−1) ≡ 1 (mod n) (probably prime), 0 if composite.
 *
 * Mirrors fermat_kernel_t<AL> from gpu_fermat.cu using __uint128_t
 * instead of CUDA intrinsics.
 */
#define DECL_FERMAT_CORE_BUCKET(FN, MONTFN) \
static inline int FN(const uint64_t *n, int nlimbs) \
{ \
    if (nlimbs <= 0 || nlimbs > FERMAT_CPU_MAX_LIMBS) return 0; \
    if (nlimbs == 1) return fermat_u64_exact(n[0]); \
    if ((n[0] & 1) == 0) return 0; \
    uint64_t ninv = mont_ninv(n[0]); \
    uint64_t one_m[FERMAT_CPU_MAX_LIMBS]; \
    cpu_rmodn_n(one_m, n, nlimbs); \
    uint64_t base_m[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(base_m, one_m, (size_t)nlimbs * sizeof(uint64_t)); \
    cpu_moddbl_n(base_m, n, nlimbs); \
    uint64_t e[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(e, n, (size_t)nlimbs * sizeof(uint64_t)); \
    e[0] -= 1; \
    int top = nlimbs - 1; \
    int msb = 63 - __builtin_clzll(e[top]); \
    uint64_t res[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(res, base_m, (size_t)nlimbs * sizeof(uint64_t)); \
    for (int limb = top; limb >= 0; limb--) { \
        int start = (limb == top) ? msb - 1 : 63; \
        for (int bit = start; bit >= 0; bit--) { \
            MONTFN(res, res, res, n, ninv, nlimbs); \
            if ((e[limb] >> bit) & 1) \
                MONTFN(res, res, base_m, n, ninv, nlimbs); \
        } \
    } \
    uint64_t one[FERMAT_CPU_MAX_LIMBS]; \
    memset(one, 0, (size_t)nlimbs * sizeof(uint64_t)); \
    one[0] = 1; \
    MONTFN(res, res, one, n, ninv, nlimbs); \
    if (res[0] != 1) return 0; \
    for (int i = 1; i < nlimbs; i++) if (res[i] != 0) return 0; \
    return 1; \
}

DECL_FERMAT_CORE_BUCKET(fermat_test_cpu_core_b4, cpu_montmul_b4)
DECL_FERMAT_CORE_BUCKET(fermat_test_cpu_core_b8, cpu_montmul_b8)
DECL_FERMAT_CORE_BUCKET(fermat_test_cpu_core_b12, cpu_montmul_b12)
DECL_FERMAT_CORE_BUCKET(fermat_test_cpu_core_b20, cpu_montmul_b20)

#define DECL_FERMAT_FIXED_BUCKET(NL, CORE) \
    static inline int fermat_test_cpu_nlimbs_##NL(const uint64_t *n) { \
        return CORE(n, (NL)); \
    }

DECL_FERMAT_FIXED_BUCKET(2,  fermat_test_cpu_core_b4)
DECL_FERMAT_FIXED_BUCKET(3,  fermat_test_cpu_core_b4)
DECL_FERMAT_FIXED_BUCKET(4,  fermat_test_cpu_core_b4)
DECL_FERMAT_FIXED_BUCKET(5,  fermat_test_cpu_core_b8)
DECL_FERMAT_FIXED_BUCKET(6,  fermat_test_cpu_core_b8)
DECL_FERMAT_FIXED_BUCKET(7,  fermat_test_cpu_core_b8)
DECL_FERMAT_FIXED_BUCKET(8,  fermat_test_cpu_core_b8)
DECL_FERMAT_FIXED_BUCKET(9,  fermat_test_cpu_core_b12)
DECL_FERMAT_FIXED_BUCKET(10, fermat_test_cpu_core_b12)
DECL_FERMAT_FIXED_BUCKET(11, fermat_test_cpu_core_b12)
DECL_FERMAT_FIXED_BUCKET(12, fermat_test_cpu_core_b12)
DECL_FERMAT_FIXED_BUCKET(13, fermat_test_cpu_core_b20)
DECL_FERMAT_FIXED_BUCKET(14, fermat_test_cpu_core_b20)
DECL_FERMAT_FIXED_BUCKET(15, fermat_test_cpu_core_b20)
DECL_FERMAT_FIXED_BUCKET(16, fermat_test_cpu_core_b20)
DECL_FERMAT_FIXED_BUCKET(17, fermat_test_cpu_core_b20)
DECL_FERMAT_FIXED_BUCKET(18, fermat_test_cpu_core_b20)
DECL_FERMAT_FIXED_BUCKET(19, fermat_test_cpu_core_b20)
DECL_FERMAT_FIXED_BUCKET(20, fermat_test_cpu_core_b20)

int fermat_test_cpu_nlimbs(const uint64_t *n, int nlimbs)
{
    switch (nlimbs) {
    case 1:  return fermat_u64_exact(n[0]);
    case 2:  return fermat_test_cpu_nlimbs_2(n);
    case 3:  return fermat_test_cpu_nlimbs_3(n);
    case 4:  return fermat_test_cpu_nlimbs_4(n);
    case 5:  return fermat_test_cpu_nlimbs_5(n);
    case 6:  return fermat_test_cpu_nlimbs_6(n);
    case 7:  return fermat_test_cpu_nlimbs_7(n);
    case 8:  return fermat_test_cpu_nlimbs_8(n);
    case 9:  return fermat_test_cpu_nlimbs_9(n);
    case 10: return fermat_test_cpu_nlimbs_10(n);
    case 11: return fermat_test_cpu_nlimbs_11(n);
    case 12: return fermat_test_cpu_nlimbs_12(n);
    case 13: return fermat_test_cpu_nlimbs_13(n);
    case 14: return fermat_test_cpu_nlimbs_14(n);
    case 15: return fermat_test_cpu_nlimbs_15(n);
    case 16: return fermat_test_cpu_nlimbs_16(n);
    case 17: return fermat_test_cpu_nlimbs_17(n);
    case 18: return fermat_test_cpu_nlimbs_18(n);
    case 19: return fermat_test_cpu_nlimbs_19(n);
    case 20: return fermat_test_cpu_nlimbs_20(n);
    default: return 0;
    }
}
