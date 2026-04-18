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
 * Uses a 4-bit fixed-window left-to-right exponentiation:
 *   Precompute win[i] = base^(2i+1) mod n, i=0..7  (8 odd powers)
 *   Scan exponent MSB→LSB, extracting 4-bit chunks w:
 *     - If w == 0: square 4 times
 *     - Else: find trailing zero count z of w, square (4-z) times,
 *             multiply by win[(w>>z)>>1], square z more times.
 *   This halves the multiply count vs binary square-and-multiply and
 *   matches GMP's k-ary window strategy (speedup ~2× vs old binary path).
 */
#define FERMAT_WIN  4                  /* window width in bits   */
#define FERMAT_WINSZ (1 << FERMAT_WIN) /* 16 entries: powers 1..15 */

/* Helper: extract 4-bit chunk starting at bit position `bit` in e[],
 * scanning from top limb downward.  Returns value 0..15. */
static inline uint32_t cpu_get_bits4(const uint64_t *e, int bit) {
    int limb = bit >> 6;
    int off  = bit & 63;
    uint32_t w = (uint32_t)(e[limb] >> off) & 0xF;
    /* If the 4-bit window straddles a limb boundary, pick up the remaining
     * bits from the next-higher limb. */
    if (off > 60 && limb + 1 < FERMAT_CPU_MAX_LIMBS)
        w |= (uint32_t)(e[limb + 1] << (64 - off)) & 0xF;
    return w;
}

#define DECL_FERMAT_CORE_BUCKET(FN, MONTFN) \
static inline int FN(const uint64_t *n, int nlimbs) \
{ \
    if (nlimbs <= 0 || nlimbs > FERMAT_CPU_MAX_LIMBS) return 0; \
    if (nlimbs == 1) return fermat_u64_exact(n[0]); \
    if ((n[0] & 1) == 0) return 0; \
    uint64_t ninv = mont_ninv(n[0]); \
    /* one_m = R mod n (Montgomery 1) */ \
    uint64_t one_m[FERMAT_CPU_MAX_LIMBS]; \
    cpu_rmodn_n(one_m, n, nlimbs); \
    /* base_m = 2 * one_m mod n (Montgomery 2) */ \
    uint64_t base_m[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(base_m, one_m, (size_t)nlimbs * sizeof(uint64_t)); \
    cpu_moddbl_n(base_m, n, nlimbs); \
    /* Precompute win[i] = base^(2i+1) mod n, in Montgomery form.
     * win[0]=base^1, win[1]=base^3, win[2]=base^5, ... win[7]=base^15 */ \
    uint64_t win[FERMAT_WINSZ / 2][FERMAT_CPU_MAX_LIMBS]; \
    uint64_t base2_m[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(win[0], base_m, (size_t)nlimbs * sizeof(uint64_t)); \
    MONTFN(base2_m, base_m, base_m, n, ninv, nlimbs); /* base^2 */ \
    for (int _w = 1; _w < FERMAT_WINSZ / 2; _w++) \
        MONTFN(win[_w], win[_w - 1], base2_m, n, ninv, nlimbs); \
    /* Exponent e = n - 1 */ \
    uint64_t e[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(e, n, (size_t)nlimbs * sizeof(uint64_t)); \
    e[0] -= 1; \
    /* Find the most-significant set bit of e */ \
    int top = nlimbs - 1; \
    while (top > 0 && e[top] == 0) top--; \
    int msb = top * 64 + 63 - __builtin_clzll(e[top]); \
    /* Init result = win[0] = base^1 (handles the leading 1 bit) */ \
    uint64_t res[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(res, base_m, (size_t)nlimbs * sizeof(uint64_t)); \
    /* Left-to-right 4-bit fixed-window scan (skip the MSB itself) */ \
    int bit = msb - 1; \
    while (bit >= 0) { \
        if (bit < FERMAT_WIN - 1) { \
            /* Fewer than 4 bits remain: process one bit at a time */ \
            MONTFN(res, res, res, n, ninv, nlimbs); \
            if ((e[bit >> 6] >> (bit & 63)) & 1) \
                MONTFN(res, res, base_m, n, ninv, nlimbs); \
            bit--; \
        } else { \
            /* Extract 4-bit window */ \
            uint32_t w = cpu_get_bits4(e, bit - (FERMAT_WIN - 1)); \
            if (w == 0) { \
                /* All-zero window: 4 squarings */ \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                bit -= FERMAT_WIN; \
            } else { \
                /* Find trailing-zero count z of w (right-adjust odd part) */ \
                int z = __builtin_ctz(w); \
                /* Square (FERMAT_WIN - z) times to consume the non-zero bits */ \
                int sq = FERMAT_WIN - z; \
                for (int _s = 0; _s < sq; _s++) \
                    MONTFN(res, res, res, n, ninv, nlimbs); \
                /* Multiply by the odd power win[(w >> z) >> 1] */ \
                MONTFN(res, res, win[(w >> z) >> 1], n, ninv, nlimbs); \
                /* Square z more times for the trailing zeros */ \
                for (int _s = 0; _s < z; _s++) \
                    MONTFN(res, res, res, n, ninv, nlimbs); \
                bit -= FERMAT_WIN; \
            } \
        } \
    } \
    /* Convert from Montgomery form: multiply by 1 */ \
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

/* ═══════════════════════════════════════════════════════════════════
 * Multi-limb CPU Euler–Plumb test: 2^((n-1)/2) ≡ ±1 (mod n)
 *
 * Halves the squaring count vs fermat_test_cpu_nlimbs by using the
 * exponent (n-1)/2 instead of (n-1).  The final comparison is done
 * in Montgomery form, avoiding one extra Montgomery multiply per call.
 *
 * one_m  = R mod n           (Montgomery form of 1)
 * nm1_m  = n − one_m         (Montgomery form of n−1, since (n−1)·R ≡ −R mod n)
 * Accept iff res == one_m  OR  res == nm1_m.
 *
 * Covers shifts 25–1024  (nlimbs 5–20).
 * ═══════════════════════════════════════════════════════════════════ */

static inline int euler_u64(uint64_t n)
{
    if (n < 4) return n >= 2;
    if (!(n & 1)) return 0;
    uint64_t e = (n - 1) >> 1;
    uint64_t acc = 1, base = 2 % n;
    while (e) {
        if (e & 1) acc = (uint64_t)(((__uint128_t)acc * base) % n);
        base = (uint64_t)(((__uint128_t)base * base) % n);
        e >>= 1;
    }
    return acc == 1 || acc == n - 1;
}

#define DECL_EULER_CORE_BUCKET(FN, MONTFN) \
static inline int FN(const uint64_t *n, int nlimbs) \
{ \
    if (nlimbs <= 0 || nlimbs > FERMAT_CPU_MAX_LIMBS) return 0; \
    if (nlimbs == 1) return euler_u64(n[0]); \
    if ((n[0] & 1) == 0) return 0; \
    uint64_t ninv = mont_ninv(n[0]); \
    /* one_m = R mod n  (Montgomery form of 1, used only for base_m) */ \
    uint64_t one_m[FERMAT_CPU_MAX_LIMBS]; \
    cpu_rmodn_n(one_m, n, nlimbs); \
    /* base_m = 2*one_m mod n  (Montgomery form of 2) */ \
    uint64_t base_m[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(base_m, one_m, (size_t)nlimbs * sizeof(uint64_t)); \
    cpu_moddbl_n(base_m, n, nlimbs); \
    /* Precompute 4-bit window: win[i] = base^(2i+1) mod n, i=0..7 */ \
    uint64_t win[FERMAT_WINSZ / 2][FERMAT_CPU_MAX_LIMBS]; \
    uint64_t base2_m[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(win[0], base_m, (size_t)nlimbs * sizeof(uint64_t)); \
    MONTFN(base2_m, base_m, base_m, n, ninv, nlimbs); \
    for (int _w = 1; _w < FERMAT_WINSZ / 2; _w++) \
        MONTFN(win[_w], win[_w - 1], base2_m, n, ninv, nlimbs); \
    /* e = (n-1)/2: n is odd so n-1 is even, right-shift is exact. \
       After the shift the top limb of e may have its high bit clear  \
       (if the top bit of n was bit 63 of the top limb), so we must    \
       re-scan to find the actual most-significant set bit.            */ \
    uint64_t e[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(e, n, (size_t)nlimbs * sizeof(uint64_t)); \
    e[0] -= 1; \
    for (int _i = 0; _i < nlimbs - 1; _i++) \
        e[_i] = (e[_i] >> 1) | (e[_i + 1] << 63); \
    e[nlimbs - 1] >>= 1; \
    /* find top non-zero limb of e (top limb may become 0 after shift) */ \
    int top = nlimbs - 1; \
    while (top > 0 && e[top] == 0) top--; \
    int msb = top * 64 + 63 - __builtin_clzll(e[top]); \
    /* Left-to-right 4-bit fixed-window, init res = base^1 (MSB=1 consumed) */ \
    uint64_t res[FERMAT_CPU_MAX_LIMBS]; \
    memcpy(res, base_m, (size_t)nlimbs * sizeof(uint64_t)); \
    int bit = msb - 1; \
    while (bit >= 0) { \
        if (bit < FERMAT_WIN - 1) { \
            MONTFN(res, res, res, n, ninv, nlimbs); \
            if ((e[bit >> 6] >> (bit & 63)) & 1) \
                MONTFN(res, res, base_m, n, ninv, nlimbs); \
            bit--; \
        } else { \
            uint32_t w = cpu_get_bits4(e, bit - (FERMAT_WIN - 1)); \
            if (w == 0) { \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                MONTFN(res, res, res, n, ninv, nlimbs); \
                bit -= FERMAT_WIN; \
            } else { \
                int z = __builtin_ctz(w); \
                int sq = FERMAT_WIN - z; \
                for (int _s = 0; _s < sq; _s++) \
                    MONTFN(res, res, res, n, ninv, nlimbs); \
                MONTFN(res, res, win[(w >> z) >> 1], n, ninv, nlimbs); \
                for (int _s = 0; _s < z; _s++) \
                    MONTFN(res, res, res, n, ninv, nlimbs); \
                bit -= FERMAT_WIN; \
            } \
        } \
    } \
    /* Convert res from Montgomery form to standard form. \
       MONTMUL(res, 1) = res * R^{-1} mod n => standard integer value. */ \
    uint64_t one[FERMAT_CPU_MAX_LIMBS]; \
    memset(one, 0, (size_t)nlimbs * sizeof(uint64_t)); \
    one[0] = 1; \
    MONTFN(res, res, one, n, ninv, nlimbs); \
    /* Accept iff res == 1 (result 1) */ \
    if (res[0] == 1) { \
        int ok = 1; \
        for (int _i = 1; _i < nlimbs; _i++) if (res[_i] != 0) { ok = 0; break; } \
        if (ok) return 1; \
    } \
    /* Accept iff res == n-1 (result -1) */ \
    uint64_t nm1[FERMAT_CPU_MAX_LIMBS]; \
    uint64_t one_std[FERMAT_CPU_MAX_LIMBS]; \
    memset(one_std, 0, (size_t)nlimbs * sizeof(uint64_t)); \
    one_std[0] = 1; \
    cpu_sub_n(nm1, n, one_std, nlimbs); \
    int eq_nm1 = 1; \
    for (int _i = 0; _i < nlimbs; _i++) if (res[_i] != nm1[_i]) { eq_nm1 = 0; break; } \
    return eq_nm1; \
}

DECL_EULER_CORE_BUCKET(euler_test_cpu_core_b4,  cpu_montmul_b4)
DECL_EULER_CORE_BUCKET(euler_test_cpu_core_b8,  cpu_montmul_b8)
DECL_EULER_CORE_BUCKET(euler_test_cpu_core_b12, cpu_montmul_b12)
DECL_EULER_CORE_BUCKET(euler_test_cpu_core_b20, cpu_montmul_b20)

#define DECL_EULER_FIXED_BUCKET(NL, CORE) \
    static inline int euler_test_cpu_nlimbs_##NL(const uint64_t *n) { \
        return CORE(n, (NL)); \
    }

DECL_EULER_FIXED_BUCKET(2,  euler_test_cpu_core_b4)
DECL_EULER_FIXED_BUCKET(3,  euler_test_cpu_core_b4)
DECL_EULER_FIXED_BUCKET(4,  euler_test_cpu_core_b4)
DECL_EULER_FIXED_BUCKET(5,  euler_test_cpu_core_b8)
DECL_EULER_FIXED_BUCKET(6,  euler_test_cpu_core_b8)
DECL_EULER_FIXED_BUCKET(7,  euler_test_cpu_core_b8)
DECL_EULER_FIXED_BUCKET(8,  euler_test_cpu_core_b8)
DECL_EULER_FIXED_BUCKET(9,  euler_test_cpu_core_b12)
DECL_EULER_FIXED_BUCKET(10, euler_test_cpu_core_b12)
DECL_EULER_FIXED_BUCKET(11, euler_test_cpu_core_b12)
DECL_EULER_FIXED_BUCKET(12, euler_test_cpu_core_b12)
DECL_EULER_FIXED_BUCKET(13, euler_test_cpu_core_b20)
DECL_EULER_FIXED_BUCKET(14, euler_test_cpu_core_b20)
DECL_EULER_FIXED_BUCKET(15, euler_test_cpu_core_b20)
DECL_EULER_FIXED_BUCKET(16, euler_test_cpu_core_b20)
DECL_EULER_FIXED_BUCKET(17, euler_test_cpu_core_b20)
DECL_EULER_FIXED_BUCKET(18, euler_test_cpu_core_b20)
DECL_EULER_FIXED_BUCKET(19, euler_test_cpu_core_b20)
DECL_EULER_FIXED_BUCKET(20, euler_test_cpu_core_b20)

int euler_test_cpu_nlimbs(const uint64_t *n, int nlimbs)
{
    switch (nlimbs) {
    case 1:  return euler_u64(n[0]);
    case 2:  return euler_test_cpu_nlimbs_2(n);
    case 3:  return euler_test_cpu_nlimbs_3(n);
    case 4:  return euler_test_cpu_nlimbs_4(n);
    case 5:  return euler_test_cpu_nlimbs_5(n);
    case 6:  return euler_test_cpu_nlimbs_6(n);
    case 7:  return euler_test_cpu_nlimbs_7(n);
    case 8:  return euler_test_cpu_nlimbs_8(n);
    case 9:  return euler_test_cpu_nlimbs_9(n);
    case 10: return euler_test_cpu_nlimbs_10(n);
    case 11: return euler_test_cpu_nlimbs_11(n);
    case 12: return euler_test_cpu_nlimbs_12(n);
    case 13: return euler_test_cpu_nlimbs_13(n);
    case 14: return euler_test_cpu_nlimbs_14(n);
    case 15: return euler_test_cpu_nlimbs_15(n);
    case 16: return euler_test_cpu_nlimbs_16(n);
    case 17: return euler_test_cpu_nlimbs_17(n);
    case 18: return euler_test_cpu_nlimbs_18(n);
    case 19: return euler_test_cpu_nlimbs_19(n);
    case 20: return euler_test_cpu_nlimbs_20(n);
    default: return 0;
    }
}
