/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* gpu_fermat.cu — CUDA batch Fermat primality testing for Gapcoin
 *
 * Each CUDA thread tests one candidate n:
 *   1. Compute Montgomery parameters (n_inv, R mod n)
 *   2. Binary exponentiation: 2^(n-1) mod n  (in Montgomery form)
 *   3. If result == 1 → probably prime, else composite
 *
 * Arithmetic width is GPU_NLIMBS × 64 bits (little-endian).
 * Default: 16 limbs = 1024 bits → shift ≤ 768.
 * Override GPU_NLIMBS at compile time for larger shifts.
 */

#include "gpu_fermat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* On MSVC (nvcc DLL build) use CRITICAL_SECTION shim; elsewhere use winpthreads / glibc. */
#ifdef _MSC_VER
#  include "compat_win32.h"
#else
#  include <pthread.h>
#endif
#include <cuda_runtime.h>

#define NL GPU_NLIMBS   /* shorthand for loop bounds */

/* ═══════════════════════════════════════════════════════════════════
 *  Device helpers: 384-bit unsigned integer arithmetic
 * ═══════════════════════════════════════════════════════════════════ */

/* Multiply-accumulate: *acc += a × b + carry_in.  Returns carry out.
   Uses PTX add.cc.u64 / addc.u64 carry chains on all CUDA architectures
   (sm_20+) — saves ~4 instructions vs the C setp+selp path per call.
   "+&l" early-clobber prevents nvcc from aliasing *acc's register with
   'lo' or 'carry' inputs.
   sm>=700 (Volta+): nvcc correctly respects the "+&l" early-clobber
   and never aliases the carry input register with the acc read-write
   register, so PTX add.cc/addc carry chains give correct results.
   sm<700 (Pascal/Maxwell/Kepler): nvcc WITHOUT "+&" CAN alias the
   carry input with the acc register, producing "add.cc acc,acc,acc"
   (doubling) instead of "add.cc acc,acc,carry" — confirmed in the
   generated PTX for sm_61.  Use the C fallback on these arches;
   the compiler lowers it to integer arithmetic that is always correct. */
__device__ static __forceinline__
uint64_t mac(uint64_t *acc, uint64_t a, uint64_t b, uint64_t carry)
{
    uint64_t lo = a * b;
    uint64_t hi = __umul64hi(a, b);
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ >= 700
    /* Volta+ (sm_70+): "+&l" early-clobber accepted; no aliasing. */
    asm volatile(
        "add.cc.u64  %0, %0, %2;\n\t"   /* acc += lo,     CF1          */
        "addc.u64    %1, %1,  0;\n\t"   /* hi  += CF1                  */
        "add.cc.u64  %0, %0, %3;\n\t"   /* acc += carry,  CF2          */
        "addc.u64    %1, %1,  0;"       /* hi  += CF2  (carry-out)     */
        : "+&l"(*acc), "+&l"(hi)
        : "l"(lo), "l"(carry)
    );
#else
    /* sm<700 or host: plain C — correct and avoids ptxas aliasing bug. */
    uint64_t sum = *acc + lo;
    uint64_t c1  = (sum < lo);
    *acc = sum + carry;
    uint64_t c2  = (*acc < carry);
    hi += c1 + c2;
#endif
    return hi;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Templated device helpers: AL-limb unsigned integer arithmetic
 *
 *  AL = "arithmetic limbs" — the actual number of 64-bit words needed
 *  for the candidate.  At shift 43, candidates are ~299 bits → AL=5.
 *  At shift 512, candidates are ~768 bits → AL=12.
 *
 *  Montgomery multiplication is O(AL²), so using AL=5 instead of
 *  NL=16 gives (16/5)² ≈ 10× speedup.  The compiler fully unrolls
 *  inner loops for each template instantiation, optimizing register
 *  allocation and instruction scheduling per size.
 * ═══════════════════════════════════════════════════════════════════ */

/* a ≥ b  (AL limbs) ? */
template<int AL>
__device__ static __forceinline__
int gte_t(const uint64_t *a, const uint64_t *b)
{
    for (int i = AL - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1;  /* equal → a ≥ b */
}

/* r = a − b  (AL limbs, unsigned wrap-around) */
template<int AL>
__device__ static __forceinline__
void sub_t(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < AL; i++) {
        uint64_t ai = a[i], bi = b[i];
        uint64_t d  = ai - bi;
        uint64_t b1 = (ai < bi);
        uint64_t d2 = d - borrow;
        uint64_t b2 = (d < borrow);
        r[i]   = d2;
        borrow = b1 + b2;
    }
}

/* a = 2a mod n  (modular doubling) */
template<int AL>
__device__ static __forceinline__
void moddbl_t(uint64_t *a, const uint64_t *n)
{
    uint64_t carry = 0;
    for (int i = 0; i < AL; i++) {
        uint64_t v = a[i];
        a[i]  = (v << 1) | carry;
        carry = v >> 63;
    }
    if (carry || gte_t<AL>(a, n))
        sub_t<AL>(a, a, n);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Montgomery multiplication (templated)
 * ═══════════════════════════════════════════════════════════════════ */

/* Compute −n⁻¹ mod 2⁶⁴  (Newton's method on the lowest limb).
   Requires n odd.  Independent of limb count. */
__device__ static __forceinline__
uint64_t compute_ninv(uint64_t n0)
{
    uint64_t x = 1;
    for (int i = 0; i < 6; i++)
        x *= 2 - n0 * x;
    return ~x + 1;
}

/* r = R mod n,  where R = 2^(64×AL).
   Fast top-down computation: we start from r = 2^topbit, where topbit is
   the index of the highest set bit of n.  Because n has bit topbit set and
   n is odd, n > 2^topbit, so 2^topbit < n and is already a valid reduced
   value in [0, n).  We then double r exactly (64*AL - topbit) times (taking
   mod n at each step) to reach R = 2^(64*AL) mod n.
   Total doublings = 64*AL - topbit.  For 976-bit n in 1024-bit R this saves
   ~48 doublings (~5%) versus starting from 2^0 = 1. */
template<int AL>
__device__ static __forceinline__
void compute_rmodn_t(uint64_t *r, const uint64_t *n)
{
    /* Find topbit = floor(log2(n)). */
    int top_limb = AL - 1;
    while (top_limb > 0 && n[top_limb] == 0) top_limb--;
    int top_bit_in_limb = 63 - __clzll(n[top_limb]);
    int topbit = top_limb * 64 + top_bit_in_limb;

    /* r = 2^topbit.  Because topbit is the MSB position of n,
       we have 2^topbit < n (n has bit topbit set plus at least the
       odd low bit), so r is already a valid reduced value in [0,n).
       Do NOT subtract n here — that would underflow and corrupt r.
       Double r (64*AL - topbit) times to reach 2^(64*AL) mod n = R mod n. */
    for (int i = 0; i < AL; i++) r[i] = 0;
    r[top_limb] = 1ULL << top_bit_in_limb;

    int remaining = 64 * AL - topbit;
    #pragma unroll 1
    for (int i = 0; i < remaining; i++)
        moddbl_t<AL>(r, n);
}

/* Montgomery multiplication:  r = a · b · R⁻¹ mod n
   CIOS (Coarsely Integrated Operand Scanning) form.
   Requires n odd, 0 ≤ a,b < n < R. */
template<int AL>
__device__ static __forceinline__
void montmul_t(uint64_t *      __restrict__ r,
               const uint64_t * __restrict__ a,
               const uint64_t * __restrict__ b,
               const uint64_t * __restrict__ n,
               uint64_t ninv)
{
    uint64_t tbuf[2 * AL + 4];
    for (int i = 0; i < 2 * AL + 4; i++) tbuf[i] = 0;
    uint64_t *t = tbuf;

    for (int i = 0; i < AL; i++) {
        uint64_t c = 0;
        for (int j = 0; j < AL; j++)
            c = mac(&t[j], a[i], b[j], c);
        uint64_t old = t[AL];
        t[AL] += c;
        t[AL + 1] += (t[AL] < old);

        uint64_t m = t[0] * ninv;
        c = 0;
        for (int j = 0; j < AL; j++)
            c = mac(&t[j], m, n[j], c);
        old = t[AL];
        t[AL] += c;
        t[AL + 1] += (t[AL] < old);

        /* Logical left-shift by one limb without AL+1 copies. */
        t++;
        t[AL + 1] = 0;
    }

    if (t[AL] || gte_t<AL>(t, n))
        sub_t<AL>(r, t, n);
    else
        for (int i = 0; i < AL; i++) r[i] = t[i];
}

/* ═══════════════════════════════════════════════════════════════════
 *  Montgomery squaring: r = a² · R⁻¹ mod n  (SOS shortcut)
 *
 *  Uses Separated Operand Scanning to skip duplicate cross-products.
 *  Saves AL(AL-1)/2 mac() calls vs montmul_t(r,a,a,...):
 *    AL=5:  10 saved  (~13%)    AL=8:  28 saved  (~22%)
 *    AL=10: 45 saved  (~23%)    AL=12: 66 saved  (~25%)
 *
 *  Algorithm (4 phases):
 *    1. Upper-triangle: tbuf[i+j] += a[i]*a[j] for i < j
 *    2. Double tbuf (each off-diagonal product appears twice in a²)
 *    3. Diagonal: tbuf[2i] += a[i]²  (only AL products vs AL² total)
 *    4. CIOS reduction: identical to montmul_t's reduction pass
 *
 *  Invariant: a < n < R → a² < n² < R·n → CIOS reduction stays in [0,2n).
 *  Phase 4 uses absolute indexing (no t++ trick) to avoid clobbering
 *  carry words set by Phase 3.
 * ═══════════════════════════════════════════════════════════════════
 * NOTE (GPU): montsqr_t is verified correct (passes 116/116 tests) but
 * is NOT called from fermat_expmod.  On GPU, the 2*AL intermediate
 * buffer (tbuf[2*AL+4]) is accessed in a scattered pattern across all
 * 4 phases, which forces the compiler to spill it to local memory
 * (LMEM), incurring ~30× end-to-end throughput regression vs
 * montmul_t(r,a,a,...).  montmul_t uses a sliding-window t++ trick
 * that keeps only AL+2 live values at a time, fits in registers with
 * zero spill, and the L1-cached sequential access pattern dominates.
 * A future CIOS-style squaring that preserves the sliding window would
 * be needed to regain the arithmetic savings on GPU.
 * ═══════════════════════════════════════════════════════════════════ */
template<int AL>
__device__ static __forceinline__
void montsqr_t(uint64_t * __restrict__ r,
               const uint64_t * __restrict__ a,
               const uint64_t * __restrict__ n,
               uint64_t ninv)
{
    uint64_t tbuf[2 * AL + 4];
    for (int i = 0; i < 2 * AL + 4; i++) tbuf[i] = 0;

    /* Phase 1: upper-triangle cross-products.
       Row i accumulates a[i]·a[j] (j > i) into tbuf[i+j], carry → tbuf[i+AL]. */
    for (int i = 0; i < AL - 1; i++) {
        uint64_t c = 0;
        for (int j = i + 1; j < AL; j++)
            c = mac(&tbuf[i + j], a[i], a[j], c);
        uint64_t old = tbuf[i + AL];
        tbuf[i + AL] += c;
        tbuf[i + AL + 1] += (tbuf[i + AL] < old);
    }

    /* Phase 2: double the accumulator (each cross-product a[i]·a[j]
       appears once; doubling accounts for the symmetric a[j]·a[i] term). */
    uint64_t carry = 0;
    #pragma unroll
    for (int i = 0; i < 2 * AL; i++) {
        uint64_t v = tbuf[i];
        tbuf[i] = (v << 1) | carry;
        carry = v >> 63;
    }
    tbuf[2 * AL] += carry;   /* at most 1; a²<R·n guarantees no further overflow */

    /* Phase 3: add diagonal a[i]² at positions (2i, 2i+1).
       mac(&tbuf[2i], a[i], a[i], 0) returns hi(a[i]²) + carry_from_add.
       3-level carry propagation mirrors primality_utils.c SOS squaring. */
    for (int i = 0; i < AL; i++) {
        uint64_t c1 = mac(&tbuf[2 * i], a[i], a[i], 0);
        uint64_t old = tbuf[2 * i + 1];
        tbuf[2 * i + 1] += c1;
        if (tbuf[2 * i + 1] < old) {          /* carry into 2i+2 */
            if (++tbuf[2 * i + 2] == 0)        /* carry into 2i+3 */
                tbuf[2 * i + 3]++;             /* (very rare; terminates here) */
        }
    }

    /* Phase 4: CIOS reduction using absolute indexing (no t++ / zeroing trick,
       which would clobber Phase-3 carry words in the upper half of tbuf). */
    for (int i = 0; i < AL; i++) {
        uint64_t m = tbuf[i] * ninv;
        uint64_t c = 0;
        for (int j = 0; j < AL; j++)
            c = mac(&tbuf[i + j], m, n[j], c);
        uint64_t old = tbuf[i + AL];
        tbuf[i + AL] += c;
        tbuf[i + AL + 1] += (tbuf[i + AL] < old);
    }

    /* Result is at tbuf[AL..2*AL-1]; overflow word at tbuf[2*AL]. */
    uint64_t *t = &tbuf[AL];
    if (tbuf[2 * AL] || gte_t<AL>(t, n))
        sub_t<AL>(r, t, n);
    else
        for (int i = 0; i < AL; i++) r[i] = t[i];
}

/* ═══════════════════════════════════════════════════════════════════
 *  Sliding-window modular exponentiation: res = base^(n-1) mod n
 *
 *  WIN_BITS selects the precomputed table size vs squaring trade-off:
 *    WIN_BITS=4  →  8 odd powers  (win[8*AL]) — low AL, low reg pressure
 *    WIN_BITS=3  →  4 odd powers  (win[4*AL]) — high AL, avoids spilling
 *                   the win[] table to GPU local memory (e.g. at AL=10
 *                   this saves 40 uint64 = 320 bytes per thread).
 *
 *  __forceinline__ is critical: it lets the compiler see all montmul
 *  calls together and keep every intermediate value in registers across
 *  the full exponentiation rather than spilling at call boundaries.
 * ═══════════════════════════════════════════════════════════════════ */
template<int AL, int WIN_BITS>
__device__ static __forceinline__
void fermat_expmod(uint64_t * __restrict__ res,
                   const uint64_t * __restrict__ e,
                   int msb_e,
                   const uint64_t * __restrict__ n,
                   uint64_t ninv,
                   const uint64_t * __restrict__ base_m)
{
    constexpr int WIN_SIZE = 1 << (WIN_BITS - 1);    /* 4-bit→8, 3-bit→4 */
    constexpr uint32_t WIN_MASK = (1u << WIN_BITS) - 1u;

    /* Precompute odd Montgomery powers: win[k] = base_m^(2k+1) */
    uint64_t win[WIN_SIZE * AL];
    uint64_t tmp[AL];
    for (int i = 0; i < AL; i++) win[i] = base_m[i];   /* win[0] = base^1 */
    montmul_t<AL>(tmp, base_m, base_m, n, ninv);         /* tmp    = base^2  */
    for (int k = 1; k < WIN_SIZE; k++)
        montmul_t<AL>(&win[k * AL], &win[(k-1) * AL], tmp, n, ninv);

    /* Seed result with the leading 1-bit: res = base_m */
    for (int i = 0; i < AL; i++) res[i] = base_m[i];

    /* Left-to-right WIN_BITS-bit sliding-window scan */
    int bit = msb_e - 1;
    while (bit >= 0) {
        if (bit < WIN_BITS - 1) {
            /* Tail: fewer than WIN_BITS bits remain — binary sq-and-mul */
            montmul_t<AL>(res, res, res, n, ninv);
            if ((e[bit >> 6] >> (bit & 63)) & 1)
                montmul_t<AL>(res, res, base_m, n, ninv);
            bit--;
        } else {
            /* Extract WIN_BITS-bit window: bits [bit-(WIN_BITS-1) .. bit] */
            int lo  = bit - (WIN_BITS - 1);
            int lm  = lo >> 6;
            int off = lo & 63;
            uint32_t w = (uint32_t)(e[lm] >> off) & WIN_MASK;
            if (off > 64 - WIN_BITS && lm + 1 < AL)
                w |= (uint32_t)(e[lm + 1] << (64 - off)) & WIN_MASK;
            if (w == 0) {
                for (int s = 0; s < WIN_BITS; s++)
                    montmul_t<AL>(res, res, res, n, ninv);
            } else {
                int z  = __ffs((int)w) - 1;   /* trailing zeros of w */
                int sq = WIN_BITS - z;
                for (int s = 0; s < sq; s++)
                    montmul_t<AL>(res, res, res, n, ninv);
                montmul_t<AL>(res, res, &win[((w >> z) >> 1) * AL], n, ninv);
                for (int s = 0; s < z; s++)
                    montmul_t<AL>(res, res, res, n, ninv);
            }
            bit -= WIN_BITS;
        }
    }

    /* from_mont: res = res · R⁻¹ mod n  (multiply by 1 in Montgomery) */
    for (int i = 0; i < AL; i++) tmp[i] = 0;
    tmp[0] = 1;
    montmul_t<AL>(res, res, tmp, n, ninv);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Templated Fermat test kernel
 *  AL = arithmetic width (limbs actually used).
 *  Storage width per candidate is compile-time NL (= GPU_NLIMBS).
 * ═══════════════════════════════════════════════════════════════════ */

template<int AL>
__global__ void fermat_kernel_t(const uint64_t * __restrict__ cands,
                                uint8_t        * __restrict__ results,
                                uint32_t count)
{
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint64_t n[AL];
    const uint64_t *src = &cands[(size_t)idx * (size_t)AL];
    /* __ldg() routes through the read-only cache (texture path), which is
       independent of L1 and improves bandwidth when many threads access
       different candidates (non-coalesced or scattered global reads). */
    for (int i = 0; i < AL; i++) n[i] = __ldg(&src[i]);

    if ((n[0] & 1) == 0) { results[idx] = 0; return; }

    uint64_t ninv = compute_ninv(n[0]);

    uint64_t base_m[AL];
    compute_rmodn_t<AL>(base_m, n);
    moddbl_t<AL>(base_m, n);

    int top = AL - 1;
    while (top > 0 && n[top] == 0) top--;

    /* Exponent e = n-1  (n is odd, so e[0] = n[0]-1, no borrow) */
    uint64_t e[AL];
    for (int i = 0; i < AL; i++) e[i] = n[i];
    e[0]--;
    int msb_e = top * 64 + (63 - __clzll(e[top]));

    /* Adaptive window: 4-bit for AL≤7 (≤448-bit, low register pressure),
       3-bit for AL≥8 (≥512-bit) — halves the precomputed table from
       8×AL to 4×AL entries, keeping win[] in registers not local memory.
       E.g. shift=384 (AL=10): win[80]→win[40] saves 320 bytes/thread.
       On sm<700 (Pascal and earlier, 2 warp schedulers, 65536 regs/SM),
       register pressure is more critical: always use WIN_BITS=3 to reduce
       the win[] table from 8×AL to 4×AL across all AL values.  This
       typically raises occupancy by ~1.5× at AL=6–7 on sm_61. */
    uint64_t res[AL];
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ < 700
    fermat_expmod<AL, 3>(res, e, msb_e, n, ninv, base_m);
#else
    if constexpr (AL <= 7)
        fermat_expmod<AL, 4>(res, e, msb_e, n, ninv, base_m);
    else
        fermat_expmod<AL, 3>(res, e, msb_e, n, ninv, base_m);
#endif

    int ok = (res[0] == 1);
    for (int i = 1; i < AL; i++)
        ok &= (res[i] == 0);

    results[idx] = ok ? 1 : 0;
}

/* SoA-specialized scalar kernel for generic AL.
   Layout: cands_soa[(limb * count) + idx]. */
template<int AL>
__global__ void fermat_kernel_soa_t(const uint64_t * __restrict__ cands_soa,
                                    uint8_t        * __restrict__ results,
                                    uint32_t count)
{
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint64_t n[AL];
    for (int i = 0; i < AL; i++)
        n[i] = __ldg(&cands_soa[(size_t)i * (size_t)count + idx]);

    if ((n[0] & 1) == 0) { results[idx] = 0; return; }

    uint64_t ninv = compute_ninv(n[0]);

    uint64_t base_m[AL];
    compute_rmodn_t<AL>(base_m, n);
    moddbl_t<AL>(base_m, n);

    int top = AL - 1;
    while (top > 0 && n[top] == 0) top--;

    uint64_t e[AL];
    for (int i = 0; i < AL; i++) e[i] = n[i];
    e[0]--;
    int msb_e = top * 64 + (63 - __clzll(e[top]));

    uint64_t res[AL];
#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ < 700
    fermat_expmod<AL, 3>(res, e, msb_e, n, ninv, base_m);
#else
    if constexpr (AL <= 7)
        fermat_expmod<AL, 4>(res, e, msb_e, n, ninv, base_m);
    else
        fermat_expmod<AL, 3>(res, e, msb_e, n, ninv, base_m);
#endif

    int ok = (res[0] == 1);
    for (int i = 1; i < AL; i++)
        ok &= (res[i] == 0);

    results[idx] = ok ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  CGBN-based Fermat kernel: template<BITS, TPI> covers all even AL.
 *
 *  Enabled with: make WITH_CGBN_FERMAT=1 ...
 *
 *  TPI selection per AL (largest power-of-2 dividing 2×AL, capped at 8):
 *    AL%4==0  →  TPI=8  (256/512/768/1024/… bit)
 *    AL%2==0  →  TPI=4  (384/640/896/… bit)
 *    AL odd   →  no CGBN, scalar fermat_kernel_t fallback.
 *
 *  Correctness fix baked in: CGBN fwmont_mul uses lazy reduction —
 *  mont_sqr can return r ∈ [N, 2N).  Explicit reduce after every
 *  squaring brings r into [0, N) before the add+cond-sub double.
 * ═══════════════════════════════════════════════════════════════════ */
#if defined(WITH_CGBN_FERMAT)
/* cgbn.h checks __CUDA_ARCH__ (not __CUDACC__) for its device path;
   the host-compilation phase of nvcc falls through to cgbn_cpu.h (#error)
   unless __GMP_H__ is defined first.  Including gmp.h routes it to
   cgbn_mpz.h instead, which provides cgbn_mem_t<BITS> for host code. */
#include <gmp.h>
#include "cgbn/cgbn.h"

/* Params struct parameterised on TPI; everything else fixed. */
template<uint32_t TPI_VAL>
struct CgbnFermatParams {
    static const uint32_t TPB           = 128;   /* threads/block       */
    static const uint32_t MAX_ROTATION  = 4;
    static const uint32_t SHM_LIMIT     = 0;
    static const bool     CONSTANT_TIME = false;
    static const uint32_t TPI           = TPI_VAL;
};

/* Single kernel template: instantiated for each (BITS, TPI) pair.
   uint64_t[BITS/64] and cgbn_mem_t<BITS> share the same little-endian
   uint32_t layout, so reinterpret_cast between them is safe.           */
template<uint32_t BITS, uint32_t TPI_VAL>
__global__ static
void cgbn_fermat_kernel_t(cgbn_mem_t<BITS> *cands,
                          uint8_t * __restrict__ results,
                          uint32_t n)
{
    int32_t id = (int32_t)((blockIdx.x * blockDim.x + threadIdx.x) / TPI_VAL);
    if ((uint32_t)id >= n) return;

    typedef cgbn_context_t<TPI_VAL, CgbnFermatParams<TPI_VAL>> ctx_t;
    typedef cgbn_env_t<ctx_t, BITS>                             env_t;
    typedef typename env_t::cgbn_t                              bn_t;

    ctx_t    ctx(cgbn_no_checks);
    env_t    env(ctx);
    bn_t     N, e, r, t, base;
    uint32_t np0;
    int32_t  pos;

    cgbn_load    (env, N,    cands + id);
    cgbn_sub_ui32(env, e,    N, 1);
    cgbn_set_ui32(env, base, 2);
    np0 = cgbn_bn2mont(env, r, base, N);
    pos = (int32_t)(BITS - 1) - (int32_t)cgbn_clz(env, e) - 1;

    while (pos >= 0) {
        cgbn_mont_sqr(env, r, r, N, np0);
        /* fwmont_mul lazy-reduces to [0,2N); add+cond_sub requires [0,N). */
        if (cgbn_compare(env, r, N) >= 0)
            cgbn_sub(env, r, r, N);
        if (cgbn_extract_bits_ui32(env, e, (uint32_t)pos, 1)) {
            uint32_t carry = cgbn_add(env, t, r, r);
            if (carry || cgbn_compare(env, t, N) >= 0)
                cgbn_sub(env, r, t, N);
            else
                cgbn_set(env, r, t);
        }
        pos--;
    }
    cgbn_mont2bn(env, r, r, N, np0);
    results[id] = (uint8_t)cgbn_equals_ui32(env, r, 1);
}

#define CGBN_FERMAT_AVAILABLE 1
#endif /* WITH_CGBN_FERMAT */

/* ── Kernel dispatch: launch the narrowest specialization that fits ──
   Candidates are stored at active_limbs stride, and the kernel
   operates on AL limbs.  Speedup ≈ (NL/AL)² from Montgomery mul.

   Specializations: every integer from 5 to 20 (and NL as fallback).
   IMPORTANT: stride == active_limbs, so every possible AL value must
   have an exact dispatch entry.  A gap (e.g. AL=7 dispatching to
   template<8>) would read past each candidate into the next one's data.
   E.g. shift 43 → AL=5 → montmul does 5²=25 ops vs 16²=256.       */
static __host__ __forceinline__
int fermat_block_size_for_al(int al)
{
    /* AL-aware launch tuning hook:
       narrower arithmetic uses fewer registers/thread, so we can run
       larger blocks for better occupancy. Keep conservative defaults. */
    if (al <= 6)  return 256;
    if (al <= 10) return 192;
    return 128;
}

template<int AL>
static __host__ __forceinline__
int fermat_block_size_for_kernel()
{
    static int cached = 0;
    if (cached > 0) return cached;

    int min_grid = 0;
    int block = 0;
    cudaError_t err = cudaOccupancyMaxPotentialBlockSize(
        &min_grid, &block, fermat_kernel_t<AL>, 0, 0);

    if (err == cudaSuccess && block > 0) {
        /* Keep launch shape warp-aligned and conservative for heavy kernels. */
        block = (block / 32) * 32;
        if (block < 64)  block = 64;
        if (block > 256) block = 256;
        cached = block;
    } else {
        cached = fermat_block_size_for_al(AL);
    }

    return cached;
}

static __host__ __forceinline__ int cgbn_supports_al(int al)
{
#if defined(CGBN_FERMAT_AVAILABLE)
    switch (al) {
    #if NL >= 2
    case 2:
    #endif
    #if NL >= 4
    case 4:
    #endif
    #if NL >= 6
    case 6:
    #endif
    #if NL >= 8
    case 8:
    #endif
    #if NL >= 12
    case 12:
    #endif
    #if NL >= 16
    case 16:
    #endif
    #if NL >= 20
    case 20:
    #endif
        return 1;
    default:
        return 0;
    }
#else
    (void)al;
    return 0;
#endif
}

static cudaError_t launch_fermat(int al, cudaStream_t stream,
                                 const uint64_t *d_cands,
                                 const uint64_t *d_cands_soa,
                                 uint8_t *d_results,
                                 uint32_t count,
                                 int use_soa_scalar)
{
#if defined(CGBN_FERMAT_AVAILABLE)
    /* CGBN dispatch for even AL values.
       TPI=8 for AL%4==0, TPI=4 for AL%2==0 (largest power-of-2 ≤ 8 dividing 2×AL).
       Odd AL falls through to the scalar FERMAT_DISPATCH macros below.
       All template instantiations share the same kernel body; nvcc compiles
       only those actually referenced in the switch cases guarded by #if NL>=. */
    {
        static int cgbn_logged = 0;
        #define CGBN_DISP(AL_VAL, TPI_VAL) \
            case AL_VAL: { \
                const int tpb  = (int)CgbnFermatParams<TPI_VAL>::TPB; \
                const int ipb  = tpb / (int)(TPI_VAL); \
                int grid = (int)((count + (uint32_t)ipb - 1u) / (uint32_t)ipb); \
                if (!__atomic_exchange_n(&cgbn_logged, 1, __ATOMIC_RELAXED)) \
                    fprintf(stderr, "GPU Fermat: CGBN kernel active " \
                            "(AL=%d, %d-bit, TPI=%d)\n", \
                            (AL_VAL), (AL_VAL) * 64, (TPI_VAL)); \
                cgbn_fermat_kernel_t<(AL_VAL)*64u, (TPI_VAL)><<<grid, tpb, 0, stream>>>( \
                    reinterpret_cast<cgbn_mem_t<(AL_VAL)*64u>*>( \
                        const_cast<uint64_t*>(d_cands)), \
                    d_results, count); \
                return cudaPeekAtLastError(); \
            }
        switch (al) {
            /* Supported (AL, TPI) pairs — largest valid power-of-2 TPI ≤ 8
               where LIMBS = 2×AL/TPI is an integer AND LIMBS ≤ TPI
               (CGBN dlimbs_algs_multi requires LIMBS ≤ TPI):

                 AL   Bits   TPI  LIMBS
                  2    128    4    1
                  4    256    8    1
                  6    384    4    3
                  8    512    8    2
                 12    768    8    3    (default GPU_BITS=768 full width)
                 16   1024    8    4
                 20   1280    8    5

               All other AL values (1,3,5,7,9,10,11,13,14,15,17,18,19,…)
               fall through to the scalar fermat_kernel_t below.              */
            #if NL >= 2
            CGBN_DISP( 2, 4)   /* 128-bit,  LIMBS=1 */
            #endif
            #if NL >= 4
            CGBN_DISP( 4, 8)   /* 256-bit,  LIMBS=1 */
            #endif
            #if NL >= 6
            CGBN_DISP( 6, 4)   /* 384-bit,  LIMBS=3 */
            #endif
            #if NL >= 8
            CGBN_DISP( 8, 8)   /* 512-bit,  LIMBS=2 */
            #endif
            #if NL >= 12
            CGBN_DISP(12, 8)   /* 768-bit,  LIMBS=3 */
            #endif
            #if NL >= 16
            CGBN_DISP(16, 8)   /* 1024-bit, LIMBS=4 */
            #endif
            #if NL >= 20
            CGBN_DISP(20, 8)   /* 1280-bit, LIMBS=5 */
            #endif
            /* All other AL: no valid TPI → scalar fermat_kernel_t */
            default: break;
        }
        #undef CGBN_DISP
    }
#endif

#define FERMAT_DISPATCH(W) \
    do { \
        int block = fermat_block_size_for_kernel<W>(); \
        int grid  = (int)((count + (uint32_t)block - 1u) / (uint32_t)block); \
        if (use_soa_scalar) \
            fermat_kernel_soa_t<W><<<grid, block, 0, stream>>>(d_cands_soa, d_results, count); \
        else \
            fermat_kernel_t<W><<<grid, block, 0, stream>>>(d_cands, d_results, count); \
    } while (0); \
    return cudaPeekAtLastError()

/* IMPORTANT: stride == active_limbs.  Every AL value from 1 to NL must have
   an exact dispatch entry so the kernel reads exactly AL limbs per candidate.
   A gap (e.g. al=4 dispatching to template<5>) would read past the end of
   each candidate's data into the next candidate's first limb, corrupting the
   modulus and producing incorrect Fermat results. */
#if NL >= 1
    if (al <= 1)  { FERMAT_DISPATCH(1);  }
#endif
#if NL >= 2
    if (al <= 2)  { FERMAT_DISPATCH(2);  }
#endif
#if NL >= 3
    if (al <= 3)  { FERMAT_DISPATCH(3);  }
#endif
#if NL >= 4
    if (al <= 4)  { FERMAT_DISPATCH(4);  }
#endif
#if NL >= 5
    if (al <= 5)  { FERMAT_DISPATCH(5);  }
#endif
#if NL >= 6
    if (al <= 6)  { FERMAT_DISPATCH(6);  }
#endif
#if NL >= 7
    if (al <= 7)  { FERMAT_DISPATCH(7);  }
#endif
#if NL >= 8
    if (al <= 8)  { FERMAT_DISPATCH(8);  }
#endif
#if NL >= 9
    if (al <= 9)  { FERMAT_DISPATCH(9);  }
#endif
#if NL >= 10
    if (al <= 10) { FERMAT_DISPATCH(10); }
#endif
#if NL >= 11
    if (al <= 11) { FERMAT_DISPATCH(11); }
#endif
#if NL >= 12
    if (al <= 12) { FERMAT_DISPATCH(12); }
#endif
#if NL >= 13
    if (al <= 13) { FERMAT_DISPATCH(13); }
#endif
#if NL >= 14
    if (al <= 14) { FERMAT_DISPATCH(14); }
#endif
#if NL >= 15
    if (al <= 15) { FERMAT_DISPATCH(15); }
#endif
#if NL >= 16
    if (al <= 16) { FERMAT_DISPATCH(16); }
#endif
#if NL >= 17
    if (al <= 17) { FERMAT_DISPATCH(17); }
#endif
#if NL >= 18
    if (al <= 18) { FERMAT_DISPATCH(18); }
#endif
#if NL >= 19
    if (al <= 19) { FERMAT_DISPATCH(19); }
#endif
#if NL >= 20
    if (al <= 20) { FERMAT_DISPATCH(20); }
#endif
    /* Fallback: compile-time maximum */
    FERMAT_DISPATCH(NL);

#undef FERMAT_DISPATCH
}

/* ═══════════════════════════════════════════════════════════════════
 *  Host API
 * ═══════════════════════════════════════════════════════════════════ */

struct gpu_fermat_ctx {
    int       device_id;
    size_t    max_batch;
    int       active_limbs;    /* arithmetic width (≤ NL); 0 = use NL  */
    /* Double-buffered async pipeline: 2 slots for overlap */
    cudaStream_t stream[2];
    uint64_t *d_cands[2];      /* device candidate buffers  */
    uint64_t *d_cands_soa[2];  /* device SoA cands for scalar AL */
    uint8_t  *d_results[2];    /* device result buffers     */
    uint64_t *h_cands[2];      /* pinned host staging cands */
    uint64_t *h_cands_soa[2];  /* pinned host SoA scalar AL */
    uint8_t  *h_results[2];    /* pinned host staging res   */
    size_t    pending[2];      /* candidates in-flight per slot (0=idle) */
    char      dev_name[256];
    /* Per-slot mutexes avoid cross-slot contention while preserving safety. */
    pthread_mutex_t slot_mu[2];
    int       slot_mu_inited[2];

    /* Per-slot completion events and condition vars for slot reuse */
    cudaEvent_t event[2];
    int         event_inited[2];
    pthread_cond_t slot_cv[2];
    int         slot_cv_inited[2];
};

static __host__ __forceinline__ cudaError_t ensure_device(int device_id)
{
    int cur = -1;
    cudaError_t err = cudaGetDevice(&cur);
    if (err != cudaSuccess) return err;
    if (cur == device_id) return cudaSuccess;
    return cudaSetDevice(device_id);
}

gpu_fermat_ctx *gpu_fermat_init(int device_id, size_t max_batch)
{
    gpu_fermat_ctx *ctx = (gpu_fermat_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    for (int s = 0; s < 2; s++) {
        if (pthread_mutex_init(&ctx->slot_mu[s], NULL) != 0) {
            for (int i = 0; i < s; i++) {
                pthread_mutex_destroy(&ctx->slot_mu[i]);
                ctx->slot_mu_inited[i] = 0;
            }
            free(ctx);
            return NULL;
        }
        ctx->slot_mu_inited[s] = 1;
    }

    cudaError_t err = ensure_device(device_id);
    if (err != cudaSuccess) {
        fprintf(stderr, "gpu_fermat: cudaSetDevice(%d): %s\n",
                device_id, cudaGetErrorString(err));
        for (int s = 0; s < 2; s++) {
            if (ctx->slot_mu_inited[s]) {
                pthread_mutex_destroy(&ctx->slot_mu[s]);
                ctx->slot_mu_inited[s] = 0;
            }
        }
        free(ctx);
        return NULL;
    }

    /* Keep init compatible with older CUDA runtimes that may lack
       cudaGetDeviceProperties_v2 at link time. */
    (void)snprintf(ctx->dev_name, sizeof(ctx->dev_name), "cuda:%d", device_id);

    ctx->device_id = device_id;
    ctx->max_batch = max_batch;
    ctx->active_limbs = NL;   /* default: full width; call set_limbs() to narrow */

    /* Allocate double-buffered device + pinned host memory */
    for (int s = 0; s < 2; s++) {
        err = cudaStreamCreate(&ctx->stream[s]);
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaStreamCreate[%d]: %s\n",
                    s, cudaGetErrorString(err));
            goto fail;
        }

        err = cudaMalloc(&ctx->d_cands[s], max_batch * NL * sizeof(uint64_t));
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaMalloc cands[%d] (%zu B): %s\n",
                    s, max_batch * NL * 8, cudaGetErrorString(err));
            goto fail;
        }

        err = cudaMalloc(&ctx->d_results[s], max_batch);
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaMalloc results[%d]: %s\n",
                    s, cudaGetErrorString(err));
            goto fail;
        }

        err = cudaMallocHost(&ctx->h_cands[s], max_batch * NL * sizeof(uint64_t));
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaMallocHost cands[%d]: %s\n",
                    s, cudaGetErrorString(err));
            goto fail;
        }

        err = cudaMallocHost(&ctx->h_results[s], max_batch);
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaMallocHost results[%d]: %s\n",
                    s, cudaGetErrorString(err));
            goto fail;
        }

        err = cudaMalloc(&ctx->d_cands_soa[s], max_batch * NL * sizeof(uint64_t));
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaMalloc cands_soa[%d] (%zu B): %s\n",
                s, max_batch * (size_t)NL * sizeof(uint64_t), cudaGetErrorString(err));
            goto fail;
        }

        err = cudaMallocHost(&ctx->h_cands_soa[s], max_batch * NL * sizeof(uint64_t));
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaMallocHost cands_soa[%d]: %s\n",
                s, cudaGetErrorString(err));
            goto fail;
        }

        ctx->pending[s] = 0;
        ctx->event_inited[s] = 0;
        ctx->slot_cv_inited[s] = 0;

        /* Create completion event (disable timing to reduce overhead) */
        err = cudaEventCreateWithFlags(&ctx->event[s], cudaEventDisableTiming);
        if (err != cudaSuccess) {
            fprintf(stderr, "gpu_fermat: cudaEventCreate[%d]: %s\n",
                    s, cudaGetErrorString(err));
            goto fail;
        }
        ctx->event_inited[s] = 1;

        if (pthread_cond_init(&ctx->slot_cv[s], NULL) != 0) {
            fprintf(stderr, "gpu_fermat: pthread_cond_init[%d] failed\n", s);
            goto fail;
        }
        ctx->slot_cv_inited[s] = 1;
    }

    return ctx;

fail:
    gpu_fermat_destroy(ctx);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Async double-buffered pipeline
 * ═══════════════════════════════════════════════════════════════════ */

/* Non-blocking variant: returns -1 immediately if the slot is still busy.
   See header for full contract. */
int gpu_fermat_submit_try(gpu_fermat_ctx *ctx, int slot,
                          const uint64_t *candidates, size_t count)
{
    if (!ctx || !candidates || count == 0) return -1;
    if (slot < 0 || slot > 1) return -1;
    if (count > ctx->max_batch) count = ctx->max_batch;

    pthread_mutex_lock(&ctx->slot_mu[slot]);
    if (ctx->pending[slot] != 0) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;  /* slot busy — return without blocking */
    }
    pthread_mutex_unlock(&ctx->slot_mu[slot]);
    /* Slot is free; delegate to the blocking submit which will not stall. */
    return gpu_fermat_submit(ctx, slot, candidates, count);
}

int gpu_fermat_submit(gpu_fermat_ctx *ctx, int slot,
                      const uint64_t *candidates, size_t count)
{
    if (!ctx || !candidates || count == 0) return -1;
    if (slot < 0 || slot > 1) return -1;
    if (count > ctx->max_batch) count = ctx->max_batch;

    pthread_mutex_lock(&ctx->slot_mu[slot]);
        /* Block until the slot is free — collect() broadcasts slot_cv
             when it drains a slot, so this wait is bounded by GPU
       kernel latency (~5-15 ms).  Never skips candidates. */
    while (ctx->pending[slot] != 0)
        pthread_cond_wait(&ctx->slot_cv[slot], &ctx->slot_mu[slot]);

    cudaError_t err = ensure_device(ctx->device_id);
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }

    int active_limbs = __atomic_load_n(&ctx->active_limbs, __ATOMIC_RELAXED);
    int use_soa_scalar = !cgbn_supports_al(active_limbs);

    if (use_soa_scalar) {
        /* Non-CGBN AL: AoS->SoA prepack for coalesced scalar kernel loads. */
        uint64_t *dst = ctx->h_cands_soa[slot];
        const uint64_t *src = candidates;
        int stride = active_limbs;
        for (size_t i = 0; i < count; i++) {
            size_t b = i * (size_t)stride;
            for (int limb = 0; limb < stride; limb++)
                dst[(size_t)limb * count + i] = src[b + (size_t)limb];
        }

        size_t soa_bytes = count * (size_t)stride * sizeof(uint64_t);
        err = cudaMemcpyAsync(ctx->d_cands_soa[slot], ctx->h_cands_soa[slot],
                              soa_bytes,
                              cudaMemcpyHostToDevice, ctx->stream[slot]);
        if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }
    } else {
        /* Use compact stride: callers now pack candidates at active_limbs
           width instead of full NL.  This cuts CPU build time, memcpy, and
           H2D transfer by NL/AL (e.g. 2.67x at shift=128). */
        int stride = active_limbs;
        size_t bytes = count * (size_t)stride * sizeof(uint64_t);

        /* Copy candidates into pinned staging buffer.
           After this memcpy the caller's buffer can be reused. */
        memcpy(ctx->h_cands[slot], candidates, bytes);

        /* Async H->D on stream[slot] */
        err = cudaMemcpyAsync(ctx->d_cands[slot], ctx->h_cands[slot],
                              bytes,
                              cudaMemcpyHostToDevice, ctx->stream[slot]);
        if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }
    }

    /* Launch kernel — CGBN for supported AL, scalar AoS/SoA otherwise. */
    err = launch_fermat(active_limbs, ctx->stream[slot],
                        ctx->d_cands[slot], ctx->d_cands_soa[slot],
                        ctx->d_results[slot], (uint32_t)count,
                        use_soa_scalar);
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }

    /* Async D→H on stream[slot] */
    err = cudaMemcpyAsync(ctx->h_results[slot], ctx->d_results[slot],
                          count, cudaMemcpyDeviceToHost,
                          ctx->stream[slot]);
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }
    /* Record an event when the D→H copy completes. */
    err = cudaEventRecord(ctx->event[slot], ctx->stream[slot]);
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }

    ctx->pending[slot] = count;
    pthread_mutex_unlock(&ctx->slot_mu[slot]);
    return 0;
}

int gpu_fermat_collect(gpu_fermat_ctx *ctx, int slot,
                       uint8_t *results, size_t count)
{
    if (!ctx || !results) return -1;
    if (slot < 0 || slot > 1) return -1;

    pthread_mutex_lock(&ctx->slot_mu[slot]);
    if (ctx->pending[slot] == 0) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return 0;
    }

    size_t n = ctx->pending[slot];
    if (count < n) n = count;

    cudaError_t err = ensure_device(ctx->device_id);
    if (err != cudaSuccess) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }
    err = cudaEventSynchronize(ctx->event[slot]);
    if (err != cudaSuccess) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    /* Results are already in pinned host buffer — copy to user */
    memcpy(results, ctx->h_results[slot], n);

    int primes = 0;
    for (size_t i = 0; i < n; i++)
        primes += results[i];

    ctx->pending[slot] = 0;
    /* Wake any thread blocked in gpu_fermat_submit waiting for this slot. */
    pthread_cond_broadcast(&ctx->slot_cv[slot]);
    pthread_mutex_unlock(&ctx->slot_mu[slot]);
    return primes;
}

/* Synchronous wrapper (backward compatible) */
int gpu_fermat_test_batch(gpu_fermat_ctx *ctx,
                          const uint64_t *candidates,
                          uint8_t *results,
                          size_t count)
{
    if (!ctx || !candidates || !results || count == 0) return 0;
    if (count > ctx->max_batch) count = ctx->max_batch;

    if (gpu_fermat_submit(ctx, 0, candidates, count) < 0)
        return -1;
    return gpu_fermat_collect(ctx, 0, results, count);
}

const char *gpu_fermat_device_name(gpu_fermat_ctx *ctx)
{
    return ctx ? ctx->dev_name : "";
}

void gpu_fermat_set_limbs(gpu_fermat_ctx *ctx, int limbs)
{
    if (!ctx) return;
    if (limbs < 1)  limbs = NL;
    if (limbs > NL) limbs = NL;
    __atomic_store_n(&ctx->active_limbs, limbs, __ATOMIC_RELAXED);
}

int gpu_fermat_get_limbs(gpu_fermat_ctx *ctx)
{
    if (!ctx) return NL;
    int al = __atomic_load_n(&ctx->active_limbs, __ATOMIC_RELAXED);
    return (al >= 1 && al <= NL) ? al : NL;
}

void gpu_fermat_destroy(gpu_fermat_ctx *ctx)
{
    if (!ctx) return;

    for (int s = 0; s < 2; s++) {
        if (ctx->slot_mu_inited[s]) pthread_mutex_lock(&ctx->slot_mu[s]);
    }
    ensure_device(ctx->device_id);
    for (int s = 0; s < 2; s++) {
        if (ctx->pending[s] && ctx->stream[s])
            cudaStreamSynchronize(ctx->stream[s]);
        if (ctx->d_cands[s])   cudaFree(ctx->d_cands[s]);
        if (ctx->d_cands_soa[s]) cudaFree(ctx->d_cands_soa[s]);
        if (ctx->d_results[s]) cudaFree(ctx->d_results[s]);
        if (ctx->h_cands[s])   cudaFreeHost(ctx->h_cands[s]);
        if (ctx->h_cands_soa[s]) cudaFreeHost(ctx->h_cands_soa[s]);
        if (ctx->h_results[s]) cudaFreeHost(ctx->h_results[s]);
        if (ctx->stream[s])    cudaStreamDestroy(ctx->stream[s]);
    }
    for (int s = 0; s < 2; s++) {
        if (ctx->slot_mu_inited[s]) {
            pthread_mutex_unlock(&ctx->slot_mu[s]);
            if (ctx->slot_cv_inited[s]) pthread_cond_destroy(&ctx->slot_cv[s]);
            if (ctx->event_inited[s]) cudaEventDestroy(ctx->event[s]);
            pthread_mutex_destroy(&ctx->slot_mu[s]);
        }
    }
    free(ctx);
}
