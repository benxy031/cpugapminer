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
   Pure C — nvcc generates correct mul.lo/mul.hi/add/adc for sm_86. */
__device__ static __forceinline__
uint64_t mac(uint64_t *acc, uint64_t a, uint64_t b, uint64_t carry)
{
    uint64_t lo = a * b;
    uint64_t hi = __umul64hi(a, b);
    lo += carry;
    hi += (lo < carry);
    uint64_t prev = *acc;
    *acc = prev + lo;
    hi += (*acc < prev);
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
   Fast top-down computation: start from the highest bit of R (bit 64*AL)
   and reduce downward.  Since R = 2^(64*AL) has exactly one bit set,
   we scan from bit (64*AL-1) down to 0, doubling r each step.
   We begin with r = 2^topbit mod n where topbit = highest bit of n,
   so r = 2^topbit - n (since 2^topbit >= n > 2^(topbit-1)).
   Then we double r for each remaining bit position, taking mod n
   at each step.  Total: (64*AL - topbit) doublings instead of 64*AL.
   For 976-bit candidates in 1024-bit R, this saves ~48 doublings (~5%). */
template<int AL>
__device__ static __forceinline__
void compute_rmodn_t(uint64_t *r, const uint64_t *n)
{
    /* Find topbit = floor(log2(n)). */
    int top_limb = AL - 1;
    while (top_limb > 0 && n[top_limb] == 0) top_limb--;
    int top_bit_in_limb = 63 - __clzll(n[top_limb]);
    int topbit = top_limb * 64 + top_bit_in_limb;

    /* r = 2^topbit - n  (this is R' mod n where R' = 2^topbit; since
       2^topbit >= n but 2^topbit < 2*n, R' mod n = 2^topbit - n). */
    /* Compute 2^topbit */
    for (int i = 0; i < AL; i++) r[i] = 0;
    r[top_limb] = 1ULL << top_bit_in_limb;
    /* r = 2^topbit - n */
    sub_t<AL>(r, r, n);

    /* Double r for each remaining bit from topbit+1 to 64*AL-1.
       After this loop, r = 2^(64*AL) mod n = R mod n. */
    int remaining = 64 * AL - 1 - topbit;
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
    montmul_t<AL>(tmp, base_m, base_m, n, ninv);        /* tmp    = base^2  */
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
    for (int i = 0; i < AL; i++) n[i] = src[i];

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
       E.g. shift=384 (AL=10): win[80]→win[40] saves 320 bytes/thread.  */
    uint64_t res[AL];
    if constexpr (AL <= 7)
        fermat_expmod<AL, 4>(res, e, msb_e, n, ninv, base_m);
    else
        fermat_expmod<AL, 3>(res, e, msb_e, n, ninv, base_m);

    int ok = (res[0] == 1);
    for (int i = 1; i < AL; i++)
        ok &= (res[i] == 0);

    results[idx] = ok ? 1 : 0;
}

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

static cudaError_t launch_fermat(int al, cudaStream_t stream,
                                 const uint64_t *d_cands, uint8_t *d_results,
                                 uint32_t count)
{
#define FERMAT_DISPATCH(W) \
    do { \
        int block = fermat_block_size_for_kernel<W>(); \
        int grid  = (int)((count + (uint32_t)block - 1u) / (uint32_t)block); \
        fermat_kernel_t<W><<<grid, block, 0, stream>>>(d_cands, d_results, count); \
    } while (0); \
    return cudaPeekAtLastError()

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
    uint8_t  *d_results[2];    /* device result buffers     */
    uint64_t *h_cands[2];      /* pinned host staging cands */
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

    /* Query device name */
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device_id) == cudaSuccess)
        strncpy(ctx->dev_name, prop.name, sizeof(ctx->dev_name) - 1);

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
    /* Use compact stride: callers now pack candidates at active_limbs
       width instead of full NL.  This cuts CPU build time, memcpy, and
       H2D transfer by NL/AL (e.g. 2.67× at shift=128). */
    int stride = active_limbs;
    size_t bytes = count * (size_t)stride * sizeof(uint64_t);

    /* Copy candidates into pinned staging buffer.
       After this memcpy the caller's buffer can be reused. */
    memcpy(ctx->h_cands[slot], candidates, bytes);

    /* Async H→D on stream[slot] */
    err = cudaMemcpyAsync(ctx->d_cands[slot], ctx->h_cands[slot],
                          bytes,
                          cudaMemcpyHostToDevice, ctx->stream[slot]);
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }

    /* Launch kernel — dispatch to narrowest matching specialization */
    err = launch_fermat(active_limbs, ctx->stream[slot],
                        ctx->d_cands[slot], ctx->d_results[slot],
                        (uint32_t)count);
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
        if (ctx->d_results[s]) cudaFree(ctx->d_results[s]);
        if (ctx->h_cands[s])   cudaFreeHost(ctx->h_cands[s]);
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
