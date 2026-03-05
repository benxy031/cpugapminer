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
#include <pthread.h>
#include <cuda_runtime.h>

#define NL GPU_NLIMBS   /* shorthand for loop bounds */

/* ═══════════════════════════════════════════════════════════════════
 *  Device helpers: 384-bit unsigned integer arithmetic
 * ═══════════════════════════════════════════════════════════════════ */

/* Multiply-accumulate: *acc += a × b + carry_in.  Returns carry out.
   Uses __umul64hi intrinsic for the upper 64 bits of 64×64 multiply. */
__device__ static __forceinline__
uint64_t mac(uint64_t *acc, uint64_t a, uint64_t b, uint64_t carry)
{
    uint64_t lo = a * b;
    uint64_t hi = __umul64hi(a, b);
    /* lo += carry */
    lo += carry;
    hi += (lo < carry);
    /* *acc += lo */
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
   Computed by 64×AL modular doublings of 1. */
template<int AL>
__device__ static
void compute_rmodn_t(uint64_t *r, const uint64_t *n)
{
    for (int i = 0; i < AL; i++) r[i] = 0;
    r[0] = 1;
    #pragma unroll 1
    for (int i = 0; i < 64 * AL; i++)
        moddbl_t<AL>(r, n);
}

/* Montgomery multiplication:  r = a · b · R⁻¹ mod n
   CIOS (Coarsely Integrated Operand Scanning) form.
   Requires n odd, 0 ≤ a,b < n < R. */
template<int AL>
__device__ static
void montmul_t(uint64_t *      __restrict__ r,
               const uint64_t * __restrict__ a,
               const uint64_t * __restrict__ b,
               const uint64_t * __restrict__ n,
               uint64_t ninv)
{
    uint64_t t[AL + 2];
    for (int i = 0; i < AL + 2; i++) t[i] = 0;

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

        for (int j = 0; j < AL + 1; j++)
            t[j] = t[j + 1];
        t[AL + 1] = 0;
    }

    if (t[AL] || gte_t<AL>(t, n))
        sub_t<AL>(r, t, n);
    else
        for (int i = 0; i < AL; i++) r[i] = t[i];
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
    const uint64_t *src = &cands[(size_t)idx * NL];
    for (int i = 0; i < AL; i++) n[i] = src[i];

    if ((n[0] & 1) == 0) { results[idx] = 0; return; }

    uint64_t ninv = compute_ninv(n[0]);

    uint64_t one_m[AL];
    compute_rmodn_t<AL>(one_m, n);

    uint64_t base_m[AL];
    for (int i = 0; i < AL; i++) base_m[i] = one_m[i];
    moddbl_t<AL>(base_m, n);

    uint64_t e[AL];
    for (int i = 0; i < AL; i++) e[i] = n[i];
    e[0] -= 1;

    int top = AL - 1;
    while (top > 0 && e[top] == 0) top--;
    int msb = 63 - __clzll(e[top]);

    uint64_t res[AL];
    for (int i = 0; i < AL; i++) res[i] = base_m[i];

    for (int limb = top; limb >= 0; limb--) {
        int start = (limb == top) ? msb - 1 : 63;
        for (int bit = start; bit >= 0; bit--) {
            montmul_t<AL>(res, res, res, n, ninv);
            if ((e[limb] >> bit) & 1)
                montmul_t<AL>(res, res, base_m, n, ninv);
        }
    }

    uint64_t one[AL];
    for (int i = 0; i < AL; i++) one[i] = 0;
    one[0] = 1;
    montmul_t<AL>(res, res, one, n, ninv);

    int ok = (res[0] == 1);
    for (int i = 1; i < AL; i++)
        ok &= (res[i] == 0);

    results[idx] = ok ? 1 : 0;
}

/* ── Kernel dispatch: launch the narrowest specialization that fits ──
   Candidates are stored with NL limbs each, but the kernel only
   operates on AL limbs.  Speedup ≈ (NL/AL)² from Montgomery mul.

   Specializations: 5, 6, 8, 10, 12, 16 (and 20 if NL ≥ 20).
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

static cudaError_t launch_fermat(int al, cudaStream_t stream,
                                 const uint64_t *d_cands, uint8_t *d_results,
                                 uint32_t count)
{
    int block = fermat_block_size_for_al(al);
    int grid  = (int)((count + block - 1) / block);

#define FERMAT_DISPATCH(W) \
    fermat_kernel_t<W><<<grid, block, 0, stream>>>(d_cands, d_results, count); \
    return cudaPeekAtLastError()

#if NL >= 5
    if (al <= 5)  { FERMAT_DISPATCH(5);  }
#endif
#if NL >= 6
    if (al <= 6)  { FERMAT_DISPATCH(6);  }
#endif
#if NL >= 8
    if (al <= 8)  { FERMAT_DISPATCH(8);  }
#endif
#if NL >= 10
    if (al <= 10) { FERMAT_DISPATCH(10); }
#endif
#if NL >= 12
    if (al <= 12) { FERMAT_DISPATCH(12); }
#endif
#if NL >= 16
    if (al <= 16) { FERMAT_DISPATCH(16); }
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
    }

    return ctx;

fail:
    gpu_fermat_destroy(ctx);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Async double-buffered pipeline
 * ═══════════════════════════════════════════════════════════════════ */

int gpu_fermat_submit(gpu_fermat_ctx *ctx, int slot,
                      const uint64_t *candidates, size_t count)
{
    if (!ctx || !candidates || count == 0) return -1;
    if (slot < 0 || slot > 1) return -1;
    if (count > ctx->max_batch) count = ctx->max_batch;

    pthread_mutex_lock(&ctx->slot_mu[slot]);
    if (ctx->pending[slot] != 0) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1; /* slot busy: caller must collect first */
    }

    cudaError_t err = ensure_device(ctx->device_id);
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }

    int active_limbs = __atomic_load_n(&ctx->active_limbs, __ATOMIC_RELAXED);

    /* Copy candidates into pinned staging buffer.
       After this memcpy the caller's buffer can be reused. */
    memcpy(ctx->h_cands[slot], candidates,
           count * NL * sizeof(uint64_t));

    /* Async H→D on stream[slot] */
    err = cudaMemcpyAsync(ctx->d_cands[slot], ctx->h_cands[slot],
                          count * NL * sizeof(uint64_t),
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
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }

    /* Wait for all operations on this stream */
    err = cudaStreamSynchronize(ctx->stream[slot]);
    if (err != cudaSuccess) { pthread_mutex_unlock(&ctx->slot_mu[slot]); return -1; }

    /* Results are already in pinned host buffer — copy to user */
    memcpy(results, ctx->h_results[slot], n);

    int primes = 0;
    for (size_t i = 0; i < n; i++)
        primes += results[i];

    ctx->pending[slot] = 0;
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
            pthread_mutex_destroy(&ctx->slot_mu[s]);
        }
    }
    free(ctx);
}
