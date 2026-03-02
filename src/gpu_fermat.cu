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

/* a ≥ b  (NL limbs) ? */
__device__ static __forceinline__
int gte(const uint64_t *a, const uint64_t *b)
{
    for (int i = NL - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1;  /* equal → a ≥ b */
}

/* r = a − b  (NL limbs, unsigned wrap-around) */
__device__ static __forceinline__
void sub(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < NL; i++) {
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
__device__ static __forceinline__
void moddbl(uint64_t *a, const uint64_t *n)
{
    uint64_t carry = 0;
    for (int i = 0; i < NL; i++) {
        uint64_t v = a[i];
        a[i]  = (v << 1) | carry;
        carry = v >> 63;
    }
    /* If carry or a ≥ n → subtract n (at most once since a < 2n) */
    if (carry || gte(a, n))
        sub(a, a, n);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Montgomery multiplication
 * ═══════════════════════════════════════════════════════════════════ */

/* Compute −n⁻¹ mod 2⁶⁴  (Newton's method on the lowest limb).
   Requires n odd. */
__device__ static __forceinline__
uint64_t compute_ninv(uint64_t n0)
{
    /* x ≡ n0⁻¹ (mod 2^k), doubling k each iteration.
       Start: n0 × 1 ≡ n0 (mod 2) ≡ 1 (mod 2) since n0 is odd. */
    uint64_t x = 1;
    for (int i = 0; i < 6; i++)          /* 6 iters: 1→2→4→8→16→32→64 bits */
        x *= 2 - n0 * x;
    return ~x + 1;                        /* −x mod 2^64 */
}

/* r = R mod n,  where R = 2^(64×NL).
   Computed by 64×NL modular doublings of 1. */
__device__ static
void compute_rmodn(uint64_t *r, const uint64_t *n)
{
    for (int i = 0; i < NL; i++) r[i] = 0;
    r[0] = 1;
    /* After k doublings: r = 2^k mod n.  After 64*NL: r = R mod n. */
    #pragma unroll 1
    for (int i = 0; i < 64 * NL; i++)
        moddbl(r, n);
}

/* Montgomery multiplication:  r = a · b · R⁻¹ mod n
   CIOS (Coarsely Integrated Operand Scanning) form.
   Requires n odd, 0 ≤ a,b < n < R. */
__device__ static
void montmul(uint64_t *      __restrict__ r,
             const uint64_t * __restrict__ a,
             const uint64_t * __restrict__ b,
             const uint64_t * __restrict__ n,
             uint64_t ninv)
{
    uint64_t t[NL + 2];
    #pragma unroll
    for (int i = 0; i < NL + 2; i++) t[i] = 0;

    for (int i = 0; i < NL; i++) {
        /* Step 1: t += a[i] × b */
        uint64_t c = 0;
        for (int j = 0; j < NL; j++)
            c = mac(&t[j], a[i], b[j], c);
        uint64_t old = t[NL];
        t[NL] += c;
        t[NL + 1] += (t[NL] < old);

        /* Step 2: Montgomery reduce — m = t[0] × ninv;  t += m × n */
        uint64_t m = t[0] * ninv;
        c = 0;
        for (int j = 0; j < NL; j++)
            c = mac(&t[j], m, n[j], c);
        old = t[NL];
        t[NL] += c;
        t[NL + 1] += (t[NL] < old);

        /* Step 3: shift right one limb (t[0] is now 0 mod 2^64) */
        for (int j = 0; j < NL + 1; j++)
            t[j] = t[j + 1];
        t[NL + 1] = 0;
    }

    /* Final reduction: if t ≥ n then t −= n */
    if (t[NL] || gte(t, n))
        sub(r, t, n);
    else
        for (int i = 0; i < NL; i++) r[i] = t[i];
}

/* ═══════════════════════════════════════════════════════════════════
 *  Fermat test kernel
 * ═══════════════════════════════════════════════════════════════════ */

__global__ void fermat_kernel(const uint64_t * __restrict__ cands,
                              uint8_t        * __restrict__ results,
                              uint32_t count)
{
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    /* ── Load candidate n ── */
    uint64_t n[NL];
    const uint64_t *src = &cands[(size_t)idx * NL];
    for (int i = 0; i < NL; i++) n[i] = src[i];

    /* Quick reject: even numbers */
    if ((n[0] & 1) == 0) { results[idx] = 0; return; }

    /* ── Montgomery setup ── */
    uint64_t ninv = compute_ninv(n[0]);

    /* one_m = R mod n  (= 1 in Montgomery form) */
    uint64_t one_m[NL];
    compute_rmodn(one_m, n);

    /* base_m = 2R mod n  (= 2 in Montgomery form) */
    uint64_t base_m[NL];
    for (int i = 0; i < NL; i++) base_m[i] = one_m[i];
    moddbl(base_m, n);

    /* ── Exponent: e = n − 1  (n is odd → no borrow) ── */
    uint64_t e[NL];
    for (int i = 0; i < NL; i++) e[i] = n[i];
    e[0] -= 1;

    /* Find highest set bit */
    int top = NL - 1;
    while (top > 0 && e[top] == 0) top--;
    int msb = 63 - __clzll(e[top]);

    /* ── Left-to-right binary exponentiation ──
       Result starts as base_m (= 2 in Montgomery form), having consumed
       the MSB of the exponent (which is always 1). */
    uint64_t res[NL];
    for (int i = 0; i < NL; i++) res[i] = base_m[i];

    for (int limb = top; limb >= 0; limb--) {
        int start = (limb == top) ? msb - 1 : 63;
        for (int bit = start; bit >= 0; bit--) {
            montmul(res, res, res, n, ninv);               /* square */
            if ((e[limb] >> bit) & 1)
                montmul(res, res, base_m, n, ninv);        /* multiply */
        }
    }

    /* ── Convert back from Montgomery form ── */
    uint64_t one[NL];
    for (int i = 0; i < NL; i++) one[i] = 0;
    one[0] = 1;
    montmul(res, res, one, n, ninv);

    /* ── Check result == 1 ── */
    int ok = (res[0] == 1);
    for (int i = 1; i < NL; i++)
        ok &= (res[i] == 0);

    results[idx] = ok ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Host API
 * ═══════════════════════════════════════════════════════════════════ */

struct gpu_fermat_ctx {
    int       device_id;
    size_t    max_batch;
    /* Double-buffered async pipeline: 2 slots for overlap */
    cudaStream_t stream[2];
    uint64_t *d_cands[2];      /* device candidate buffers  */
    uint8_t  *d_results[2];    /* device result buffers     */
    uint64_t *h_cands[2];      /* pinned host staging cands */
    uint8_t  *h_results[2];    /* pinned host staging res   */
    size_t    pending[2];      /* candidates in-flight per slot (0=idle) */
    char      dev_name[256];
};

gpu_fermat_ctx *gpu_fermat_init(int device_id, size_t max_batch)
{
    gpu_fermat_ctx *ctx = (gpu_fermat_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    cudaError_t err = cudaSetDevice(device_id);
    if (err != cudaSuccess) {
        fprintf(stderr, "gpu_fermat: cudaSetDevice(%d): %s\n",
                device_id, cudaGetErrorString(err));
        free(ctx);
        return NULL;
    }

    /* Query device name */
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device_id) == cudaSuccess)
        strncpy(ctx->dev_name, prop.name, sizeof(ctx->dev_name) - 1);

    ctx->device_id = device_id;
    ctx->max_batch = max_batch;

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

    cudaError_t err = cudaSetDevice(ctx->device_id);
    if (err != cudaSuccess) return -1;

    /* Copy candidates into pinned staging buffer.
       After this memcpy the caller's buffer can be reused. */
    memcpy(ctx->h_cands[slot], candidates,
           count * NL * sizeof(uint64_t));

    /* Async H→D on stream[slot] */
    err = cudaMemcpyAsync(ctx->d_cands[slot], ctx->h_cands[slot],
                          count * NL * sizeof(uint64_t),
                          cudaMemcpyHostToDevice, ctx->stream[slot]);
    if (err != cudaSuccess) return -1;

    /* Launch kernel on stream[slot] */
    int block = 128;
    int grid  = (int)((count + block - 1) / block);
    fermat_kernel<<<grid, block, 0, ctx->stream[slot]>>>(
        ctx->d_cands[slot], ctx->d_results[slot], (uint32_t)count);

    /* Async D→H on stream[slot] */
    err = cudaMemcpyAsync(ctx->h_results[slot], ctx->d_results[slot],
                          count, cudaMemcpyDeviceToHost,
                          ctx->stream[slot]);
    if (err != cudaSuccess) return -1;

    ctx->pending[slot] = count;
    return 0;
}

int gpu_fermat_collect(gpu_fermat_ctx *ctx, int slot,
                       uint8_t *results, size_t count)
{
    if (!ctx || !results) return -1;
    if (slot < 0 || slot > 1) return -1;
    if (ctx->pending[slot] == 0) return 0;

    size_t n = ctx->pending[slot];
    if (count < n) n = count;

    cudaError_t err = cudaSetDevice(ctx->device_id);
    if (err != cudaSuccess) return -1;

    /* Wait for all operations on this stream */
    err = cudaStreamSynchronize(ctx->stream[slot]);
    if (err != cudaSuccess) return -1;

    /* Results are already in pinned host buffer — copy to user */
    memcpy(results, ctx->h_results[slot], n);

    int primes = 0;
    for (size_t i = 0; i < n; i++)
        primes += results[i];

    ctx->pending[slot] = 0;
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

void gpu_fermat_destroy(gpu_fermat_ctx *ctx)
{
    if (!ctx) return;
    cudaSetDevice(ctx->device_id);
    for (int s = 0; s < 2; s++) {
        if (ctx->pending[s] && ctx->stream[s])
            cudaStreamSynchronize(ctx->stream[s]);
        if (ctx->d_cands[s])   cudaFree(ctx->d_cands[s]);
        if (ctx->d_results[s]) cudaFree(ctx->d_results[s]);
        if (ctx->h_cands[s])   cudaFreeHost(ctx->h_cands[s]);
        if (ctx->h_results[s]) cudaFreeHost(ctx->h_results[s]);
        if (ctx->stream[s])    cudaStreamDestroy(ctx->stream[s]);
    }
    free(ctx);
}
