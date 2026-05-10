/* gpu_sieve.cu — GPU-accelerated presieve (batch composite marking)
 *
 * Experimental GPU sieve for the Phase-2 large-prime path.
 * GPU marks composites into a byte-per-candidate scratch buffer, then packs
 * that scratch buffer into the bitset format expected by the CPU sieve code.
 *
 * Kernel strategy:
 *   - One CUDA thread per prime for composite marking
 *   - One CUDA thread per output byte for bitmap packing
 *
 * Memory layout:
 *   - d_segment: device scratch array (byte, 1=composite)
 *   - d_bits:    device packed bitmap (8 candidates per byte)
 *   - d_primes:  device array of primes (copied from host input)
 *   - d_k0:      device array of first-hit indices per prime
 */
/* gpu_sieve.cu — GPU-accelerated presieve (batch composite marking)
 *
 * Phase-2 large-prime GPU sieve.  k0 (first-composite index per prime) is
 * now computed entirely on-device by kernel_compute_k0, which computes L%p
 * inline in parallel.  base_mod_p (big_base%p) is uploaded once per block
 * header and cached on the device, eliminating the 15 MB k0 host→device
 * transfer and the ~22 ms CPU k0-computation loop.
 *
 * Pipeline per window:
 *   1. [rare] H→D base_mod_p[] upload (only on header change)
 *   2. kernel_compute_k0  — from base_mod_p + L scalar → d_k0[]
 *   3. kernel_mark_composites — d_k0[] → d_segment[] byte marks
 *   4. kernel_pack_bits   — d_segment[] → d_bits[] packed bitmap
 *   5. D→H d_bits copy
 *
 * Device memory layout:
 *   d_segment    — byte-per-candidate scratch (1=composite)
 *   d_bits       — packed output bitmap (8 candidates per byte)
 *   d_primes     — prime strides (stable; uploaded once per thread)
 *   d_base_mod_p — big_base % p per prime (per block header)
 *   d_k0         — first composite index per prime (produced by kernel)
 */

#include "gpu_sieve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <cuda_runtime.h>

#define GPU_SIEVE_THREADS_PER_BLOCK 256

static int gpu_sieve_timing_enabled(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;
    {
        const char *v = getenv("GPU_SIEVE_TIMING");
        cached = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
    }
    return cached;
}

/* Experimental path switch:
 * 0 (default): keep legacy compact logic (phase-2-only compact attempt).
 * 1: enable phase1-aware final survivor compaction path. */
static int gpu_sieve_final_compact_enabled(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;
    {
        const char *v = getenv("GPU_SIEVE_FINAL_COMPACT");
        cached = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
    }
    return cached;
}

/* Default cap for compact survivor buffer (entries, not bytes).
 * Configurable via GPU_SIEVE_SURV_CAP env var. */
static uint32_t gpu_sieve_get_surv_cap(void)
{
    static uint32_t cached = 0;
    if (cached) return cached;
    const char *v = getenv("GPU_SIEVE_SURV_CAP");
    if (v && *v) {
        long val = atol(v);
        if (val > 0 && val <= 16 * 1024 * 1024)
            cached = (uint32_t)val;
    }
    if (!cached) cached = 262144; /* 256 K entries = 1 MB pinned */
    return cached;
}

/* Decide whether compact survivor mode is worth attempting.
 *
 * Compact currently counts Phase-2 survivors before Phase-1 intersection.
 * For large non-CRT windows, this almost always overflows survivors_cap and
 * adds extra kernel + sync overhead with no benefit. Keep compact enabled for
 * small windows (e.g. CRT-sized windows), but skip it when overflow is nearly
 * certain.
 */
static int gpu_sieve_should_try_compact(
    size_t segment_len,
    uint32_t survivors_cap,
    const uint64_t *h_primes,
    int n_primes)
{
    if (survivors_cap == 0 || !h_primes || n_primes <= 0)
        return 0;

    if (segment_len <= (size_t)survivors_cap)
        return 1;

    /* If window is massively larger than cap, overflow is effectively certain
     * in Phase-2-only survivor space. */
    if (segment_len > (size_t)survivors_cap * 32u)
        return 0;

    uint64_t pmin = h_primes[0];
    uint64_t pmax = h_primes[n_primes - 1];
    if (pmin < 3 || pmax <= pmin)
        return (segment_len <= (size_t)survivors_cap * 2u);

    /* Mertens-style range estimate for keep ratio over [pmin, pmax]:
     *   keep ~= log(pmin)/log(pmax)
     * Use a generous 2x cap margin to avoid false "skip compact" in small
     * or unusual windows where compact might still fit. */
    double lpmin = log((double)pmin);
    double lpmax = log((double)pmax);
    if (!(lpmin > 0.0) || !(lpmax > lpmin))
        return (segment_len <= (size_t)survivors_cap * 2u);

    double keep = lpmin / lpmax;
    if (keep < 0.0) keep = 0.0;
    if (keep > 1.0) keep = 1.0;

    double est_surv = (double)segment_len * keep;
    return est_surv <= (double)survivors_cap * 2.0;
}

/* Simple CUDA error check (inline) */
#define CUDA_CHECK(call) do {                              \
    cudaError_t err = (call);                              \
    if (err != cudaSuccess) {                              \
        fprintf(stderr, "GPU sieve CUDA error: %s\n",      \
                cudaGetErrorString(err));                  \
        return -1;                                         \
    }                                                      \
} while(0)

/* ═══════════════════════════════════════════════════════════════════
 *  Device Kernel: Mark composites for batch of primes
 * ═══════════════════════════════════════════════════════════════════ */

/* Kernel: Each thread marks multiples of one prime in the segment.
 *
 * Params:
 *   segment      — byte array, size segment_len (1=composite, 0=candidate)
 *   segment_len  — size of segment in (odd) candidates
 *   primes       — device array of primes (one per thread, used as stride)
 *   k0_array     — device array of starting indices; k0_array[idx] is the
 *                  first index where prime primes[idx] divides the candidate.
 *                  Precomputed on CPU with full base_mod_p correction.
 *                  If k0_array[idx] >= segment_len, nothing to mark.
 *   n_primes     — total number of primes / k0 entries
 */
__global__ static void kernel_mark_composites(
    uint8_t *segment,
    size_t segment_len,
    const uint64_t *primes,
    const uint64_t *k0_array,
    int n_primes
)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx >= n_primes)
        return;  /* tail threads exit */

    uint64_t p = primes[idx];
    uint64_t k = k0_array[idx];  /* first composite index, precomputed on CPU */

    for (uint64_t ki = k; ki < segment_len; ki += p)
        segment[ki] = 1;
}

__global__ static void kernel_pack_bits(
    const uint8_t *segment,
    uint8_t *bits,
    size_t segment_len,
    size_t bit_len
)
{
    size_t byte_idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (byte_idx >= bit_len)
        return;

    size_t base = byte_idx << 3;
    uint8_t packed = 0;

    if (base + 0 < segment_len && segment[base + 0]) packed |= 1u << 0;
    if (base + 1 < segment_len && segment[base + 1]) packed |= 1u << 1;
    if (base + 2 < segment_len && segment[base + 2]) packed |= 1u << 2;
    if (base + 3 < segment_len && segment[base + 3]) packed |= 1u << 3;
    if (base + 4 < segment_len && segment[base + 4]) packed |= 1u << 4;
    if (base + 5 < segment_len && segment[base + 5]) packed |= 1u << 5;
    if (base + 6 < segment_len && segment[base + 6]) packed |= 1u << 6;
    if (base + 7 < segment_len && segment[base + 7]) packed |= 1u << 7;

    bits[byte_idx] = packed;
}

/* Kernel: compact survivors from segment into a fixed-capacity index array.
 *
 * Each thread checks one candidate position; positions where segment[pos]==0
 * are Phase-2 survivors (not composite by any Phase-2 prime).
 *
 * Warp-ballot compaction reduces global atomics to one per warp:
 *   1. __ballot_sync  — all 32 lanes vote, producing a bitmask
 *   2. lane-0 atomicAdd claims a contiguous range in out_indices
 *   3. __shfl_sync    — broadcast the range start to all lanes
 *   4. Each surviving lane computes its offset via __popc and writes
 *
 * If out_count exceeds cap, writes are suppressed but the counter keeps
 * incrementing.  The caller detects overflow by checking out_count > cap.
 */
__global__ static void kernel_compact_survivors(
    const uint8_t *segment,
    uint32_t       seg_len,
    uint32_t      *out_indices,
    uint32_t      *out_count,
    uint32_t       cap
) {
    uint32_t pos = (uint32_t)(blockIdx.x * blockDim.x + threadIdx.x);
    int is_surv = (pos < seg_len) && (segment[pos] == 0);

    unsigned ballot = __ballot_sync(0xFFFFFFFFu, is_surv);
    uint32_t warp_count = (uint32_t)__popc(ballot);
    int lane = (int)(threadIdx.x & 31u);

    uint32_t warp_start = 0;
    if (lane == 0 && warp_count > 0)
        warp_start = atomicAdd(out_count, warp_count);
    warp_start = __shfl_sync(0xFFFFFFFFu, warp_start, 0);

    if (is_surv) {
        uint32_t offset = (uint32_t)__popc(ballot & ((1u << lane) - 1u));
        uint32_t gpos = warp_start + offset;
        if (gpos < cap)
            out_indices[gpos] = pos;
    }
}

/* Kernel: compact survivors that pass both Phase-2 marks and Phase-1 bitmap.
 *
 * phase1_bits is a packed bitmap where bit=1 means composite from Phase-1.
 * A survivor position must satisfy:
 *   segment[pos] == 0  (not marked by Phase-2)
 *   phase1_bits[pos] == 0 (not marked by Phase-1)
 */
__global__ static void kernel_compact_survivors_with_phase1(
    const uint8_t *segment,
    const uint8_t *phase1_bits,
    uint32_t       seg_len,
    uint32_t      *out_indices,
    uint32_t      *out_count,
    uint32_t       cap
) {
    uint32_t pos = (uint32_t)(blockIdx.x * blockDim.x + threadIdx.x);
    int is_surv = 0;
    if (pos < seg_len && segment[pos] == 0) {
        uint8_t b = phase1_bits[pos >> 3];
        is_surv = ((b & (uint8_t)(1u << (pos & 7))) == 0);
    }

    unsigned ballot = __ballot_sync(0xFFFFFFFFu, is_surv);
    uint32_t warp_count = (uint32_t)__popc(ballot);
    int lane = (int)(threadIdx.x & 31u);

    uint32_t warp_start = 0;
    if (lane == 0 && warp_count > 0)
        warp_start = atomicAdd(out_count, warp_count);
    warp_start = __shfl_sync(0xFFFFFFFFu, warp_start, 0);

    if (is_surv) {
        uint32_t offset = (uint32_t)__popc(ballot & ((1u << lane) - 1u));
        uint32_t gpos = warp_start + offset;
        if (gpos < cap)
            out_indices[gpos] = pos;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  Public API Implementation
/* Kernel: compute k0[j] = first composite index in [0, segment_len) for
 * prime primes[j], given:
 *   base_mod_p[j] = big_base % primes[j]   (cached per block header)
 *   L              = window start value     (odd candidate offset, scalar)
 *   R              = window end value       (exclusive, scalar)
 *   segment_len    = (R - L) / 2 + 1       (odd-only candidate count)
 *
 * The 64-bit modulo (L % p) is computed inline in parallel across threads,
 * replacing the sequential CPU loop that formerly took ~22 ms.
 */
__global__ static void kernel_compute_k0(
    uint64_t *k0,
    const uint64_t *primes,
    const uint64_t *base_mod_p,
    uint64_t L, uint64_t R, size_t segment_len,
    uint32_t L_u32, int L_fits_u32,
    int n_primes
)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_primes) return;

    uint64_t p = primes[idx];
    /* lrem = (big_base + L) % p = (base_mod_p + L%p) % p */
    uint64_t lmod;
    if (L_fits_u32 && p <= 0xFFFFFFFFULL) {
        lmod = (uint64_t)(L_u32 % (uint32_t)p);
    } else {
        lmod = L % p;
    }
    uint64_t lrem = base_mod_p[idx] + lmod;
    if (lrem >= p) lrem -= p;
    /* First candidate offset m where p | (big_base + m), with m odd */
    uint64_t start = L + (lrem == 0 ? 0 : p - lrem);
    if ((start & 1) == 0) start += p;  /* align to odd */
    k0[idx] = (start < R) ? (start - L) >> 1 : segment_len;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Public API Implementation
 * ═══════════════════════════════════════════════════════════════════ */
 

extern "C" {

int gpu_sieve_ctx_alloc(
    gpu_sieve_ctx_t *ctx,
    size_t max_segment,
    size_t max_primes,
    int device_id
)
{
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->device_id = device_id;
    ctx->d_segment_cap = max_segment;
    ctx->d_bits_cap = (max_segment + 7) >> 3;
    ctx->d_primes_cap = max_primes;
    
    /* Set device */
    cudaError_t err = cudaSetDevice(device_id);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaSetDevice(%d) failed: %s\n", device_id, cudaGetErrorString(err));
        return -1;
    }
    
    /* Allocate segment buffer */
    err = cudaMalloc(&ctx->d_segment, ctx->d_segment_cap);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(segment, %zu) failed: %s\n", 
                ctx->d_segment_cap, cudaGetErrorString(err));
        return -1;
    }
    
    /* Allocate packed bitmap buffer */
    err = cudaMalloc(&ctx->d_bits, ctx->d_bits_cap);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(bits, %zu) failed: %s\n",
                ctx->d_bits_cap, cudaGetErrorString(err));
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }

    /* Allocate primes buffer */
    err = cudaMalloc(&ctx->d_primes, ctx->d_primes_cap * sizeof(uint64_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(primes, %zu) failed: %s\n",
                ctx->d_primes_cap * sizeof(uint64_t), cudaGetErrorString(err));
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }

    /* Allocate k0 buffer (one starting index per prime) */
    err = cudaMalloc(&ctx->d_k0, ctx->d_primes_cap * sizeof(uint64_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(k0, %zu) failed: %s\n",
                ctx->d_primes_cap * sizeof(uint64_t), cudaGetErrorString(err));
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }
    
    /* Allocate base_mod_p buffer (one entry per prime, per block header) */
    err = cudaMalloc(&ctx->d_base_mod_p, ctx->d_primes_cap * sizeof(uint64_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(base_mod_p, %zu) failed: %s\n",
                ctx->d_primes_cap * sizeof(uint64_t), cudaGetErrorString(err));
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }

    ctx->loaded_base_mod_p_src = NULL;
    ctx->loaded_base_mod_p_version = (uint64_t)-1; /* force upload on first call */

    err = cudaHostAlloc((void **)&ctx->h_bits_pinned, ctx->d_bits_cap, cudaHostAllocDefault);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaHostAlloc(bits_pinned, %zu) failed: %s\n",
                ctx->d_bits_cap, cudaGetErrorString(err));
        cudaFree(ctx->d_base_mod_p);
        ctx->d_base_mod_p = NULL;
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }
    ctx->h_bits_pinned_cap = ctx->d_bits_cap;

    cudaStream_t stream = NULL;
    err = cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaStreamCreateWithFlags failed: %s\n",
                cudaGetErrorString(err));
        cudaFreeHost(ctx->h_bits_pinned);
        ctx->h_bits_pinned = NULL;
        ctx->h_bits_pinned_cap = 0;
        cudaFree(ctx->d_base_mod_p);
        ctx->d_base_mod_p = NULL;
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }
    ctx->stream = (void *)stream;

    /* ── Compact survivor buffers ── */
    uint32_t scap = gpu_sieve_get_surv_cap();
    ctx->survivors_cap = scap;

    err = cudaMalloc(&ctx->d_survivors, (size_t)scap * sizeof(uint32_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(d_survivors, %zu) failed: %s\n",
                (size_t)scap * sizeof(uint32_t), cudaGetErrorString(err));
        cudaStreamDestroy(stream);
        ctx->stream = NULL;
        cudaFreeHost(ctx->h_bits_pinned);
        ctx->h_bits_pinned = NULL;
        ctx->h_bits_pinned_cap = 0;
        cudaFree(ctx->d_base_mod_p);
        ctx->d_base_mod_p = NULL;
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }

    err = cudaMalloc((void **)&ctx->d_surv_count, sizeof(uint32_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(d_surv_count) failed: %s\n",
                cudaGetErrorString(err));
        cudaFree(ctx->d_survivors);
        ctx->d_survivors = NULL;
        cudaStreamDestroy(stream);
        ctx->stream = NULL;
        cudaFreeHost(ctx->h_bits_pinned);
        ctx->h_bits_pinned = NULL;
        ctx->h_bits_pinned_cap = 0;
        cudaFree(ctx->d_base_mod_p);
        ctx->d_base_mod_p = NULL;
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }

    err = cudaHostAlloc((void **)&ctx->h_surv_pinned,
                        (size_t)scap * sizeof(uint32_t), cudaHostAllocDefault);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaHostAlloc(h_surv_pinned, %zu) failed: %s\n",
                (size_t)scap * sizeof(uint32_t), cudaGetErrorString(err));
        cudaFree(ctx->d_surv_count);
        ctx->d_surv_count = NULL;
        cudaFree(ctx->d_survivors);
        ctx->d_survivors = NULL;
        cudaStreamDestroy(stream);
        ctx->stream = NULL;
        cudaFreeHost(ctx->h_bits_pinned);
        ctx->h_bits_pinned = NULL;
        ctx->h_bits_pinned_cap = 0;
        cudaFree(ctx->d_base_mod_p);
        ctx->d_base_mod_p = NULL;
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }

    err = cudaHostAlloc((void **)&ctx->h_surv_count_pinned,
                        sizeof(uint32_t), cudaHostAllocDefault);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaHostAlloc(h_surv_count_pinned) failed: %s\n",
                cudaGetErrorString(err));
        cudaFreeHost(ctx->h_surv_pinned);
        ctx->h_surv_pinned = NULL;
        cudaFree(ctx->d_surv_count);
        ctx->d_surv_count = NULL;
        cudaFree(ctx->d_survivors);
        ctx->d_survivors = NULL;
        cudaStreamDestroy(stream);
        ctx->stream = NULL;
        cudaFreeHost(ctx->h_bits_pinned);
        ctx->h_bits_pinned = NULL;
        ctx->h_bits_pinned_cap = 0;
        cudaFree(ctx->d_base_mod_p);
        ctx->d_base_mod_p = NULL;
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
        return -1;
    }

    ctx->h_base_mod_p_shadow = (uint64_t *)malloc(ctx->d_primes_cap * sizeof(uint64_t));
    if (!ctx->h_base_mod_p_shadow) {
        fprintf(stderr, "GPU sieve: malloc(base_mod_p_shadow, %zu) failed\n",
                ctx->d_primes_cap * sizeof(uint64_t));
        gpu_sieve_ctx_free(ctx);
        return -1;
    }

    ctx->h_primes_shadow = (uint64_t *)malloc(ctx->d_primes_cap * sizeof(uint64_t));
    if (!ctx->h_primes_shadow) {
        fprintf(stderr, "GPU sieve: malloc(primes_shadow, %zu) failed\n",
                ctx->d_primes_cap * sizeof(uint64_t));
        gpu_sieve_ctx_free(ctx);
        return -1;
    }

    ctx->initialized = 1;
    return 0;
}

void gpu_sieve_ctx_free(gpu_sieve_ctx_t *ctx)
{
    if (!ctx)
        return;

    cudaSetDevice(ctx->device_id);

    if (ctx->stream) {
        cudaStreamDestroy((cudaStream_t)ctx->stream);
        ctx->stream = NULL;
    }

    if (ctx->h_bits_pinned) {
        cudaFreeHost(ctx->h_bits_pinned);
        ctx->h_bits_pinned = NULL;
        ctx->h_bits_pinned_cap = 0;
    }

    if (ctx->h_base_mod_p_shadow) {
        free(ctx->h_base_mod_p_shadow);
        ctx->h_base_mod_p_shadow = NULL;
    }

    if (ctx->h_primes_shadow) {
        free(ctx->h_primes_shadow);
        ctx->h_primes_shadow = NULL;
    }

    if (ctx->h_surv_count_pinned) {
        cudaFreeHost(ctx->h_surv_count_pinned);
        ctx->h_surv_count_pinned = NULL;
    }

    if (ctx->h_surv_pinned) {
        cudaFreeHost(ctx->h_surv_pinned);
        ctx->h_surv_pinned = NULL;
    }

    if (ctx->d_surv_count) {
        cudaFree(ctx->d_surv_count);
        ctx->d_surv_count = NULL;
    }

    if (ctx->d_survivors) {
        cudaFree(ctx->d_survivors);
        ctx->d_survivors = NULL;
    }

    if (ctx->d_segment) {
        cudaFree(ctx->d_segment);
        ctx->d_segment = NULL;
    }

    if (ctx->d_bits) {
        cudaFree(ctx->d_bits);
        ctx->d_bits = NULL;
    }
    
    if (ctx->d_primes) {
        cudaFree(ctx->d_primes);
        ctx->d_primes = NULL;
    }

    if (ctx->d_k0) {
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
    }

    if (ctx->d_base_mod_p) {
        cudaFree(ctx->d_base_mod_p);
        ctx->d_base_mod_p = NULL;
    }

    ctx->loaded_primes_src = NULL;
    ctx->loaded_base_mod_p_src = NULL;
    ctx->loaded_primes_n = 0;
    ctx->loaded_base_mod_p_n = 0;
    ctx->loaded_base_mod_p_version = (uint64_t)-1;
    ctx->initialized = 0;
}

}  /* extern "C" */

extern "C" {

int gpu_sieve_mark_batch(
    gpu_sieve_ctx_t *ctx,
    uint8_t *h_bits,
    size_t bit_len,
    size_t segment_len,
    const uint8_t *h_phase1_bits,
    const uint64_t *h_primes,
    const uint64_t *h_base_mod_p,
    uint64_t base_mod_p_version,
    uint64_t L, uint64_t R,
    int n_primes
)
{
    if (!ctx || !ctx->initialized || !h_bits || !h_primes || !h_base_mod_p || n_primes <= 0)
        return -1;

    ctx->last_us_base_upload = 0;
    ctx->last_us_compute_k0 = 0;
    ctx->last_us_mark = 0;
    ctx->last_us_compact = 0;
    ctx->last_us_pack = 0;
    ctx->last_us_bits_dl = 0;
    ctx->last_surv_count = 0;

    size_t out_bytes = (segment_len + 7) >> 3;

    /* Bounds checks */
    if (segment_len > ctx->d_segment_cap) {
        fprintf(stderr, "GPU sieve: segment_len (%zu) exceeds capacity (%zu)\n",
                segment_len, ctx->d_segment_cap);
        return -1;
    }
    if (out_bytes > ctx->d_bits_cap || bit_len < out_bytes) {
        fprintf(stderr, "GPU sieve: bit_len/cap mismatch (need %zu, host %zu, device %zu)\n",
                out_bytes, bit_len, ctx->d_bits_cap);
        return -1;
    }
    if ((size_t)n_primes > ctx->d_primes_cap) {
        fprintf(stderr, "GPU sieve: n_primes (%d) exceeds device capacity (%zu)\n",
                n_primes, ctx->d_primes_cap);
        return -1;
    }

    cudaError_t err = cudaSetDevice(ctx->device_id);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaSetDevice(%d) failed: %s\n",
                ctx->device_id, cudaGetErrorString(err));
        return -1;
    }

    if (!ctx->stream)
        return -1;
    cudaStream_t stream = (cudaStream_t)ctx->stream;
    size_t primes_bytes = 0;
    int need_primes_upload = 0;
    int L_fits_u32 = (L <= 0xFFFFFFFFULL) ? 1 : 0;
    uint32_t L_u32 = (uint32_t)L;

    int timing = gpu_sieve_timing_enabled();
    /* 7 CUDA events: base_upload (ev0/ev1), compute_k0 (ev1/ev2),
     *               mark (ev2/ev3), compact (ev3/ev4), pack (ev4/ev5),
     *               bits_dl (ev5/ev6) */
    cudaEvent_t ev0, ev1, ev2, ev3, ev4, ev5, ev6;
    if (timing) {
        cudaEventCreate(&ev0); cudaEventCreate(&ev1);
        cudaEventCreate(&ev2); cudaEventCreate(&ev3);
        cudaEventCreate(&ev4); cudaEventCreate(&ev5);
        cudaEventCreate(&ev6);
    }

    int blocks = (n_primes + GPU_SIEVE_THREADS_PER_BLOCK - 1) / GPU_SIEVE_THREADS_PER_BLOCK;

    /* ── Stage 0 (rare): H→D base_mod_p upload ──────────────────── */
    if (timing) cudaEventRecord(ev0, stream);
    size_t base_mod_p_bytes = (size_t)n_primes * sizeof(uint64_t);
    int need_base_mod_p_upload =
        (ctx->loaded_base_mod_p_version != base_mod_p_version) ||
        (ctx->loaded_base_mod_p_n != n_primes) ||
        (ctx->h_base_mod_p_shadow == NULL);

    if (need_base_mod_p_upload) {
        err = cudaMemcpy(ctx->d_base_mod_p, h_base_mod_p,
                 base_mod_p_bytes, cudaMemcpyHostToDevice);
        if (err != cudaSuccess) {
            fprintf(stderr, "GPU sieve: cudaMemcpy(H→D base_mod_p) failed: %s\n",
                    cudaGetErrorString(err));
            goto timing_cleanup;
        }
        memcpy(ctx->h_base_mod_p_shadow, h_base_mod_p, base_mod_p_bytes);
        ctx->loaded_base_mod_p_src = h_base_mod_p;
        ctx->loaded_base_mod_p_version = base_mod_p_version;
        ctx->loaded_base_mod_p_n = n_primes;
    } else {
        ctx->loaded_base_mod_p_src = h_base_mod_p;
    }
    if (timing) cudaEventRecord(ev1, stream); /* ev0..ev1 = base_mod_p upload (0 ms when cached) */

    /* Upload primes on count/pointer change. The prime slice is immutable for
     * a given run, so full-buffer memcmp here only adds host-side overhead. */
    primes_bytes = (size_t)n_primes * sizeof(uint64_t);
    need_primes_upload =
        (ctx->loaded_primes_n != n_primes) ||
        (ctx->h_primes_shadow == NULL) ||
        (ctx->loaded_primes_src != h_primes);

    if (need_primes_upload) {
        err = cudaMemcpy(ctx->d_primes, h_primes,
                 primes_bytes, cudaMemcpyHostToDevice);
        if (err != cudaSuccess) {
            fprintf(stderr, "GPU sieve: cudaMemcpy(H→D primes) failed: %s\n",
                    cudaGetErrorString(err));
            goto timing_cleanup;
        }
        memcpy(ctx->h_primes_shadow, h_primes, primes_bytes);
        ctx->loaded_primes_src = h_primes;
        ctx->loaded_primes_n = n_primes;
    } else {
        ctx->loaded_primes_src = h_primes;
    }

    /* Zero the segment scratch buffer for this window. */
    err = cudaMemsetAsync(ctx->d_segment, 0, segment_len, stream);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMemset(segment) failed: %s\n", cudaGetErrorString(err));
        goto timing_cleanup;
    }

    /* ── Stage 1: compute k0 on GPU ─────────────────────────────── */
    kernel_compute_k0<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
        ctx->d_k0, ctx->d_primes, ctx->d_base_mod_p,
        L, R, segment_len, L_u32, L_fits_u32, n_primes);
    if (timing) cudaEventRecord(ev2, stream); /* ev1..ev2 = compute_k0 kernel */
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: kernel_compute_k0 launch failed: %s\n",
                cudaGetErrorString(err));
        goto timing_cleanup;
    }

    /* ── Stage 2: kernel_mark_composites ───────────────────────── */
    kernel_mark_composites<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
        ctx->d_segment, segment_len, ctx->d_primes, ctx->d_k0, n_primes);
    if (timing) cudaEventRecord(ev3, stream); /* ev2..ev3 = mark kernel */
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: kernel_mark_composites launch failed: %s\n",
                cudaGetErrorString(err));
        goto timing_cleanup;
    }

    /* ── Stage 2.5: kernel_compact_survivors ────────────────────── */
    {
        int has_surv_buf = (ctx->d_survivors && ctx->d_surv_count &&
                            ctx->h_surv_pinned && ctx->h_surv_count_pinned &&
                            ctx->survivors_cap > 0);
        int use_phase1_compact = (h_phase1_bits != NULL) && gpu_sieve_final_compact_enabled();
        int try_compact = has_surv_buf &&
            (use_phase1_compact || gpu_sieve_should_try_compact(
                segment_len, ctx->survivors_cap, h_primes, n_primes));

        if (try_compact) {
            if (use_phase1_compact) {
                err = cudaMemcpyAsync(ctx->d_bits, h_phase1_bits, out_bytes,
                                      cudaMemcpyHostToDevice, stream);
                if (err != cudaSuccess) {
                    fprintf(stderr, "GPU sieve: phase1 bitmap H→D failed, falling back to bitmap path: %s\n",
                            cudaGetErrorString(err));
                    try_compact = 0;
                }
            }
        }

        if (try_compact) {
            err = cudaMemsetAsync(ctx->d_surv_count, 0, sizeof(uint32_t), stream);
            if (err != cudaSuccess) {
                fprintf(stderr, "GPU sieve: cudaMemsetAsync(d_surv_count) failed: %s\n",
                        cudaGetErrorString(err));
                goto timing_cleanup;
            }
            int surv_blocks = (int)((segment_len + GPU_SIEVE_THREADS_PER_BLOCK - 1)
                                    / GPU_SIEVE_THREADS_PER_BLOCK);
            if (use_phase1_compact) {
                kernel_compact_survivors_with_phase1<<<surv_blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                    ctx->d_segment, ctx->d_bits, (uint32_t)segment_len,
                    ctx->d_survivors, ctx->d_surv_count, ctx->survivors_cap);
            } else {
                kernel_compact_survivors<<<surv_blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                    ctx->d_segment, (uint32_t)segment_len,
                    ctx->d_survivors, ctx->d_surv_count, ctx->survivors_cap);
            }
            err = cudaGetLastError();
            if (err != cudaSuccess) {
                fprintf(stderr, "GPU sieve: kernel_compact_survivors launch failed: %s\n",
                        cudaGetErrorString(err));
                goto timing_cleanup;
            }
        }
        if (timing) cudaEventRecord(ev4, stream); /* ev3..ev4 = compact kernel */

        /* Fast path: try compact mode first, and only fall back to bitmap pack
         * if survivor count exceeds cap (or compact transfer fails). */
        if (try_compact) {
            err = cudaMemcpyAsync(ctx->h_surv_count_pinned, ctx->d_surv_count,
                                  sizeof(uint32_t), cudaMemcpyDeviceToHost, stream);
            if (err == cudaSuccess)
                err = cudaStreamSynchronize(stream);
            if (err == cudaSuccess) {
                uint32_t surv_count = *ctx->h_surv_count_pinned;
                if (surv_count <= ctx->survivors_cap) {
                    size_t surv_bytes = (size_t)surv_count * sizeof(uint32_t);
                    if (surv_bytes > 0) {
                        err = cudaMemcpyAsync(ctx->h_surv_pinned, ctx->d_survivors,
                                              surv_bytes, cudaMemcpyDeviceToHost, stream);
                        if (err == cudaSuccess)
                            err = cudaStreamSynchronize(stream);
                    }
                    if (err == cudaSuccess) {
                        ctx->last_surv_count = surv_count;
                        if (timing) {
                            float ms;
                            cudaEventSynchronize(ev4);
                            if (cudaEventElapsedTime(&ms, ev0, ev1) == cudaSuccess)
                                ctx->last_us_base_upload = (uint64_t)(ms * 1000.0f + 0.5f);
                            if (cudaEventElapsedTime(&ms, ev1, ev2) == cudaSuccess)
                                ctx->last_us_compute_k0 = (uint64_t)(ms * 1000.0f + 0.5f);
                            if (cudaEventElapsedTime(&ms, ev2, ev3) == cudaSuccess)
                                ctx->last_us_mark = (uint64_t)(ms * 1000.0f + 0.5f);
                            if (cudaEventElapsedTime(&ms, ev3, ev4) == cudaSuccess)
                                ctx->last_us_compact = (uint64_t)(ms * 1000.0f + 0.5f);
                            cudaEventDestroy(ev0); cudaEventDestroy(ev1);
                            cudaEventDestroy(ev2); cudaEventDestroy(ev3);
                            cudaEventDestroy(ev4); cudaEventDestroy(ev5);
                            cudaEventDestroy(ev6);
                        }
                        /* h_bits is intentionally not filled in compact mode. */
                        return 1;
                    }
                    fprintf(stderr, "GPU sieve: compact survivor D→H failed, falling back to bitmap: %s\n",
                            cudaGetErrorString(err));
                }
            } else {
                fprintf(stderr, "GPU sieve: survivor-count D→H failed, falling back to bitmap: %s\n",
                        cudaGetErrorString(err));
            }
        }
    }

    /* ── Stage 3: kernel_pack_bits (bitmap fallback path) ───────── */
    {
        int pack_blocks = (int)((out_bytes + GPU_SIEVE_THREADS_PER_BLOCK - 1)
                                / GPU_SIEVE_THREADS_PER_BLOCK);
        kernel_pack_bits<<<pack_blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
            ctx->d_segment, ctx->d_bits, segment_len, out_bytes);
    }
    if (timing) cudaEventRecord(ev5, stream); /* ev4..ev5 = pack kernel */
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: kernel_pack_bits launch failed: %s\n",
                cudaGetErrorString(err));
        goto timing_cleanup;
    }

    /* ── Stage 4: bitmap download (fallback path) ───────────────── */
    if (ctx->h_bits_pinned && out_bytes <= ctx->h_bits_pinned_cap) {
        err = cudaMemcpyAsync(ctx->h_bits_pinned, ctx->d_bits, out_bytes,
                              cudaMemcpyDeviceToHost, stream);
    } else {
        err = cudaMemcpyAsync(h_bits, ctx->d_bits, out_bytes,
                              cudaMemcpyDeviceToHost, stream);
    }
    if (timing) cudaEventRecord(ev6, stream); /* ev5..ev6 = bits download */
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMemcpy(D→H bits) failed: %s\n",
                cudaGetErrorString(err));
        goto timing_cleanup;
    }

    err = cudaStreamSynchronize(stream);
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaStreamSynchronize failed: %s\n",
                cudaGetErrorString(err));
        goto timing_cleanup;
    }

    /* Collect per-stage timing.
     *   ev0..ev1 : base_mod_p H→D upload (0 when cached)
     *   ev1..ev2 : kernel_compute_k0
     *   ev2..ev3 : kernel_mark_composites
     *   ev3..ev4 : kernel_compact_survivors
     *   ev4..ev5 : kernel_pack_bits
     *   ev5..ev6 : D→H download
     */
    if (timing) {
        float ms;
        cudaEventSynchronize(ev6);
        if (cudaEventElapsedTime(&ms, ev0, ev1) == cudaSuccess)
            ctx->last_us_base_upload = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev1, ev2) == cudaSuccess)
            ctx->last_us_compute_k0 = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev2, ev3) == cudaSuccess)
            ctx->last_us_mark = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev3, ev4) == cudaSuccess)
            ctx->last_us_compact = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev4, ev5) == cudaSuccess)
            ctx->last_us_pack = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev5, ev6) == cudaSuccess)
            ctx->last_us_bits_dl = (uint64_t)(ms * 1000.0f + 0.5f);
    }

    if (timing) {
        cudaEventDestroy(ev0); cudaEventDestroy(ev1);
        cudaEventDestroy(ev2); cudaEventDestroy(ev3);
        cudaEventDestroy(ev4); cudaEventDestroy(ev5);
        cudaEventDestroy(ev6);
    }

    /* Bitmap mode: copy from pinned staging to caller h_bits */
    if (ctx->h_bits_pinned && out_bytes <= ctx->h_bits_pinned_cap) {
        memcpy(h_bits, ctx->h_bits_pinned, out_bytes);
    }
    return 0; /* bitmap mode */

timing_cleanup:
    if (timing) {
        cudaEventDestroy(ev0); cudaEventDestroy(ev1);
        cudaEventDestroy(ev2); cudaEventDestroy(ev3);
        cudaEventDestroy(ev4); cudaEventDestroy(ev5);
        cudaEventDestroy(ev6);
    }
    return -1;

}  /* gpu_sieve_mark_batch */

}  /* extern "C" */
