/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

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
#include <mutex>
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

/* Optional diagnostic mode: serialize GPU sieve calls while timing is enabled
 * so stage timings are less distorted by cross-stream queueing. */
static int gpu_sieve_timing_serial_enabled(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;
    {
        const char *v = getenv("GPU_SIEVE_TIMING_SERIAL");
        cached = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
    }
    return cached;
}

static std::mutex g_gpu_sieve_timing_serial_mu;

/* Runtime A/B switch for the direct packed-bitmap mark path.
 * Default ON; set GPU_SIEVE_DIRECT_BITS=0 to force scratch+pack fallback. */
static int gpu_sieve_direct_bits_enabled(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;
    {
        const char *v = getenv("GPU_SIEVE_DIRECT_BITS");
        cached = (!v || !*v || strcmp(v, "0") != 0) ? 1 : 0;
    }
    return cached;
}

/* Optional clear-kernel A/B switch.
 * Default OFF; set GPU_SIEVE_CLEAR_KERNEL=1 to replace cudaMemsetAsync with
 * a simple grid-stride zero kernel for the active output surface. */
static int gpu_sieve_clear_kernel_enabled(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;
    {
        const char *v = getenv("GPU_SIEVE_CLEAR_KERNEL");
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

    uint32_t seg_len32 = (uint32_t)segment_len;
    uint32_t p = (uint32_t)primes[idx];
    uint32_t k = (uint32_t)k0_array[idx];  /* first composite index, cached residue */

    for (uint32_t ki = k; ki < seg_len32; ki += p)
        segment[ki] = 1;
}

/* Kernel: mark composites directly into the packed output bitmap.
 * Each thread owns one prime and atomic-ORs candidate bits into d_bits. */
__global__ static void kernel_mark_composites_bits(
    uint8_t *bits,
    size_t segment_len,
    const uint64_t *primes,
    const uint64_t *k0_array,
    int n_primes
)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx >= n_primes)
        return;

    uint32_t seg_len32 = (uint32_t)segment_len;
    uint32_t p = (uint32_t)primes[idx];
    uint32_t k = (uint32_t)k0_array[idx];
    uint32_t *words = (uint32_t *)bits;

    for (uint32_t ki = k; ki < seg_len32; ki += p)
        atomicOr(words + (ki >> 5), 1u << (ki & 31));
}

/* Optional diagnostic clear kernel for A/B timing against cudaMemsetAsync. */
__global__ static void kernel_clear_bytes(
    uint8_t *buf,
    size_t len)
{
    size_t tid = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    size_t stride = (size_t)gridDim.x * blockDim.x;
    size_t n64 = len >> 3;
    uint64_t *buf64 = (uint64_t *)buf;

    for (size_t i = tid; i < n64; i += stride)
        buf64[i] = 0ULL;

    for (size_t i = (n64 << 3) + tid; i < len; i += stride)
        buf[i] = 0;
}

__global__ static void kernel_pack_bits(
    const uint8_t *segment,
    uint8_t *bits,
    size_t segment_len,
    size_t bit_len
)
{
    uint32_t pos = (uint32_t)((size_t)blockIdx.x * blockDim.x + threadIdx.x);
    uint32_t lane = (uint32_t)(threadIdx.x & 31u);
    uint32_t warp_base = pos & ~31u;
    int is_set = ((size_t)pos < segment_len) && (segment[pos] != 0);
    uint32_t packed32 = __ballot_sync(0xFFFFFFFFu, is_set);

    if (lane == 0u) {
        size_t byte_base = (size_t)warp_base >> 3;
        if (byte_base >= bit_len)
            return;

        if (byte_base + 4u <= bit_len) {
            bits[byte_base + 0] = (uint8_t)( packed32        & 0xFFu);
            bits[byte_base + 1] = (uint8_t)((packed32 >> 8)  & 0xFFu);
            bits[byte_base + 2] = (uint8_t)((packed32 >> 16) & 0xFFu);
            bits[byte_base + 3] = (uint8_t)((packed32 >> 24) & 0xFFu);
        } else {
            if (byte_base + 0u < bit_len) bits[byte_base + 0] = (uint8_t)( packed32        & 0xFFu);
            if (byte_base + 1u < bit_len) bits[byte_base + 1] = (uint8_t)((packed32 >> 8)  & 0xFFu);
            if (byte_base + 2u < bit_len) bits[byte_base + 2] = (uint8_t)((packed32 >> 16) & 0xFFu);
            if (byte_base + 3u < bit_len) bits[byte_base + 3] = (uint8_t)((packed32 >> 24) & 0xFFu);
        }
    }
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
    (void)R;
    (void)segment_len;
    /* Keep residue in [0, p): clipping to segment_len is done implicitly
     * by kernel_mark_composites (k >= segment_len means no marks). */
    k0[idx] = (start - L) >> 1;
}

/* Kernel: precompute dmod[idx] = delta_idx % primes[idx].
 * Used to avoid variable modulo in the hot incremental update path. */
__global__ static void kernel_prepare_delta_mod(
    uint32_t *dmod,
    const uint64_t *primes,
    uint32_t delta_idx,
    int n_primes
)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_primes) return;

    uint32_t p = (uint32_t)primes[idx];
    dmod[idx] = delta_idx % p;
}

/* Kernel: hot incremental path.
 * Update cached k0 residue and immediately mark segment, avoiding a separate
 * full pass that writes d_k0 and then reads it back in kernel_mark_composites.
 */
__global__ static void kernel_increment_k0_and_mark_cached(
    uint8_t *segment,
    size_t segment_len,
    const uint64_t *primes,
    uint64_t *k0,
    const uint32_t *dmod,
    int subtract_dir,
    int n_primes
)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_primes) return;

    uint32_t seg_len32 = (uint32_t)segment_len;
    uint32_t p = (uint32_t)primes[idx];
    uint32_t k = (uint32_t)k0[idx];
    uint32_t d = dmod[idx];
    uint32_t kn;
    if (subtract_dir) {
        kn = (k >= d) ? (k - d) : (k + (p - d));
    } else {
        uint32_t s = k + d;
        kn = (s >= p) ? (s - p) : s;
    }
    k0[idx] = (uint64_t)kn;

    for (uint32_t ki = kn; ki < seg_len32; ki += p)
        segment[ki] = 1;
}

/* Kernel: hot incremental path for direct bitmap output.
 * Update cached k0 residue and immediately mark packed d_bits. */
__global__ static void kernel_increment_k0_and_mark_bits_cached(
    uint8_t *bits,
    size_t segment_len,
    const uint64_t *primes,
    uint64_t *k0,
    const uint32_t *dmod,
    int subtract_dir,
    int n_primes
)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_primes) return;

    uint32_t seg_len32 = (uint32_t)segment_len;
    uint32_t p = (uint32_t)primes[idx];
    uint32_t k = (uint32_t)k0[idx];
    uint32_t d = dmod[idx];
    uint32_t kn;
    uint32_t *words = (uint32_t *)bits;

    if (subtract_dir) {
        kn = (k >= d) ? (k - d) : (k + (p - d));
    } else {
        uint32_t s = k + d;
        kn = (s >= p) ? (s - p) : s;
    }
    k0[idx] = (uint64_t)kn;

    for (uint32_t ki = kn; ki < seg_len32; ki += p)
        atomicOr(words + (ki >> 5), 1u << (ki & 31));
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

    /* Allocate cached delta_mod buffer (one uint32 per prime). */
    err = cudaMalloc(&ctx->d_delta_mod, ctx->d_primes_cap * sizeof(uint32_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(delta_mod, %zu) failed: %s\n",
                ctx->d_primes_cap * sizeof(uint32_t), cudaGetErrorString(err));
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
    
    /* Allocate base_mod_p buffer (one entry per prime, per block header) */
    err = cudaMalloc(&ctx->d_base_mod_p, ctx->d_primes_cap * sizeof(uint64_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: cudaMalloc(base_mod_p, %zu) failed: %s\n",
                ctx->d_primes_cap * sizeof(uint64_t), cudaGetErrorString(err));
        cudaFree(ctx->d_k0);
        ctx->d_k0 = NULL;
        cudaFree(ctx->d_delta_mod);
        ctx->d_delta_mod = NULL;
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
        cudaFree(ctx->d_delta_mod);
        ctx->d_delta_mod = NULL;
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
        cudaFree(ctx->d_delta_mod);
        ctx->d_delta_mod = NULL;
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
        cudaFree(ctx->d_delta_mod);
        ctx->d_delta_mod = NULL;
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

    if (ctx->d_delta_mod) {
        cudaFree(ctx->d_delta_mod);
        ctx->d_delta_mod = NULL;
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
    ctx->k0_cache_valid = 0;
    ctx->last_k0_L = 0;
    ctx->last_k0_segment_len = 0;
    ctx->last_k0_n_primes = 0;
    ctx->last_delta_idx = 0;
    ctx->delta_mod_valid = 0;
    ctx->last_k0_mode_inc = 0;
    ctx->last_k0_delta_prepared = 0;
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
    ctx->last_us_zero = 0;
    ctx->last_us_compute_k0 = 0;
    ctx->last_us_mark = 0;
    ctx->last_us_compact = 0;
    ctx->last_us_pack = 0;
    ctx->last_us_bits_dl = 0;
    ctx->last_surv_count = 0;
    ctx->last_k0_mode_inc = 0;
    ctx->last_k0_delta_prepared = 0;

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
    int use_incremental_k0 = 0;
    uint32_t delta_idx_abs_u32 = 0;
    int delta_subtract_dir = 1;
    int has_surv_buf = 0;
    int use_phase1_compact = 0;
    int try_compact = 0;
    int direct_bitmap_path = 0;
    int timing_serial_lock_held = 0;

    int timing = gpu_sieve_timing_enabled();
    /* Event timings are elapsed time on this stream, so with pooled contexts
     * they can include queueing contention from other in-flight GPU sieve calls.
     * Use GPU_SIEVE_TIMING_SERIAL=1 for less contended diagnostic timings. */
    /* 8 CUDA events: base/setup (ev0/ev1), clear (ev1/ev2), compute_k0 (ev2/ev3),
     *                mark (ev3/ev4), compact (ev4/ev5), pack (ev5/ev6),
     *                bits_dl (ev6/ev7) */
    cudaEvent_t ev0, ev1, ev2, ev3, ev4, ev5, ev6, ev7;
    if (timing && gpu_sieve_timing_serial_enabled()) {
        g_gpu_sieve_timing_serial_mu.lock();
        timing_serial_lock_held = 1;
    }
    if (timing) {
        cudaEventCreate(&ev0); cudaEventCreate(&ev1);
        cudaEventCreate(&ev2); cudaEventCreate(&ev3);
        cudaEventCreate(&ev4); cudaEventCreate(&ev5);
        cudaEventCreate(&ev6); cudaEventCreate(&ev7);
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
        ctx->k0_cache_valid = 0;
        ctx->delta_mod_valid = 0;
    } else {
        ctx->loaded_base_mod_p_src = h_base_mod_p;
    }
    /* Upload primes on count/pointer change. The prime slice is immutable for
     * a given run, so full-buffer memcmp here only adds host-side overhead. */
    primes_bytes = (size_t)n_primes * sizeof(uint64_t);
    need_primes_upload =
        (ctx->loaded_primes_n != n_primes) ||
        (ctx->h_primes_shadow == NULL);

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
        ctx->k0_cache_valid = 0;
        ctx->delta_mod_valid = 0;
    } else {
        ctx->loaded_primes_src = h_primes;
    }

    if (ctx->k0_cache_valid &&
        !need_base_mod_p_upload &&
        !need_primes_upload &&
        ctx->last_k0_n_primes == n_primes &&
        ctx->last_k0_segment_len == segment_len &&
        h_primes[n_primes - 1] <= 0xFFFFFFFFULL) {
        uint64_t delta_L;
        if (L >= ctx->last_k0_L) {
            delta_L = L - ctx->last_k0_L;
            delta_subtract_dir = 1;
        } else {
            delta_L = ctx->last_k0_L - L;
            delta_subtract_dir = 0;
        }
        if ((delta_L & 1ULL) == 0ULL) {
            uint64_t delta_idx_abs = delta_L >> 1;
            if (delta_idx_abs <= 0xFFFFFFFFULL) {
                use_incremental_k0 = 1;
                delta_idx_abs_u32 = (uint32_t)delta_idx_abs;
            }
        }
    }

    has_surv_buf = (ctx->d_survivors && ctx->d_surv_count &&
                    ctx->h_surv_pinned && ctx->h_surv_count_pinned &&
                    ctx->survivors_cap > 0);
    use_phase1_compact = (h_phase1_bits != NULL) && gpu_sieve_final_compact_enabled();
    try_compact = has_surv_buf &&
        (use_phase1_compact || gpu_sieve_should_try_compact(
            segment_len, ctx->survivors_cap, h_primes, n_primes));
    direct_bitmap_path = !try_compact && gpu_sieve_direct_bits_enabled();

    if (timing) cudaEventRecord(ev1, stream); /* ev0..ev1 = upload/setup before clear */

    /* Zero the active GPU output surface for this window. */
    {
        uint8_t *clear_ptr = direct_bitmap_path ? ctx->d_bits : ctx->d_segment;
        size_t clear_len = direct_bitmap_path ? out_bytes : segment_len;
        if (gpu_sieve_clear_kernel_enabled()) {
            int clear_blocks = (int)((clear_len + GPU_SIEVE_THREADS_PER_BLOCK - 1)
                                     / GPU_SIEVE_THREADS_PER_BLOCK);
            if (clear_blocks < 1)
                clear_blocks = 1;
            if (clear_blocks > 4096)
                clear_blocks = 4096;
            kernel_clear_bytes<<<clear_blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                clear_ptr, clear_len);
            err = cudaGetLastError();
            if (err != cudaSuccess) {
                fprintf(stderr, "GPU sieve: clear kernel launch failed: %s\n",
                        cudaGetErrorString(err));
                goto timing_cleanup;
            }
        } else {
            err = cudaMemsetAsync(clear_ptr, 0, clear_len, stream);
            if (err != cudaSuccess) {
                fprintf(stderr, "GPU sieve: cudaMemset(%s) failed: %s\n",
                        direct_bitmap_path ? "bits" : "segment",
                        cudaGetErrorString(err));
                goto timing_cleanup;
            }
        }
    }
    if (timing) cudaEventRecord(ev2, stream); /* ev1..ev2 = active surface clear */

    /* ── Stage 1: compute k0 on GPU ─────────────────────────────── */
    if (use_incremental_k0) {
        ctx->last_k0_mode_inc = 1;
        if (!ctx->delta_mod_valid || ctx->last_delta_idx != delta_idx_abs_u32) {
            kernel_prepare_delta_mod<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                ctx->d_delta_mod, ctx->d_primes, delta_idx_abs_u32, n_primes);
            err = cudaGetLastError();
            if (err != cudaSuccess) {
                fprintf(stderr, "GPU sieve: kernel_prepare_delta_mod launch failed: %s\n",
                        cudaGetErrorString(err));
                goto timing_cleanup;
            }
            ctx->last_delta_idx = delta_idx_abs_u32;
            ctx->delta_mod_valid = 1;
            ctx->last_k0_delta_prepared = 1;
        }
        if (timing) cudaEventRecord(ev3, stream); /* ev2..ev3 = delta_mod prep (or ~0 when cached) */
        if (direct_bitmap_path) {
            kernel_increment_k0_and_mark_bits_cached<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                ctx->d_bits, segment_len, ctx->d_primes, ctx->d_k0,
                ctx->d_delta_mod, delta_subtract_dir, n_primes);
        } else {
            kernel_increment_k0_and_mark_cached<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                ctx->d_segment, segment_len, ctx->d_primes, ctx->d_k0,
                ctx->d_delta_mod, delta_subtract_dir, n_primes);
        }
    } else {
        kernel_compute_k0<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
            ctx->d_k0, ctx->d_primes, ctx->d_base_mod_p,
            L, R, segment_len, L_u32, L_fits_u32, n_primes);
        ctx->delta_mod_valid = 0;
        if (timing) cudaEventRecord(ev3, stream); /* ev2..ev3 = compute_k0 kernel */
    }
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "GPU sieve: kernel_compute_k0 launch failed: %s\n",
                cudaGetErrorString(err));
        goto timing_cleanup;
    }
    ctx->k0_cache_valid = 1;
    ctx->last_k0_L = L;
    ctx->last_k0_segment_len = segment_len;
    ctx->last_k0_n_primes = n_primes;

    /* ── Stage 2: kernel_mark_composites ───────────────────────── */
    if (use_incremental_k0) {
        if (timing) cudaEventRecord(ev4, stream); /* ev3..ev4 = fused incr+mark kernel */
        err = cudaGetLastError();
        if (err != cudaSuccess) {
            fprintf(stderr, "GPU sieve: fused incremental mark launch failed: %s\n",
                    cudaGetErrorString(err));
            goto timing_cleanup;
        }
    } else {
        if (direct_bitmap_path) {
            kernel_mark_composites_bits<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                ctx->d_bits, segment_len, ctx->d_primes, ctx->d_k0, n_primes);
        } else {
            kernel_mark_composites<<<blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
                ctx->d_segment, segment_len, ctx->d_primes, ctx->d_k0, n_primes);
        }
        if (timing) cudaEventRecord(ev4, stream); /* ev3..ev4 = mark kernel */
        err = cudaGetLastError();
        if (err != cudaSuccess) {
            fprintf(stderr, "GPU sieve: mark kernel launch failed: %s\n",
                    cudaGetErrorString(err));
            goto timing_cleanup;
        }
    }

    /* ── Stage 2.5: kernel_compact_survivors ────────────────────── */
    if (!direct_bitmap_path) {
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
        if (timing) cudaEventRecord(ev5, stream); /* ev4..ev5 = compact kernel */

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
                            cudaEventSynchronize(ev5);
                            if (cudaEventElapsedTime(&ms, ev0, ev1) == cudaSuccess)
                                ctx->last_us_base_upload = (uint64_t)(ms * 1000.0f + 0.5f);
                            if (cudaEventElapsedTime(&ms, ev1, ev2) == cudaSuccess)
                                ctx->last_us_zero = (uint64_t)(ms * 1000.0f + 0.5f);
                            if (cudaEventElapsedTime(&ms, ev2, ev3) == cudaSuccess)
                                ctx->last_us_compute_k0 = (uint64_t)(ms * 1000.0f + 0.5f);
                            if (cudaEventElapsedTime(&ms, ev3, ev4) == cudaSuccess)
                                ctx->last_us_mark = (uint64_t)(ms * 1000.0f + 0.5f);
                            if (cudaEventElapsedTime(&ms, ev4, ev5) == cudaSuccess)
                                ctx->last_us_compact = (uint64_t)(ms * 1000.0f + 0.5f);
                            cudaEventDestroy(ev0); cudaEventDestroy(ev1);
                            cudaEventDestroy(ev2); cudaEventDestroy(ev3);
                            cudaEventDestroy(ev4); cudaEventDestroy(ev5);
                            cudaEventDestroy(ev6); cudaEventDestroy(ev7);
                        }
                        /* h_bits is intentionally not filled in compact mode. */
                            if (timing_serial_lock_held) {
                                g_gpu_sieve_timing_serial_mu.unlock();
                                timing_serial_lock_held = 0;
                            }
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
    } else if (timing) {
        cudaEventRecord(ev5, stream); /* ev4..ev5 = compact stage skipped */
    }

    /* ── Stage 3: kernel_pack_bits (bitmap fallback path) ───────── */
    if (direct_bitmap_path) {
        if (timing) cudaEventRecord(ev6, stream); /* ev5..ev6 = pack stage skipped */
    } else {
        int pack_blocks = (int)((segment_len + GPU_SIEVE_THREADS_PER_BLOCK - 1)
                                / GPU_SIEVE_THREADS_PER_BLOCK);
        kernel_pack_bits<<<pack_blocks, GPU_SIEVE_THREADS_PER_BLOCK, 0, stream>>>(
            ctx->d_segment, ctx->d_bits, segment_len, out_bytes);
        if (timing) cudaEventRecord(ev6, stream); /* ev5..ev6 = pack kernel */
        err = cudaGetLastError();
        if (err != cudaSuccess) {
            fprintf(stderr, "GPU sieve: kernel_pack_bits launch failed: %s\n",
                    cudaGetErrorString(err));
            goto timing_cleanup;
        }
    }

    /* ── Stage 4: bitmap download (fallback path) ───────────────── */
    if (ctx->h_bits_pinned && out_bytes <= ctx->h_bits_pinned_cap) {
        err = cudaMemcpyAsync(ctx->h_bits_pinned, ctx->d_bits, out_bytes,
                              cudaMemcpyDeviceToHost, stream);
    } else {
        err = cudaMemcpyAsync(h_bits, ctx->d_bits, out_bytes,
                              cudaMemcpyDeviceToHost, stream);
    }
    if (timing) cudaEventRecord(ev7, stream); /* ev6..ev7 = bits download */
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
     *   ev0..ev1 : upload/setup before clear
     *   ev1..ev2 : active surface clear
     *   ev2..ev3 : compute_k0 / delta_mod-prepare stage
     *   ev3..ev4 : mark stage (or fused incr+mark)
     *   ev4..ev5 : kernel_compact_survivors
     *   ev5..ev6 : kernel_pack_bits
     *   ev6..ev7 : D→H download
     */
    if (timing) {
        float ms;
        cudaEventSynchronize(ev7);
        if (cudaEventElapsedTime(&ms, ev0, ev1) == cudaSuccess)
            ctx->last_us_base_upload = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev1, ev2) == cudaSuccess)
            ctx->last_us_zero = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev2, ev3) == cudaSuccess)
            ctx->last_us_compute_k0 = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev3, ev4) == cudaSuccess)
            ctx->last_us_mark = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev4, ev5) == cudaSuccess)
            ctx->last_us_compact = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev5, ev6) == cudaSuccess)
            ctx->last_us_pack = (uint64_t)(ms * 1000.0f + 0.5f);
        if (cudaEventElapsedTime(&ms, ev6, ev7) == cudaSuccess)
            ctx->last_us_bits_dl = (uint64_t)(ms * 1000.0f + 0.5f);
    }

    if (timing) {
        cudaEventDestroy(ev0); cudaEventDestroy(ev1);
        cudaEventDestroy(ev2); cudaEventDestroy(ev3);
        cudaEventDestroy(ev4); cudaEventDestroy(ev5);
        cudaEventDestroy(ev6); cudaEventDestroy(ev7);
    }

    /* Bitmap mode: copy from pinned staging to caller h_bits */
    if (ctx->h_bits_pinned && out_bytes <= ctx->h_bits_pinned_cap) {
        memcpy(h_bits, ctx->h_bits_pinned, out_bytes);
    }
    if (timing_serial_lock_held) {
        g_gpu_sieve_timing_serial_mu.unlock();
        timing_serial_lock_held = 0;
    }
    return 0; /* bitmap mode */

timing_cleanup:
    if (timing) {
        cudaEventDestroy(ev0); cudaEventDestroy(ev1);
        cudaEventDestroy(ev2); cudaEventDestroy(ev3);
        cudaEventDestroy(ev4); cudaEventDestroy(ev5);
        cudaEventDestroy(ev6); cudaEventDestroy(ev7);
    }
    if (timing_serial_lock_held) {
        g_gpu_sieve_timing_serial_mu.unlock();
        timing_serial_lock_held = 0;
    }
    return -1;

}  /* gpu_sieve_mark_batch */

}  /* extern "C" */
