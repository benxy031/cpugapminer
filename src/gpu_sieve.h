/* gpu_sieve.h — GPU-accelerated presieve (batch composite marking)
 *
 * Experimental Phase 1 GPU sieve for monolithic CRT mode only.
 * GPU kernel marks composites for batches of mid-range primes;
 * CPU handles edges (primes 2–999, tail primes >batch_hi).
 *
 * For use in presieve_window() path: presieve_utils.c calls
 * gpu_sieve_mark_batch() to accelerate composite marking.
 *
 * Compilation: WITH_CUDA=1 only. Not enabled in producer-consumer mode.
 */

#ifndef GPU_SIEVE_H
#define GPU_SIEVE_H

#include <stddef.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════════════════════════
 *  GPU Sieve Context (device memory management)
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  *d_segment;      /* device memory: byte-per-candidate mark buffer */
    uint8_t  *d_bits;         /* device memory: packed output bitmap */
    uint64_t *d_primes;       /* device memory: prime array (H→D copy input) */
    uint64_t *d_k0;           /* device memory: starting index per prime (H→D copy input) */
    size_t    d_segment_cap;  /* max segment size allocated */
    size_t    d_bits_cap;     /* max packed bitmap bytes allocated */
    size_t    d_primes_cap;   /* max primes in device array */
    const uint64_t *loaded_primes_src; /* last host prime slice uploaded */
    int       loaded_n_primes;/* last prime count uploaded */
    int       device_id;      /* GPU device ordinal (0–7) */
    int       initialized;    /* 1 = allocations succeeded */
    /* base_mod_p cache: d_base_mod_p[j] = (big_base) % primes[j].
     * Uploaded once per block header; reused across all windows. */
    uint64_t *d_base_mod_p;          /* device memory: base_mod_p per prime */
    const uint64_t *loaded_base_mod_p_src; /* last host base_mod_p slice uploaded */
    uint64_t  loaded_base_mod_p_version; /* version counter from caller; re-upload on mismatch */
    uint8_t  *h_bits_pinned;         /* pinned host staging for async D->H bitmap copy */
    size_t    h_bits_pinned_cap;     /* bytes allocated in h_bits_pinned */
    void     *stream;                /* cudaStream_t stored as opaque pointer */
    /* Compact survivor buffer (Phase-2 survivors, fixed-cap with overflow fallback).
     * When survivor count fits in cap, gpu_sieve_mark_batch returns 1 (compact mode)
     * and h_surv_pinned[0..last_surv_count-1] holds the Phase-2 survivor positions.
     * On overflow (count > survivors_cap), falls back to bitmap mode (return 0). */
    uint32_t *d_survivors;           /* device: compact survivor positions (uint32) */
    uint32_t *h_surv_pinned;         /* pinned host: survivor staging */
    uint32_t *d_surv_count;          /* device: atomic survivor count (1 element) */
    uint32_t *h_surv_count_pinned;   /* pinned host: count staging (1 element) */
    uint32_t  survivors_cap;         /* max survivors before bitmap fallback */
    uint32_t  last_surv_count;       /* survivors from last compact-mode call */
    /* Per-call timing (filled by gpu_sieve_mark_batch, in microseconds). */
    uint64_t  last_us_base_upload;   /* H->D base_mod_p transfer (rare) */
    uint64_t  last_us_compute_k0;    /* kernel_compute_k0 execution */
    uint64_t  last_us_mark;          /* kernel_mark_composites execution */
    uint64_t  last_us_compact;       /* kernel_compact_survivors execution */
    uint64_t  last_us_pack;          /* kernel_pack_bits execution (overflow path only) */
    uint64_t  last_us_bits_dl;       /* D->H bits download */
} gpu_sieve_ctx_t;

/* ═══════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════ */

#ifdef __cplusplus
extern "C" {
#endif

/* Allocate GPU device memory for sieve context.
 * Returns 0 on success, -1 on failure.
 * seg_cap:    bytes for device segment buffer (>= sieve_size/2 + 1).
 * primes_cap: entries for device primes buffer (>= small_primes_count). */
int gpu_sieve_ctx_alloc(
    gpu_sieve_ctx_t *ctx,
    size_t max_segment,   /* segment buffer bytes */
    size_t max_primes,    /* prime buffer entries */
    int device_id         /* GPU device ordinal */
);

/* Free GPU device memory. Safe to call multiple times. */
void gpu_sieve_ctx_free(gpu_sieve_ctx_t *ctx);

/* Mark composites in segment using GPU batch sieving.
 *
 * Input:
 *   ctx          — GPU context (must be initialized via gpu_sieve_ctx_alloc)
 *   h_bits       — host output bitmap, size bit_len bytes
 *   bit_len      — host bitmap capacity in bytes (must be >= (segment_len+7)/8)
 *   segment_len  — segment size in (odd) candidates
 *   h_primes     — host array of primes (stride for each thread)
 *   h_k0         — host array of starting indices: k0[j] is the first index in
 *                  [0, segment_len) where prime h_primes[j] divides the candidate.
 *                  Precomputed by caller including base_mod_p contribution.
 *                  Set k0[j] = segment_len to skip a prime (no multiples in window).
 *   n_primes     — number of entries in h_primes and h_k0
 *
 * Output:
 *   h_bits filled with a packed composite bitmap for the segment.
 *   Returns 0 on success (bitmap mode), 1 if compact survivors fit in cap
 *   (ctx->h_surv_pinned[0..last_surv_count-1] holds Phase-2 survivor positions),
 *   -1 on GPU error.
 */
/* Mark composites in segment using GPU batch sieving.
 *
 * k0 (first-composite index per prime) is now computed entirely on the GPU:
 *   k0[j] = first offset in [0, segment_len) where primes[j] divides the
 *           candidate, given base_mod_p[j] = big_base % primes[j].
 *
 * h_base_mod_p is uploaded to the device only when base_mod_p_version differs
 * from ctx->loaded_base_mod_p_version, avoiding a 15 MB transfer on every window.
 * Increment base_mod_p_version each time the block header (and thus base) changes.
 *
 * L and R are the odd-indexed window bounds; passed as kernel scalars (8 bytes each).
 *
 * Returns 0 on success, -1 on GPU error (caller should CPU-fallback).
 */
int gpu_sieve_mark_batch(
    gpu_sieve_ctx_t *ctx,
    uint8_t *h_bits,              /* host output bitmap (packed, seg_len/8 bytes) */
    size_t bit_len,               /* capacity of h_bits in bytes */
    size_t segment_len,           /* segment size in odd candidates */
    const uint64_t *h_primes,     /* host prime slice (stride per thread) */
    const uint64_t *h_base_mod_p, /* host base_mod_p slice (one entry per prime) */
    uint64_t base_mod_p_version,  /* caller-incremented on header change */
    uint64_t L,                   /* window start (odd candidate offset) */
    uint64_t R,                   /* window end (exclusive) */
    int n_primes
);

#ifdef __cplusplus
}
#endif

#endif /* GPU_SIEVE_H */
