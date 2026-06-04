/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PRESIEVE_UTILS_H
#define PRESIEVE_UTILS_H

#include <stdint.h>
#include <stddef.h>

struct presieve_buf {
    uint64_t *pr;
    size_t    cap;
    size_t    cnt;
    uint64_t  L;
    uint64_t  R;
};

int presieve_buf_ensure(struct presieve_buf *b, size_t need);
int presieve_window(int64_t widx, uint64_t base,
                    uint64_t sieve_size, uint64_t adder_max,
                    uint64_t *out_L, uint64_t *out_R);

/* GPU sieve integration (Phase 1 experimental, monolithic CRT only) */
#ifdef WITH_CUDA
#ifndef WITH_CRT_GPU_CONSUMER

/* Global flag to enable/disable GPU sieve at runtime */
extern int g_gpu_sieve_enable;

/* Initialize GPU sieve context (call once at startup if using GPU sieve).
 * seg_cap:    device segment buffer bytes (>= sieve_size/2 + 1).
 * primes_cap: device primes buffer entries (>= small_primes_count).
 * Returns 0 on success, -1 on GPU unavailable. */
int gpu_sieve_init(size_t seg_cap, size_t primes_cap);

/* Configure CUDA device IDs used by GPU sieve worker contexts.
 * If not called (or n_devices <= 0), gpu_sieve_init() defaults to all visible
 * CUDA devices.  Call before gpu_sieve_init().
 * Returns 0 on success, -1 on invalid input. */
int gpu_sieve_set_devices(const int *device_ids, int n_devices);

/* Returns selected GPU sieve CUDA device IDs in out_device_ids (up to max_ids).
 * Returns number of IDs written (or available if max_ids <= 0). */
int gpu_sieve_get_devices(int *out_device_ids, int max_ids);

/* Mark composites in segment using GPU batch sieving.
 * h_k0[j] is the precomputed first-composite index for h_primes[j],
 * accounting for base_mod_p. Set h_k0[j] = segment_len to skip a prime.
 * h_bits receives the packed bitmap for the odd-only segment.
 * Returns 0 on success, -1 on GPU error (caller should CPU-fallback). */
/* Mark composites in segment using GPU batch sieving.
 * k0 is computed on-device from base_mod_p[j] and L.
 * base_mod_p_version must be incremented by the caller each time the block
 * header (and thus base) changes; the GPU ctx re-uploads base_mod_p only then.
 * h_bits receives the packed bitmap for the odd-only segment.
 * Returns 0 on success, -1 on GPU error (caller should CPU-fallback). */
int gpu_sieve_mark_segment_batch(
    uint8_t *h_bits,
    size_t bit_len,
    size_t segment_len,
    const uint8_t *h_phase1_bits,
    const uint64_t *h_primes,
    const uint64_t *h_base_mod_p,
    uint64_t base_mod_p_version,
    uint64_t L,
    uint64_t R,
    int n_primes
);

void gpu_sieve_cleanup(void);

/* After a call to gpu_sieve_mark_segment_batch that returned 1 (compact mode),
 * returns a pointer to the thread-local array of Phase-2 survivor positions
 * (uint32 indices into the odd-candidate segment).  count_out is set to the
 * number of entries.  Returns NULL if the last call was bitmap mode or failed.
 * Valid only until the next call to gpu_sieve_mark_segment_batch on this thread. */
const uint32_t *gpu_sieve_last_survivors(uint32_t *count_out);

#endif /* !WITH_CRT_GPU_CONSUMER */
#endif /* WITH_CUDA */

#endif /* PRESIEVE_UTILS_H */
