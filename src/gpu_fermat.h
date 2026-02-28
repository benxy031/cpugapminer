/* gpu_fermat.h — CUDA batch Fermat primality testing for Gapcoin
 *
 * Tests batches of large prime candidates using Fermat's little theorem:
 *   n is probably prime if 2^(n-1) ≡ 1 (mod n)
 *
 * Uses Montgomery multiplication on GPU for efficient modular arithmetic.
 * Each CUDA thread independently tests one candidate.
 *
 * GPU_NLIMBS controls the maximum candidate size:
 *   6 limbs = 384 bits  → shift ≤ 128
 *  12 limbs = 768 bits  → shift ≤ 512
 *  16 limbs = 1024 bits → shift ≤ 768  (default)
 *  20 limbs = 1280 bits → shift ≤ 1024
 *
 * Override at compile time: -DGPU_NLIMBS=16 or via Makefile GPU_BITS=1024
 */
#ifndef GPU_FERMAT_H
#define GPU_FERMAT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Number of 64-bit limbs per candidate.
   Default 16 limbs = 1024 bits, sufficient for hash(256) + shift(≤768).
   Override with -DGPU_NLIMBS=N at compile time for other shift ranges. */
#ifndef GPU_NLIMBS
#define GPU_NLIMBS 16
#endif

/* Opaque GPU context */
typedef struct gpu_fermat_ctx gpu_fermat_ctx;

/* Initialize GPU Fermat tester.
   device_id:  CUDA device index (usually 0).
   max_batch:  maximum candidates per batch call.
   Returns NULL on failure (no GPU, driver error, out of memory). */
gpu_fermat_ctx *gpu_fermat_init(int device_id, size_t max_batch);

/* Batch Fermat primality test.
   candidates: array of count candidates, each GPU_NLIMBS uint64_t limbs
               in little-endian limb order (limb[0] = least significant).
   results:    output array of count bytes, 1 = probably prime, 0 = composite.
   count:      number of candidates to test.
   Returns number of probable primes found, or -1 on error. */
int gpu_fermat_test_batch(gpu_fermat_ctx *ctx,
                          const uint64_t *candidates,
                          uint8_t *results,
                          size_t count);

/* Return the CUDA device name (for logging).  Returns "" on error. */
const char *gpu_fermat_device_name(gpu_fermat_ctx *ctx);

/* Free GPU resources. */
void gpu_fermat_destroy(gpu_fermat_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* GPU_FERMAT_H */
