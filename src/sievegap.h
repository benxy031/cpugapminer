#ifndef SIEVEGAP_H
#define SIEVEGAP_H

#include <stddef.h>
#include <stdint.h>

/* Standalone segmented odd-only sieve path.
 *
 * This API is intentionally independent from the legacy sieve pipeline in
 * main.c (presieve template, wheel backend, adaptive presieve, etc.).
 *
 * Inputs:
 *   L, R              relative odd-candidate range [L, R)
 *   h256, shift        base hash and shift (used only when base_mod_p cache is absent)
 *   small_primes       sorted prime table (same cache used by miner)
 *   small_primes_count number of entries in small_primes
 *   prime_limit        upper bound for sieving primes
 *   base_mod_p         optional cache: (h256 << shift) % p for each prime index
 *   base_mod_p_ready   whether base_mod_p is valid
 *   base_mod_p_version cache generation for CUDA offload path
 *
 * Output:
 *   *out_count         number of surviving offsets
 *   return value       pointer to thread-local array with surviving offsets
 */
uint64_t *sievegap_run_range(uint64_t L,
                             uint64_t R,
                             size_t *out_count,
                             const uint8_t *h256,
                             int shift,
                             const uint64_t *small_primes,
                             size_t small_primes_count,
                             uint64_t prime_limit,
                             const uint64_t *base_mod_p,
                             int base_mod_p_ready,
                             uint64_t base_mod_p_version);

/* Releases thread-local buffers allocated by sievegap_run_range(). */
void sievegap_free_tls_buffers(void);

#endif
