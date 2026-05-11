#ifndef PRIMALITY_UTILS_H
#define PRIMALITY_UTILS_H

#include <stdint.h>

int primality_miller_rabin_u64(uint64_t n);
int primality_fast_fermat_u64(uint64_t n);

/* Maximum limb count supported by fermat_test_cpu_nlimbs().
 * 20 limbs = 1280 bits, covering shifts up to 1024. */
#define FERMAT_CPU_MAX_LIMBS 20

/* Base-2 Fermat test for a multi-limb integer stored as an array of
 * nlimbs little-endian 64-bit words.  Uses CIOS Montgomery multiplication
 * with __uint128_t — faster than GMP mpz_powm for small fixed limb counts.
 * Returns 1 (probably prime) or 0 (composite). */
int fermat_test_cpu_nlimbs(const uint64_t *n, int nlimbs);

/* Euler–Plumb criterion: 2^((n-1)/2) ≡ ±1 (mod n).
 * ~50% fewer squarings than fermat_test_cpu_nlimbs.
 * Same CIOS Montgomery core; comparison done in Montgomery form
 * (no final de-Montgomery multiply).
 * Returns 1 (probably prime) or 0 (composite). */
int euler_test_cpu_nlimbs(const uint64_t *n, int nlimbs);

/* CPU Montgomery backend feature status.
 * On ADX/BMI2 builds, runtime detection may disable ADX path and use
 * portable CIOS fallback when the host CPU lacks required instructions. */
int primality_cpu_adx_compiled(void);
int primality_cpu_adx_enabled(void);

#endif
