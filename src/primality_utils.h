/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PRIMALITY_UTILS_H
#define PRIMALITY_UTILS_H

#include <stdint.h>

int primality_miller_rabin_u64(uint64_t n);
int primality_fast_fermat_u64(uint64_t n);

/* Maximum limb count supported by fermat_test_cpu_nlimbs().
 * 20 limbs = 1280 bits, covering shifts up to 1024. */
#define FERMAT_CPU_MAX_LIMBS 20

#define FERMAT_PRECOMP_WIN_ODD_COUNT 8

/* Exact-path precompute state for reusing candidate-specific Montgomery setup
 * across multiple base-2 tests on the same odd candidate.
 *
 * This variant is intended for workloads that run both Euler and Fermat on the
 * same candidate. It caches Montgomery base/window setup plus the prebuilt
 * exponents for win=4 exact-path execution.
 */
typedef struct {
	int nlimbs;
	int win_bits;
	uint64_t ninv;
	uint64_t n[FERMAT_CPU_MAX_LIMBS];
	uint64_t base_m[FERMAT_CPU_MAX_LIMBS];
	uint64_t win[FERMAT_PRECOMP_WIN_ODD_COUNT][FERMAT_CPU_MAX_LIMBS];
	uint64_t nm1[FERMAT_CPU_MAX_LIMBS];
	uint64_t fermat_exp[FERMAT_CPU_MAX_LIMBS];
	uint64_t euler_exp[FERMAT_CPU_MAX_LIMBS];
	int fermat_msb;
	int euler_msb;
} primality_exact_precomp_t;

/* Base-2 Fermat test for a multi-limb integer stored as an array of
 * nlimbs little-endian 64-bit words.  Uses CIOS Montgomery multiplication
 * with __uint128_t — faster than GMP mpz_powm for small fixed limb counts.
 * Returns 1 (probably prime) or 0 (composite). */
int fermat_test_cpu_nlimbs(const uint64_t *n, int nlimbs);
int primality_exact_precomp_init(primality_exact_precomp_t *precomp,
								 const uint64_t *n, int nlimbs);
int fermat_test_cpu_nlimbs_precomp(const primality_exact_precomp_t *precomp);

/* Euler–Plumb criterion: 2^((n-1)/2) ≡ ±1 (mod n).
 * ~50% fewer squarings than fermat_test_cpu_nlimbs.
 * Same CIOS Montgomery core; comparison done in Montgomery form
 * (no final de-Montgomery multiply).
 * Returns 1 (probably prime) or 0 (composite). */
int euler_test_cpu_nlimbs(const uint64_t *n, int nlimbs);
int euler_test_cpu_nlimbs_precomp(const primality_exact_precomp_t *precomp);

/* CPU Montgomery backend feature status.
 * On ADX/BMI2 builds, runtime detection may disable ADX path and use
 * portable CIOS fallback when the host CPU lacks required instructions. */
int primality_cpu_adx_compiled(void);
int primality_cpu_adx_enabled(void);

#endif
