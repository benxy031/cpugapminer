#ifndef CRT_SOLVER_H
#define CRT_SOLVER_H

#include <stdint.h>
#include <stddef.h>

/*
 * CRT Solver per-nonce window template
 * ──────────────────────────────────────────────────────────────────
 * In CRT_MODE_SOLVER the sieve window is always [L=1, R=gap_scan_max)
 * relative to the CRT-aligned base.  After CRT alignment and
 * rebase_for_gap_check(candidate), tls_base_mod_p[i] holds:
 *
 *   candidate ≡  tls_base_mod_p[i]  (mod prime_list[i])
 *
 * A position t in the window is composite (divisible by prime p_i) iff:
 *
 *   (candidate + t) ≡ 0 (mod p_i)  →  t ≡ -tls_base_mod_p[i] (mod p_i)
 *
 * Key invariant: primorial is the product of all CRT primes, so
 *   primorial mod p_i = 0  for every CRT prime p_i.
 * When the base advances by one primorial between windows,
 * tls_base_mod_p[i] is UNCHANGED.  Therefore a template built once
 * after rebase_for_gap_check() is valid for ALL windows in that nonce.
 *
 * The template is stored per-thread (TLS) so multiple sieve threads
 * can each maintain their own without synchronisation.
 *
 * Impact on other paths
 * ─────────────────────
 * • Non-CRT sliding-window sieve   — untouched (branch on CRT_MODE_SOLVER)
 * • CRT_MODE_TEMPLATE (binary CRT) — untouched (separate branch)
 * • GPU Fermat path                — zero change; template only affects
 *   the bitmap init inside sieve_range(); the same survivors array is
 *   then fed to the GPU, with fewer CPU cycles spent building it.
 * • Producer-consumer heap         — sieve PRODUCER threads each build
 *   their own TLS template per nonce; CONSUMER threads never call
 *   sieve_range(), so they are unaffected.
 */

/* Index into small_primes_cache[] of the first prime ABOVE g_crt_max_prime.
 * Set once at startup by crt_solver_init(); used as skip_to in sieve_range()
 * when the per-nonce template is active. */
extern int g_crt_solver_skip_to;

/*
 * crt_solver_init — call once at startup after populate_small_primes_cache().
 * Computes and stores g_crt_solver_skip_to.
 */
void crt_solver_init(uint64_t       crt_max_prime,
                     const uint64_t *prime_cache,
                     size_t          prime_count);

/*
 * crt_solver_rebuild_thread_tmpl — call once per nonce, immediately after
 * rebase_for_gap_check() has populated tls_base_mod_p[].
 *
 * Builds a per-thread composite bitmap of size (gap_scan_max/2+1+7)/8 bytes.
 * The bitmap marks every odd position t in [1, gap_scan_max] that is
 * divisible by at least one CRT prime as composite (bit = 1).  All other
 * positions are left as 0 (candidate).  sieve_range() then memcpy's this
 * bitmap and continues from prime_cache[g_crt_solver_skip_to] onward.
 *
 * The template depends only on the CRT offsets, not on the block hash.
 * It is built ONCE at startup by crt_solver_build_static_tmpl() and
 * reused for every nonce.  crt_solver_rebuild_thread_tmpl() is a no-op.
 */

/*
 * crt_solver_build_static_tmpl — call once at startup after loading the
 * CRT file (after crt_solver_init).  Builds a read-only shared bitmap from
 * the fixed per-prime offsets.  Thread-safe once built (read-only after).
 *
 *   offsets     — g_crt_offsets[]   (offset[i] for prime i)
 *   primes      — g_crt_prime_list[] (prime values)
 *   n_primes    — g_crt_n_primes
 *   gap_scan_max — g_crt_gap_target * 2 (clamped to >= 10000)
 */
/*
 * adj — odd-adjustment: 0 if base+nAdd0 is always even, 1 if always odd.
 * base = h256<<shift is always even, so adj = nAdd0(base=0) mod 2.
 * Compute in main.c via crt_nAdd0_parity() and pass here.
 * When adj=1 (base+nAdd0 odd), candidate = base+nAdd0-1, so composite
 * positions shift: t ≡ (offset_i + adj) mod p_i.
 */
void crt_solver_build_static_tmpl(const int *offsets,
                                  const int *primes,
                                  int        n_primes,
                                  int        gap_scan_max,
                                  int        adj);

/* No-op kept for call-site compatibility. */
void crt_solver_rebuild_thread_tmpl(const uint64_t *base_mod_p,
                                    const uint64_t *prime_cache,
                                    int             gap_scan_max);

/*
 * crt_solver_get_thread_tmpl — called by sieve_range().
 * Returns the global static template if it covers bit_size bytes,
 * and sets *out_skip_to = g_crt_solver_skip_to.  Returns NULL otherwise.
 */
const uint8_t *crt_solver_get_thread_tmpl(size_t bit_size, int *out_skip_to);

#endif /* CRT_SOLVER_H */
