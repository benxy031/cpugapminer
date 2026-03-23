#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "crt_solver.h"

/* ── Startup globals ── */
int g_crt_solver_skip_to = 0;

void crt_solver_init(uint64_t       crt_max_prime,
                     const uint64_t *prime_cache,
                     size_t          prime_count)
{
    g_crt_solver_skip_to = 0;
    if (!prime_cache || crt_max_prime == 0) return;
    for (size_t i = 0; i < prime_count; i++) {
        if (prime_cache[i] > crt_max_prime) break;
        g_crt_solver_skip_to = (int)(i + 1);
    }
}

/* ── Per-thread (TLS) template ── */
static __thread uint8_t *tls_nonce_tmpl       = NULL;
static __thread size_t   tls_nonce_tmpl_bytes = 0;
static __thread int      tls_nonce_tmpl_valid = 0;

void crt_solver_rebuild_thread_tmpl(const uint64_t *base_mod_p,
                                    const uint64_t *prime_cache,
                                    int             gap_scan_max)
{
    /* sieve_range() odd-only bitmap layout:
     *   L = 1 (odd), R = gap_scan_max+1 (odd, since gap_scan_max is even)
     *   seg_size = (R - L)/2 + 1 = gap_scan_max/2 + 1
     * Position k in the bitmap represents odd value t = 1 + 2k.
     *
     * After CRT alignment + rebase_for_gap_check(candidate):
     *   candidate mod p_i  =  base_mod_p[i]
     * Position t is composite for prime p_i iff:
     *   (candidate + t) mod p_i == 0  →  t ≡ (p_i - base_mod_p[i]) mod p_i
     *
     * Invariant: primorial mod p_i = 0 for every CRT prime p_i, so
     * base_mod_p[i] is unchanged across all windows in one nonce.
     * Build once per nonce; reuse for all windows.                       */

    if (!base_mod_p || !prime_cache || g_crt_solver_skip_to <= 0) {
        tls_nonce_tmpl_valid = 0;
        return;
    }

    size_t seg_size = (size_t)gap_scan_max / 2 + 1;
    size_t bytes    = (seg_size + 7) / 8;

    if (tls_nonce_tmpl_bytes < bytes) {
        free(tls_nonce_tmpl);
        tls_nonce_tmpl = (uint8_t *)malloc(bytes);
        if (!tls_nonce_tmpl) {
            tls_nonce_tmpl_bytes = 0;
            tls_nonce_tmpl_valid = 0;
            return;
        }
        tls_nonce_tmpl_bytes = bytes;
    }

    /* Start: all positions are prime candidates (0 = not composite). */
    memset(tls_nonce_tmpl, 0, bytes);

    for (int i = 0; i < g_crt_solver_skip_to; i++) {
        uint64_t p = prime_cache[i];
        if (p == 2) continue; /* odd-only sieve; even positions excluded */

        /* Forbidden residue: first odd t >= 1 where (candidate+t) % p == 0. */
        uint64_t r = (base_mod_p[i] == 0) ? 0 : (p - base_mod_p[i]);
        /* r is in [0, p-1].  r==0 means t=p is the first composite (p is odd). */
        uint64_t t = (r == 0) ? p : r;
        /* Ensure t is odd: if even, add p (p is odd → flips parity). */
        if ((t & 1) == 0) t += p;

        /* Mark all odd composite positions in [1, gap_scan_max]. */
        for (; t <= (uint64_t)gap_scan_max; t += 2 * p) {
            size_t pos = (size_t)(t - 1) / 2; /* odd-only bitmap index */
            if (pos < seg_size)
                tls_nonce_tmpl[pos >> 3] |= (uint8_t)(1u << (pos & 7));
        }
    }

    /* Set tail bits beyond seg_size as composite (excluded region). */
    for (size_t b = seg_size; b < bytes * 8; b++)
        tls_nonce_tmpl[b >> 3] |= (uint8_t)(1u << (b & 7));

    tls_nonce_tmpl_valid = 1;
}

const uint8_t *crt_solver_get_thread_tmpl(size_t bit_size, int *out_skip_to)
{
    if (!tls_nonce_tmpl_valid || !tls_nonce_tmpl
            || bit_size > tls_nonce_tmpl_bytes)
        return NULL;
    *out_skip_to = g_crt_solver_skip_to;
    return tls_nonce_tmpl;
}
