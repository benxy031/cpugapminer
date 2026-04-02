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

/* ── Global static template (built once at startup from fixed offsets) ── */
static uint8_t *g_static_tmpl       = NULL;
static size_t   g_static_tmpl_bytes = 0;
static int      g_static_tmpl_valid = 0;

void crt_solver_build_static_tmpl(const int *offsets,
                                  const int *primes,
                                  int        n_primes,
                                  int        gap_scan_max,
                                  int        adj)
{
    g_static_tmpl_valid = 0;
    if (!offsets || !primes || n_primes <= 0 || gap_scan_max <= 0) return;

    size_t seg_size = (size_t)gap_scan_max / 2 + 1;
    size_t bytes    = (seg_size + 7) / 8;

    if (g_static_tmpl_bytes < bytes) {
        free(g_static_tmpl);
        g_static_tmpl = (uint8_t *)malloc(bytes);
        if (!g_static_tmpl) { g_static_tmpl_bytes = 0; return; }
        g_static_tmpl_bytes = bytes;
    }

    memset(g_static_tmpl, 0, bytes);

    /* Mark composites: after CRT alignment with odd-adjustment adj,
       candidate ≡ -(offset_i + adj) (mod p_i), so (candidate + t) ≡ 0
       when t ≡ (offset_i + adj) (mod p_i).
       Only primes with original offset != 0 are in the primorial.
       Skip p=2: sieve is odd-only, base is always even. */
    for (int i = 0; i < n_primes; i++) {
        uint64_t p = (uint64_t)primes[i];
        if (p == 2) continue;
        if (offsets[i] == 0) continue; /* zero-offset: excluded from primorial */

        uint64_t o = ((uint64_t)offsets[i] + (uint64_t)adj) % p;
        /* o == 0 means first hit at t = p (not excluded — offset_i != 0) */
        uint64_t t = (o == 0) ? p : o;
        if ((t & 1) == 0) t += p; /* ensure t is odd */

        for (; t <= (uint64_t)gap_scan_max; t += 2 * p) {
            size_t pos = (size_t)(t - 1) / 2;
            if (pos < seg_size)
                g_static_tmpl[pos >> 3] |= (uint8_t)(1u << (pos & 7));
        }
    }

    /* Mark tail bits beyond seg_size as composite (excluded region). */
    for (size_t b = seg_size; b < bytes * 8; b++)
        g_static_tmpl[b >> 3] |= (uint8_t)(1u << (b & 7));

    g_static_tmpl_valid = 1;

    /* Reduce skip_to to stop before the first zero-offset prime (other than p=2).
       Zero-offset primes are excluded from the primorial, so candidate mod p is
       hash-dependent — the sieve loop must handle them per-window. */
    {
        int eff_skip = g_crt_solver_skip_to;
        for (int i = 0; i < n_primes && i < eff_skip; i++) {
            if (primes[i] == 2) continue;
            if (offsets[i] == 0) { eff_skip = i; break; }
        }
        g_crt_solver_skip_to = eff_skip;
    }
}

/* No-op: template is now built once at startup, not per-nonce. */
void crt_solver_rebuild_thread_tmpl(const uint64_t *base_mod_p,
                                    const uint64_t *prime_cache,
                                    int             gap_scan_max)
{
    (void)base_mod_p; (void)prime_cache; (void)gap_scan_max;
}


const uint8_t *crt_solver_get_thread_tmpl(size_t bit_size, int *out_skip_to)
{
    if (!g_static_tmpl_valid || !g_static_tmpl
            || bit_size > g_static_tmpl_bytes)
        return NULL;
    *out_skip_to = g_crt_solver_skip_to;
    return g_static_tmpl;
}
