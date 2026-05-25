#include "sievegap.h"

#include <stdlib.h>
#include <string.h>

#include "uint256_utils.h"

#if defined(__AVX2__) || defined(__SSE2__)
#include <immintrin.h>
#endif

#ifdef WITH_CUDA
#include "presieve_utils.h"
#endif

#define SIEVEGAP_GPU_SPLIT_BITS (32768ULL * 8ULL)

static __thread uint8_t *tls_bits = NULL;
static __thread size_t tls_bits_cap = 0;

static __thread uint64_t *tls_survivors = NULL;
static __thread size_t tls_survivors_cap = 0;

#ifdef WITH_CUDA
static __thread uint8_t *tls_gpu_bits = NULL;
static __thread size_t tls_gpu_bits_cap = 0;
#endif

/* Scratch buffer for precomputed base_mod_p values when not available from
 * the caller — avoids recomputing uint256_mod_small per prime per L1 block. */
static __thread uint64_t *tls_base_scratch = NULL;
static __thread size_t tls_base_scratch_cap = 0;

static int ensure_base_scratch_capacity(size_t count) {
    if (tls_base_scratch_cap >= count)
        return 0;
    free(tls_base_scratch);
    tls_base_scratch = (uint64_t *)malloc(count * sizeof(uint64_t));
    if (!tls_base_scratch) {
        tls_base_scratch_cap = 0;
        return -1;
    }
    tls_base_scratch_cap = count;
    return 0;
}

static int ensure_bits_capacity(size_t bytes) {
    if (tls_bits_cap >= bytes)
        return 0;
    free(tls_bits);
    tls_bits = (uint8_t *)malloc(bytes);
    if (!tls_bits) {
        tls_bits_cap = 0;
        return -1;
    }
    tls_bits_cap = bytes;
    return 0;
}

static int ensure_survivor_capacity(size_t count) {
    if (tls_survivors_cap >= count)
        return 0;
    free(tls_survivors);
    tls_survivors = (uint64_t *)malloc(count * sizeof(uint64_t));
    if (!tls_survivors) {
        tls_survivors_cap = 0;
        return -1;
    }
    tls_survivors_cap = count;
    return 0;
}

#ifdef WITH_CUDA
static int ensure_gpu_bits_capacity(size_t bytes) {
    if (tls_gpu_bits_cap >= bytes)
        return 0;
    free(tls_gpu_bits);
    tls_gpu_bits = (uint8_t *)malloc(bytes);
    if (!tls_gpu_bits) {
        tls_gpu_bits_cap = 0;
        return -1;
    }
    tls_gpu_bits_cap = bytes;
    return 0;
}
#endif

static inline void mark_prime_cpu(uint8_t *bits,
                                  uint64_t L,
                                  uint64_t R,
                                  uint64_t p,
                                  uint64_t base_mod_p,
                                  size_t bit_bytes) {
    uint64_t l_mod_p = L % p;
    uint64_t rem = base_mod_p + l_mod_p;
    if (rem >= p)
        rem -= p;

    uint64_t m = (rem == 0) ? L : (L + (p - rem));
    if ((m & 1ULL) == 0ULL)
        m += p;

    uint64_t pos = (m - L) >> 1;
    uint64_t pos_end = (R - L) >> 1;

    if (pos >= pos_end)
        return;

    /* Short spans: scalar tail is cheaper than preparing 8-way masks. */
    if (pos + 7 * p >= pos_end) {
        for (; pos < pos_end; pos += p)
            bits[pos >> 3] |= (uint8_t)(1u << (pos & 7));
        return;
    }

    uint64_t q = p >> 3;
    uint64_t r = p & 7;
    uint64_t b = pos & 7;
    uint32_t off[8];
    uint8_t msk[8];
    uint64_t acc = b;
    for (int k = 0; k < 8; k++, acc += r) {
        off[k] = (uint32_t)((uint64_t)k * q + (acc >> 3));
        msk[k] = (uint8_t)(1u << (acc & 7));
    }

    uint8_t *s = bits + (pos >> 3);

#if defined(__AVX2__)
    if (p <= 64) {
        uint8_t mlo[32] = {0};
        uint8_t mhi[32] = {0};
        for (int k = 0; k < 8; k++) {
            uint32_t o = off[k];
            if (o < 32u)
                mlo[o] |= msk[k];
            else
                mhi[o - 32u] |= msk[k];
        }
        __m256i mask_lo = _mm256_loadu_si256((const __m256i *)mlo);
        __m256i mask_hi = _mm256_loadu_si256((const __m256i *)mhi);
        size_t span = (p <= 32) ? 32u : 64u;

        while (pos + 7 * p < pos_end) {
            size_t s_off = (size_t)(s - bits);
            if (s_off + span > bit_bytes)
                break;
            __m256i v0 = _mm256_loadu_si256((const __m256i *)s);
            v0 = _mm256_or_si256(v0, mask_lo);
            _mm256_storeu_si256((__m256i *)s, v0);
            if (span == 64u) {
                __m256i v1 = _mm256_loadu_si256((const __m256i *)(s + 32));
                v1 = _mm256_or_si256(v1, mask_hi);
                _mm256_storeu_si256((__m256i *)(s + 32), v1);
            }
            s += p;
            pos += 8 * p;
        }
    } else
#endif
#if defined(__SSE2__)
    if (p <= 32) {
        uint8_t mlo[16] = {0};
        uint8_t mhi[16] = {0};
        for (int k = 0; k < 8; k++) {
            uint32_t o = off[k];
            if (o < 16u)
                mlo[o] |= msk[k];
            else
                mhi[o - 16u] |= msk[k];
        }
        __m128i mask_lo = _mm_loadu_si128((const __m128i *)mlo);
        __m128i mask_hi = _mm_loadu_si128((const __m128i *)mhi);
        size_t span = (p <= 16) ? 16u : 32u;

        while (pos + 7 * p < pos_end) {
            size_t s_off = (size_t)(s - bits);
            if (s_off + span > bit_bytes)
                break;
            __m128i v0 = _mm_loadu_si128((const __m128i *)s);
            v0 = _mm_or_si128(v0, mask_lo);
            _mm_storeu_si128((__m128i *)s, v0);
            if (span == 32u) {
                __m128i v1 = _mm_loadu_si128((const __m128i *)(s + 16));
                v1 = _mm_or_si128(v1, mask_hi);
                _mm_storeu_si128((__m128i *)(s + 16), v1);
            }
            s += p;
            pos += 8 * p;
        }
    } else
#endif
    while (pos + 7 * p < pos_end) {
        s[off[0]] |= msk[0];
        s[off[1]] |= msk[1];
        s[off[2]] |= msk[2];
        s[off[3]] |= msk[3];
        s[off[4]] |= msk[4];
        s[off[5]] |= msk[5];
        s[off[6]] |= msk[6];
        s[off[7]] |= msk[7];
        s += p;
        pos += 8 * p;
    }

    for (; pos < pos_end; pos += p)
        bits[pos >> 3] |= (uint8_t)(1u << (pos & 7));
}

/* Extract survivor offsets from odd-only bitmap using 64-bit chunks.
 * bits[k]=0 means candidate survives, so we iterate over ~composite_mask. */
static inline size_t extract_survivors_ctz(const uint8_t *bits,
                                           uint64_t odd_count,
                                           uint64_t L,
                                           uint64_t *out_survivors) {
    size_t out = 0;
    size_t full_words = (size_t)(odd_count >> 6);
    uint64_t rem_bits = odd_count & 63ULL;

    for (size_t w = 0; w < full_words; w++) {
        uint64_t composites = 0;
        memcpy(&composites, bits + (w << 3), sizeof(composites));
        uint64_t survivors = ~composites;
        while (survivors) {
            uint64_t bit = (uint64_t)__builtin_ctzll(survivors);
            uint64_t k = ((uint64_t)w << 6) + bit;
            out_survivors[out++] = L + (k << 1);
            survivors &= survivors - 1;
        }
        if (w + 8 < full_words)
            __builtin_prefetch(bits + ((w + 8) << 3), 0, 1);
    }

    if (rem_bits) {
        uint64_t composites = 0;
        size_t rem_bytes = (size_t)((rem_bits + 7ULL) >> 3);
        memcpy(&composites, bits + (full_words << 3), rem_bytes);
        uint64_t survivors = ~composites;
        survivors &= (1ULL << rem_bits) - 1ULL;
        while (survivors) {
            uint64_t bit = (uint64_t)__builtin_ctzll(survivors);
            uint64_t k = ((uint64_t)full_words << 6) + bit;
            out_survivors[out++] = L + (k << 1);
            survivors &= survivors - 1;
        }
    }

    return out;
}

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
                             uint64_t base_mod_p_version) {
#ifndef WITH_CUDA
    (void)base_mod_p_version;
#endif
    if (!out_count || !small_primes || small_primes_count == 0 || L >= R) {
        if (out_count)
            *out_count = 0;
        return NULL;
    }

    uint64_t seg_size = R - L;
    size_t bit_bytes = (size_t)((seg_size + 15ULL) >> 4);
    if (bit_bytes == 0)
        bit_bytes = 1;

    if (ensure_bits_capacity(bit_bytes) != 0 || ensure_survivor_capacity((size_t)seg_size) != 0) {
        *out_count = 0;
        return NULL;
    }

    uint8_t *bits = tls_bits;
    memset(bits, 0, bit_bytes);

    size_t sieve_start = 1; /* skip prime 2 for odd-only bitmap */
    size_t sieve_end = sieve_start;
    while (sieve_end < small_primes_count && small_primes[sieve_end] <= prime_limit)
        sieve_end++;

    size_t gpu_split = sieve_end;
    for (size_t i = sieve_start; i < sieve_end; i++) {
        if ((small_primes[i] << 1) >= SIEVEGAP_GPU_SPLIT_BITS) {
            gpu_split = i;
            break;
        }
    }

    /* Phase 1: small primes, L1-blocked.
     * Precompute base (= h256 mod p) once per prime before the block loop;
     * reuse across blocks so uint256_mod_small is not called repeatedly. */
    const uint64_t *eff_base = NULL;
    if (base_mod_p_ready && base_mod_p) {
        eff_base = base_mod_p;
    } else if (h256 && gpu_split > 0) {
        if (ensure_base_scratch_capacity(gpu_split) == 0) {
            for (size_t i = sieve_start; i < gpu_split; i++)
                tls_base_scratch[i] = uint256_mod_small(h256, shift, small_primes[i]);
            eff_base = tls_base_scratch;
        }
    }

    /* Block size matches L1D cache (32 KB = SIEVEGAP_GPU_SPLIT_BITS bits).
     * Inner prime loop touches only blk_bit_bytes bytes of bitmap per pass,
     * keeping the working set hot across all primes in the block. */
    uint64_t seg_bits = (seg_size + 1ULL) >> 1;
    for (uint64_t blk_bit = 0; blk_bit < seg_bits; blk_bit += SIEVEGAP_GPU_SPLIT_BITS) {
        uint64_t blk_end_bit = blk_bit + SIEVEGAP_GPU_SPLIT_BITS;
        if (blk_end_bit > seg_bits)
            blk_end_bit = seg_bits;
        uint64_t blk_L = L + (blk_bit << 1);
        uint64_t blk_R = L + (blk_end_bit << 1);
        uint8_t *blk_bits = bits + (blk_bit >> 3);
        size_t blk_bit_bytes = (size_t)((blk_end_bit - blk_bit + 7) >> 3);

        for (size_t i = sieve_start; i < gpu_split; i++) {
            uint64_t base = eff_base ? eff_base[i] : 0;
            mark_prime_cpu(blk_bits, blk_L, blk_R, small_primes[i], base, blk_bit_bytes);
        }
    }

#ifdef WITH_CUDA
    int used_gpu_compact = 0;
    if (g_gpu_sieve_enable && gpu_split < sieve_end && base_mod_p_ready && base_mod_p) {
        int gpu_ok = 0;
        size_t n_phase2 = sieve_end - gpu_split;
        if (n_phase2 > 0 && ensure_gpu_bits_capacity(bit_bytes) == 0) {
            uint8_t *phase2_bits_buf = tls_gpu_bits;
            memset(phase2_bits_buf, 0, bit_bytes);
            /* segment_len must be the ODD candidate count (d_segment is
             * indexed by odd-position: segment[i] corresponds to L+2*i). */
            int mode = gpu_sieve_mark_segment_batch(phase2_bits_buf,
                                                    bit_bytes,
                                                    (seg_size + 1) >> 1,
                                                    bits,
                                                    small_primes + gpu_split,
                                                    base_mod_p + gpu_split,
                                                    base_mod_p_version,
                                                    L,
                                                    R,
                                                    (int)n_phase2);
            if (mode == 0) {
                for (size_t b = 0; b < bit_bytes; b++)
                    bits[b] |= phase2_bits_buf[b];
                gpu_ok = 1;
            } else if (mode == 1) {
                used_gpu_compact = 1;
                gpu_ok = 1;
            }
        }

        if (!gpu_ok) {
            for (size_t i = gpu_split; i < sieve_end; i++) {
                uint64_t p = small_primes[i];
                mark_prime_cpu(bits, L, R, p, base_mod_p[i], bit_bytes);
            }
        }
    } else {
        for (size_t i = gpu_split; i < sieve_end; i++) {
            uint64_t p = small_primes[i];
            uint64_t base = 0;
            if (base_mod_p_ready && base_mod_p)
                base = base_mod_p[i];
            else if (h256)
                base = uint256_mod_small(h256, shift, p);
            mark_prime_cpu(bits, L, R, p, base, bit_bytes);
        }
    }
#else
    for (size_t i = gpu_split; i < sieve_end; i++) {
        uint64_t p = small_primes[i];
        uint64_t base = 0;
        if (base_mod_p_ready && base_mod_p)
            base = base_mod_p[i];
        else if (h256)
            base = uint256_mod_small(h256, shift, p);
        mark_prime_cpu(bits, L, R, p, base, bit_bytes);
    }
#endif

    size_t out = 0;
#ifdef WITH_CUDA
    if (used_gpu_compact) {
        uint32_t n_surv = 0;
        const uint32_t *surv = gpu_sieve_last_survivors(&n_surv);
        if (surv && n_surv > 0) {
            for (uint32_t i = 0; i < n_surv; i++) {
                uint32_t pos = surv[i];
                size_t byte = (size_t)(pos >> 3);
                uint8_t mask = (uint8_t)(1U << (pos & 7U));
                if (byte < bit_bytes && (bits[byte] & mask) == 0)
                    tls_survivors[out++] = L + ((uint64_t)pos << 1);
            }
            *out_count = out;
            return tls_survivors;
        }
    }
#endif

    {
        uint64_t odd_count = (seg_size + 1ULL) >> 1;
        out = extract_survivors_ctz(bits, odd_count, L, tls_survivors);
    }

    *out_count = out;
    return tls_survivors;
}

void sievegap_free_tls_buffers(void) {
    free(tls_bits);
    free(tls_survivors);
    free(tls_base_scratch);
#ifdef WITH_CUDA
    free(tls_gpu_bits);
    tls_gpu_bits = NULL;
    tls_gpu_bits_cap = 0;
#endif
    tls_bits = NULL;
    tls_survivors = NULL;
    tls_bits_cap = 0;
    tls_survivors_cap = 0;
    tls_base_scratch = NULL;
    tls_base_scratch_cap = 0;
}
