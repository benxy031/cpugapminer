/*
 * mpresieve_avx512.h — AVX-512BW inner loops for the multi-table pre-sieve.
 *
 * Provides two functions called from mpresieve_tile() in main.c:
 *
 *   mpresieve_avx512_aligned()  — shift == 0 path, 64-byte OR with masked tail
 *   mpresieve_avx512_shifted()  — shift  > 0 path, 64-byte unpack/shift/pack
 *
 * Guard: compiled only when __AVX512BW__ is defined (requires AVX-512F +
 * AVX-512BW; present on Ice Lake, Zen 4, and later).
 *
 * cpugapminer sieve convention: 1 = composite, 0 = candidate.
 * We OR the table bytes into the sieve (primesieve ANDs; our convention is the
 * inverse).
 *
 * Sentinel: each table is allocated period+1 bytes with table[period]=table[0].
 * The shifted path loads one byte past the 64-byte block (tp+64); with the
 * loop bound (i+64 <= chunk, src[j]+chunk <= period), the maximum address
 * accessed is table[period] which the sentinel covers.
 */

#ifndef MPRESIEVE_AVX512_H
#define MPRESIEVE_AVX512_H

#ifdef __AVX512BW__

#pragma GCC push_options
#pragma GCC target("avx512f,avx512bw")
#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>

/*
 * mpresieve_avx512_aligned
 *
 * OR-tiles ntables tables (byte-aligned, shift==0) into dst[0..chunk).
 * Handles non-multiple-of-64 tail with a masked store.
 * Returns chunk (all bytes written).
 */
static inline size_t
mpresieve_avx512_aligned(uint8_t *dst, size_t chunk,
                         uint8_t * const *tables, const size_t *src,
                         int ntables)
{
    size_t i = 0;

    for (; i + 64 <= chunk; i += 64) {
        __m512i acc = _mm512_loadu_si512((const void *)(tables[0] + src[0] + i));
        for (int j = 1; j < ntables; j++)
            acc = _mm512_or_si512(acc,
                  _mm512_loadu_si512((const void *)(tables[j] + src[j] + i)));
        _mm512_storeu_si512((void *)(dst + i), acc);
    }

    /* Masked tail: (chunk - i) < 64 bytes remain. */
    if (i < chunk) {
        __mmask64 mask = ((uint64_t)1 << (chunk - i)) - 1;
        __m512i acc = _mm512_maskz_loadu_epi8(mask, tables[0] + src[0] + i);
        for (int j = 1; j < ntables; j++)
            acc = _mm512_or_si512(acc,
                  _mm512_maskz_loadu_epi8(mask, tables[j] + src[j] + i));
        _mm512_mask_storeu_epi8(dst + i, mask, acc);
        i = chunk;
    }

    return i; /* == chunk */
}

/*
 * mpresieve_avx512_shifted
 *
 * OR-tiles ntables tables (bit-shifted, shift > 0) into dst[0..chunk).
 * Processes all full 64-byte blocks; caller handles the tail (< 64 bytes)
 * with SSE2 or scalar code.
 *
 * For each output byte k:
 *   dst[k] |= (table[src+k] >> shift) | (table[src+k+1] << (8-shift))
 *
 * Technique: pack consecutive byte pairs into 16-bit words, right-shift the
 * word, mask the lower byte.  Works within 128-bit lanes, so unpack/pack
 * produces the correct linear byte order across the full 512-bit register.
 *
 * Returns the number of bytes written (multiple of 64).
 */
static inline size_t
mpresieve_avx512_shifted(uint8_t *dst, size_t chunk, unsigned shift,
                         uint8_t * const *tables, const size_t *src,
                         int ntables)
{
    const __m512i mask8 = _mm512_set1_epi16(0x00FF);
    size_t i = 0;

    for (; i + 64 <= chunk; i += 64) {
        __m512i acc = _mm512_setzero_si512();
        for (int j = 0; j < ntables; j++) {
            const uint8_t *tp = tables[j] + src[j] + i;
            /* lo = table[i..i+63], hi = table[i+1..i+64] (sentinel covers +64) */
            __m512i lo  = _mm512_loadu_si512((const void *)tp);
            __m512i hi  = _mm512_loadu_si512((const void *)(tp + 1));
            /* Interleave each byte pair into a 16-bit word: hi8<<8 | lo8.
               unpacklo operates within each 128-bit lane:
                 lane k → pairs (lo[16k..16k+7], hi[16k..16k+7])
               unpackhi → pairs (lo[16k+8..16k+15], hi[16k+8..16k+15])     */
            __m512i wlo = _mm512_unpacklo_epi8(lo, hi); /* 16-bit: hi<<8|lo */
            __m512i whi = _mm512_unpackhi_epi8(lo, hi);
            /* Shift the 16-bit word right by `shift` and keep low byte:
               result = (hi<<8|lo) >> shift  &  0x00FF
                      = (lo>>shift) | (hi<<(8-shift))                        */
            __m512i slo = _mm512_and_si512(_mm512_srli_epi16(wlo, shift), mask8);
            __m512i shi = _mm512_and_si512(_mm512_srli_epi16(whi, shift), mask8);
            /* Pack back to bytes; packus within each 128-bit lane reassembles
               the 8 even-index and 8 odd-index results in the correct order.  */
            acc = _mm512_or_si512(acc, _mm512_packus_epi16(slo, shi));
        }
        _mm512_storeu_si512((void *)(dst + i), acc);
    }

    return i; /* bytes consumed; i % 64 == 0, remainder handled by caller */
}

#pragma GCC pop_options

#endif /* __AVX512BW__ */
#endif /* MPRESIEVE_AVX512_H */
