#include "wheel_sieve.h"

#include <stdlib.h>
#include <string.h>

static unsigned int g_wheel_size = 0;
static uint8_t *g_wheel_tmpl = NULL;
static size_t g_wheel_bytes = 0;
static size_t g_wheel_skip = 0;

static uint64_t gcd_u64(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static size_t wheel_skip_to(unsigned int wheel_size) {
    switch (wheel_size) {
    case 30:   return 3; /* skip primes 2,3,5 */
    case 210:  return 4; /* skip primes 2,3,5,7 */
    case 2310: return 5; /* skip primes 2,3,5,7,11 */
    case 30030: return 6; /* skip primes 2,3,5,7,11,13 */
    case 510510:return 7; /* skip primes 2,3,5,7,11,13,17 */
    case 9699690:return 8; /* skip primes 2,3,5,7,11,13,17,19 */
    default:   return 0;
    }
}

static int wheel_template_init(unsigned int wheel_size) {
    if (wheel_size != 30 && wheel_size != 210 && wheel_size != 2310
            && wheel_size != 30030 && wheel_size != 510510
            && wheel_size != 9699690)
        return -1;

    if (g_wheel_tmpl && g_wheel_size == wheel_size)
        return 0;

    free(g_wheel_tmpl);
    g_wheel_tmpl = NULL;
    g_wheel_size = wheel_size;
    g_wheel_skip = wheel_skip_to(wheel_size);
    g_wheel_bytes = (size_t)wheel_size / 2U;
    g_wheel_tmpl = (uint8_t *)calloc(1, g_wheel_bytes);
    if (!g_wheel_tmpl) {
        g_wheel_size = 0;
        g_wheel_bytes = 0;
        g_wheel_skip = 0;
        return -1;
    }

    const uint64_t total_bits = (uint64_t)g_wheel_bytes * 8ULL;
    for (uint64_t j = 0; j < total_bits; j++) {
        uint64_t odd = 2ULL * j + 1ULL;
        if (gcd_u64(odd, wheel_size) != 1ULL)
            g_wheel_tmpl[j >> 3] |= (uint8_t)(1u << (j & 7));
    }
    return 0;
}

int wheel_sieve_configure(unsigned int wheel_size) {
    if (wheel_size == 0) {
        free(g_wheel_tmpl);
        g_wheel_tmpl = NULL;
        g_wheel_size = 0;
        g_wheel_bytes = 0;
        g_wheel_skip = 0;
        return 0;
    }
    return wheel_template_init(wheel_size);
}

int wheel_sieve_enabled(void) {
    return g_wheel_tmpl != NULL && g_wheel_size != 0;
}

unsigned int wheel_sieve_size(void) {
    return g_wheel_size;
}

size_t wheel_sieve_skip_to(void) {
    return g_wheel_skip;
}

size_t wheel_sieve_period_bytes(void) {
    return g_wheel_bytes;
}

size_t wheel_sieve_start_bit(uint64_t base_mod, uint64_t L) {
    if (!g_wheel_size)
        return 0;
    uint64_t residue = (base_mod + L) % (uint64_t)g_wheel_size;
    if ((residue & 1ULL) == 0ULL)
        residue = (residue + 1ULL) % (uint64_t)g_wheel_size;
    return (size_t)((residue - 1ULL) / 2ULL);
}

void wheel_sieve_tile(uint8_t *sieve, size_t sieve_bytes, size_t start_bit) {
    if (!g_wheel_tmpl || g_wheel_bytes == 0 || !sieve)
        return;

    size_t period_bytes = g_wheel_bytes;
    size_t src_byte = (start_bit / 8U) % period_bytes;
    unsigned shift = (unsigned)(start_bit & 7U);

    if (shift == 0U) {
        size_t rem = sieve_bytes;
        size_t dst = 0;
        while (rem > 0) {
            size_t chunk = period_bytes - src_byte;
            if (chunk > rem) chunk = rem;
            memcpy(sieve + dst, g_wheel_tmpl + src_byte, chunk);
            dst += chunk;
            rem -= chunk;
            src_byte = 0;
        }
    } else {
        unsigned inv = 8U - shift;
        for (size_t i = 0; i < sieve_bytes; i++) {
            uint8_t lo = g_wheel_tmpl[src_byte];
            size_t nx = src_byte + 1;
            if (nx >= period_bytes) nx = 0;
            uint8_t hi = g_wheel_tmpl[nx];
            sieve[i] = (uint8_t)((lo >> shift) | (hi << inv));
            src_byte = nx;
        }
    }
}