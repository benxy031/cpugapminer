#include "uint256_utils.h"

#include <math.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <string.h>

#ifndef M_LN2
#define M_LN2 0.693147180559945309417232121458
#endif

static uint64_t pow2_mod_u64(uint64_t exp, uint64_t mod) {
    __uint128_t result = 1 % mod;
    __uint128_t base = 2 % mod;
    while (exp) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return (uint64_t)result;
}

void hash_to_256(const char *s, int is_hex, uint8_t out[32]) {
    memset(out, 0, 32);
    if (is_hex) {
        size_t len = strlen(s);
        if (len > 64) len = 64;
        for (size_t i = 0; i < len / 2; i++) {
            char hi = s[2 * i], lo = s[2 * i + 1];
            int vh = (hi >= '0' && hi <= '9') ? (hi - '0')
                     : (hi >= 'a' && hi <= 'f') ? (10 + hi - 'a')
                     : (10 + hi - 'A');
            int vl = (lo >= '0' && lo <= '9') ? (lo - '0')
                     : (lo >= 'a' && lo <= 'f') ? (10 + lo - 'a')
                     : (10 + lo - 'A');
            out[i] = (uint8_t)((vh << 4) | vl);
        }
    } else {
        unsigned char md[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)s, strlen(s), md);
        memcpy(out, md, 32);
    }
}

uint64_t uint256_mod_small(const uint8_t h[32], int shift, uint64_t p) {
    if (p <= 1) return 0;

    __uint128_t rem = 0;
    for (int i = 0; i < 32; i++)
        rem = (rem * 256 + h[i]) % p;

    uint64_t shift_u = (shift > 0) ? (uint64_t)shift : 0;
    __uint128_t pow2 = pow2_mod_u64(shift_u, p);

    return (uint64_t)((__uint128_t)rem * pow2 % p);
}

double uint256_log_approx(const uint8_t h[32], int shift) {
    uint64_t leading = 0;
    for (int i = 0; i < 8; i++) leading = (leading << 8) | h[i];
    if (leading == 0) return (double)(192 + shift) * M_LN2;
    return log((double)leading) + (double)(192 + shift) * M_LN2;
}
