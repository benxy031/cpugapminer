#ifndef UINT256_UTILS_H
#define UINT256_UTILS_H

#include <stdint.h>

/* Convert a header string to a 256-bit big-endian integer.
   is_hex=1 decodes hex directly, is_hex=0 hashes the input string with SHA-256. */
void hash_to_256(const char *s, int is_hex, uint8_t out[32]);

/* Compute (h << shift) % p for a 256-bit big-endian h and uint64_t modulus p. */
uint64_t uint256_mod_small(const uint8_t h[32], int shift, uint64_t p);

/* Approximate log(h << shift) for merit calculation using the top 64 bits of h. */
double uint256_log_approx(const uint8_t h[32], int shift);

#endif
