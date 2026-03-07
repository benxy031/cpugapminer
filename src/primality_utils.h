#ifndef PRIMALITY_UTILS_H
#define PRIMALITY_UTILS_H

#include <stdint.h>

int primality_miller_rabin_u64(uint64_t n);
int primality_fast_fermat_u64(uint64_t n);

#endif
