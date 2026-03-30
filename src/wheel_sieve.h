#ifndef WHEEL_SIEVE_H
#define WHEEL_SIEVE_H

#include <stddef.h>
#include <stdint.h>

int wheel_sieve_configure(unsigned int wheel_size);
int wheel_sieve_enabled(void);
unsigned int wheel_sieve_size(void);
size_t wheel_sieve_skip_to(void);
size_t wheel_sieve_period_bytes(void);
size_t wheel_sieve_start_bit(uint64_t base_mod, uint64_t L);
void wheel_sieve_tile(uint8_t *sieve, size_t sieve_bytes, size_t start_bit);

#endif /* WHEEL_SIEVE_H */