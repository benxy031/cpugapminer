#ifndef SIEVE_CACHE_H
#define SIEVE_CACHE_H

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>

/* Default sieve prime COUNT matching GapMiner (--sieve-primes N = N primes). */
#define DEFAULT_SIEVE_PRIME_COUNT 900000

/* Trial-division pre-filter count above sieve prime limit. */
#define TD_EXTRA_CNT 64

extern uint64_t cli_sieve_prime_limit;
extern uint64_t cli_sieve_prime_count;

/* Cache of small primes used for segmented sieving (allocated once). */
extern uint64_t *small_primes_cache;
extern size_t small_primes_count;
extern size_t small_primes_cap;
extern pthread_once_t small_primes_once;

/* Extra TD primes slightly above sieve limit. */
extern uint32_t td_extra_primes[TD_EXTRA_CNT];
extern int td_extra_count;
extern pthread_once_t td_extra_once;

void populate_small_primes_cache(void);
void populate_td_extra_primes(void);

#endif /* SIEVE_CACHE_H */
