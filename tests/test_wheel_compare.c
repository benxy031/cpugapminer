#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/wheel_sieve.h"

static uint64_t gcd_u64(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static int is_default_presieve_survivor(uint64_t n) {
    static const uint64_t primes[] = {3, 5, 7, 11, 13, 17};
    if ((n & 1ULL) == 0ULL) return 0;
    for (size_t i = 0; i < sizeof(primes) / sizeof(primes[0]); i++) {
        if (n == primes[i]) return 1;
        if (n % primes[i] == 0ULL) return 0;
    }
    return 1;
}

static size_t count_default(uint64_t L, uint64_t R) {
    size_t count = 0;
    if (L > R) return 0;
    if ((L & 1ULL) == 0ULL) L++;
    if ((R & 1ULL) == 0ULL) R++;
    for (uint64_t n = L; n < R; n += 2ULL) {
        if (is_default_presieve_survivor(n))
            count++;
    }
    return count;
}

static size_t count_wheel(uint64_t L, uint64_t R, unsigned int wheel_size) {
    size_t count = 0;
    if (L > R) return 0;
    if ((L & 1ULL) == 0ULL) L++;
    if ((R & 1ULL) == 0ULL) R++;

    if (wheel_sieve_configure(wheel_size) != 0)
        return 0;

    uint64_t base_mod = 0;
    size_t start_bit = wheel_sieve_start_bit(base_mod, L);
    size_t bits = (size_t)((R - L) / 2ULL + 1ULL);
    size_t bytes = (bits + 7U) / 8U;
    uint8_t *buf = (uint8_t *)calloc(bytes, 1);
    if (!buf) return 0;
    wheel_sieve_tile(buf, bytes, start_bit);

    for (size_t i = 0; i < bits; i++) {
        uint64_t odd = L + (uint64_t)i * 2ULL;
        int marked = (buf[i >> 3] >> (i & 7U)) & 1U;
        int expected_marked = gcd_u64(odd, wheel_size) != 1ULL;
        if (marked != expected_marked) {
            fprintf(stderr, "FAIL: wheel bitmap mismatch for W=%u odd=%llu\n",
                    wheel_size, (unsigned long long)odd);
            free(buf);
            wheel_sieve_configure(0);
            exit(2);
        }
        if (!marked)
            count++;
    }

    free(buf);
    wheel_sieve_configure(0);
    return count;
}

static void compare_case(uint64_t L, uint64_t R) {
    size_t def_cnt = count_default(L, R);
    size_t w30 = count_wheel(L, R, 30);
    size_t w210 = count_wheel(L, R, 210);
    size_t w2310 = count_wheel(L, R, 2310);
    size_t w30030 = count_wheel(L, R, 30030);
    size_t w510510 = count_wheel(L, R, 510510);
    size_t w9699690 = count_wheel(L, R, 9699690);

    printf("range=%llu..%llu default=%zu wheel30=%zu wheel210=%zu wheel2310=%zu wheel30030=%zu wheel510510=%zu wheel9699690=%zu\n",
           (unsigned long long)L,
           (unsigned long long)R,
           def_cnt, w30, w210, w2310, w30030, w510510, w9699690);
}

int main(void) {
    const uint64_t ranges[][2] = {
        {1ULL, 1000ULL},
        {1001ULL, 10000ULL},
        {12345ULL, 54321ULL},
        {100000ULL, 200000ULL},
    };

    for (size_t i = 0; i < sizeof(ranges) / sizeof(ranges[0]); i++)
        compare_case(ranges[i][0], ranges[i][1]);

    return 0;
}