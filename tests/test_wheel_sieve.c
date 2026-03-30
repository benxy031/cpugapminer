#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/wheel_sieve.h"

static uint64_t gcd_u64(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = a % b;
        a = b;
        b = t;
    }
    return a;
}

static void set_bit(uint8_t *buf, size_t bit) {
    buf[bit >> 3] |= (uint8_t)(1U << (bit & 7U));
}

static void assert_true(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        exit(1);
    }
}

static void check_wheel_size(unsigned int wheel_size) {
    assert_true(wheel_sieve_configure(wheel_size) == 0, "wheel configure failed");
    assert_true(wheel_sieve_enabled() != 0, "wheel not enabled after configure");
    assert_true(wheel_sieve_size() == wheel_size, "wheel size mismatch");

    size_t expected_skip = 0;
    if (wheel_size == 30) expected_skip = 3;
    else if (wheel_size == 210) expected_skip = 4;
    else if (wheel_size == 2310) expected_skip = 5;
    else if (wheel_size == 30030) expected_skip = 6;
    else if (wheel_size == 510510) expected_skip = 7;
    else if (wheel_size == 9699690) expected_skip = 8;
    assert_true(wheel_sieve_skip_to() == expected_skip, "wheel skip_to mismatch");
    assert_true(wheel_sieve_period_bytes() == (size_t)wheel_size / 2U,
                "wheel period bytes mismatch");

    const uint64_t total_bits = (uint64_t)wheel_sieve_period_bytes() * 8ULL;
    const uint64_t bases[] = {0ULL, 1ULL, 2ULL, 3ULL, 17ULL, 30ULL, 1234ULL, 98765ULL};
    const uint64_t lens[] = {1ULL, 2ULL, 7ULL, 31ULL, 64ULL, 127ULL, 256ULL, 511ULL, 1024ULL};

    for (size_t bi = 0; bi < sizeof(bases) / sizeof(bases[0]); bi++) {
        for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
            uint64_t base_mod = bases[bi] % wheel_size;
            uint64_t L = lens[li] | 1ULL;
            size_t start_bit = wheel_sieve_start_bit(base_mod, L);

            uint64_t residue = (base_mod + L) % wheel_size;
            if ((residue & 1ULL) == 0ULL)
                residue = (residue + 1ULL) % wheel_size;
            size_t expected_start_bit = (size_t)((residue - 1ULL) / 2ULL);
            assert_true(start_bit == expected_start_bit, "wheel start_bit mismatch");

            size_t out_bytes = (size_t)(lens[li] + 7ULL) / 8ULL + 8U;
            uint8_t *out = (uint8_t *)calloc(out_bytes, 1);
            uint8_t *ref = (uint8_t *)calloc(out_bytes, 1);
            assert_true(out && ref, "allocation failed");

            wheel_sieve_tile(out, out_bytes, start_bit);

            for (size_t bit = 0; bit < out_bytes * 8U; bit++) {
                uint64_t tmpl_bit = (start_bit + bit) % total_bits;
                uint64_t odd = 2ULL * tmpl_bit + 1ULL;
                if (gcd_u64(odd, wheel_size) != 1ULL)
                    set_bit(ref, bit);
            }

            if (memcmp(out, ref, out_bytes) != 0) {
                fprintf(stderr,
                        "FAIL: wheel mismatch for W=%u base_mod=%llu L=%llu start_bit=%zu\n",
                        wheel_size,
                        (unsigned long long)base_mod,
                        (unsigned long long)L,
                        start_bit);
                free(out);
                free(ref);
                exit(2);
            }

            free(out);
            free(ref);
        }
    }

    wheel_sieve_configure(0);
}

int main(void) {
    check_wheel_size(30);
    check_wheel_size(210);
    check_wheel_size(2310);
    check_wheel_size(30030);
    check_wheel_size(510510);
    check_wheel_size(9699690);
    printf("All wheel sieve tests passed.\n");
    return 0;
}