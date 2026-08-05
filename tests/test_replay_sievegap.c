/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/sievegap.h"
#include "../src/uint256_utils.h"

typedef struct {
    char id[64];
    uint64_t L;
    uint64_t R;
    int shift;
    uint64_t prime_limit;
    uint64_t exp_count;
    uint64_t exp_xor;
    uint64_t exp_sum;
    int has_expected;
} ReplayCase;

typedef struct {
    uint64_t count;
    uint64_t xorsum;
    uint64_t sum;
} ReplayMetrics;

static int is_prime_u64(uint64_t x) {
    if (x < 2)
        return 0;
    if ((x & 1ULL) == 0ULL)
        return x == 2;
    for (uint64_t d = 3; d * d <= x; d += 2) {
        if (x % d == 0)
            return 0;
    }
    return 1;
}

static size_t build_small_primes(uint64_t *out, size_t cap, uint64_t limit) {
    size_t n = 0;
    for (uint64_t v = 2; v <= limit; v++) {
        if (!is_prime_u64(v))
            continue;
        if (n >= cap)
            break;
        out[n++] = v;
    }
    return n;
}

static int parse_line(const char *line, ReplayCase *out) {
    char id[64] = {0};
    unsigned long long L = 0;
    unsigned long long R = 0;
    int shift = 0;
    unsigned long long prime_limit = 0;
    unsigned long long exp_count = 0;
    unsigned long long exp_xor = 0;
    unsigned long long exp_sum = 0;

    int n = sscanf(line,
                   "%63s %llu %llu %d %llu %llu %llu %llu",
                   id,
                   &L,
                   &R,
                   &shift,
                   &prime_limit,
                   &exp_count,
                   &exp_xor,
                   &exp_sum);

    if (n < 5)
        return 0;

    memset(out, 0, sizeof(*out));
    strncpy(out->id, id, sizeof(out->id) - 1);
    out->L = (uint64_t)L;
    out->R = (uint64_t)R;
    out->shift = shift;
    out->prime_limit = (uint64_t)prime_limit;
    if (n >= 8) {
        out->exp_count = (uint64_t)exp_count;
        out->exp_xor = (uint64_t)exp_xor;
        out->exp_sum = (uint64_t)exp_sum;
        out->has_expected = 1;
    }
    return 1;
}

static ReplayMetrics run_case(const ReplayCase *c,
                              const uint8_t *h256,
                              const uint64_t *primes,
                              size_t n_primes) {
    ReplayMetrics m = {0, 0, 0};
    uint64_t *base_mod = (uint64_t *)malloc(n_primes * sizeof(uint64_t));
    if (!base_mod) {
        fprintf(stderr, "FAIL: out of memory\n");
        exit(1);
    }

    for (size_t i = 0; i < n_primes; i++)
        base_mod[i] = uint256_mod_small(h256, c->shift, primes[i]);

    size_t out_count = 0;
    const uint64_t *surv = sievegap_run_range(c->L,
                                              c->R,
                                              &out_count,
                                              h256,
                                              c->shift,
                                              primes,
                                              n_primes,
                                              c->prime_limit,
                                              base_mod,
                                              1,
                                              1);
    free(base_mod);

    if (!surv) {
        fprintf(stderr, "FAIL: sievegap_run_range returned NULL for case %s\n", c->id);
        exit(1);
    }

    m.count = out_count;
    for (size_t i = 0; i < out_count; i++) {
        m.xorsum ^= surv[i];
        m.sum += surv[i];
    }
    return m;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s [--generate] <corpus-file>\n", argv[0]);
        return 2;
    }

    int generate = 0;
    const char *corpus = NULL;
    if (argc == 3) {
        if (strcmp(argv[1], "--generate") != 0) {
            fprintf(stderr, "unknown option: %s\n", argv[1]);
            return 2;
        }
        generate = 1;
        corpus = argv[2];
    } else {
        corpus = argv[1];
    }

    FILE *f = fopen(corpus, "rb");
    if (!f) {
        perror("fopen");
        return 2;
    }

    uint64_t primes[4096];
    size_t n_primes = build_small_primes(primes, 4096, 50000);
    if (n_primes < 100) {
        fprintf(stderr, "FAIL: could not build small-prime table\n");
        fclose(f);
        return 1;
    }

    uint8_t h256[32];
    for (int i = 0; i < 32; i++)
        h256[i] = (uint8_t)(i * 11 + 5);

    char line[512];
    uint64_t pass = 0;
    uint64_t fail = 0;

    if (generate)
        puts("# id L R shift prime_limit exp_count exp_xor exp_sum");

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#')
            continue;
        if (line[0] == '\n' || line[0] == '\r')
            continue;

        ReplayCase c;
        if (!parse_line(line, &c)) {
            fprintf(stderr, "FAIL: malformed corpus line: %s", line);
            fclose(f);
            return 1;
        }

        ReplayMetrics m = run_case(&c, h256, primes, n_primes);

        if (generate) {
            printf("%s %" PRIu64 " %" PRIu64 " %d %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                   c.id,
                   c.L,
                   c.R,
                   c.shift,
                   c.prime_limit,
                   m.count,
                   m.xorsum,
                   m.sum);
            continue;
        }

        if (!c.has_expected) {
            fprintf(stderr, "FAIL: case %s missing expected values\n", c.id);
            fclose(f);
            return 1;
        }

        if (m.count != c.exp_count || m.xorsum != c.exp_xor || m.sum != c.exp_sum) {
            fprintf(stderr,
                    "FAIL %s: got(count=%" PRIu64 ",xor=%" PRIu64 ",sum=%" PRIu64 ") "
                    "want(count=%" PRIu64 ",xor=%" PRIu64 ",sum=%" PRIu64 ")\n",
                    c.id,
                    m.count,
                    m.xorsum,
                    m.sum,
                    c.exp_count,
                    c.exp_xor,
                    c.exp_sum);
            fail++;
        } else {
            pass++;
        }
    }

    fclose(f);
    sievegap_free_tls_buffers();

    if (generate)
        return 0;

    if (fail > 0) {
        fprintf(stderr, "Replay corpus validation failed: pass=%" PRIu64 " fail=%" PRIu64 "\n", pass, fail);
        return 1;
    }

    printf("Replay corpus validation passed: %" PRIu64 " cases\n", pass);
    return 0;
}