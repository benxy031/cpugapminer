/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crt_gap_scan.h"

static void fail_u64(const char *name, uint64_t got, uint64_t want) {
    fprintf(stderr,
            "FAIL %s: got=%llu want=%llu\n",
            name,
            (unsigned long long)got,
            (unsigned long long)want);
    exit(1);
}

static void expect_u64(const char *name, uint64_t got, uint64_t want) {
    if (got != want)
        fail_u64(name, got, want);
}

static void expect_true(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        exit(1);
    }
}

int main(void) {
    int mode = -1;

    expect_true("parse fixed", crt_gap_scan_mode_parse("fixed", &mode) && mode == CRT_GAP_SCAN_FIXED);
    expect_true("parse original", crt_gap_scan_mode_parse("original", &mode) && mode == CRT_GAP_SCAN_ORIGINAL);
    expect_true("parse dynamic", crt_gap_scan_mode_parse("dynamic", &mode) && mode == CRT_GAP_SCAN_ORIGINAL);
    expect_true("parse hybrid", crt_gap_scan_mode_parse("hybrid", &mode) && mode == CRT_GAP_SCAN_ORIG_FLOOR);
    expect_true("parse invalid", !crt_gap_scan_mode_parse("bogus", &mode));

    expect_u64("fixed zero", crt_gap_scan_fixed_window(0), 10000ULL);
    expect_u64("fixed small", crt_gap_scan_fixed_window(4000), 10000ULL);
    expect_u64("fixed large", crt_gap_scan_fixed_window(9000), 18000ULL);
    expect_u64("fixed overflow", crt_gap_scan_fixed_window(UINT64_MAX), UINT64_MAX);

    expect_u64("fixed shift>=450", crt_gap_scan_fixed_window_for_shift(6000, 450), 12000ULL);
    expect_u64("fixed shift<450", crt_gap_scan_fixed_window_for_shift(6000, 128), 10500ULL);

    expect_u64("template original floor 8",
               crt_gap_scan_template_window(0, 0, CRT_GAP_SCAN_ORIGINAL, 0),
               8ULL);
    expect_u64("template orig-floor default floor",
               crt_gap_scan_template_window(100, 0, CRT_GAP_SCAN_ORIG_FLOOR, 0),
               10000ULL);
    expect_u64("template fixed",
               crt_gap_scan_template_window(6000, 128, CRT_GAP_SCAN_FIXED, 0),
               10500ULL);

    expect_u64("nonce original cap to target",
               crt_gap_scan_for_nonce(30.0, 100.0, 2000ULL, 0, CRT_GAP_SCAN_ORIGINAL, 0),
               2000ULL);
    expect_u64("nonce original min 8",
               crt_gap_scan_for_nonce(0.0, 0.0, 0ULL, 0, CRT_GAP_SCAN_ORIGINAL, 0),
               8ULL);
    expect_u64("nonce orig-floor floor clamp",
               crt_gap_scan_for_nonce(30.0, 10.0, 5000ULL, 0, CRT_GAP_SCAN_ORIG_FLOOR, 1000ULL),
               1000ULL);

    expect_u64("nonce fixed dynamic cap",
               crt_gap_scan_for_nonce(30.0, 200.0, 8000ULL, 700, CRT_GAP_SCAN_FIXED, 0),
               12000ULL);
    expect_u64("nonce fixed no cap",
               crt_gap_scan_for_nonce(30.0, 300.0, 8000ULL, 700, CRT_GAP_SCAN_FIXED, 0),
               16000ULL);

    puts("test_boundary_crt_gap_scan: OK");
    return 0;
}
