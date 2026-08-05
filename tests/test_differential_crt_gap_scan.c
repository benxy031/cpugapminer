/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/crt_gap_scan.h"

static void fail_case(const char *label,
                      uint64_t gap_target,
                      int shift,
                      int mode,
                      double target_merit,
                      double logbase,
                      uint64_t runtime,
                      uint64_t templ) {
    fprintf(stderr,
            "FAIL %s: mode=%d gap_target=%llu shift=%d target=%.6f logbase=%.6f runtime=%llu template=%llu\n",
            label,
            mode,
            (unsigned long long)gap_target,
            shift,
            target_merit,
            logbase,
            (unsigned long long)runtime,
            (unsigned long long)templ);
    exit(1);
}

static void check_invariants(uint64_t gap_target,
                             int shift,
                             int mode,
                             uint64_t floor_value,
                             double target_merit,
                             double logbase) {
    uint64_t templ = crt_gap_scan_template_window(gap_target,
                                                   shift,
                                                   mode,
                                                   floor_value);
    uint64_t runtime = crt_gap_scan_for_nonce(target_merit,
                                              logbase,
                                              gap_target,
                                              shift,
                                              mode,
                                              floor_value);

    if (gap_target > 0ULL && runtime > templ) {
        fail_case("runtime<=template",
                  gap_target,
                  shift,
                  mode,
                  target_merit,
                  logbase,
                  runtime,
                  templ);
    }

    if (mode == CRT_GAP_SCAN_ORIGINAL && gap_target > 0ULL && gap_target < 8ULL) {
        if (runtime > gap_target) {
            fail_case("original<=gap_target",
                      gap_target,
                      shift,
                      mode,
                      target_merit,
                      logbase,
                      runtime,
                      templ);
        }
    } else if (runtime < 8ULL) {
        fail_case("runtime>=8",
                  gap_target,
                  shift,
                  mode,
                  target_merit,
                  logbase,
                  runtime,
                  templ);
    }

    if (mode == CRT_GAP_SCAN_FIXED && runtime < 10000ULL) {
        fail_case("fixed>=10000",
                  gap_target,
                  shift,
                  mode,
                  target_merit,
                  logbase,
                  runtime,
                  templ);
    }

    if (mode == CRT_GAP_SCAN_ORIG_FLOOR) {
        uint64_t floor_scan = floor_value > 0ULL ? floor_value : CRT_GAP_SCAN_FLOOR_DEFAULT;
        if (floor_scan < 8ULL)
            floor_scan = 8ULL;
        if (runtime < floor_scan) {
            fail_case("orig-floor>=floor",
                      gap_target,
                      shift,
                      mode,
                      target_merit,
                      logbase,
                      runtime,
                      templ);
        }
    }
}

int main(void) {
    const uint64_t targets[] = {0ULL, 7ULL, 123ULL, 5000ULL, 10000ULL, 20000ULL, 500000ULL};
    const int shifts[] = {0, 64, 128, 449, 450, 768};
    const double merits[] = {0.0, 1.0, 12.5, 21.0, 30.0, 45.0};
    const double logbases[] = {0.0, 2.0, 20.0, 80.0, 160.0, 320.0};
    const int modes[] = {CRT_GAP_SCAN_FIXED, CRT_GAP_SCAN_ORIGINAL, CRT_GAP_SCAN_ORIG_FLOOR};

    for (size_t ti = 0; ti < sizeof(targets) / sizeof(targets[0]); ti++) {
        for (size_t si = 0; si < sizeof(shifts) / sizeof(shifts[0]); si++) {
            for (size_t mi = 0; mi < sizeof(modes) / sizeof(modes[0]); mi++) {
                for (size_t ri = 0; ri < sizeof(merits) / sizeof(merits[0]); ri++) {
                    for (size_t li = 0; li < sizeof(logbases) / sizeof(logbases[0]); li++) {
                        check_invariants(targets[ti], shifts[si], modes[mi], 0,
                                         merits[ri], logbases[li]);
                        check_invariants(targets[ti], shifts[si], modes[mi], 12000,
                                         merits[ri], logbases[li]);
                    }
                }
            }
        }
    }

    puts("test_differential_crt_gap_scan: OK");
    return 0;
}
