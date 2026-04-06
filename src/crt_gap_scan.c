#include "crt_gap_scan.h"

#include <limits.h>
#include <math.h>
#include <string.h>

static uint64_t gap_scan_floor_or_default(uint64_t floor_value) {
    uint64_t floor_scan = floor_value > 0ULL
        ? floor_value : CRT_GAP_SCAN_FLOOR_DEFAULT;
    if (floor_scan < 8ULL)
        floor_scan = 8ULL;
    return floor_scan;
}

const char *crt_gap_scan_mode_name(int mode) {
    if (mode == CRT_GAP_SCAN_ORIGINAL)
        return "original";
    if (mode == CRT_GAP_SCAN_ORIG_FLOOR)
        return "original-floor";
    return "fixed";
}

int crt_gap_scan_mode_parse(const char *mode, int *out_mode) {
    if (!mode || !out_mode)
        return 0;

    if (!strcmp(mode, "fixed")) {
        *out_mode = CRT_GAP_SCAN_FIXED;
        return 1;
    }
    if (!strcmp(mode, "original") || !strcmp(mode, "orig")
            || !strcmp(mode, "dynamic")) {
        *out_mode = CRT_GAP_SCAN_ORIGINAL;
        return 1;
    }
    if (!strcmp(mode, "original-floor") || !strcmp(mode, "orig-floor")
            || !strcmp(mode, "dynamic-floor") || !strcmp(mode, "hybrid")) {
        *out_mode = CRT_GAP_SCAN_ORIG_FLOOR;
        return 1;
    }
    return 0;
}

uint64_t crt_gap_scan_fixed_window(uint64_t gap_target) {
    uint64_t gap_scan = (gap_target > (UINT64_MAX / 2ULL))
        ? UINT64_MAX : (gap_target * 2ULL);
    if (gap_scan < 10000ULL)
        gap_scan = 10000ULL;
    return gap_scan;
}

uint64_t crt_gap_scan_template_window(uint64_t gap_target,
                                      int mode,
                                      uint64_t floor_value) {
    if (mode == CRT_GAP_SCAN_ORIGINAL) {
        uint64_t gap_scan = (gap_target > 0ULL) ? gap_target : 8ULL;
        if (gap_scan < 8ULL)
            gap_scan = 8ULL;
        return gap_scan;
    }
    if (mode == CRT_GAP_SCAN_ORIG_FLOOR) {
        uint64_t gap_scan = (gap_target > 0ULL) ? gap_target : 8ULL;
        uint64_t floor_scan = gap_scan_floor_or_default(floor_value);
        if (gap_scan < floor_scan)
            gap_scan = floor_scan;
        return gap_scan;
    }
    return crt_gap_scan_fixed_window(gap_target);
}

uint64_t crt_gap_scan_for_nonce(double target_merit,
                                double logbase,
                                uint64_t gap_target,
                                int mode,
                                uint64_t floor_value) {
    if (mode == CRT_GAP_SCAN_ORIGINAL || mode == CRT_GAP_SCAN_ORIG_FLOOR) {
        double raw = target_merit * logbase;
        uint64_t gap_scan = 0;

        if (raw > 0.0 && raw < (double)UINT64_MAX)
            gap_scan = (uint64_t)ceil(raw);

        if (gap_scan < 8ULL)
            gap_scan = 8ULL;

        if (gap_target > 0ULL && gap_scan > gap_target)
            gap_scan = gap_target;

        if (mode == CRT_GAP_SCAN_ORIG_FLOOR) {
            uint64_t floor_scan = gap_scan_floor_or_default(floor_value);
            if (gap_scan < floor_scan)
                gap_scan = floor_scan;
        }

        return gap_scan;
    }

    return crt_gap_scan_fixed_window(gap_target);
}
