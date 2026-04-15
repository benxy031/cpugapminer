#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../src/crt_runtime.h"

static void assert_u64_eq(uint64_t got, uint64_t want, const char *msg) {
    if (got != want) {
        fprintf(stderr, "FAIL: %s (got=%llu want=%llu)\n",
                msg,
                (unsigned long long)got,
                (unsigned long long)want);
        exit(1);
    }
}

static void assert_int_eq(int got, int want, const char *msg) {
    if (got != want) {
        fprintf(stderr, "FAIL: %s (got=%d want=%d)\n", msg, got, want);
        exit(1);
    }
}

static void assert_size_eq(size_t got, size_t want, const char *msg) {
    if (got != want) {
        fprintf(stderr, "FAIL: %s (got=%zu want=%zu)\n", msg, got, want);
        exit(1);
    }
}

static void test_adaptive_gap_scan_window(void) {
    struct crt_gap_scan_adapt_cfg cfg = {
        .shrink_drop_pct = 20.0,
        .shrink_fill_pct = 90.0,
        .shrink_factor = 0.5,
        .grow_wait_pct = 60.0,
        .grow_fill_pct = 30.0,
        .grow_factor = 1.2,
    };

    /* Base clamp to 8. */
    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            4, 0, 0,
            0, 100,
            100, 0, 0,
            100, 0,
            &cfg),
        8,
        "adaptive window must clamp base to minimum 8");

    /* Null cfg/heap cap zero should return base (after clamp). */
    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            7, 0, 0,
            10, 100,
            10, 0, 0,
            10, 0,
            NULL),
        8,
        "adaptive window should bypass policy when cfg is null");

    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            40, 0, 0,
            10, 0,
            10, 0, 0,
            10, 0,
            &cfg),
        40,
        "adaptive window should bypass policy when heap cap is zero");

    /* Shrink from drop pressure. */
    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            100, 0, 0,
            10, 100,
            80, 0, 20,
            100, 0,
            &cfg),
        50,
        "adaptive window should shrink when drop percentage is high");

    /* Shrink from fill pressure even with low drop percentage. */
    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            100, 0, 0,
            95, 100,
            99, 0, 1,
            100, 0,
            &cfg),
        50,
        "adaptive window should shrink when heap fill percentage is high");

    /* Grow from waits + low fill. */
    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            100, 0, 0,
            20, 100,
            100, 0, 0,
            30, 70,
            &cfg),
        120,
        "adaptive window should grow when wait percentage is high and fill low");

    /* Fallback factors when cfg values are invalid. */
    {
        struct crt_gap_scan_adapt_cfg bad_cfg = cfg;
        bad_cfg.shrink_factor = 0.0;
        bad_cfg.grow_factor = 1.0;

        assert_u64_eq(
            crt_runtime_adaptive_gap_scan_window(
                100, 0, 0,
                10, 100,
                70, 0, 30,
                100, 0,
                &bad_cfg),
            85,
            "adaptive shrink should use fallback factor 0.85");

        assert_u64_eq(
            crt_runtime_adaptive_gap_scan_window(
                100, 0, 0,
                20, 100,
                100, 0, 0,
                30, 70,
                &bad_cfg),
            110,
            "adaptive grow should use fallback factor 1.10");
    }

    /* Floor and hard cap enforcement. */
    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            100, 60, 0,
            95, 100,
            100, 0, 0,
            100, 0,
            &cfg),
        60,
        "adaptive window should respect floor cap");

    assert_u64_eq(
        crt_runtime_adaptive_gap_scan_window(
            200, 0, 220,
            20, 100,
            100, 0, 0,
            30, 70,
            &cfg),
        220,
        "adaptive window should respect hard cap");
}

static void test_accum_need_preflush(void) {
    struct crt_accum_backpressure_cfg cfg = {
        .soft_cap_candidates = 24576,
        .hard_cap_candidates = 65536,
        .slow_flush_ms = 8.0,
        .slow_collect_ms = 8.0,
    };

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            100, 100, 1,
            4096, 0.0, 0.0,
            NULL),
        0,
        "preflush should be disabled when cfg is null");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            100, 100, 0,
            4096, 0.0, 0.0,
            &cfg),
        0,
        "preflush should require inflight activity");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            100, 0, 1,
            4096, 0.0, 0.0,
            &cfg),
        0,
        "preflush should ignore empty incoming windows");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            SIZE_MAX, 1, 1,
            4096, 0.0, 0.0,
            &cfg),
        1,
        "preflush should trigger on size_t overflow risk");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            65000, 1000, 1,
            4096, 0.0, 0.0,
            &cfg),
        1,
        "preflush should trigger on hard cap overflow");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            24000, 1000, 1,
            4096, 0.0, 0.0,
            &cfg),
        1,
        "preflush should trigger on soft cap overflow");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            0, 2000, 1,
            1000, 20.0, 20.0,
            &cfg),
        0,
        "preflush should allow first window when buffer is empty");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            1000, 100, 1,
            1200, 20.0, 20.0,
            &cfg),
        0,
        "preflush should not trigger below nominal threshold");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            2000, 500, 1,
            1000, 9.0, 1.0,
            &cfg),
        1,
        "preflush should trigger on slow flush above pressure threshold");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            2000, 500, 1,
            1000, 1.0, 9.0,
            &cfg),
        1,
        "preflush should trigger on slow collect above pressure threshold");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            2000, 500, 1,
            1000, 1.0, 1.0,
            &cfg),
        0,
        "preflush should not trigger when latency is healthy");

    assert_int_eq(
        crt_runtime_accum_need_preflush(
            100, 100, 1,
            0, 20.0, 20.0,
            &cfg),
        0,
        "preflush should not use latency path when nominal threshold is zero");
}

static void test_adaptive_gpu_batch_threshold(void) {
    struct crt_gpu_batch_adapt_cfg cfg = {
        .min_batch = 512,
        .max_batch = 8192,
        .pressure_fill_pct = 90.0,
        .grow_fill_pct = 50.0,
        .slow_flush_ms = 1.0,
        .slow_collect_ms = 1.0,
        .fast_flush_ms = 0.30,
        .fast_collect_ms = 0.30,
        .shrink_factor = 0.80,
        .grow_factor = 1.25,
    };

    int dir = 99;

    /* Null cfg falls back to safe clamps and keeps direction neutral. */
    assert_size_eq(
        crt_runtime_adaptive_gpu_batch_threshold(
            32, 100,
            1.0, 1.0,
            NULL, &dir),
        64,
        "adaptive gpu batch should clamp to global fallback minimum when cfg is null");
    assert_int_eq(dir, 0, "adaptive gpu batch should keep neutral direction when cfg is null");

    /* Shrink under pressure when fill and latency are both high. */
    dir = 99;
    assert_size_eq(
        crt_runtime_adaptive_gpu_batch_threshold(
            4096, 3900,
            1.4, 0.2,
            &cfg, &dir),
        3277,
        "adaptive gpu batch should shrink under pressure");
    assert_int_eq(dir, -1, "adaptive gpu batch should report shrink direction");

    /* Grow when batches are sparse and both latencies are healthy. */
    dir = 99;
    assert_size_eq(
        crt_runtime_adaptive_gpu_batch_threshold(
            2048, 800,
            0.10, 0.15,
            &cfg, &dir),
        2560,
        "adaptive gpu batch should grow when underutilized and fast");
    assert_int_eq(dir, 1, "adaptive gpu batch should report grow direction");

    /* Hold when neither shrink nor grow criteria match. */
    dir = 99;
    assert_size_eq(
        crt_runtime_adaptive_gpu_batch_threshold(
            2048, 1300,
            0.40, 0.35,
            &cfg, &dir),
        2048,
        "adaptive gpu batch should hold threshold for mixed telemetry");
    assert_int_eq(dir, 0, "adaptive gpu batch should report hold direction");

    /* Clamp shrink at min and grow at max. */
    dir = 99;
    assert_size_eq(
        crt_runtime_adaptive_gpu_batch_threshold(
            600, 600,
            2.0, 2.0,
            &cfg, &dir),
        512,
        "adaptive gpu batch should clamp shrink to configured min");
    assert_int_eq(dir, -1, "adaptive gpu batch clamp-to-min should still report shrink");

    dir = 99;
    assert_size_eq(
        crt_runtime_adaptive_gpu_batch_threshold(
            7000, 2000,
            0.10, 0.10,
            &cfg, &dir),
        8192,
        "adaptive gpu batch should clamp growth to configured max");
    assert_int_eq(dir, 1, "adaptive gpu batch clamp-to-max should still report grow");
}

static void test_drop_density(void) {
    assert_int_eq(
        crt_runtime_should_drop_density(
            10, 0, 100,
            60, 100,
            1.15),
        0,
        "density drop should ignore zero span");

    assert_int_eq(
        crt_runtime_should_drop_density(
            10, 1000, 0,
            60, 100,
            1.15),
        0,
        "density drop should ignore zero needed gap");

    assert_int_eq(
        crt_runtime_should_drop_density(
            10, 1000, 100,
            40, 100,
            1.15),
        0,
        "density drop should ignore low queue pressure");

    assert_int_eq(
        crt_runtime_should_drop_density(
            10, 1000, 100,
            60, 100,
            1.15),
        1,
        "density drop should trigger under pressure for low density");

    assert_int_eq(
        crt_runtime_should_drop_density(
            23, 1000, 50,
            60, 100,
            1.15),
        0,
        "density drop should not trigger at threshold equality");

    assert_int_eq(
        crt_runtime_should_drop_density(
            30, 1000, 50,
            60, 100,
            1.15),
        0,
        "density drop should not trigger for healthy density");
}

int main(void) {
    test_adaptive_gap_scan_window();
    test_accum_need_preflush();
    test_adaptive_gpu_batch_threshold();
    test_drop_density();

    printf("All CRT runtime policy tests passed.\n");
    return 0;
}
