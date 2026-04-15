#include "crt_runtime.h"

#include <limits.h>

static double pct_u64(uint64_t num, uint64_t den) {
    if (den == 0)
        return 0.0;
    return (100.0 * (double)num) / (double)den;
}

static size_t clamp_size_t(size_t v, size_t lo, size_t hi) {
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

uint64_t crt_runtime_adaptive_gap_scan_window(
    uint64_t base_window,
    uint64_t floor_window,
    uint64_t hard_cap_window,
    uint64_t heap_count,
    uint64_t heap_cap,
    uint64_t heap_push_ok,
    uint64_t heap_push_replace,
    uint64_t heap_push_drop,
    uint64_t heap_pop_ok,
    uint64_t heap_waits,
    const struct crt_gap_scan_adapt_cfg *cfg) {
    if (base_window < 8ULL)
        base_window = 8ULL;

    if (!cfg || heap_cap == 0)
        return base_window;

    double fill_pct = pct_u64(heap_count, heap_cap);
    uint64_t heap_push_total = heap_push_ok + heap_push_replace + heap_push_drop;
    double drop_pct = pct_u64(heap_push_drop, heap_push_total);
    double wait_pct = pct_u64(heap_waits, heap_waits + heap_pop_ok);

    double win = (double)base_window;

    if (drop_pct >= cfg->shrink_drop_pct || fill_pct >= cfg->shrink_fill_pct) {
        double factor = cfg->shrink_factor;
        if (factor <= 0.0 || factor >= 1.0)
            factor = 0.85;
        win *= factor;
    } else if (wait_pct >= cfg->grow_wait_pct && fill_pct <= cfg->grow_fill_pct) {
        double factor = cfg->grow_factor;
        if (factor <= 1.0)
            factor = 1.10;
        win *= factor;
    }

    uint64_t out = (win <= 0.0) ? base_window : (uint64_t)(win + 0.5);
    if (out < 8ULL)
        out = 8ULL;

    if (floor_window > 0ULL && out < floor_window)
        out = floor_window;
    if (hard_cap_window > 0ULL && out > hard_cap_window)
        out = hard_cap_window;

    return out;
}

int crt_runtime_accum_need_preflush(size_t current_total,
                                    size_t incoming_count,
                                    int inflight_active,
                                    size_t nominal_threshold,
                                    double avg_flush_ms,
                                    double avg_collect_ms,
                                    const struct crt_accum_backpressure_cfg *cfg) {
    if (!cfg || !inflight_active || incoming_count == 0)
        return 0;

    if (current_total > SIZE_MAX - incoming_count)
        return 1;

    size_t projected = current_total + incoming_count;

    if (cfg->hard_cap_candidates > 0 &&
        incoming_count <= cfg->hard_cap_candidates &&
        projected > cfg->hard_cap_candidates)
        return 1;

    if (cfg->soft_cap_candidates > 0 &&
        incoming_count <= cfg->soft_cap_candidates &&
        projected > cfg->soft_cap_candidates)
        return 1;

    /* If fill buffer is empty, accept one window and evaluate pressure again
       on the next add() call. This prevents preflush loops on large windows. */
    if (current_total == 0)
        return 0;

    if (nominal_threshold == 0 || projected <= nominal_threshold)
        return 0;

    if ((avg_flush_ms >= cfg->slow_flush_ms ||
         avg_collect_ms >= cfg->slow_collect_ms) &&
        projected > (nominal_threshold + nominal_threshold / 2))
        return 1;

    return 0;
}

size_t crt_runtime_adaptive_gpu_batch_threshold(
    size_t current_threshold,
    size_t observed_batch,
    double ema_flush_ms,
    double ema_collect_ms,
    const struct crt_gpu_batch_adapt_cfg *cfg,
    int *direction_out) {
    if (direction_out)
        *direction_out = 0;

    size_t min_batch = 64;
    size_t max_batch = (size_t)(1U << 20);
    if (cfg) {
        if (cfg->min_batch > 0)
            min_batch = cfg->min_batch;
        if (cfg->max_batch > 0)
            max_batch = cfg->max_batch;
    }
    if (max_batch < min_batch)
        max_batch = min_batch;

    size_t cur = current_threshold == 0 ? min_batch : current_threshold;
    cur = clamp_size_t(cur, min_batch, max_batch);
    if (!cfg || observed_batch == 0)
        return cur;

    double pressure_fill_pct = cfg->pressure_fill_pct > 0.0
        ? cfg->pressure_fill_pct : 95.0;
    double grow_fill_pct = cfg->grow_fill_pct > 0.0
        ? cfg->grow_fill_pct : 50.0;
    double slow_flush_ms = cfg->slow_flush_ms > 0.0
        ? cfg->slow_flush_ms : 0.45;
    double slow_collect_ms = cfg->slow_collect_ms > 0.0
        ? cfg->slow_collect_ms : 0.45;
    double fast_flush_ms = cfg->fast_flush_ms > 0.0
        ? cfg->fast_flush_ms : 0.20;
    double fast_collect_ms = cfg->fast_collect_ms > 0.0
        ? cfg->fast_collect_ms : 0.20;
    double shrink_factor = (cfg->shrink_factor > 0.0 && cfg->shrink_factor < 1.0)
        ? cfg->shrink_factor : 0.85;
    double grow_factor = cfg->grow_factor > 1.0
        ? cfg->grow_factor : 1.15;

    double fill_pct = pct_u64((uint64_t)observed_batch, (uint64_t)cur);
    size_t next = cur;

    if (fill_pct >= pressure_fill_pct &&
        (ema_flush_ms >= slow_flush_ms || ema_collect_ms >= slow_collect_ms)) {
        next = (size_t)((double)cur * shrink_factor + 0.5);
        next = clamp_size_t(next, min_batch, max_batch);
        if (next < cur && direction_out)
            *direction_out = -1;
    } else if (fill_pct <= grow_fill_pct &&
               ema_flush_ms <= fast_flush_ms &&
               ema_collect_ms <= fast_collect_ms) {
        next = (size_t)((double)cur * grow_factor + 0.5);
        next = clamp_size_t(next, min_batch, max_batch);
        if (next > cur && direction_out)
            *direction_out = 1;
    }

    return next;
}

int crt_runtime_should_drop_density(uint64_t surv_cnt,
                                    uint64_t span_cs,
                                    uint64_t needed_gap_cs,
                                    uint64_t heap_count,
                                    uint64_t heap_cap,
                                    double min_surv_per_needed) {
    if (span_cs == 0 || heap_cap == 0 || needed_gap_cs == 0)
        return 0;

    if (heap_count < (heap_cap / 2ULL))
        return 0;

    double surv_per_needed =
        ((double)surv_cnt * (double)needed_gap_cs) / (double)span_cs;
    return surv_per_needed < min_surv_per_needed;
}
