#ifndef CRT_RUNTIME_H
#define CRT_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

struct crt_gap_scan_adapt_cfg {
    double shrink_drop_pct;
    double shrink_fill_pct;
    double shrink_factor;
    double grow_wait_pct;
    double grow_fill_pct;
    double grow_factor;
};

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
    const struct crt_gap_scan_adapt_cfg *cfg);

struct crt_accum_backpressure_cfg {
    size_t soft_cap_candidates;
    size_t hard_cap_candidates;
    double slow_flush_ms;
    double slow_collect_ms;
};

struct crt_gpu_batch_adapt_cfg {
    size_t min_batch;
    size_t max_batch;
    double pressure_fill_pct;
    double grow_fill_pct;
    double slow_flush_ms;
    double slow_collect_ms;
    double fast_flush_ms;
    double fast_collect_ms;
    double shrink_factor;
    double grow_factor;
};

/* Return 1 when caller should flush/collect in-flight GPU work before add(). */
int crt_runtime_accum_need_preflush(size_t current_total,
                                    size_t incoming_count,
                                    int inflight_active,
                                    size_t nominal_threshold,
                                    double avg_flush_ms,
                                    double avg_collect_ms,
                                    const struct crt_accum_backpressure_cfg *cfg);

/* Returns a clamped threshold value and reports direction via direction_out:
   -1 = shrink, 0 = keep, +1 = grow. */
size_t crt_runtime_adaptive_gpu_batch_threshold(
    size_t current_threshold,
    size_t observed_batch,
    double ema_flush_ms,
    double ema_collect_ms,
    const struct crt_gpu_batch_adapt_cfg *cfg,
    int *direction_out);

int crt_runtime_should_drop_density(uint64_t surv_cnt,
                                    uint64_t span_cs,
                                    uint64_t needed_gap_cs,
                                    uint64_t heap_count,
                                    uint64_t heap_cap,
                                    double min_surv_per_needed);

#endif /* CRT_RUNTIME_H */
