/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* rgm_check.c — Prime-gap health checks.
 *
 * Two complementary statistics:
 *
 * 1. Mean-gap check (primary health indicator):
 *    E[gap between consecutive primes near x] = log(x) by the Prime Number
 *    Theorem.  This is independent of clustering or correlations.  A deviation
 *    of >5% reliably indicates a primality-pipeline bug.
 *
 * 2. RGM (Ratio Geometric Mean, informational only):
 *    The theoretical value assumes i.i.d. exponential prime gaps, but actual
 *    prime gaps are correlated (clustered), so observed RGM is systematically
 *    below theory (e.g. ~-66% at logbase=21, ~-26% at logbase=199).
 *    The values are logged for fingerprinting, NOT used for health warnings.
 *
 * Implementation notes:
 *   - One mutex per bucket keeps contention minimal.
 *   - pthread_once initialises all mutexes lazily on first use.
 */

#include "rgm_check.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

/* ── per-bucket accumulator (RGM) ────────────────────────────────────── */

struct rgm_bucket {
    pthread_mutex_t mu;
    double          sum_log_ratio; /* Σ log(max_gap / min_gap) */
    uint64_t        count;
};

static struct rgm_bucket g_rgm[RGM_MAX_N + 1];

/* ── mean-gap accumulator ─────────────────────────────────────────────── */

static struct {
    pthread_mutex_t mu;
    double          sum_span;    /* Σ (last_prime - first_prime) per window */
    double          sum_logbase; /* Σ logbase weighted by gap-count          */
    uint64_t        count;       /* Σ (num_primes - 1) per window            */
} g_mean_gap;

static pthread_once_t g_rgm_once = PTHREAD_ONCE_INIT;

static void rgm_init_once(void) {
    for (int i = 0; i <= RGM_MAX_N; i++) {
        g_rgm[i].sum_log_ratio = 0.0;
        g_rgm[i].count         = 0;
        pthread_mutex_init(&g_rgm[i].mu, NULL);
    }
    g_mean_gap.sum_span    = 0.0;
    g_mean_gap.sum_logbase = 0.0;
    g_mean_gap.count       = 0;
    pthread_mutex_init(&g_mean_gap.mu, NULL);
}

/* ── math helpers ─────────────────────────────────────────────────────── */

static double binom(int n, int k) {
    if (k < 0 || k > n) return 0.0;
    if (k == 0 || k == n) return 1.0;
    if (k > n - k) k = n - k;
    double r = 1.0;
    for (int i = 0; i < k; i++)
        r = r * (double)(n - i) / (double)(i + 1);
    return r;
}

double rgm_theory(int n) {
    if (n < 2) return 1.0;
    double s = log((double)n);
    for (int j = 2; j <= n; j++) {
        double term = binom(n - 1, j - 1) * log((double)j) / (double)j;
        s += (double)n * ((j % 2 == 0) ? term : -term);
    }
    return exp(s);
}

/* ── public API ───────────────────────────────────────────────────────── */

void rgm_observe(int n_gaps, uint64_t max_gap, uint64_t min_gap) {
    if (n_gaps < 2 || n_gaps > RGM_MAX_N) return;
    if (max_gap == 0 || min_gap == 0 || min_gap > max_gap) return;
    double log_ratio = log((double)max_gap / (double)min_gap);
    pthread_once(&g_rgm_once, rgm_init_once);
    struct rgm_bucket *b = &g_rgm[n_gaps];
    pthread_mutex_lock(&b->mu);
    b->sum_log_ratio += log_ratio;
    b->count++;
    pthread_mutex_unlock(&b->mu);
}

void rgm_accumulate_window(const uint64_t *primes, size_t prime_cnt, int chunk_n) {
    if (chunk_n < 2 || chunk_n > RGM_MAX_N) return;
    size_t step = (size_t)(chunk_n + 1);
    if (prime_cnt < step) return;
    pthread_once(&g_rgm_once, rgm_init_once);
    size_t i = 0;
    while (i + step <= prime_cnt) {
        uint64_t max_g = 0, min_g = 0;
        for (int j = 0; j < chunk_n; j++) {
            uint64_t g = primes[i + j + 1] - primes[i + j];
            if (g > max_g) max_g = g;
            if (min_g == 0 || g < min_g) min_g = g;
        }
        if (max_g > 0) {
            double log_ratio = log((double)max_g / (double)min_g);
            struct rgm_bucket *b = &g_rgm[chunk_n];
            pthread_mutex_lock(&b->mu);
            b->sum_log_ratio += log_ratio;
            b->count++;
            pthread_mutex_unlock(&b->mu);
        }
        i += step;
    }
}

void rgm_accumulate_mean_gap(const uint64_t *primes, size_t prime_cnt,
                             double logbase) {
    if (prime_cnt < 2 || logbase <= 1.0) return;
    pthread_once(&g_rgm_once, rgm_init_once);
    double span  = (double)(primes[prime_cnt - 1] - primes[0]);
    uint64_t ngaps = (uint64_t)(prime_cnt - 1);
    pthread_mutex_lock(&g_mean_gap.mu);
    g_mean_gap.sum_span    += span;
    g_mean_gap.sum_logbase += logbase * (double)ngaps;
    g_mean_gap.count       += ngaps;
    pthread_mutex_unlock(&g_mean_gap.mu);
}

int rgm_mean_gap_snapshot(double *mean_gap_out, double *logbase_out,
                          uint64_t *count_out) {
    pthread_once(&g_rgm_once, rgm_init_once);
    pthread_mutex_lock(&g_mean_gap.mu);
    uint64_t cnt      = g_mean_gap.count;
    double   sum_span = g_mean_gap.sum_span;
    double   sum_lb   = g_mean_gap.sum_logbase;
    pthread_mutex_unlock(&g_mean_gap.mu);
    if (count_out)    *count_out    = cnt;
    if (cnt == 0)     return 0;
    if (mean_gap_out) *mean_gap_out = sum_span / (double)cnt;
    if (logbase_out)  *logbase_out  = sum_lb   / (double)cnt;
    return 1;
}

int rgm_snapshot(int n_gaps, double *gm_out, double *theory_out,
                 uint64_t *count_out) {
    if (n_gaps < 2 || n_gaps > RGM_MAX_N) return 0;
    pthread_once(&g_rgm_once, rgm_init_once);
    struct rgm_bucket *b = &g_rgm[n_gaps];
    pthread_mutex_lock(&b->mu);
    uint64_t cnt = b->count;
    double   sum = b->sum_log_ratio;
    pthread_mutex_unlock(&b->mu);
    if (count_out) *count_out = cnt;
    if (cnt == 0)  return 0;
    if (gm_out)     *gm_out     = exp(sum / (double)cnt);
    if (theory_out) *theory_out = rgm_theory(n_gaps);
    return 1;
}

void rgm_report(uint64_t min_samples, double logbase) {
    /* Snapshot mean-gap */
    pthread_once(&g_rgm_once, rgm_init_once);
    pthread_mutex_lock(&g_mean_gap.mu);
    uint64_t mg_count = g_mean_gap.count;
    double   mg_sum   = g_mean_gap.sum_span;
    pthread_mutex_unlock(&g_mean_gap.mu);

    if (mg_count >= min_samples && logbase > 1.0) {
        double mean_gap = mg_sum / (double)mg_count;
        double dev_pct  = 100.0 * (mean_gap - logbase) / logbase;
        printf("  mean_gap_check: observed=%.4f  theory=%.4f  dev=%+.3f%%  "
               "gaps=%llu%s\n",
               mean_gap, logbase, dev_pct, (unsigned long long)mg_count,
               (fabs(dev_pct) > 5.0) ? "  *** FAIL ***" : "");
    }

    /* RGM info table */
    for (int n = 2; n <= RGM_MAX_N; n++) {
        double   gm, theory;
        uint64_t cnt;
        if (!rgm_snapshot(n, &gm, &theory, &cnt)) continue;
        if (cnt < min_samples) continue;
        double dev_pct = 100.0 * (gm - theory) / theory;
        printf("  rgm n=%2d: gm=%.4f  theory=%.4f  dev=%+.3f%%  samples=%llu\n",
               n, gm, theory, dev_pct, (unsigned long long)cnt);
    }
}

/* ── Option B: per-region gap-spread scoring ──────────────────────────────
 *
 * For each alive region, collect the gaps between the sampled primes that
 * fall inside it.  Compute log(max_gap/min_gap) for those gaps and compare
 * to the calibrated empirical mean log-ratio (from rgm_accumulate_window).
 *
 * Scoring logic:
 *   mean_lr  = calibrated mean log-ratio for chunk_n (from full windows)
 *   region_lr = log(max_g / min_g) of sampled-prime gaps inside this region
 *
 * A region that is "uniformly dense" (all sampled gaps similar) has low
 * region_lr.  If region_lr < mean_lr - skip_thresh * sigma, mark it dead.
 *
 * We estimate sigma ≈ mean_lr (log-ratio distributions have CV ≈ 1 near
 * these scales — validated empirically).  This is conservative: it won't
 * skip a region unless its spread is substantially below baseline.
 */
int rgm_score_regions(
    const uint64_t *sampled_primes,
    size_t          sp_cnt,
    const uint64_t *reg_lo,
    const uint64_t *reg_hi,
    int            *reg_alive,
    size_t          n_regions,
    size_t          target_gap,
    int             chunk_n,
    double          skip_thresh,
    uint64_t        cal_min_samples)
{
    if (!sampled_primes || !reg_lo || !reg_hi || !reg_alive || n_regions == 0)
        return 0;
    if (chunk_n < 2 || chunk_n > RGM_MAX_N) return 0;

    /* Get calibrated baseline: mean log-ratio for this chunk_n */
    pthread_once(&g_rgm_once, rgm_init_once);
    struct rgm_bucket *b = &g_rgm[chunk_n];
    pthread_mutex_lock(&b->mu);
    uint64_t cal_cnt = b->count;
    double   cal_sum = b->sum_log_ratio;
    pthread_mutex_unlock(&b->mu);

    if (cal_cnt < cal_min_samples) return 0; /* not calibrated yet */

    double mean_lr = cal_sum / (double)cal_cnt;
    /* Conservative sigma estimate: CV=1 → sigma = mean_lr */
    double threshold = mean_lr - skip_thresh * mean_lr;
    if (threshold <= 0.0) return 0; /* threshold below 0 → nothing to skip */

    int n_killed = 0;

    for (size_t r = 0; r < n_regions; r++) {
        if (!reg_alive[r]) continue;

        uint64_t lo = reg_lo[r];
        uint64_t hi = reg_hi[r];

        /* Always keep regions whose raw width already spans target_gap —
           the boundary sampled primes themselves define a qualifying gap. */
        if (hi != (uint64_t)-1 && hi > lo && (hi - lo) >= (uint64_t)target_gap)
            continue;

        /* Collect sampled primes inside this region */
        uint64_t max_g = 0, min_g = (uint64_t)-1;
        int n_gaps_in_region = 0;
        uint64_t prev = 0;
        int prev_valid = 0;

        for (size_t i = 0; i < sp_cnt; i++) {
            uint64_t p = sampled_primes[i];
            if (p <= lo) continue;
            if (hi != (uint64_t)-1 && p >= hi) break;
            if (prev_valid) {
                uint64_t g = p - prev;
                if (g > max_g) max_g = g;
                if (g < min_g) min_g = g;
                n_gaps_in_region++;
            }
            prev = p;
            prev_valid = 1;
        }

        /* Need at least 2 gaps (3 sampled primes) for a meaningful score */
        if (n_gaps_in_region < 2 || min_g == 0) continue;

        double region_lr = log((double)max_g / (double)min_g);

        /* If region spread is far below calibrated baseline → skip */
        if (region_lr < threshold) {
            reg_alive[r] = 0;
            n_killed++;
        }
    }

    return n_killed;
}

/* ── Option C: empirical qualifying-gap probability ──────────────────────── */

static struct {
    pthread_mutex_t mu;
    uint64_t        pairs_scanned;
    uint64_t        quals_found;
    double          sum_target;   /* weighted sum for mean target tracking */
} g_qual_stat;

static pthread_once_t g_qual_once = PTHREAD_ONCE_INIT;

static void qual_init_once(void) {
    g_qual_stat.pairs_scanned = 0;
    g_qual_stat.quals_found   = 0;
    g_qual_stat.sum_target    = 0.0;
    pthread_mutex_init(&g_qual_stat.mu, NULL);
}

void rgm_accum_qual(uint64_t pairs_scanned, uint64_t quals_found,
                    double target_merit) {
    if (pairs_scanned == 0) return;
    pthread_once(&g_qual_once, qual_init_once);
    pthread_mutex_lock(&g_qual_stat.mu);
    g_qual_stat.pairs_scanned += pairs_scanned;
    g_qual_stat.quals_found   += quals_found;
    g_qual_stat.sum_target    += target_merit * (double)pairs_scanned;
    pthread_mutex_unlock(&g_qual_stat.mu);
}

int rgm_qual_prob_snapshot(double *p_out, uint64_t *pairs_out,
                           uint64_t *quals_out, double *target_out) {
    pthread_once(&g_qual_once, qual_init_once);
    pthread_mutex_lock(&g_qual_stat.mu);
    uint64_t ps = g_qual_stat.pairs_scanned;
    uint64_t qf = g_qual_stat.quals_found;
    double   st = g_qual_stat.sum_target;
    pthread_mutex_unlock(&g_qual_stat.mu);

    if (pairs_out)  *pairs_out  = ps;
    if (quals_out)  *quals_out  = qf;
    if (target_out) *target_out = (ps > 0) ? st / (double)ps : 0.0;
    if (ps == 0) return 0;
    if (p_out) *p_out = (double)qf / (double)ps;
    return 1;
}

/* ── RGM state persistence ──────────────────────────────────────────────── */

int rgm_save_state(const char *path) {
    if (!path || !*path) return -1;
    pthread_once(&g_rgm_once, rgm_init_once);

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "# cpugapminer rgm_state v1\n");
    fprintf(f, "# bucket <n> <count> <sum_log_ratio>\n");
    fprintf(f, "# meangap <count> <sum_span> <sum_logbase>\n");

    /* Save only the two buckets used by rgm_score_regions */
    for (int n = 10; n <= 20; n += 10) {
        struct rgm_bucket *b = &g_rgm[n];
        pthread_mutex_lock(&b->mu);
        uint64_t cnt = b->count;
        double   sum = b->sum_log_ratio;
        pthread_mutex_unlock(&b->mu);
        if (cnt > 0)
            fprintf(f, "bucket %d %llu %.17g\n", n,
                    (unsigned long long)cnt, sum);
    }

    pthread_mutex_lock(&g_mean_gap.mu);
    uint64_t mg_cnt = g_mean_gap.count;
    double   mg_sp  = g_mean_gap.sum_span;
    double   mg_lb  = g_mean_gap.sum_logbase;
    pthread_mutex_unlock(&g_mean_gap.mu);

    if (mg_cnt > 0)
        fprintf(f, "meangap %llu %.17g %.17g\n",
                (unsigned long long)mg_cnt, mg_sp, mg_lb);

    return fclose(f);
}

int rgm_load_state(const char *path) {
    if (!path || !*path) return -1;
    pthread_once(&g_rgm_once, rgm_init_once);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    int merged = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        if (strncmp(line, "bucket ", 7) == 0) {
            int n; unsigned long long cnt; double sum;
            if (sscanf(line + 7, "%d %llu %lf", &n, &cnt, &sum) == 3) {
                if (n >= 2 && n <= RGM_MAX_N && cnt > 0) {
                    struct rgm_bucket *b = &g_rgm[n];
                    pthread_mutex_lock(&b->mu);
                    b->count         += (uint64_t)cnt;
                    b->sum_log_ratio += sum;
                    pthread_mutex_unlock(&b->mu);
                    merged++;
                }
            }
        } else if (strncmp(line, "meangap ", 8) == 0) {
            unsigned long long cnt; double sp, lb;
            if (sscanf(line + 8, "%llu %lf %lf", &cnt, &sp, &lb) == 3) {
                if (cnt > 0) {
                    pthread_mutex_lock(&g_mean_gap.mu);
                    g_mean_gap.count       += (uint64_t)cnt;
                    g_mean_gap.sum_span    += sp;
                    g_mean_gap.sum_logbase += lb;
                    pthread_mutex_unlock(&g_mean_gap.mu);
                    merged++;
                }
            }
        }
    }
    fclose(f);
    return merged;
}
