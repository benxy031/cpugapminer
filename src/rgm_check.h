#pragma once

#include <stddef.h>
#include <stdint.h>

/* ── RGM (Ratio Geometric Mean) info ────────────────────────────────────────
 *
 * NOTE: RGM theory assumes i.i.d. exponential prime gaps, but actual prime
 * gaps are clustered (positive correlations), making the observed RGM
 * systematically below the theoretical value for i.i.d. exponentials.
 * The RGM values are logged as information only; the primary health check
 * is the mean-gap check (E[gap] = logbase, valid regardless of clustering).
 *
 * For n+1 consecutive primes p_1 < ... < p_{n+1}, let g_i = p_{i+1}-p_i.
 * The theoretical geometric mean of (max_gap/min_gap) for i.i.d. Exp(λ):
 *
 *   log rgm(n) = log(n) + n * sum_{j=2}^{n} (-1)^j * C(n-1,j-1) * log(j)/j
 *
 * ── Mean-gap health check ────────────────────────────────────────────────
 *
 * E[gap between consecutive primes near x] = log(x)  (Prime Number Theorem)
 *
 * If the primality pipeline misclassifies composites as primes, the observed
 * mean gap will be shorter than logbase.  If real primes are rejected, the
 * mean gap will be longer.  Deviations > 5% over 10 000+ gaps are anomalous.
 *
 * API is thread-safe; accumulation is cheap (one mutex lock per window). */

#define RGM_MAX_N 32   /* maximum number of gaps tracked per RGM bucket */

/* Feed one window observation (used internally; prefer rgm_accumulate_window). */
void rgm_observe(int n_gaps, uint64_t max_gap, uint64_t min_gap);

/* Snapshot RGM statistics for a given n_gaps value. Returns 1 if data exist. */
int rgm_snapshot(int n_gaps, double *gm_out, double *theory_out,
                 uint64_t *count_out);

/* Compute the theoretical rgm(n) value for i.i.d. exponential gaps. */
double rgm_theory(int n);

/* Chunk a full sorted prime array into non-overlapping groups of chunk_n+1
 * consecutive primes and accumulate RGM statistics.  chunk_n ∈ [2, RGM_MAX_N]. */
void rgm_accumulate_window(const uint64_t *primes, size_t prime_cnt, int chunk_n);

/* Accumulate mean-gap statistics from a full sorted prime window.
 * Adds (primes[cnt-1] - primes[0]) to the span sum and (cnt-1) to the count.
 * Also records the logbase used so the snapshot can self-contain the theory. */
void rgm_accumulate_mean_gap(const uint64_t *primes, size_t prime_cnt,
                             double logbase);

/* Snapshot mean-gap statistics.
 * Returns 1 if >= 1 gap has been accumulated, 0 otherwise.
 *   mean_gap_out : observed mean prime gap (sum_span / count)
 *   logbase_out  : weighted-average logbase stored alongside spans
 *   count_out    : total number of prime gaps accumulated */
int rgm_mean_gap_snapshot(double *mean_gap_out, double *logbase_out,
                          uint64_t *count_out);

/* Print RGM info table and mean-gap health check to the log/console.
 *   min_samples : minimum gap-pair count before printing any row
 *   logbase     : log(mining_base) — theoretical mean prime gap */
void rgm_report(uint64_t min_samples, double logbase);

/* ── Option B: per-region gap-spread scoring ────────────────────────────────
 *
 * After GPU phase 1 yields sampled_primes[sp_cnt], each candidate region
 * [lo, hi) contains some number of sampled primes.  The spread of their
 * consecutive gaps (max/min) is a proxy for heterogeneity inside the region:
 *
 *   high spread → dense cluster + at least one large gap → qualifying gap likely
 *   low spread  → uniformly dense → no qualifying gap inside, safe to skip
 *
 * The score is compared against the calibrated empirical RGM baseline
 * (accumulated from full windows with --sample-stride 1).  A region scores
 * SKIP if its spread is more than `skip_thresh` standard deviations *below*
 * the baseline mean log-ratio.  Returns the number of regions marked dead.
 *
 * safe_gap_width: the raw width [hi-lo] of the region in candidate positions.
 *   Regions whose sampled span already exceeds target_gap are kept regardless
 *   (they contain at least one large gap by construction — the sampled pair
 *   that opened the region).  Only the interior spread score matters for
 *   sub-regions with sp_cnt >= 3 sampled primes.
 *
 * Typical skip_thresh: 0.5 (conservative) … 1.5 (aggressive).
 * Returns 0 if calibration data insufficient (< cal_min_samples). */
int rgm_score_regions(
    const uint64_t *sampled_primes, /* phase-1 survivors, sorted            */
    size_t          sp_cnt,         /* count of phase-1 survivors            */
    const uint64_t *reg_lo,         /* region lower bounds (sp value)        */
    const uint64_t *reg_hi,         /* region upper bounds (sp value)        */
    int            *reg_alive,      /* in/out: 0 = already dead              */
    size_t          n_regions,
    size_t          target_gap,     /* target_local * logbase, in candidates */
    int             chunk_n,        /* RGM bucket to use as baseline (e.g. 10)*/
    double          skip_thresh,    /* SD units below baseline to skip        */
    uint64_t        cal_min_samples /* minimum baseline samples required      */
);

/* ── Option C: empirical qualifying-gap probability ─────────────────────────
 *
 * Accumulate (qualifying_gaps_found, consecutive_pairs_scanned) to derive
 * an empirical p = P(gap >= target | consecutive prime pair).
 *
 * Unlike the theoretical e^{-merit}, this captures clustering effects and
 * any deviation from the Cramér model.  Used to recalibrate the ETA estimate.
 *
 * rgm_accum_qual: called each time a window is scanned.
 *   pairs_scanned   : number of consecutive prime pairs tested
 *   quals_found     : number of qualifying gaps (merit >= target) found
 *   target_merit    : merit threshold used (for bucketing if needed)
 *
 * rgm_qual_prob_snapshot: returns empirical p and sample count.
 *   Returns 1 if enough data, 0 otherwise. */
void rgm_accum_qual(uint64_t pairs_scanned, uint64_t quals_found,
                    double target_merit);
int  rgm_qual_prob_snapshot(double *p_out, uint64_t *pairs_out,
                            uint64_t *quals_out, double *target_out);
