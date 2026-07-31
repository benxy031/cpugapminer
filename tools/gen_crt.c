/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * gen_crt.c  –  CRT (Chinese Remainder Theorem) gap solver for Gapcoin mining
 *
 * Two-phase algorithm compatible with GapMiner --calc-ctr parameters:
 *
 *   Phase 1 (Greedy):  For each prime p_i in order, pick the offset o_i
 *                       (0 ≤ o_i < p_i) that covers the most currently-
 *                       uncovered positions in the gap range [1, G].
 *                       Repeated with random tie-breaking (--ctr-strength).
 *
 *   Phase 2 (Evolution): Refine the greedy population via tournament
 *                         selection, uniform crossover, mutation, and
 *                         local-search on non-fixed primes (--ctr-fixed).
 *
 * A position d ∈ [1, G] is "covered" by prime p_i with offset o_i when
 * d ≡ o_i (mod p_i).  The miner then only searches starting values n such
 * that (-n mod p_i) = o_i for all CRT primes (unique via CRT modulo the
 * primorial).  Positions not covered by any CRT prime are "candidates"
 * that must be eliminated by the sieve of larger primes + Fermat testing.
 *
 * Output: human-readable text file consumed by the miner (--crt-file).
 *
 * Build:
 *   make gen_crt
 *
 * Example:
 *   gen_crt --calc-ctr --ctr-primes 24 --ctr-merit 22 --ctr-bits 14 \
 *           --ctr-strength 100 --ctr-evolution --ctr-fixed 8       \
 *           --ctr-ivs 20 --ctr-file crt_24.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
/* rand_r is POSIX-only; provide a simple LCG shim for Windows */
static int rand_r(unsigned *seed) {
    *seed = *seed * 1103515245u + 12345u;
    return (int)((*seed >> 16) & 0x7fff);
}
static int get_cpu_count(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}
/* nanosleep shim: MinGW winpthreads provides it, but guard for MSVC */
#  if defined(_MSC_VER)
#    include <time.h>
static int nanosleep(const struct timespec *req, struct timespec *rem) {
    (void)rem;
    DWORD ms = (DWORD)(req->tv_sec * 1000 + req->tv_nsec / 1000000);
    Sleep(ms ? ms : 1);
    return 0;
}
#  endif
#else
#  include <unistd.h>
static int get_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 1) ? (int)n : 1;
}
#endif

/* ------------------------------------------------------------------ */
/* First 200 primes (covers up to prime 1223, log2 primorial ~ 1588)  */
/* ------------------------------------------------------------------ */
static const int PRIMES[] = {
      2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
     31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
     73,  79,  83,  89,  97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997,1009,1013,
   1019,1021,1031,1033,1039,1049,1051,1061,1063,1069,
   1087,1091,1093,1097,1103,1109,1117,1123,1129,1151,
   1153,1163,1171,1181,1187,1193,1201,1213,1217,1223
};
#define N_PRIMES_AVAIL ((int)(sizeof(PRIMES) / sizeof(PRIMES[0])))

/* ------------------------------------------------------------------ */
/* Per-position primality weight for the weighted fitness function.    */
/*                                                                     */
/* w(d) = ∏(1 - 1/p) for p in WEIGHT_PRIMES where p does NOT divide d */
/*                                                                     */
/* Rationale: positions coprime to many small primes are harder to     */
/* eliminate by subsequent sieving (they don't have "free" small-prime  */
/* coverage and will linger as Fermat candidates longer on average).   */
/* Weighting by w(d) gives the optimizer a smoother, continuous        */
/* landscape — analogous to cross-entropy vs. 0-1 loss — reducing      */
/* degeneracy from large flat integer plateaus.                        */
/* ------------------------------------------------------------------ */
static const int    WEIGHT_PRIMES[]   = {3,5,7,11,13,17,19,23,29,31};
#define N_WEIGHT_PRIMES 10

/* Penalize adjacent uncovered positions so the optimizer prefers
 * candidates that are not clustered into weak dense runs. */
#define CLUSTER_PENALTY_WEIGHT 0.45

/* ------------------------------------------------------------------ */
/* Phase-1 diagnostic score (shadow only; does NOT affect optimisation)
 *
 * Kernel from forum fit idea:
 *   K(x) = exp(-a * |x/scale|^b)
 *
 * We compute this only for final/best solutions to avoid perturbing hot
 * optimisation loops. Lower score implies sparser candidate mass under this
 * kernel (heuristically better for long-gap probability).
 */
#define PHASE1_A_DEFAULT 5.8
#define PHASE1_B_DEFAULT 3.3

typedef struct {
    int    remaining;
    double score_raw;
    double score_mean;
    double a;
    double b;
    double scale;
} Phase1Diag;

typedef enum {
    FITNESS_CANDIDATE = 0,
    FITNESS_PROBABILITY = 1
} FitnessMode;

typedef struct {
    FitnessMode mode;
    double window_factor;
    int window_cap;
    double kernel_a;
    double kernel_b;
} FitnessConfig;

static double position_weight(int d) {
    /* Positions coprime to small primes are harder to eliminate by
     * subsequent sieving (no small factor to anchor a residue test)
     * → higher weight = more valuable to cover via CRT.
     * Positions that ARE divisible by a small prime p have at least
     * one sieve event covering them with probability 1 for that p,
     * so their net coverage value is discounted by (1 - 1/p). */
    double w = 1.0;
    for (int i = 0; i < N_WEIGHT_PRIMES; i++)
        if (d % WEIGHT_PRIMES[i] == 0)   /* divisible → discount */
            w *= (1.0 - 1.0 / WEIGHT_PRIMES[i]);
    return w;
}

/* ------------------------------------------------------------------ */
/* Solution: a set of offsets and its fitness (n_candidates)           */
/* ------------------------------------------------------------------ */
typedef struct {
    int    n_primes;
    int    gap_size;
    int   *offsets;       /* offsets[i] for PRIMES[i], 0 <= o < p_i    */
    int    n_candidates;  /* integer uncovered count (display/file out) */
    double w_score;       /* weighted fitness used for optimization     */
    double opt_score;     /* future primary objective (mode-dependent)  */
    double aux_score;     /* future diagnostic / tie-break score        */
} Solution;

static Phase1Diag phase1_diag(const int *offsets, int n_primes, int gap_size,
                              uint8_t *buf, double a, double b) {
    Phase1Diag d;
    d.remaining = 0;
    d.score_raw = 0.0;
    d.score_mean = 0.0;
    d.a = a;
    d.b = b;
    d.scale = (gap_size > 0) ? (double)gap_size : 1.0;

    memset(buf, 0, (size_t)(gap_size + 1));
    for (int i = 0; i < n_primes; i++) {
        int p = PRIMES[i];
        int o = offsets[i] % p;
        for (int x = (o ? o : p); x <= gap_size; x += p)
            buf[x] = 1;
    }

    /* Center kernel around the middle of [1..gap_size]. */
    double center = 0.5 * (double)gap_size;
    for (int x = 1; x <= gap_size; x++) {
        if (buf[x]) continue;
        d.remaining++;
        double t = fabs(((double)x - center) / d.scale);
        d.score_raw += exp(-a * pow(t, b));
    }
    if (d.remaining > 0)
        d.score_mean = d.score_raw / (double)d.remaining;
    return d;
}

static bool solution_better(const Solution *a, const Solution *b) {
    if (a->n_candidates != b->n_candidates)
        return a->n_candidates < b->n_candidates;
    return a->w_score < b->w_score;
}

static bool solution_better_mode(const Solution *a, const Solution *b,
                                 const FitnessConfig *fc) {
    if (fc->mode == FITNESS_PROBABILITY) {
        if (a->opt_score != b->opt_score)
            return a->opt_score < b->opt_score;
        if (a->n_candidates != b->n_candidates)
            return a->n_candidates < b->n_candidates;
        return a->aux_score < b->aux_score;
    }
    if (a->n_candidates != b->n_candidates)
        return a->n_candidates < b->n_candidates;
    if (a->opt_score != b->opt_score)
        return a->opt_score < b->opt_score;
    return a->aux_score < b->aux_score;
}

static bool solution_better_metrics_mode(int a_cnt, double a_opt, double a_aux,
                                         int b_cnt, double b_opt, double b_aux,
                                         const FitnessConfig *fc) {
    if (fc->mode == FITNESS_PROBABILITY) {
        if (a_opt != b_opt)
            return a_opt < b_opt;
        if (a_cnt != b_cnt)
            return a_cnt < b_cnt;
        return a_aux < b_aux;
    }
    if (a_cnt != b_cnt)
        return a_cnt < b_cnt;
    if (a_opt != b_opt)
        return a_opt < b_opt;
    return a_aux < b_aux;
}

static bool solution_better_phase3(const Solution *a, const Phase1Diag *a_p1,
                                   const Solution *b, const Phase1Diag *b_p1,
                                   int delta_candidates,
                                   double mean_eps) {
    if (a->n_candidates < b->n_candidates - delta_candidates)
        return true;
    if (b->n_candidates < a->n_candidates - delta_candidates)
        return false;

    if (a_p1->score_mean > b_p1->score_mean + mean_eps)
        return true;
    if (b_p1->score_mean > a_p1->score_mean + mean_eps)
        return false;

    if (a_p1->score_raw != b_p1->score_raw)
        return a_p1->score_raw > b_p1->score_raw;
    return solution_better(a, b);
}

/* ---- helpers ---- */

static double primorial_log2(int n) {
    double s = 0.0;
    for (int i = 0; i < n && i < N_PRIMES_AVAIL; i++)
        s += log2((double)PRIMES[i]);
    return s;
}

static int fitness_window_size(int gap_size, const FitnessConfig *fc) {
    int window = (int)ceil(fc->window_factor * (double)gap_size);
    if (window < gap_size)
        window = gap_size;
    if (fc->window_cap > 0 && window > fc->window_cap)
        window = fc->window_cap;
    return window;
}

static double legacy_display_score(FitnessMode mode, double opt_score, double aux_score) {
    return (mode == FITNESS_PROBABILITY) ? aux_score : opt_score;
}

static Solution sol_alloc(int n_primes, int gap_size) {
    Solution s;
    s.n_primes     = n_primes;
    s.gap_size     = gap_size;
    s.offsets      = (int *)malloc((size_t)n_primes * sizeof(int));
    s.n_candidates = INT_MAX;
    s.w_score      = 1e18;
    s.opt_score    = 1e18;
    s.aux_score    = 1e18;
    if (!s.offsets) { perror("malloc"); exit(1); }
    return s;
}

static Solution sol_clone(const Solution *src) {
    Solution c = sol_alloc(src->n_primes, src->gap_size);
    memcpy(c.offsets, src->offsets, (size_t)src->n_primes * sizeof(int));
    c.n_candidates = src->n_candidates;
    c.w_score      = src->w_score;
    c.opt_score    = src->opt_score;
    c.aux_score    = src->aux_score;
    return c;
}

static void sol_free(Solution *s) {
    free(s->offsets);
    s->offsets = NULL;
}

/* ------------------------------------------------------------------ */
/* Evaluate: count uncovered positions in [1, gap_size].              */
/* Uses caller-owned buffer buf[0..gap_size] (uint8_t).               */
/* ------------------------------------------------------------------ */
static int evaluate_candidate(const int *offsets, int n_primes, int gap_size,
                              uint8_t *buf, double *opt_out, double *aux_out) {
    memset(buf, 0, (size_t)(gap_size + 1));
    for (int i = 0; i < n_primes; i++) {
        int p = PRIMES[i];
        int o = offsets[i] % p;
        /* positions d == o (mod p), d in [1, gap_size] */
        for (int d = (o ? o : p); d <= gap_size; d += p)
            buf[d] = 1;
    }
    int    cnt = 0;
    double wt  = 0.0;
    double cluster_penalty = 0.0;
    int prev_uncovered = 0;
    int run_len = 0;
    for (int d = 1; d <= gap_size; d++) {
        if (!buf[d]) {
            cnt++;
            wt += position_weight(d);
            if (prev_uncovered) {
                run_len++;
                cluster_penalty += 1.0 + 0.25 * (double)(run_len - 1);
            } else {
                run_len = 1;
            }
            prev_uncovered = 1;
        } else {
            prev_uncovered = 0;
            run_len = 0;
        }
    }
    if (opt_out) *opt_out = wt + CLUSTER_PENALTY_WEIGHT * cluster_penalty;
    if (aux_out) *aux_out = wt;
    return cnt;
}

static int evaluate_probability(const int *offsets, int n_primes, int gap_size,
                                uint8_t *buf, uint8_t *buf_wide,
                                const FitnessConfig *fc,
                                double *opt_out, double *aux_out) {
    int window = fitness_window_size(gap_size, fc);
    uint8_t *owned_wide = NULL;
    if (!buf_wide) {
        owned_wide = (uint8_t *)calloc((size_t)(window + 1), 1);
        if (!owned_wide) {
            perror("calloc");
            exit(1);
        }
        buf_wide = owned_wide;
    }

    memset(buf, 0, (size_t)(gap_size + 1));
    memset(buf_wide, 0, (size_t)(window + 1));

    for (int i = 0; i < n_primes; i++) {
        int p = PRIMES[i];
        int o = offsets[i] % p;
        int start = (o ? o : p);
        for (int d = start; d <= gap_size; d += p)
            buf[d] = 1;
        for (int d = start; d <= window; d += p)
            buf_wide[d] = 1;
    }

    int cnt = 0;
    double wt = 0.0;
    double cluster_penalty = 0.0;
    int prev_uncovered = 0;
    int run_len = 0;
    for (int d = 1; d <= gap_size; d++) {
        if (!buf[d]) {
            cnt++;
            wt += position_weight(d);
            if (prev_uncovered) {
                run_len++;
                cluster_penalty += 1.0 + 0.25 * (double)(run_len - 1);
            } else {
                run_len = 1;
            }
            prev_uncovered = 1;
        } else {
            prev_uncovered = 0;
            run_len = 0;
        }
    }

    double center = 0.5 * (double)gap_size;
    double scale = (gap_size > 0) ? (double)gap_size : 1.0;
    double score = 0.0;
    for (int d = 1; d <= window; d++) {
        if (buf_wide[d])
            continue;
        double t = fabs(((double)d - center) / scale);
        score += exp(-fc->kernel_a * pow(t, fc->kernel_b));
    }

    if (opt_out) *opt_out = score;
    if (aux_out) *aux_out = wt + CLUSTER_PENALTY_WEIGHT * cluster_penalty;

    free(owned_wide);
    return cnt;
}

static int evaluate_solution(const int *offsets, int n_primes, int gap_size,
                             uint8_t *buf, uint8_t *buf_wide,
                             const FitnessConfig *fc,
                             double *opt_out, double *aux_out) {
    if (fc && fc->mode == FITNESS_PROBABILITY) {
        return evaluate_probability(offsets, n_primes, gap_size,
                                    buf, buf_wide, fc,
                                    opt_out, aux_out);
    }
    return evaluate_candidate(offsets, n_primes, gap_size,
                              buf, opt_out, aux_out);
}

/* Legacy entrypoint preserved until all optimization paths are migrated to
 * mode-aware evaluation/comparison. */
/* ------------------------------------------------------------------ */
/* Greedy algorithm: assign offsets one prime at a time, choosing the  */
/* offset that covers the most currently-uncovered gap positions.      */
/* Ties are broken randomly (reservoir sampling) for diversity.        */
/* ------------------------------------------------------------------ */
static void greedy_solve(int *offsets, int n_primes, int gap_size,
                         uint8_t *buf, unsigned *rng) {
    int *order = (int *)malloc((size_t)n_primes * sizeof(int));
    if (!order) { perror("malloc"); exit(1); }

    memset(buf, 0, (size_t)(gap_size + 1));

    for (int i = 0; i < n_primes; i++)
        order[i] = i;

    for (int i = n_primes - 1; i > 0; i--) {
        int j = (int)(rand_r(rng) % (unsigned)(i + 1));
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }

    for (int k = 0; k < n_primes; k++) {
        int i = order[k];
        int p = PRIMES[i];
        int best_o = 1, ties = 0;  /* never use offset 0: n ≡ 0 (mod p) → n composite */
        double best_new = -1.0;

        for (int o = 1; o < p; o++) {  /* start at 1, skip 0 */
            double new_cov = 0.0;
            for (int d = o; d <= gap_size; d += p)
                if (!buf[d]) new_cov += position_weight(d);

            if (new_cov > best_new) {
                best_new = new_cov;
                best_o   = o;
                ties     = 1;
            } else if (new_cov == best_new) {
                ties++;
                if ((int)(rand_r(rng) % (unsigned)ties) == 0) best_o = o;
            }
        }

        offsets[i] = best_o;
        for (int d = best_o; d <= gap_size; d += p)
            buf[d] = 1;
    }

    free(order);
}

/* Randomly perturb a few non-fixed offsets to escape greedy plateaus. */
static void kick_offsets(int *offsets, int n_primes, int fixed, int kicks,
                         unsigned *rng) {
    if (fixed >= n_primes || kicks <= 0) return;

    int nfree = n_primes - fixed;
    if (kicks > nfree) kicks = nfree;

    for (int k = 0; k < kicks; k++) {
        int idx = fixed + (int)(rand_r(rng) % (unsigned)nfree);
        int p = PRIMES[idx];
        int next = (int)(rand_r(rng) % (unsigned)p);
        if (next == 0) next = 1;
        if (next == offsets[idx])
            next = (next % (p - 1)) + 1;
        offsets[idx] = next;
    }
}

/* Score how much a prime contributes uniquely at its current offset. */
static double prime_unique_score(const int *offsets, int n_primes, int gap_size,
                                 int idx, uint8_t *buf) {
    memset(buf, 0, (size_t)(gap_size + 1));
    for (int i = 0; i < n_primes; i++) {
        if (i == idx) continue;
        int p = PRIMES[i];
        int o = offsets[i] % p;
        for (int d = (o ? o : p); d <= gap_size; d += p)
            buf[d] = 1;
    }

    int p = PRIMES[idx];
    int o = offsets[idx] % p;
    double score = 0.0;
    for (int d = (o ? o : p); d <= gap_size; d += p)
        if (!buf[d]) score += position_weight(d);
    return score;
}

/* Pick the weakest non-fixed prime by unique coverage. */
static int weakest_nonfixed_prime(const int *offsets, int n_primes, int gap_size,
                                  int fixed, uint8_t *buf) {
    int best_idx = -1;
    double best_score = 1e18;
    for (int i = fixed; i < n_primes; i++) {
        double score = prime_unique_score(offsets, n_primes, gap_size, i, buf);
        if (score < best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    return best_idx;
}

/* Strong escape jump: randomize the weakest non-fixed prime. */
static int kick_weakest_prime(int *offsets, int n_primes, int gap_size,
                              int fixed, uint8_t *buf, unsigned *rng) {
    int idx = weakest_nonfixed_prime(offsets, n_primes, gap_size, fixed, buf);
    if (idx < 0) return -1;
    int p = PRIMES[idx];
    int next = (int)(rand_r(rng) % (unsigned)p);
    if (next == 0) next = 1;
    if (next == offsets[idx])
        next = (next % (p - 1)) + 1;
    offsets[idx] = next;
    return idx;
}

/* ------------------------------------------------------------------ */
/* Local search: for one prime, find the best offset given all others. */
/* Returns 1 if the offset changed.                                    */
/* ------------------------------------------------------------------ */
static int local_search_one(int *offsets, int n_primes, int gap_size,
                            int idx, uint8_t *buf) {
    /* mark covered by all primes except idx */
    memset(buf, 0, (size_t)(gap_size + 1));
    for (int i = 0; i < n_primes; i++) {
        if (i == idx) continue;
        int p = PRIMES[i];
        int o = offsets[i] % p;
        for (int d = (o ? o : p); d <= gap_size; d += p)
            buf[d] = 1;
    }
    /* find best offset for prime at idx; skip offset 0 (n ≡ 0 mod p → composite) */
    int    p       = PRIMES[idx];
    int    best_o  = (offsets[idx] > 0) ? offsets[idx] : 1;
    double best_new = -1.0;
    for (int o = 1; o < p; o++) {  /* start at 1, skip 0 */
        double cnt = 0.0;
        for (int d = o; d <= gap_size; d += p)
            if (!buf[d]) cnt += position_weight(d);
        if (cnt > best_new) {
            best_new = cnt;
            best_o   = o;
        }
    }
    int changed = (best_o != offsets[idx]);
    offsets[idx] = best_o;
    return changed;
}

static int local_search_one_probability(int *offsets, int n_primes, int gap_size,
                                        int idx, uint8_t *buf, uint8_t *buf_wide,
                                        const FitnessConfig *fc) {
    int p = PRIMES[idx];
    int best_o = (offsets[idx] > 0) ? offsets[idx] : 1;
    int best_cnt = INT_MAX;
    double best_opt = 1e18;
    double best_aux = 1e18;

    int original = offsets[idx];
    for (int o = 1; o < p; o++) {
        offsets[idx] = o;
        double opt_score, aux_score;
        int cnt = evaluate_solution(offsets, n_primes, gap_size,
                                    buf, buf_wide, fc,
                                    &opt_score, &aux_score);
        if (solution_better_metrics_mode(cnt, opt_score, aux_score,
                                         best_cnt, best_opt, best_aux, fc)) {
            best_cnt = cnt;
            best_opt = opt_score;
            best_aux = aux_score;
            best_o = o;
        }
    }

    offsets[idx] = best_o;
    return best_o != original;
}

/* ------------------------------------------------------------------ */
/* Pair local search: jointly optimise two primes (idx_a, idx_b).     */
/* For every candidate offset of prime a, finds the best offset of    */
/* prime b given the remaining primes.  Keeps the (a, b) pair that    */
/* minimises total uncovered positions.  Returns 1 if any changed.    */
/* Uses two caller-owned buffers: base_buf and work_buf.              */
/* ------------------------------------------------------------------ */
static int local_search_pair(int *offsets, int n_primes, int gap_size,
                             int idx_a, int idx_b,
                             uint8_t *base_buf, uint8_t *work_buf) {
    int pa = PRIMES[idx_a], pb = PRIMES[idx_b];

    /* build base coverage excluding both idx_a and idx_b */
    memset(base_buf, 0, (size_t)(gap_size + 1));
    for (int i = 0; i < n_primes; i++) {
        if (i == idx_a || i == idx_b) continue;
        int p = PRIMES[i];
        int o = offsets[i] % p;
        for (int d = (o ? o : p); d <= gap_size; d += p)
            base_buf[d] = 1;
    }

    /* start both at 1 — offset 0 means n ≡ 0 (mod p) → n composite */
    int best_oa = (offsets[idx_a] > 0) ? offsets[idx_a] : 1;
    int best_ob = (offsets[idx_b] > 0) ? offsets[idx_b] : 1;
    double best_uncov = 1e18;

    for (int oa = 1; oa < pa; oa++) {  /* skip offset 0 */
        /* overlay prime a onto base coverage */
        memcpy(work_buf, base_buf, (size_t)(gap_size + 1));
        for (int d = oa; d <= gap_size; d += pa)
            work_buf[d] = 1;

        /* find best offset for prime b given base + a */
        int    local_best_ob  = 1;
        double local_best_new = -1.0;
        for (int ob = 1; ob < pb; ob++) {  /* skip offset 0 */
            double cnt = 0.0;
            for (int d = ob; d <= gap_size; d += pb)
                if (!work_buf[d]) cnt += position_weight(d);
            if (cnt > local_best_new) {
                local_best_new = cnt;
                local_best_ob  = ob;
            }
        }

        /* count total uncovered = positions not hit by base + a + best_b */
        double uncov = 0.0;
        for (int d = 1; d <= gap_size; d++) {
            if (!work_buf[d]) {
                /* check if prime b covers this position */
                if (d % pb != local_best_ob)
                    uncov += position_weight(d);
            }
        }

        if (uncov < best_uncov) {
            best_uncov = uncov;
            best_oa = oa;
            best_ob = local_best_ob;
        }
    }

    int changed = (best_oa != offsets[idx_a] || best_ob != offsets[idx_b]);
    offsets[idx_a] = best_oa;
    offsets[idx_b] = best_ob;
    return changed;
}

static int local_search_pair_probability(int *offsets, int n_primes, int gap_size,
                                         int idx_a, int idx_b,
                                         uint8_t *buf, uint8_t *buf_wide,
                                         const FitnessConfig *fc) {
    int pa = PRIMES[idx_a], pb = PRIMES[idx_b];
    int best_oa = (offsets[idx_a] > 0) ? offsets[idx_a] : 1;
    int best_ob = (offsets[idx_b] > 0) ? offsets[idx_b] : 1;
    int best_cnt = INT_MAX;
    double best_opt = 1e18;
    double best_aux = 1e18;
    int original_a = offsets[idx_a];
    int original_b = offsets[idx_b];

    for (int oa = 1; oa < pa; oa++) {
        offsets[idx_a] = oa;
        for (int ob = 1; ob < pb; ob++) {
            offsets[idx_b] = ob;
            double opt_score, aux_score;
            int cnt = evaluate_solution(offsets, n_primes, gap_size,
                                        buf, buf_wide, fc,
                                        &opt_score, &aux_score);
            if (solution_better_metrics_mode(cnt, opt_score, aux_score,
                                             best_cnt, best_opt, best_aux, fc)) {
                best_cnt = cnt;
                best_opt = opt_score;
                best_aux = aux_score;
                best_oa = oa;
                best_ob = ob;
            }
        }
    }

    offsets[idx_a] = best_oa;
    offsets[idx_b] = best_ob;
    return best_oa != original_a || best_ob != original_b;
}

static int local_search_triple_probability(int *offsets, int n_primes, int gap_size,
                                           int idx_a, int idx_b, int idx_c,
                                           uint8_t *buf, uint8_t *buf_wide,
                                           const FitnessConfig *fc) {
    int pa = PRIMES[idx_a], pb = PRIMES[idx_b], pc = PRIMES[idx_c];
    int best_oa = (offsets[idx_a] > 0) ? offsets[idx_a] : 1;
    int best_ob = (offsets[idx_b] > 0) ? offsets[idx_b] : 1;
    int best_oc = (offsets[idx_c] > 0) ? offsets[idx_c] : 1;
    int best_cnt = INT_MAX;
    double best_opt = 1e18;
    double best_aux = 1e18;
    int original_a = offsets[idx_a];
    int original_b = offsets[idx_b];
    int original_c = offsets[idx_c];

    for (int oa = 1; oa < pa; oa++) {
        offsets[idx_a] = oa;
        for (int ob = 1; ob < pb; ob++) {
            offsets[idx_b] = ob;
            for (int oc = 1; oc < pc; oc++) {
                offsets[idx_c] = oc;
                double opt_score, aux_score;
                int cnt = evaluate_solution(offsets, n_primes, gap_size,
                                            buf, buf_wide, fc,
                                            &opt_score, &aux_score);
                if (solution_better_metrics_mode(cnt, opt_score, aux_score,
                                                 best_cnt, best_opt, best_aux, fc)) {
                    best_cnt = cnt;
                    best_opt = opt_score;
                    best_aux = aux_score;
                    best_oa = oa;
                    best_ob = ob;
                    best_oc = oc;
                }
            }
        }
    }

    offsets[idx_a] = best_oa;
    offsets[idx_b] = best_ob;
    offsets[idx_c] = best_oc;
    return best_oa != original_a || best_ob != original_b || best_oc != original_c;
}

static int local_search_triple_sweep_probability(int *offsets, int n_primes, int gap_size,
                                                 int fixed, int max_triplets,
                                                 uint8_t *buf, uint8_t *buf_wide,
                                                 const FitnessConfig *fc) {
    int total = 0;
    int seen = 0;
    for (int i = fixed; i < n_primes && seen < max_triplets; i++) {
        for (int j = i + 1; j < n_primes && seen < max_triplets; j++) {
            for (int k = j + 1; k < n_primes && seen < max_triplets; k++) {
                total += local_search_triple_probability(offsets, n_primes, gap_size,
                                                         i, j, k,
                                                         buf, buf_wide, fc);
                seen++;
            }
        }
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* Full single-prime sweep: optimise every non-fixed prime in order,   */
/* repeating until no offset changes.  Returns total changes made.     */
/* ------------------------------------------------------------------ */
static int local_search_sweep(int *offsets, int n_primes, int gap_size,
                              int fixed, uint8_t *buf) {
    int total = 0;
    for (;;) {
        int changed = 0;
        for (int i = fixed; i < n_primes; i++)
            changed += local_search_one(offsets, n_primes, gap_size, i, buf);
        total += changed;
        if (!changed) break;
    }
    return total;
}

/* ------------------------------------------------------------------ */
/* Exhaustive pair sweep: try all C(nfree, 2) pairs, repeating until  */
/* no pair improves.  Returns total changes made.                      */
/* ------------------------------------------------------------------ */
static int pair_search_sweep(int *offsets, int n_primes, int gap_size,
                             int fixed, uint8_t *buf, uint8_t *buf2) {
    int total = 0;
    for (;;) {
        int changed = 0;
        for (int i = fixed; i < n_primes; i++)
            for (int j = i + 1; j < n_primes; j++)
                changed += local_search_pair(offsets, n_primes, gap_size,
                                             i, j, buf, buf2);
        total += changed;
        if (!changed) break;
    }
    return total;
}

/* forward declarations (needed by evolve) */
static void greedy_solve(int *offsets, int n_primes, int gap_size,
                         uint8_t *buf, unsigned *rng);
static int local_search_one(int *offsets, int n_primes, int gap_size,
                            int idx, uint8_t *buf);
static int local_search_pair(int *offsets, int n_primes, int gap_size,
                             int idx_a, int idx_b,
                             uint8_t *base_buf, uint8_t *work_buf);
static int local_search_sweep(int *offsets, int n_primes, int gap_size,
                              int fixed, uint8_t *buf);
static int pair_search_sweep(int *offsets, int n_primes, int gap_size,
                             int fixed, uint8_t *buf, uint8_t *buf2);
static int kick_weakest_prime(int *offsets, int n_primes, int gap_size,
                              int fixed, uint8_t *buf, unsigned *rng);

/* ------------------------------------------------------------------ */
/* Evolutionary algorithm — Memetic EA with parallel child generation  */
/*                                                                     */
/* Each generation spawns n_threads worker threads.  Each worker:      */
/*   1. Tournament-selects 2 parents from the population (read-only).  */
/*   2. Uniform crossover on free primes.                              */
/*   3. Mutates exactly 1 free prime (2 when stale).                   */
/*   4. Runs local_search_sweep to bring the child to a local optimum. */
/*   5. Evaluates the child.                                           */
/* The main thread then inserts improvements into the population.      */
/*                                                                     */
/* Applying full local search to every child converts the EA into a    */
/* Memetic Algorithm.  Greedy already reaches good local optima; the   */
/* EA's job is to recombine partial solutions from different greedy     */
/* starts and escape to new basins via crossover + repair.             */
/* ------------------------------------------------------------------ */
typedef struct {
    int             n_primes;
    int             gap_size;
    int             fixed;
    int             nfree;
    unsigned        rng;
    const FitnessConfig *fc;
    const Solution *pop;       /* read-only during child generation     */
    int             pop_size;
    int            *offsets;   /* output: child offsets                 */
    int             n_candidates;
    double          opt_score;
    double          aux_score;
    double          w_score;
    int             stale;     /* input: guides extra mutation          */
    int             mut_level; /* adaptive mutation intensity (0..4)    */
    int             max_gens;  /* input: stale threshold denominator    */
    uint8_t        *buf;       /* pre-allocated (gap_size+1) bytes      */
    uint8_t        *buf_wide;  /* pre-allocated probability window buf   */
} EvoChildArgs;

static void *evo_child_fn(void *arg) {
    EvoChildArgs *a   = (EvoChildArgs *)arg;
    int np    = a->n_primes, gs = a->gap_size;
    int fixed = a->fixed,  nfree = a->nfree;
    unsigned rng = a->rng;

    /* tournament select two parents */
    int ai = (int)(rand_r(&rng) % (unsigned)a->pop_size);
    int bi = (int)(rand_r(&rng) % (unsigned)a->pop_size);
    int p1 = solution_better_mode(&a->pop[ai], &a->pop[bi], a->fc) ? ai : bi;
    ai = (int)(rand_r(&rng) % (unsigned)a->pop_size);
    bi = (int)(rand_r(&rng) % (unsigned)a->pop_size);
    int p2 = solution_better_mode(&a->pop[ai], &a->pop[bi], a->fc) ? ai : bi;

    /* uniform crossover: fixed primes from p1, free primes random */
    int *child = a->offsets;
    for (int i = 0; i < np; i++) {
        child[i] = (i < fixed || (rand_r(&rng) & 1))
                   ? a->pop[p1].offsets[i]
                   : a->pop[p2].offsets[i];
    }

    /* Adaptive mutation pressure (Gapben-style level escalation).
     * Level rises when generations stall, and drops after improvements. */
    if (nfree > 0) {
        int kicks = 1;
        if (a->mut_level == 1) {
            kicks = 2;
        } else if (a->mut_level == 2) {
            kicks = 3 + (int)(rand_r(&rng) % 3u);
        } else if (a->mut_level == 3) {
            kicks = 5 + (int)(rand_r(&rng) % 4u);
            kick_weakest_prime(child, np, gs, fixed, a->buf, &rng);
        } else if (a->mut_level >= 4) {
            if ((rand_r(&rng) & 3) == 0) {
                for (int i = fixed; i < np; i++) {
                    int p = PRIMES[i];
                    child[i] = 1 + (int)(rand_r(&rng) % (unsigned)(p - 1));
                }
            }
            kicks = 8 + (int)(rand_r(&rng) % 5u);
            kick_weakest_prime(child, np, gs, fixed, a->buf, &rng);
        }

        for (int m = 0; m < kicks; m++) {
            int idx = fixed + (int)(rand_r(&rng) % (unsigned)nfree);
            int p   = PRIMES[idx];
            child[idx] = 1 + (int)(rand_r(&rng) % (unsigned)(p - 1));
        }
    }

    /* memetic core: bring child to the nearest local optimum */
    if (a->fc->mode == FITNESS_PROBABILITY) {
        for (;;) {
            int changed = 0;
            for (int i = fixed; i < np; i++)
                changed += local_search_one_probability(child, np, gs, i,
                                                        a->buf, a->buf_wide,
                                                        a->fc);
            if (!changed) break;
        }
    } else {
        local_search_sweep(child, np, gs, fixed, a->buf);
    }

    /* evaluate */
    a->n_candidates = evaluate_solution(child, np, gs,
                                        a->buf, a->buf_wide, a->fc,
                                        &a->opt_score, &a->aux_score);
    a->w_score = legacy_display_score(a->fc->mode, a->opt_score, a->aux_score);

    /* write back advanced RNG state so the next generation gets a
     * different seed even when reusing the same EvoChildArgs slot */
    a->rng = rng;

    return NULL;
}

static void evolve(Solution *pop, int pop_size, int n_primes, int gap_size,
                   int fixed, int max_gens, unsigned *rng, int n_threads,
                   const FitnessConfig *fc) {
    int nfree = n_primes - fixed;

    /* allocate per-thread state once; reuse across all generations */
    EvoChildArgs *wargs = (EvoChildArgs *)malloc((size_t)n_threads * sizeof(EvoChildArgs));
    pthread_t    *tids  = (pthread_t    *)malloc((size_t)n_threads * sizeof(pthread_t));
    if (!wargs || !tids) { perror("alloc"); exit(1); }

    for (int t = 0; t < n_threads; t++) {
        wargs[t].n_primes  = n_primes;
        wargs[t].gap_size  = gap_size;
        wargs[t].fixed     = fixed;
        wargs[t].nfree     = nfree;
        wargs[t].rng       = *rng ^ ((unsigned)t * 2246822519u);
        wargs[t].fc        = fc;
        wargs[t].pop       = pop;
        wargs[t].pop_size  = pop_size;
        wargs[t].max_gens  = max_gens;
        wargs[t].offsets   = (int     *)malloc((size_t)n_primes * sizeof(int));
        wargs[t].buf       = (uint8_t *)calloc((size_t)(gap_size + 1), 1);
        wargs[t].buf_wide  = NULL;
        if (fc->mode == FITNESS_PROBABILITY) {
            int window = fitness_window_size(gap_size, fc);
            wargs[t].buf_wide = (uint8_t *)calloc((size_t)(window + 1), 1);
        }
        if (!wargs[t].offsets || !wargs[t].buf ||
            (fc->mode == FITNESS_PROBABILITY && !wargs[t].buf_wide)) {
            perror("alloc");
            exit(1);
        }
    }

    /* find initial best */
    int    best_ever_cnt = INT_MAX;
    double best_ever_opt = 1e18;
    double best_ever_aux = 1e18;
    int    best_ever_min_cnt = INT_MAX;
    for (int i = 0; i < pop_size; i++) {
        if (solution_better_metrics_mode(pop[i].n_candidates,
                                         pop[i].opt_score,
                                         pop[i].aux_score,
                                         best_ever_cnt,
                                         best_ever_opt,
                                         best_ever_aux,
                                         fc)) {
            best_ever_cnt = pop[i].n_candidates;
            best_ever_opt = pop[i].opt_score;
            best_ever_aux = pop[i].aux_score;
        }
        if (pop[i].n_candidates < best_ever_min_cnt)
            best_ever_min_cnt = pop[i].n_candidates;
    }

    if (fc->mode == FITNESS_PROBABILITY) {
        fprintf(stderr,
            "  evolution seed: obj-best=%d cand-min=%d\n",
            best_ever_cnt, best_ever_min_cnt);
    }

    int stale = 0;
    int mut_level = 0;
    int no_improve_gens = 0;

    for (int gen = 0; gen < max_gens; gen++) {
        /* spawn n_threads children in parallel */
        for (int t = 0; t < n_threads; t++) {
            wargs[t].stale = stale;
            wargs[t].mut_level = mut_level;
            pthread_create(&tids[t], NULL, evo_child_fn, &wargs[t]);
        }
        for (int t = 0; t < n_threads; t++)
            pthread_join(tids[t], NULL);

        /* find worst in population */
        int worst = 0;
        for (int i = 1; i < pop_size; i++) {
            if (solution_better_mode(&pop[worst], &pop[i], fc))
                worst = i;
        }

        /* insert each child that beats the current worst */
        bool any_improved = false;
        for (int t = 0; t < n_threads; t++) {
            EvoChildArgs *w = &wargs[t];
            if (solution_better_metrics_mode(w->n_candidates,
                                             w->opt_score,
                                             w->aux_score,
                                             pop[worst].n_candidates,
                                             pop[worst].opt_score,
                                             pop[worst].aux_score,
                                             fc)) {
                memcpy(pop[worst].offsets, w->offsets,
                       (size_t)n_primes * sizeof(int));
                pop[worst].n_candidates = w->n_candidates;
                pop[worst].opt_score    = w->opt_score;
                pop[worst].aux_score    = w->aux_score;
                pop[worst].w_score      = w->w_score;
                /* re-find worst after each insertion */
                worst = 0;
                for (int i = 1; i < pop_size; i++) {
                    if (solution_better_mode(&pop[worst], &pop[i], fc))
                        worst = i;
                }
            }
            if (solution_better_metrics_mode(w->n_candidates,
                                             w->opt_score,
                                             w->aux_score,
                                             best_ever_cnt,
                                             best_ever_opt,
                                             best_ever_aux,
                                             fc)) {
                best_ever_cnt = w->n_candidates;
                best_ever_opt = w->opt_score;
                best_ever_aux = w->aux_score;
                any_improved  = true;
            }
            if (w->n_candidates < best_ever_min_cnt)
                best_ever_min_cnt = w->n_candidates;
        }

        if (any_improved) {
            stale = 0;
            no_improve_gens = 0;
            if (mut_level > 0)
                mut_level--;
        } else {
            stale++;
            no_improve_gens++;
            if (no_improve_gens % 40 == 0 && mut_level < 4)
                mut_level++;
        }

        /* progress */
        if ((gen + 1) % 200 == 0 || gen == max_gens - 1) {
            if (fc->mode == FITNESS_PROBABILITY) {
                fprintf(stderr,
                    "\r  evolution: gen %d/%d  obj-best=%d  cand-min=%d  stale=%d  lvl=%d     ",
                    gen + 1, max_gens, best_ever_cnt, best_ever_min_cnt,
                    stale, mut_level);
            } else {
                fprintf(stderr,
                    "\r  evolution: gen %d/%d  best=%d  stale=%d  lvl=%d     ",
                    gen + 1, max_gens, best_ever_cnt, stale, mut_level);
            }
            fflush(stderr);
        }

        /* early stop when no improvement for half the budget */
        if (stale > max_gens / 2 && stale > 100) break;
    }

    fprintf(stderr, "\n");

    for (int t = 0; t < n_threads; t++) {
        free(wargs[t].offsets);
        free(wargs[t].buf);
        free(wargs[t].buf_wide);
    }
    free(wargs);
    free(tids);
}

/* ------------------------------------------------------------------ */
/* Greedy worker thread                                                */
/* Runs `restarts` independent greedy+local-search trials, keeps the  */
/* best `keep_n` solutions in `results[]`.                            */
/* ------------------------------------------------------------------ */
typedef struct {
    int          n_primes;
    int          gap_size;
    int          ctr_fixed;
    int          restarts;
    unsigned     seed;
    const FitnessConfig *fc;
    Solution    *results;   /* pre-allocated array of keep_n solutions */
    int          keep_n;
    int          best_cnt;  /* best n_candidates seen by this thread   */
    /* shared progress counter (atomic via __sync) */
    volatile int *done_restarts;
} GreedyWorkerArgs;

static void *greedy_worker(void *arg) {
    GreedyWorkerArgs *a = (GreedyWorkerArgs *)arg;
    int np  = a->n_primes;
    int gs  = a->gap_size;
    unsigned rng = a->seed;

    uint8_t *buf = (uint8_t *)calloc((size_t)(gs + 1), 1);
    uint8_t *buf_wide = NULL;
    if (a->fc->mode == FITNESS_PROBABILITY) {
        int window = fitness_window_size(gs, a->fc);
        buf_wide = (uint8_t *)calloc((size_t)(window + 1), 1);
    }
    int     *tmp = (int     *)malloc((size_t)np * sizeof(int));
    if (!buf || !tmp || (a->fc->mode == FITNESS_PROBABILITY && !buf_wide)) {
        perror("malloc");
        exit(1);
    }

    int best_cnt = INT_MAX;

    for (int r = 0; r < a->restarts; r++) {
        greedy_solve(tmp, np, gs, buf, &rng);
        if (a->ctr_fixed < np) {
            int kicks = 1 + (int)(rand_r(&rng) % 3);
            kick_offsets(tmp, np, a->ctr_fixed, kicks, &rng);
            local_search_sweep(tmp, np, gs, a->ctr_fixed, buf);
        }
        double opt_nc, aux_nc;
        int nc = evaluate_solution(tmp, np, gs, buf, buf_wide, a->fc,
                       &opt_nc, &aux_nc);
        double w_nc = legacy_display_score(a->fc->mode, opt_nc, aux_nc);
        if (nc < best_cnt) best_cnt = nc;

        /* insert into local result pool if better than worst */
        int worst = 0;
        for (int i = 1; i < a->keep_n; i++) {
            if (solution_better_mode(&a->results[worst], &a->results[i], a->fc))
                worst = i;
        }
        if (solution_better_metrics_mode(nc, opt_nc, aux_nc,
                                         a->results[worst].n_candidates,
                                         a->results[worst].opt_score,
                                         a->results[worst].aux_score,
                                         a->fc)) {
            memcpy(a->results[worst].offsets, tmp, (size_t)np * sizeof(int));
            a->results[worst].n_candidates = nc;
            a->results[worst].opt_score    = opt_nc;
            a->results[worst].aux_score    = aux_nc;
            a->results[worst].w_score      = w_nc;
        }

        __sync_fetch_and_add(a->done_restarts, 1);
    }

    a->best_cnt = best_cnt;
    free(buf_wide);
    free(buf);
    free(tmp);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* ILS worker thread                                                   */
/* Runs independent ILS rounds starting from a fixed seed solution.   */
/* ------------------------------------------------------------------ */
typedef struct {
    int       n_primes;
    int       gap_size;
    int       ils_fixed;
    int       rounds;
    unsigned  seed;
    const FitnessConfig *fc;
    int      *start_offsets;   /* read-only: initial solution to start from */
    Solution  result;          /* best solution found by this thread */
} ILSWorkerArgs;

static void *ils_worker(void *arg) {
    ILSWorkerArgs *a = (ILSWorkerArgs *)arg;
    int np = a->n_primes;
    int gs = a->gap_size;
    unsigned rng = a->seed;

    uint8_t *buf  = (uint8_t *)calloc((size_t)(gs + 1), 1);
    uint8_t *buf2 = (uint8_t *)calloc((size_t)(gs + 1), 1);
    uint8_t *buf_wide = NULL;
    if (a->fc->mode == FITNESS_PROBABILITY) {
        int window = fitness_window_size(gs, a->fc);
        buf_wide = (uint8_t *)calloc((size_t)(window + 1), 1);
    }
    int     *work = (int     *)malloc((size_t)np * sizeof(int));
    if (!buf || !buf2 || !work ||
        (a->fc->mode == FITNESS_PROBABILITY && !buf_wide)) {
        perror("malloc");
        exit(1);
    }

    /* start from a copy of the seed solution, already local-search refined */
    memcpy(work, a->start_offsets, (size_t)np * sizeof(int));
    if (a->fc->mode == FITNESS_PROBABILITY) {
        for (;;) {
            int changed = 0;
            for (int i = a->ils_fixed; i < np; i++)
                changed += local_search_one_probability(work, np, gs, i,
                                                        buf, buf_wide,
                                                        a->fc);
            if (!changed) break;
        }
    } else {
        local_search_sweep(work, np, gs, a->ils_fixed, buf);
    }
    double best_opt, best_aux;
    int best_cnt = evaluate_solution(work, np, gs, buf, buf_wide, a->fc,
                                     &best_opt, &best_aux);

    int *best_offsets = (int *)malloc((size_t)np * sizeof(int));
    if (!best_offsets) { perror("malloc"); exit(1); }
    memcpy(best_offsets, work, (size_t)np * sizeof(int));

    int nfree = np - a->ils_fixed;
    int stale = 0;
    for (int r = 0; r < a->rounds; r++) {
        memcpy(work, best_offsets, (size_t)np * sizeof(int));

        /* Kick: 1-3 random free primes + occasionally kick the weakest.
           More diverse perturbation escapes narrow local optima faster
           than always kicking only the single weakest prime. */
        int n_kicks = 1 + (int)(rand_r(&rng) % 3u);
        for (int k = 0; k < n_kicks && nfree > 0; k++) {
            int idx = a->ils_fixed + (int)(rand_r(&rng) % (unsigned)nfree);
            int p = PRIMES[idx];
            work[idx] = 1 + (int)(rand_r(&rng) % (unsigned)(p - 1));
        }
        /* also kick the weakest prime every 4th round for targeted repair */
        if ((r & 3) == 0) {
            int weak_idx = kick_weakest_prime(work, np, gs, a->ils_fixed, buf2, &rng);
            if (weak_idx >= 0) {
                if (a->fc->mode == FITNESS_PROBABILITY) {
                    local_search_one_probability(work, np, gs, weak_idx,
                                                 buf, buf_wide, a->fc);
                } else {
                    local_search_one(work, np, gs, weak_idx, buf);
                }
            }
        }
        /* fast local search only — pair_search_sweep runs once at chain end */
        if (a->fc->mode == FITNESS_PROBABILITY) {
            for (;;) {
                int changed = 0;
                for (int i = a->ils_fixed; i < np; i++)
                    changed += local_search_one_probability(work, np, gs, i,
                                                            buf, buf_wide,
                                                            a->fc);
                if (!changed) break;
            }
        } else {
            local_search_sweep(work, np, gs, a->ils_fixed, buf);
        }

        double opt_nc, aux_nc;
        int nc = evaluate_solution(work, np, gs, buf, buf_wide, a->fc,
                                   &opt_nc, &aux_nc);
        if (solution_better_metrics_mode(nc, opt_nc, aux_nc,
                                         best_cnt, best_opt, best_aux,
                                         a->fc)) {
            memcpy(best_offsets, work, (size_t)np * sizeof(int));
            best_cnt = nc;
            best_opt = opt_nc;
            best_aux = aux_nc;
            stale    = 0;
        } else {
            stale++;
        }
        if (stale > a->rounds / 3 && stale > 60) break;
    }

    /* pair_search_sweep once at chain end: polishes the best found without
       paying its cost on every round (~100x fewer pair-sweep calls total) */
    if (a->fc->mode == FITNESS_PROBABILITY) {
        int nfree = np - a->ils_fixed;
        for (;;) {
            int changed = 0;
            for (int i = a->ils_fixed; i < np; i++)
                for (int j = i + 1; j < np; j++)
                    changed += local_search_pair_probability(best_offsets, np, gs,
                                                             i, j,
                                                             buf, buf_wide,
                                                             a->fc);
            if (!changed) break;
        }
        if (nfree >= 3) {
            int max_triplets = 8;
            local_search_triple_sweep_probability(best_offsets, np, gs,
                                                  a->ils_fixed, max_triplets,
                                                  buf, buf_wide, a->fc);
        }
    } else {
        pair_search_sweep(best_offsets, np, gs, a->ils_fixed, buf, buf2);
    }
    best_cnt = evaluate_solution(best_offsets, np, gs, buf, buf_wide, a->fc,
                                 &best_opt, &best_aux);

    a->result.offsets      = best_offsets;
    a->result.n_candidates = best_cnt;
    a->result.opt_score    = best_opt;
    a->result.aux_score    = best_aux;
    a->result.w_score      = legacy_display_score(a->fc->mode, best_opt, best_aux);
    a->result.n_primes     = np;
    a->result.gap_size     = gs;

    free(work);
    free(buf_wide);
    free(buf2);
    free(buf);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Write CRT text file                                                 */
/* ------------------------------------------------------------------ */
static void write_crt_file(const char *path, const Solution *sol,
                           double merit, int shift,
                           const Phase1Diag *p1,
                           const FitnessConfig *fc) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }

    fprintf(f, "# CRT sieve file generated by cpugapminer gen_crt\n");
    fprintf(f, "n_primes %d\n", sol->n_primes);
    fprintf(f, "merit %.2f\n", merit);
    fprintf(f, "shift %d\n", shift);
    fprintf(f, "gap_target %d\n", sol->gap_size);
    fprintf(f, "n_candidates %d\n", sol->n_candidates);
    fprintf(f, "# fitness_mode %s\n",
            fc->mode == FITNESS_PROBABILITY ? "probability" : "candidate");
    if (fc->mode == FITNESS_PROBABILITY) {
        fprintf(f, "# probability_score %.9f\n", sol->opt_score);
        fprintf(f, "# candidate_weighted_score %.9f\n", sol->aux_score);
        fprintf(f, "# fitness_window_factor %.6f\n", fc->window_factor);
        fprintf(f, "# fitness_window_cap %d\n", fc->window_cap);
        fprintf(f, "# fitness_kernel_a %.6f\n", fc->kernel_a);
        fprintf(f, "# fitness_kernel_b %.6f\n", fc->kernel_b);
    } else {
        fprintf(f, "# candidate_weighted_score %.9f\n", sol->opt_score);
        fprintf(f, "# candidate_raw_weight_sum %.9f\n", sol->aux_score);
    }
    if (p1) {
        fprintf(f, "# phase1_kernel exp(-a*|x/scale|^b)\n");
        fprintf(f, "# phase1_a %.6f\n", p1->a);
        fprintf(f, "# phase1_b %.6f\n", p1->b);
        fprintf(f, "# phase1_scale %.6f\n", p1->scale);
        fprintf(f, "# phase1_remaining %d\n", p1->remaining);
        fprintf(f, "# phase1_score_raw %.9f\n", p1->score_raw);
        fprintf(f, "# phase1_score_mean %.9f\n", p1->score_mean);
    }

    for (int i = 0; i < sol->n_primes; i++)
        fprintf(f, "%d %d\n", PRIMES[i], sol->offsets[i]);

    fclose(f);
    fprintf(stderr, "wrote %s  (%d primes, %d candidates)\n",
            path, sol->n_primes, sol->n_candidates);
}

/* ------------------------------------------------------------------ */
/* CLI help                                                            */
/* ------------------------------------------------------------------ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --calc-ctr [options]\n"
        "\n"
        "CRT gap solver -- generates optimised prime offsets for gap mining.\n"
        "\n"
        "  --calc-ctr            Enable CRT calculation mode\n"
        "  --ctr-primes N        Number of CRT primes (default: 14)\n"
        "  --ctr-merit  M        Target merit (default: 22.0)\n"
        "  --ctr-bits   B        Extra bits: shift - log2(primorial) (default: 0)\n"
        "  --ctr-strength S      Greedy restarts / quality (default: 50)\n"
        "  --ctr-evolution       Enable evolutionary refinement\n"
        "  --ctr-fixed  F        Primes frozen during evolution (default: 8)\n"
        "  --ctr-ivs    I        Population size for evolution (default: 10)\n"
        "  --ctr-range  R        Percent deviation from n_primes (default: 0)\n"
        "  --ctr-file   FILE     Output CRT file path (required)\n"
        "  --threads    N        Parallel threads for greedy+ILS (default: CPU count)\n"
        "  --fitness-mode MODE  Optimization objective: candidate|probability (default: candidate)\n"
        "  --fitness-window-factor F  Probability mode window factor W=ceil(F*gap) (default: 2.0)\n"
        "  --fitness-window-cap N     Probability mode hard cap for W, 0=no cap (default: 0)\n"
        "  --fitness-kernel-a A       Probability mode kernel parameter a (default: 5.8)\n"
        "  --fitness-kernel-b B       Probability mode kernel parameter b (default: 3.3)\n"
        "                           Probability mode also enables probability-aware\n"
        "                           one-prime/pair local search plus a bounded\n"
        "                           three-prime final polish pass.\n"
        "  --phase3             Enable hybrid selection (feature-gated; default: off)\n"
        "  --phase3-delta N     Candidate tolerance window for phase3 (default: 2)\n"
        "  --phase3-mean-eps E  Minimum phase1 mean improvement for phase3 (default: 0.0005)\n"
        "  --help                Show this help\n"
        "\n"
        "Gap size = ceil(merit * (256 + shift) * ln2)\n"
        "Minimum shift = ceil(log2(p1 * p2 * ... * pN)) + ctr-bits\n"
        "\n"
        "Example -- 24 primes for shift 128, merit 22:\n"
        "  %s --calc-ctr --ctr-primes 24 --ctr-merit 22 --ctr-bits 14 \\\n"
        "     --ctr-strength 100 --ctr-evolution --ctr-fixed 8 --ctr-ivs 20 \\\n"
        "     --ctr-file crt_24.txt\n"
        "\n"
        "Tip: the original GapMiner docs recommend ctr-merit = target_merit - 1\n"
        "     for best sieving results.\n",
        prog, prog);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    /* defaults */
    int    ctr_primes   = 14;
    double ctr_merit    = 22.0;
    int    ctr_bits     = 0;
    int    ctr_strength = 50;
    bool   ctr_evolution = false;
    int    ctr_fixed    = 8;
    int    ctr_ivs      = 10;
    int    ctr_range    = 0;
    char  *ctr_file     = NULL;
    int    n_threads    = 0;   /* 0 = auto-detect */
    FitnessConfig fitness_cfg = {
        FITNESS_CANDIDATE,
        2.0,
        0,
        PHASE1_A_DEFAULT,
        PHASE1_B_DEFAULT,
    };
    bool   phase3_enabled = false;
    int    phase3_delta = 2;
    double phase3_mean_eps = 0.0005;

    static struct option long_opts[] = {
        {"calc-ctr",       no_argument,       NULL, 'C'},
        {"ctr-primes",     required_argument, NULL, 'p'},
        {"ctr-merit",      required_argument, NULL, 'm'},
        {"ctr-bits",       required_argument, NULL, 'b'},
        {"ctr-strength",   required_argument, NULL, 's'},
        {"ctr-evolution",  no_argument,       NULL, 'e'},
        {"ctr-fixed",      required_argument, NULL, 'f'},
        {"ctr-ivs",        required_argument, NULL, 'i'},
        {"ctr-range",      required_argument, NULL, 'r'},
        {"ctr-file",       required_argument, NULL, 'o'},
        {"threads",        required_argument, NULL, 'T'},
        {"fitness-mode",   required_argument, NULL, 'F'},
        {"fitness-window-factor", required_argument, NULL, 'W'},
        {"fitness-window-cap", required_argument, NULL, 'c'},
        {"fitness-kernel-a", required_argument, NULL, 'A'},
        {"fitness-kernel-b", required_argument, NULL, 'B'},
        {"phase3",         no_argument,       NULL, 'P'},
        {"phase3-delta",   required_argument, NULL, 'd'},
        {"phase3-mean-eps",required_argument, NULL, 'q'},
        {"help",           no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "Cp:m:b:s:ef:i:r:o:T:F:W:c:A:B:Pd:q:h",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'C': /* --calc-ctr: accepted for compat, always active */ break;
        case 'p': ctr_primes   = atoi(optarg); break;
        case 'm': ctr_merit    = atof(optarg); break;
        case 'b': ctr_bits     = atoi(optarg); break;
        case 's': ctr_strength = atoi(optarg); break;
        case 'e': ctr_evolution = true;         break;
        case 'f': ctr_fixed    = atoi(optarg); break;
        case 'i': ctr_ivs      = atoi(optarg); break;
        case 'r': ctr_range    = atoi(optarg); break;
        case 'o': ctr_file     = optarg;        break;
        case 'T': n_threads    = atoi(optarg); break;
        case 'F':
            if (strcmp(optarg, "candidate") == 0) {
                fitness_cfg.mode = FITNESS_CANDIDATE;
            } else if (strcmp(optarg, "probability") == 0) {
                fitness_cfg.mode = FITNESS_PROBABILITY;
            } else {
                fprintf(stderr, "error: --fitness-mode must be candidate or probability\n");
                return 1;
            }
            break;
        case 'W': fitness_cfg.window_factor = atof(optarg); break;
        case 'c': fitness_cfg.window_cap = atoi(optarg); break;
        case 'A': fitness_cfg.kernel_a = atof(optarg); break;
        case 'B': fitness_cfg.kernel_b = atof(optarg); break;
        case 'P': phase3_enabled = true;         break;
        case 'd': phase3_delta = atoi(optarg);   break;
        case 'q': phase3_mean_eps = atof(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (!ctr_file) {
        fprintf(stderr, "error: --ctr-file is required\n\n");
        usage(argv[0]);
        return 1;
    }
    if (ctr_primes < 2 || ctr_primes > N_PRIMES_AVAIL) {
        fprintf(stderr, "error: --ctr-primes must be 2..%d\n", N_PRIMES_AVAIL);
        return 1;
    }
    if (ctr_merit <= 0) {
        fprintf(stderr, "error: --ctr-merit must be > 0\n");
        return 1;
    }
    if (ctr_fixed < 0) ctr_fixed = 0;
    if (ctr_fixed > ctr_primes) ctr_fixed = ctr_primes;
    if (ctr_ivs < 2) ctr_ivs = 2;
    if (ctr_strength < 1) ctr_strength = 1;
    if (fitness_cfg.window_factor < 1.0) fitness_cfg.window_factor = 1.0;
    if (fitness_cfg.window_cap < 0) fitness_cfg.window_cap = 0;
    if (fitness_cfg.kernel_a <= 0.0) fitness_cfg.kernel_a = PHASE1_A_DEFAULT;
    if (fitness_cfg.kernel_b <= 0.0) fitness_cfg.kernel_b = PHASE1_B_DEFAULT;
    if (phase3_delta < 0) phase3_delta = 0;
    if (phase3_mean_eps < 0.0) phase3_mean_eps = 0.0;

    /* resolve thread count */
    if (n_threads <= 0)
        n_threads = get_cpu_count();
    if (n_threads > ctr_strength) n_threads = ctr_strength;
    if (n_threads < 1) n_threads = 1;

    /* ---- derived parameters ---- */
    double prim_bits = primorial_log2(ctr_primes);
    int    shift     = (int)ceil(prim_bits) + ctr_bits;
    int    gap_size  = (int)ceil(ctr_merit * (256.0 + (double)shift) * log(2.0));
    int    effective_ivs = ctr_ivs;
    if (effective_ivs > ctr_strength)
        effective_ivs = ctr_strength;

    fprintf(stderr, "CRT gap solver\n");
    fprintf(stderr, "  primes      : %d  (2 .. %d)\n",
            ctr_primes, PRIMES[ctr_primes - 1]);
    fprintf(stderr, "  primorial   : %.1f bits\n", prim_bits);
    fprintf(stderr, "  ctr-bits    : %d\n", ctr_bits);
    fprintf(stderr, "  shift       : %d\n", shift);
    fprintf(stderr, "  merit       : %.2f\n", ctr_merit);
    fprintf(stderr, "  gap target  : %d\n", gap_size);
    fprintf(stderr, "  strength    : %d  (greedy restarts)\n", ctr_strength);
    fprintf(stderr, "  threads     : %d\n", n_threads);
        fprintf(stderr, "  fitness     : %s\n",
            fitness_cfg.mode == FITNESS_PROBABILITY ? "probability" : "candidate");
        if (fitness_cfg.mode == FITNESS_PROBABILITY) {
        fprintf(stderr, "  fit-window  : factor=%.2f  cap=%d\n",
            fitness_cfg.window_factor, fitness_cfg.window_cap);
        fprintf(stderr, "  fit-kernel  : a=%.3f  b=%.3f\n",
            fitness_cfg.kernel_a, fitness_cfg.kernel_b);
        }
    if (ctr_evolution)
        fprintf(stderr, "  evolution   : ivs=%d (effective=%d)  fixed=%d\n",
                ctr_ivs, effective_ivs, ctr_fixed);
    if (ctr_range > 0)
        fprintf(stderr, "  range       : +/-%d%%  (primes %d..%d)\n",
                ctr_range,
                ctr_primes - ctr_primes * ctr_range / 100,
                ctr_primes + ctr_primes * ctr_range / 100);
    if (phase3_enabled)
        fprintf(stderr, "  phase3      : on  (delta=%d mean_eps=%.6f)\n",
                phase3_delta, phase3_mean_eps);
    fprintf(stderr, "\n");

    srand((unsigned)time(NULL));

    /* ---- range of prime counts to explore ---- */
    int lo_np = ctr_primes, hi_np = ctr_primes;
    if (ctr_range > 0) {
        int dev = ctr_primes * ctr_range / 100;
        if (dev < 1) dev = 1;
        lo_np = ctr_primes - dev;
        hi_np = ctr_primes + dev;
        if (lo_np < 2)              lo_np = 2;
        if (hi_np > N_PRIMES_AVAIL) hi_np = N_PRIMES_AVAIL;
    }

    Solution global_best;
    global_best.offsets      = NULL;
    global_best.n_candidates = INT_MAX;
    global_best.w_score      = 1e18;
    global_best.n_primes     = 0;
    global_best.gap_size     = 0;

    Solution phase1_shadow_best;
    phase1_shadow_best.offsets      = NULL;
    phase1_shadow_best.n_candidates = INT_MAX;
    phase1_shadow_best.w_score      = 1e18;
    phase1_shadow_best.n_primes     = 0;
    phase1_shadow_best.gap_size     = 0;
    Phase1Diag phase1_shadow_diag;
    phase1_shadow_diag.remaining  = 0;
    phase1_shadow_diag.score_raw  = -1.0;
    phase1_shadow_diag.score_mean = -1.0;
    phase1_shadow_diag.a          = PHASE1_A_DEFAULT;
    phase1_shadow_diag.b          = PHASE1_B_DEFAULT;
    phase1_shadow_diag.scale      = 1.0;

    Phase1Diag global_best_phase1;
    global_best_phase1.remaining  = 0;
    global_best_phase1.score_raw  = 0.0;
    global_best_phase1.score_mean = 0.0;
    global_best_phase1.a          = PHASE1_A_DEFAULT;
    global_best_phase1.b          = PHASE1_B_DEFAULT;
    global_best_phase1.scale      = 1.0;

    int greedy_best_cnt = INT_MAX;
    int greedy_best_mode_cnt = INT_MAX;
    double greedy_best_mode_opt = 1e18;
    double greedy_best_mode_aux = 1e18;
    int phase_best_cnt  = INT_MAX;
    int phase_best_mode_cnt = INT_MAX;
    double phase_best_mode_opt = 1e18;
    double phase_best_mode_aux = 1e18;
    int phase_best_min_cnt = INT_MAX;

    for (int np = lo_np; np <= hi_np; np++) {
        double pb = primorial_log2(np);
        int    sh = (int)ceil(pb) + ctr_bits;
        int    gs = (int)ceil(ctr_merit * (256.0 + (double)sh) * log(2.0));

        if (lo_np != hi_np)
            fprintf(stderr, "--- %d primes  (shift=%d, gap=%d) ---\n",
                    np, sh, gs);

        /* allocate shared work buffer */
        uint8_t *buf = (uint8_t *)calloc((size_t)(gs + 1), 1);
        if (!buf) { perror("calloc"); exit(1); }

        /* population size for evolution (or just 1 if no evolution) */
        int pop_size = ctr_evolution ? ctr_ivs : 1;
        if (pop_size > ctr_strength) pop_size = ctr_strength;

        Solution *pop = (Solution *)calloc((size_t)pop_size, sizeof(Solution));
        for (int i = 0; i < pop_size; i++)
            pop[i] = sol_alloc(np, gs);

        /* ---- Phase 1: greedy restarts, parallel ---- */
        /* Distribute restarts across threads; each thread keeps its own
           pool of pop_size best solutions, merged into pop[] at the end. */
        int actual_threads = n_threads;
        if (actual_threads > ctr_strength) actual_threads = ctr_strength;

        pthread_t        *tids  = (pthread_t        *)malloc((size_t)actual_threads * sizeof(pthread_t));
        GreedyWorkerArgs *wargs = (GreedyWorkerArgs *)malloc((size_t)actual_threads * sizeof(GreedyWorkerArgs));
        /* Each thread keeps up to pop_size results; merged below. */
        Solution **thread_results = (Solution **)malloc((size_t)actual_threads * sizeof(Solution *));
        if (!tids || !wargs || !thread_results) { perror("malloc"); exit(1); }

        volatile int done_restarts = 0;
        unsigned base_seed = (unsigned)time(NULL) ^ 0xDEADBEEFu;

        for (int t = 0; t < actual_threads; t++) {
            int r_start = (ctr_strength *  t     ) / actual_threads;
            int r_end   = (ctr_strength * (t + 1)) / actual_threads;
            wargs[t].n_primes       = np;
            wargs[t].gap_size       = gs;
            wargs[t].ctr_fixed      = ctr_fixed;
            wargs[t].restarts       = r_end - r_start;
            wargs[t].seed           = base_seed ^ ((unsigned)t * 2654435761u);
            wargs[t].fc             = &fitness_cfg;
            wargs[t].keep_n         = pop_size;
            wargs[t].best_cnt       = INT_MAX;
            wargs[t].done_restarts  = &done_restarts;
            thread_results[t] = (Solution *)calloc((size_t)pop_size, sizeof(Solution));
            if (!thread_results[t]) { perror("calloc"); exit(1); }
            for (int i = 0; i < pop_size; i++)
                thread_results[t][i] = sol_alloc(np, gs);
            wargs[t].results = thread_results[t];
            pthread_create(&tids[t], NULL, greedy_worker, &wargs[t]);
        }

        /* progress display while threads work */
        int last_shown = -1;
        for (;;) {
            int done = done_restarts;
            if (done != last_shown) {
                /* find best across thread result pools so far (racy but cosmetic) */
                int display_best = INT_MAX;
                for (int t = 0; t < actual_threads; t++)
                    if (wargs[t].best_cnt < display_best)
                        display_best = wargs[t].best_cnt;
                if (fitness_cfg.mode == FITNESS_PROBABILITY) {
                    fprintf(stderr,
                        "\r  greedy: %d/%d restarts  cand-min=%d     ",
                        done, ctr_strength,
                        display_best < INT_MAX ? display_best : 0);
                } else {
                    fprintf(stderr,
                        "\r  greedy: %d/%d restarts  best=%d candidates     ",
                        done, ctr_strength,
                        display_best < INT_MAX ? display_best : 0);
                }
                fflush(stderr);
                last_shown = done;
            }
            if (done >= ctr_strength) break;
            struct timespec ts = {0, 20000000}; /* 20 ms */
            nanosleep(&ts, NULL);
        }
        for (int t = 0; t < actual_threads; t++)
            pthread_join(tids[t], NULL);
        fprintf(stderr, "\n");

        /* merge all thread pools into pop[] */
        for (int t = 0; t < actual_threads; t++) {
            if (wargs[t].best_cnt < greedy_best_cnt)
                greedy_best_cnt = wargs[t].best_cnt;
            for (int i = 0; i < pop_size; i++) {
                Solution *src = &thread_results[t][i];
                if (src->n_candidates == INT_MAX) continue;
                int worst = 0;
                for (int j = 1; j < pop_size; j++)
                    if (solution_better_mode(&pop[worst], &pop[j], &fitness_cfg))
                        worst = j;
                if (solution_better_metrics_mode(src->n_candidates,
                                                 src->opt_score,
                                                 src->aux_score,
                                                 pop[worst].n_candidates,
                                                 pop[worst].opt_score,
                                                 pop[worst].aux_score,
                                                 &fitness_cfg)) {
                    memcpy(pop[worst].offsets, src->offsets,
                           (size_t)np * sizeof(int));
                    pop[worst].n_candidates = src->n_candidates;
                    pop[worst].opt_score    = src->opt_score;
                    pop[worst].aux_score    = src->aux_score;
                    pop[worst].w_score      = src->w_score;
                }
                if (solution_better_metrics_mode(src->n_candidates,
                                                 src->opt_score,
                                                 src->aux_score,
                                                 greedy_best_mode_cnt,
                                                 greedy_best_mode_opt,
                                                 greedy_best_mode_aux,
                                                 &fitness_cfg)) {
                    greedy_best_mode_cnt = src->n_candidates;
                    greedy_best_mode_opt = src->opt_score;
                    greedy_best_mode_aux = src->aux_score;
                }
            }
            for (int i = 0; i < pop_size; i++) sol_free(&thread_results[t][i]);
            free(thread_results[t]);
        }
        free(thread_results);
        free(wargs);
        free(tids);

        /* The greedy pool in pop[] already contains pop_size diverse,
         * locally-optimal solutions (every greedy restart ends with a full
         * local_search_sweep).  Do NOT rebuild around a handful of elite
         * seeds — that collapses the structural diversity that makes
         * crossover between different greedy basins effective. */

        /* ---- Phase 2: evolution ---- */
        if (ctr_evolution && pop_size > 1) {
            unsigned evo_rng = (unsigned)time(NULL) ^ 0xBEEFCAFEu;

            int adj_fixed = ctr_fixed;
            if (adj_fixed > np) adj_fixed = np;

            /* Each generation produces n_threads locally-optimal children
             * (full local_search_sweep per child = memetic EA).  Fewer
             * generations are needed because every child is locally polished
             * before it competes for a population slot.  Wall time target:
             * ~30 s for typical shift=256 runs on 8 threads. */
            int gens = pop_size;
            if (gens < 1000)  gens = 1000;
            if (gens > 6000)  gens = 6000;

                 evolve(pop, pop_size, np, gs, adj_fixed, gens, &evo_rng,
                     actual_threads, &fitness_cfg);
        }

        /* ---- Phase 3: Iterated Local Search (ILS), parallel ---- */
        /* Run n_threads independent ILS chains, each starting from the
           current best solution (after an initial local-search polish).
           Chains are fully independent — no synchronisation needed.    */
        {
            /* find current best */
            int bi = 0;
            for (int i = 1; i < pop_size; i++)
                if (solution_better_mode(&pop[i], &pop[bi], &fitness_cfg))
                    bi = i;

            int ils_fixed = ctr_fixed < np ? ctr_fixed : np;
            int nfree     = np - ils_fixed;
            int ils_rounds = nfree * nfree * 5;
            if (ils_rounds < 200)   ils_rounds = 200;
            if (ils_rounds > 25000) ils_rounds = 25000;

            /* rounds per thread (each explores a separate random walk) */
            int rounds_per_thread = (ils_rounds + actual_threads - 1)
                                    / actual_threads;

            pthread_t     *ils_tids  = (pthread_t    *)malloc((size_t)actual_threads * sizeof(pthread_t));
            ILSWorkerArgs *ils_wargs = (ILSWorkerArgs*)malloc((size_t)actual_threads * sizeof(ILSWorkerArgs));
            if (!ils_tids || !ils_wargs) { perror("malloc"); exit(1); }

            unsigned ils_base_seed = (unsigned)time(NULL) ^ 0xC0FFEE00u;
            for (int t = 0; t < actual_threads; t++) {
                /* Each thread starts from a different population member so
                   chains explore distinct basins. Threads beyond pop_size
                   wrap around to reuse population slots with a perturbed seed. */
                int start_idx = (pop_size > 1) ? (t % pop_size) : bi;
                ils_wargs[t].n_primes      = np;
                ils_wargs[t].gap_size      = gs;
                ils_wargs[t].ils_fixed     = ils_fixed;
                ils_wargs[t].rounds        = rounds_per_thread;
                ils_wargs[t].seed          = ils_base_seed ^ ((unsigned)t * 1234567891u);
                ils_wargs[t].fc            = &fitness_cfg;
                ils_wargs[t].start_offsets = pop[start_idx].offsets;
                ils_wargs[t].result.offsets = NULL;
                pthread_create(&ils_tids[t], NULL, ils_worker, &ils_wargs[t]);
            }

            /* progress: just wait */
            fprintf(stderr, "  ILS: %d chains x %d rounds (pair-sweep at chain end) ...",
                    actual_threads, rounds_per_thread);
            fflush(stderr);

            for (int t = 0; t < actual_threads; t++)
                pthread_join(ils_tids[t], NULL);

            /* pick best result across all ILS chains */
            int ils_best_cnt = pop[bi].n_candidates;
            for (int t = 0; t < actual_threads; t++) {
                ILSWorkerArgs *w = &ils_wargs[t];
                if (w->result.offsets &&
                    solution_better_metrics_mode(w->result.n_candidates,
                                                 w->result.opt_score,
                                                 w->result.aux_score,
                                                 ils_best_cnt,
                                                 pop[bi].opt_score,
                                                 pop[bi].aux_score,
                                                 &fitness_cfg)) {
                    memcpy(pop[bi].offsets, w->result.offsets,
                           (size_t)np * sizeof(int));
                    pop[bi].n_candidates = w->result.n_candidates;
                    pop[bi].opt_score    = w->result.opt_score;
                    pop[bi].aux_score    = w->result.aux_score;
                    pop[bi].w_score      = w->result.w_score;
                    ils_best_cnt         = w->result.n_candidates;
                }
                free(w->result.offsets);
            }
            fprintf(stderr, "  best=%d\n", ils_best_cnt);

            free(ils_wargs);
            free(ils_tids);
        }

        /* ---- find best in population ---- */
        int best_idx = 0;
        Phase1Diag best_idx_diag;
        int have_best_idx_diag = 0;

        if (phase3_enabled) {
            int pop_min_cnt = pop[0].n_candidates;
            for (int i = 1; i < pop_size; i++)
                if (pop[i].n_candidates < pop_min_cnt)
                    pop_min_cnt = pop[i].n_candidates;

            int min_anchor = pop_min_cnt + phase3_delta;
            int seeded = 0;
            for (int i = 0; i < pop_size; i++) {
                if (pop[i].n_candidates <= min_anchor) {
                    best_idx = i;
                    seeded = 1;
                    break;
                }
            }
            if (!seeded)
                best_idx = 0;

            best_idx_diag = phase1_diag(pop[best_idx].offsets,
                                        np,
                                        gs,
                                        buf,
                                        PHASE1_A_DEFAULT,
                                        PHASE1_B_DEFAULT);
            have_best_idx_diag = 1;
            for (int i = 1; i < pop_size; i++) {
                if (pop[i].n_candidates > min_anchor)
                    continue;
                Phase1Diag cand_diag = phase1_diag(pop[i].offsets,
                                                   np,
                                                   gs,
                                                   buf,
                                                   PHASE1_A_DEFAULT,
                                                   PHASE1_B_DEFAULT);
                if (solution_better_phase3(&pop[i], &cand_diag,
                                           &pop[best_idx], &best_idx_diag,
                                           phase3_delta,
                                           phase3_mean_eps)) {
                    best_idx = i;
                    best_idx_diag = cand_diag;
                }
            }
        } else {
            for (int i = 1; i < pop_size; i++)
                if (solution_better_mode(&pop[i], &pop[best_idx], &fitness_cfg))
                    best_idx = i;
        }

        phase_best_cnt = pop[best_idx].n_candidates;
        phase_best_mode_cnt = pop[best_idx].n_candidates;
        phase_best_mode_opt = pop[best_idx].opt_score;
        phase_best_mode_aux = pop[best_idx].aux_score;
        phase_best_min_cnt = pop[0].n_candidates;
        for (int i = 1; i < pop_size; i++) {
            if (pop[i].n_candidates < phase_best_min_cnt)
                phase_best_min_cnt = pop[i].n_candidates;
        }

        /* Phase-2 shadow ranking: independently track highest phase1 score.
           This does NOT affect production best selection. */
        int shadow_idx = 0;
        Phase1Diag shadow_diag = phase1_diag(pop[0].offsets,
                                             np,
                                             gs,
                                             buf,
                                             PHASE1_A_DEFAULT,
                                             PHASE1_B_DEFAULT);
        for (int i = 1; i < pop_size; i++) {
            Phase1Diag cand_diag = phase1_diag(pop[i].offsets,
                                               np,
                                               gs,
                                               buf,
                                               PHASE1_A_DEFAULT,
                                               PHASE1_B_DEFAULT);
            int better = 0;
            if (cand_diag.score_mean > shadow_diag.score_mean) {
                better = 1;
            } else if (cand_diag.score_mean == shadow_diag.score_mean &&
                       cand_diag.score_raw > shadow_diag.score_raw) {
                better = 1;
            } else if (cand_diag.score_mean == shadow_diag.score_mean &&
                       cand_diag.score_raw == shadow_diag.score_raw &&
                       solution_better_mode(&pop[i], &pop[shadow_idx], &fitness_cfg)) {
                better = 1;
            }
            if (better) {
                shadow_idx = i;
                shadow_diag = cand_diag;
            }
        }

        if (!phase1_shadow_best.offsets ||
            shadow_diag.score_mean > phase1_shadow_diag.score_mean ||
            (shadow_diag.score_mean == phase1_shadow_diag.score_mean &&
             shadow_diag.score_raw > phase1_shadow_diag.score_raw) ||
            (shadow_diag.score_mean == phase1_shadow_diag.score_mean &&
             shadow_diag.score_raw == phase1_shadow_diag.score_raw &&
             solution_better_mode(&pop[shadow_idx], &phase1_shadow_best, &fitness_cfg))) {
            if (phase1_shadow_best.offsets) sol_free(&phase1_shadow_best);
            phase1_shadow_best = sol_clone(&pop[shadow_idx]);
            phase1_shadow_diag = shadow_diag;
        }

        if (!global_best.offsets) {
            global_best = sol_clone(&pop[best_idx]);
            if (phase3_enabled && have_best_idx_diag)
                global_best_phase1 = best_idx_diag;
        } else {
            int replace_global = 0;
            if (phase3_enabled && have_best_idx_diag) {
                replace_global = solution_better_phase3(&pop[best_idx],
                                                        &best_idx_diag,
                                                        &global_best,
                                                        &global_best_phase1,
                                                        phase3_delta,
                                                        phase3_mean_eps);
            } else {
                replace_global = solution_better_mode(&pop[best_idx], &global_best, &fitness_cfg);
            }
            if (replace_global) {
                sol_free(&global_best);
                global_best = sol_clone(&pop[best_idx]);
                if (phase3_enabled && have_best_idx_diag)
                    global_best_phase1 = best_idx_diag;
            }
        }

        for (int i = 0; i < pop_size; i++) sol_free(&pop[i]);
        free(pop);
        free(buf);
    }

    /* ---- Summary ---- */
    double pb = primorial_log2(global_best.n_primes);
    int    sh = (int)ceil(pb) + ctr_bits;

    fprintf(stderr, "\n========================================\n");
    if (fitness_cfg.mode == FITNESS_PROBABILITY) {
        fprintf(stderr, "  greedy (cand-min):    %d candidates\n", greedy_best_cnt);
        fprintf(stderr, "  greedy (obj-best):    %d candidates\n", greedy_best_mode_cnt);
        fprintf(stderr,
                "  evolution (obj-best): %d candidates  [p=%.6f, aux=%.3f]\n",
                phase_best_mode_cnt, phase_best_mode_opt, phase_best_mode_aux);
        fprintf(stderr, "  evolution (cand-min): %d candidates\n", phase_best_min_cnt);
    } else {
        fprintf(stderr, "  greedy:    %d candidates\n", greedy_best_cnt);
        fprintf(stderr, "  evolution: %d candidates\n", phase_best_cnt);
    }
    fprintf(stderr, "  best:  %d candidates  (%d primes, shift=%d)\n",
            global_best.n_candidates, global_best.n_primes, sh);
    fprintf(stderr, "  uncovered ratio: %.2f%%\n",
            100.0 * (double)global_best.n_candidates
                   / (double)global_best.gap_size);
    fprintf(stderr, "  objective mode: %s\n",
            fitness_cfg.mode == FITNESS_PROBABILITY ? "probability" : "candidate");
    if (fitness_cfg.mode == FITNESS_PROBABILITY) {
        fprintf(stderr, "  probability score: %.6f\n", global_best.opt_score);
        fprintf(stderr, "  candidate weighted score: %.3f  (mean w/cand: %.4f)\n",
                global_best.w_score,
                global_best.n_candidates > 0
                    ? global_best.w_score / (double)global_best.n_candidates
                    : 0.0);
    } else {
        fprintf(stderr, "  candidate weighted score: %.3f  (mean w/cand: %.4f)\n",
                global_best.w_score,
                global_best.n_candidates > 0
                    ? global_best.w_score / (double)global_best.n_candidates
                    : 0.0);
    }
    fprintf(stderr, "========================================\n");

    uint8_t *p1_buf = (uint8_t *)calloc((size_t)(global_best.gap_size + 1), 1);
    if (!p1_buf) {
        perror("calloc");
        sol_free(&global_best);
        return 1;
    }
    Phase1Diag p1 = phase1_diag(global_best.offsets,
                                global_best.n_primes,
                                global_best.gap_size,
                                p1_buf,
                                PHASE1_A_DEFAULT,
                                PHASE1_B_DEFAULT);
    free(p1_buf);

    fprintf(stderr,
            "  phase1(score): raw=%.4f  mean=%.6f  remaining=%d  [a=%.2f b=%.2f]\n",
            p1.score_raw, p1.score_mean, p1.remaining, p1.a, p1.b);
        if (phase1_shadow_best.offsets) {
        fprintf(stderr,
            "  phase2(shadow): p1-best=%d cand  raw=%.4f  mean=%.6f"
            "  (delta_vs_best=%+d)\n",
            phase1_shadow_best.n_candidates,
            phase1_shadow_diag.score_raw,
            phase1_shadow_diag.score_mean,
            phase1_shadow_best.n_candidates - global_best.n_candidates);
        }
    fprintf(stderr, "========================================\n");

    /* print offsets */
    fprintf(stderr, "\n  prime -> offset:\n");
    for (int i = 0; i < global_best.n_primes; i++)
        fprintf(stderr, "    %4d -> %d\n",
                PRIMES[i], global_best.offsets[i]);

    /* ---- Write output file ---- */
    write_crt_file(ctr_file, &global_best, ctr_merit, sh, &p1, &fitness_cfg);

    if (phase1_shadow_best.offsets)
        sol_free(&phase1_shadow_best);
    sol_free(&global_best);
    return 0;
}
