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
} Solution;

static bool solution_better(const Solution *a, const Solution *b) {
    if (a->n_candidates != b->n_candidates)
        return a->n_candidates < b->n_candidates;
    return a->w_score < b->w_score;
}

static bool solution_better_metrics(int a_cnt, double a_w,
                                    int b_cnt, double b_w) {
    if (a_cnt != b_cnt)
        return a_cnt < b_cnt;
    return a_w < b_w;
}

/* ---- helpers ---- */

static double primorial_log2(int n) {
    double s = 0.0;
    for (int i = 0; i < n && i < N_PRIMES_AVAIL; i++)
        s += log2((double)PRIMES[i]);
    return s;
}

static Solution sol_alloc(int n_primes, int gap_size) {
    Solution s;
    s.n_primes     = n_primes;
    s.gap_size     = gap_size;
    s.offsets      = (int *)malloc((size_t)n_primes * sizeof(int));
    s.n_candidates = INT_MAX;
    s.w_score      = 1e18;
    if (!s.offsets) { perror("malloc"); exit(1); }
    return s;
}

static Solution sol_clone(const Solution *src) {
    Solution c = sol_alloc(src->n_primes, src->gap_size);
    memcpy(c.offsets, src->offsets, (size_t)src->n_primes * sizeof(int));
    c.n_candidates = src->n_candidates;
    c.w_score      = src->w_score;
    return c;
}

static void sol_free(Solution *s) {
    free(s->offsets);
    s->offsets = NULL;
}

/* ------------------------------------------------------------------ */
/* Evaluate: count uncovered positions in [1, gap_size].              */
/* Uses caller-owned buffer buf[0..gap_size] (uint8_t).               */
/* If w_out is non-NULL, also computes weighted fitness score.         */
/* ------------------------------------------------------------------ */
static int evaluate(const int *offsets, int n_primes, int gap_size,
                    uint8_t *buf, double *w_out) {
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
    if (w_out) *w_out = wt + CLUSTER_PENALTY_WEIGHT * cluster_penalty;
    return cnt;
}

/* ------------------------------------------------------------------ */
/* Greedy algorithm: assign offsets one prime at a time, choosing the  */
/* offset that covers the most currently-uncovered gap positions.      */
/* Ties are broken randomly (reservoir sampling) for diversity.        */
/* ------------------------------------------------------------------ */
static void greedy_solve(int *offsets, int n_primes, int gap_size,
                         uint8_t *buf) {
    int *order = (int *)malloc((size_t)n_primes * sizeof(int));
    if (!order) { perror("malloc"); exit(1); }

    memset(buf, 0, (size_t)(gap_size + 1));

    for (int i = 0; i < n_primes; i++)
        order[i] = i;

    for (int i = n_primes - 1; i > 0; i--) {
        int j = rand() % (i + 1);
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
                if (rand() % ties == 0) best_o = o;
            }
        }

        offsets[i] = best_o;
        for (int d = best_o; d <= gap_size; d += p)
            buf[d] = 1;
    }

    free(order);
}

/* Randomly perturb a few non-fixed offsets to escape greedy plateaus. */
static void kick_offsets(int *offsets, int n_primes, int fixed, int kicks) {
    if (fixed >= n_primes || kicks <= 0) return;

    int nfree = n_primes - fixed;
    if (kicks > nfree) kicks = nfree;

    for (int k = 0; k < kicks; k++) {
        int idx = fixed + rand() % nfree;
        int p = PRIMES[idx];
        int next = rand() % p;
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
                              int fixed, uint8_t *buf) {
    int idx = weakest_nonfixed_prime(offsets, n_primes, gap_size, fixed, buf);
    if (idx < 0) return -1;
    int p = PRIMES[idx];
    int next = rand() % p;
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
static int evaluate(const int *offsets, int n_primes, int gap_size,
                    uint8_t *buf, double *w_out);
static void greedy_solve(int *offsets, int n_primes, int gap_size,
                         uint8_t *buf);
static int local_search_one(int *offsets, int n_primes, int gap_size,
                            int idx, uint8_t *buf);
static int local_search_pair(int *offsets, int n_primes, int gap_size,
                             int idx_a, int idx_b,
                             uint8_t *base_buf, uint8_t *work_buf);
static int local_search_sweep(int *offsets, int n_primes, int gap_size,
                              int fixed, uint8_t *buf);
static int pair_search_sweep(int *offsets, int n_primes, int gap_size,
                             int fixed, uint8_t *buf, uint8_t *buf2);

/* ------------------------------------------------------------------ */
/* Evolutionary algorithm                                              */
/* Tournament selection, uniform crossover on non-fixed primes,        */
/* random mutation + local-search refinement.                          */
/* ------------------------------------------------------------------ */
static void evolve(Solution *pop, int pop_size, int n_primes, int gap_size,
                   int fixed, int max_gens) {
    int     *child = (int *)malloc((size_t)n_primes * sizeof(int));
    uint8_t *buf   = (uint8_t *)calloc((size_t)(gap_size + 1), 1);
    uint8_t *buf2  = (uint8_t *)calloc((size_t)(gap_size + 1), 1);
    if (!child || !buf || !buf2) { perror("alloc"); exit(1); }

    int    best_ever_cnt = INT_MAX;
    double best_ever_w   = 1e18;
    for (int i = 0; i < pop_size; i++) {
        if (solution_better_metrics(pop[i].n_candidates, pop[i].w_score,
                                    best_ever_cnt, best_ever_w)) {
            best_ever_cnt = pop[i].n_candidates;
            best_ever_w   = pop[i].w_score;
        }
    }

    int stale = 0;

    for (int gen = 0; gen < max_gens; gen++) {
        /* tournament select two parents */
        int a = rand() % pop_size, b = rand() % pop_size;
        int p1 = solution_better(&pop[a], &pop[b]) ? a : b;
        a = rand() % pop_size; b = rand() % pop_size;
        int p2 = solution_better(&pop[a], &pop[b]) ? a : b;

        /* uniform crossover */
        for (int i = 0; i < n_primes; i++) {
            if (i < fixed)
                child[i] = pop[p1].offsets[i];
            else
                child[i] = (rand() & 1) ? pop[p1].offsets[i]
                                         : pop[p2].offsets[i];
        }

        /* random mutation: adaptive rate — ramp up when stale */
        int mut_thresh = (stale > 10000) ? n_primes / 2 : 2;
        for (int i = fixed; i < n_primes; i++) {
            if (rand() % n_primes < mut_thresh)
                child[i] = rand() % PRIMES[i];
        }

        /* local-search refinement is intentionally sparse; greedy already
         * does most of the useful work. */
        if (rand() % 25 == 0 && fixed < n_primes) {
            int nfree = n_primes - fixed;
            if (nfree >= 2 && rand() % 2 == 0) {
                /* pair search: jointly optimise two random primes */
                int ia = fixed + rand() % nfree;
                int ib = fixed + rand() % nfree;
                while (ib == ia) ib = fixed + rand() % nfree;
                local_search_pair(child, n_primes, gap_size,
                                  ia, ib, buf, buf2);
            } else {
                int idx = fixed + rand() % nfree;
                local_search_one(child, n_primes, gap_size, idx, buf);
            }
        }

        /* Controlled escape: jump one weakest prime, then repair locally. */
        if (fixed < n_primes && (stale > 8000 || (rand() % 24) == 0)) {
            int weak_idx = kick_weakest_prime(child, n_primes, gap_size,
                                             fixed, buf2);
            if (weak_idx >= 0) {
                local_search_one(child, n_primes, gap_size, weak_idx, buf);
                if (rand() % 2 == 0 && weak_idx + 1 < n_primes)
                    local_search_pair(child, n_primes, gap_size,
                                      weak_idx,
                                      weak_idx + 1,
                                      buf, buf2);
            }
        }

        /* evaluate */
        double fitness_w;
        int fitness = evaluate(child, n_primes, gap_size, buf, &fitness_w);

        /* replace worst if child is better */
        int worst = 0;
        for (int i = 1; i < pop_size; i++) {
            if (pop[i].n_candidates > pop[worst].n_candidates ||
                (pop[i].n_candidates == pop[worst].n_candidates &&
                 pop[i].w_score > pop[worst].w_score))
                worst = i;
        }

        if (solution_better_metrics(fitness, fitness_w,
                                    pop[worst].n_candidates,
                                    pop[worst].w_score)) {
            memcpy(pop[worst].offsets, child, (size_t)n_primes * sizeof(int));
            pop[worst].n_candidates = fitness;
            pop[worst].w_score      = fitness_w;
        }

        if (solution_better_metrics(fitness, fitness_w,
                                    best_ever_cnt, best_ever_w)) {
            best_ever_cnt = fitness;
            best_ever_w   = fitness_w;
            stale = 0;
        } else {
            stale++;
        }

        /* progress */
        if ((gen + 1) % 10000 == 0 || gen == max_gens - 1) {
            fprintf(stderr, "\r  evolution: gen %d/%d  best=%d  stale=%d     ",
                    gen + 1, max_gens, best_ever_cnt, stale);
            fflush(stderr);
        }

        /* early stop if no improvement for a long time */
        if (stale > max_gens / 10 && stale > 8000) break;
    }

    fprintf(stderr, "\n");
    free(child);
    free(buf);
    free(buf2);
}

/* ------------------------------------------------------------------ */
/* Write CRT text file                                                 */
/* ------------------------------------------------------------------ */
static void write_crt_file(const char *path, const Solution *sol,
                           double merit, int shift) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }

    fprintf(f, "# CRT sieve file generated by cpugapminer gen_crt\n");
    fprintf(f, "n_primes %d\n", sol->n_primes);
    fprintf(f, "merit %.2f\n", merit);
    fprintf(f, "shift %d\n", shift);
    fprintf(f, "gap_target %d\n", sol->gap_size);
    fprintf(f, "n_candidates %d\n", sol->n_candidates);

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
        {"help",           no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "Cp:m:b:s:ef:i:r:o:h",
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

    /* ---- derived parameters ---- */
    double prim_bits = primorial_log2(ctr_primes);
    int    shift     = (int)ceil(prim_bits) + ctr_bits;
    int    gap_size  = (int)ceil(ctr_merit * (256.0 + (double)shift) * log(2.0));

    fprintf(stderr, "CRT gap solver\n");
    fprintf(stderr, "  primes      : %d  (2 .. %d)\n",
            ctr_primes, PRIMES[ctr_primes - 1]);
    fprintf(stderr, "  primorial   : %.1f bits\n", prim_bits);
    fprintf(stderr, "  ctr-bits    : %d\n", ctr_bits);
    fprintf(stderr, "  shift       : %d\n", shift);
    fprintf(stderr, "  merit       : %.2f\n", ctr_merit);
    fprintf(stderr, "  gap target  : %d\n", gap_size);
    fprintf(stderr, "  strength    : %d  (greedy restarts)\n", ctr_strength);
    if (ctr_evolution)
        fprintf(stderr, "  evolution   : ivs=%d  fixed=%d\n",
                ctr_ivs, ctr_fixed);
    if (ctr_range > 0)
        fprintf(stderr, "  range       : +/-%d%%  (primes %d..%d)\n",
                ctr_range,
                ctr_primes - ctr_primes * ctr_range / 100,
                ctr_primes + ctr_primes * ctr_range / 100);
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

    int greedy_best_cnt = INT_MAX;
    int phase_best_cnt  = INT_MAX;

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

        /* ---- Phase 1: greedy restarts, keep best pop_size ---- */
        int *tmp = (int *)malloc((size_t)np * sizeof(int));
        for (int r = 0; r < ctr_strength; r++) {
            unsigned seed = (unsigned)time(NULL) ^ ((unsigned)r * 2654435761u)
                            ^ (unsigned)rand();
            srand(seed);
            greedy_solve(tmp, np, gs, buf);
            if (ctr_fixed < np) {
                int kicks = 1 + rand() % 3;
                kick_offsets(tmp, np, ctr_fixed, kicks);
                local_search_sweep(tmp, np, gs, ctr_fixed, buf);
            }
            double w_nc;
            int nc = evaluate(tmp, np, gs, buf, &w_nc);

            /* insert into population if better than worst */
            int worst = 0;
            for (int i = 1; i < pop_size; i++)
                if (pop[i].n_candidates > pop[worst].n_candidates ||
                    (pop[i].n_candidates == pop[worst].n_candidates &&
                     pop[i].w_score > pop[worst].w_score))
                    worst = i;

            if (solution_better_metrics(nc, w_nc,
                                        pop[worst].n_candidates,
                                        pop[worst].w_score)) {
                memcpy(pop[worst].offsets, tmp, (size_t)np * sizeof(int));
                pop[worst].n_candidates = nc;
                pop[worst].w_score      = w_nc;
            }

            if (nc < greedy_best_cnt)
                greedy_best_cnt = nc;

            if ((r + 1) % 5 == 0 || r == ctr_strength - 1) {
                fprintf(stderr,
                    "\r  greedy: %d/%d restarts  best=%d candidates     ",
                    r + 1, ctr_strength, greedy_best_cnt);
                fflush(stderr);
            }
        }
        free(tmp);
        fprintf(stderr, "\n");

        /* Keep a small elite bank of the best greedy solutions. */
        int elite_keep = pop_size < 8 ? pop_size : 8;
        Solution *elite_bank = (Solution *)calloc((size_t)elite_keep,
                                                  sizeof(Solution));
        bool *picked = (bool *)calloc((size_t)pop_size, sizeof(bool));
        uint8_t *seed_buf = NULL;
        if (!elite_bank || !picked) { perror("calloc"); exit(1); }

        for (int i = 0; i < elite_keep; i++)
            elite_bank[i].offsets = NULL;

        for (int e = 0; e < elite_keep; e++) {
            int best_idx = -1;
            for (int i = 0; i < pop_size; i++) {
                if (picked[i]) continue;
                if (best_idx < 0 || solution_better(&pop[i], &pop[best_idx]))
                    best_idx = i;
            }
            picked[best_idx] = true;
            elite_bank[e] = sol_clone(&pop[best_idx]);
        }

        if (ctr_evolution && pop_size > 1) {
            seed_buf = (uint8_t *)calloc((size_t)(gs + 1), 1);
            if (!seed_buf) { perror("calloc"); exit(1); }

            /* Rebuild the population around the elite bank. */
            for (int i = 0; i < pop_size; i++) {
                int src = i % elite_keep;
                memcpy(pop[i].offsets, elite_bank[src].offsets,
                       (size_t)np * sizeof(int));

                if (i >= elite_keep) {
                    int weak_idx = kick_weakest_prime(pop[i].offsets, np, gs,
                                                      ctr_fixed, seed_buf);
                    if (weak_idx >= 0) {
                        local_search_one(pop[i].offsets, np, gs, weak_idx,
                                         seed_buf);
                        if ((i & 1) == 0 && weak_idx + 1 < np)
                            local_search_pair(pop[i].offsets, np, gs,
                                              weak_idx, weak_idx + 1,
                                              seed_buf, buf);
                    }
                }

                pop[i].n_candidates = evaluate(pop[i].offsets, np, gs,
                                               seed_buf, &pop[i].w_score);
            }
        }

        for (int i = 0; i < elite_keep; i++)
            sol_free(&elite_bank[i]);
        free(elite_bank);
        free(picked);
        free(seed_buf);

        /* ---- Phase 2: evolution ---- */
        if (ctr_evolution && pop_size > 1) {
            /* re-seed so evolution is not deterministic */
            srand((unsigned)time(NULL) ^ 0xBEEFCAFE);

            int adj_fixed = ctr_fixed;
            if (adj_fixed > np) adj_fixed = np;

            /* adaptive generation count: keep evolution as a light
             * refinement pass, not a second full search. */
            int gens = np * pop_size * 1200;
            if (gens < 30000)  gens = 30000;
            if (gens > 400000) gens = 400000;

            evolve(pop, pop_size, np, gs, adj_fixed, gens);
        }

        /* ---- Phase 3: Iterated Local Search (ILS) ---- */
        /* Take the best solution, apply full sweeps + pair sweeps,     */
        /* then repeatedly perturb 1-2 offsets and re-sweep.            */
        {
            uint8_t *ils_buf  = (uint8_t *)calloc((size_t)(gs + 1), 1);
            uint8_t *ils_buf2 = (uint8_t *)calloc((size_t)(gs + 1), 1);
            int     *ils_work = (int *)malloc((size_t)np * sizeof(int));
            if (!ils_buf || !ils_buf2 || !ils_work) {
                perror("alloc"); exit(1);
            }

            /* find current best */
            int bi = 0;
            for (int i = 1; i < pop_size; i++)
                if (solution_better(&pop[i], &pop[bi]))
                    bi = i;

            /* initial full sweep + pair sweep on a copy so ILS cannot
             * make the best solution worse before it has earned the update. */
            memcpy(ils_work, pop[bi].offsets, (size_t)np * sizeof(int));
            local_search_sweep(ils_work, np, gs,
                               ctr_fixed < np ? ctr_fixed : np, ils_buf);
            pair_search_sweep(ils_work, np, gs,
                              ctr_fixed < np ? ctr_fixed : np,
                              ils_buf, ils_buf2);
            double ils_init_w;
            int ils_init_cnt = evaluate(ils_work, np, gs, ils_buf, &ils_init_w);
            if (solution_better_metrics(ils_init_cnt, ils_init_w,
                                        pop[bi].n_candidates,
                                        pop[bi].w_score)) {
                memcpy(pop[bi].offsets, ils_work, (size_t)np * sizeof(int));
                pop[bi].n_candidates = ils_init_cnt;
                pop[bi].w_score      = ils_init_w;
            }

            double ils_best_w   = pop[bi].w_score;
            int    ils_best_cnt = pop[bi].n_candidates;
            int ils_fixed = ctr_fixed < np ? ctr_fixed : np;
            int nfree = np - ils_fixed;

            /* ILS rounds: perturb + re-sweep */
            int ils_rounds = nfree * nfree * 5;
            if (ils_rounds < 200)    ils_rounds = 200;
            if (ils_rounds > 25000)   ils_rounds = 25000;
            int ils_stale = 0;

            for (int r = 0; r < ils_rounds; r++) {
                /* copy best solution */
                memcpy(ils_work, pop[bi].offsets,
                       (size_t)np * sizeof(int));

                /* one controlled escape on the weakest non-fixed prime */
                int weak_idx = kick_weakest_prime(ils_work, np, gs,
                                                 ils_fixed, ils_buf2);
                if (weak_idx >= 0) {
                    local_search_one(ils_work, np, gs, weak_idx, ils_buf);
                    if (weak_idx + 1 < np)
                        local_search_pair(ils_work, np, gs,
                                          weak_idx, weak_idx + 1,
                                          ils_buf, ils_buf2);
                }

                /* re-sweep: single then pair */
                local_search_sweep(ils_work, np, gs, ils_fixed, ils_buf);
                pair_search_sweep(ils_work, np, gs, ils_fixed,
                                  ils_buf, ils_buf2);
                double w_nc;
                int nc = evaluate(ils_work, np, gs, ils_buf, &w_nc);

                                  if (solution_better_metrics(nc, w_nc, ils_best_cnt, ils_best_w)) {
                    memcpy(pop[bi].offsets, ils_work,
                           (size_t)np * sizeof(int));
                    pop[bi].n_candidates = nc;
                    pop[bi].w_score      = w_nc;
                    ils_best_w   = w_nc;
                    ils_best_cnt = nc;
                    ils_stale = 0;
                } else {
                    ils_stale++;
                }

                if ((r + 1) % 50 == 0 || r == ils_rounds - 1) {
                    fprintf(stderr,
                        "\r  ILS: %d/%d rounds  best=%d  stale=%d     ",
                        r + 1, ils_rounds, ils_best_cnt, ils_stale);
                    fflush(stderr);
                }

                if (ils_stale > ils_rounds / 5 && ils_stale > 80) break;
            }
            fprintf(stderr, "\n");

            free(ils_work);
            free(ils_buf2);
            free(ils_buf);
        }

        /* ---- find best in population ---- */
        int best_idx = 0;
        for (int i = 1; i < pop_size; i++)
            if (solution_better(&pop[i], &pop[best_idx]))
                best_idx = i;

        phase_best_cnt = pop[best_idx].n_candidates;

        if (!global_best.offsets || solution_better(&pop[best_idx], &global_best)) {
            if (global_best.offsets) sol_free(&global_best);
            global_best = sol_clone(&pop[best_idx]);
        }

        for (int i = 0; i < pop_size; i++) sol_free(&pop[i]);
        free(pop);
        free(buf);
    }

    /* ---- Summary ---- */
    double pb = primorial_log2(global_best.n_primes);
    int    sh = (int)ceil(pb) + ctr_bits;

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, "  greedy:    %d candidates\n", greedy_best_cnt);
    fprintf(stderr, "  evolution: %d candidates\n", phase_best_cnt);
    fprintf(stderr, "  best:  %d candidates  (%d primes, shift=%d)\n",
            global_best.n_candidates, global_best.n_primes, sh);
    fprintf(stderr, "  uncovered ratio: %.2f%%\n",
            100.0 * (double)global_best.n_candidates
                   / (double)global_best.gap_size);
    fprintf(stderr, "  weighted score:  %.3f  (mean w/cand: %.4f)\n",
            global_best.w_score,
            global_best.n_candidates > 0
                ? global_best.w_score / (double)global_best.n_candidates
                : 0.0);
    fprintf(stderr, "========================================\n");

    /* print offsets */
    fprintf(stderr, "\n  prime -> offset:\n");
    for (int i = 0; i < global_best.n_primes; i++)
        fprintf(stderr, "    %4d -> %d\n",
                PRIMES[i], global_best.offsets[i]);

    /* ---- Write output file ---- */
    write_crt_file(ctr_file, &global_best, ctr_merit, sh);

    sol_free(&global_best);
    return 0;
}
