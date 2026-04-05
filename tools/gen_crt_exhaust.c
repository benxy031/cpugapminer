/*
 * gen_crt_exhaust.c  –  Exhaustive / random-restart CRT offset finder
 *
 * Ported and adapted from primeinterval.cpp (original author unknown).
 *
 * Algorithm:
 *   For small prime counts (n_primes ≤ MAX_EXHAUST_PRIMES):
 *     Enumerate all combinations of per-prime offsets exhaustively using
 *     an odometer counter.  The key speedup is INCREMENTAL evaluation:
 *     each layer buf[i] is only rebuilt from the level that changed,
 *     making the inner loop O(interval / p_n) instead of O(n * interval).
 *
 *   For larger prime counts:
 *     Random-restart: randomise all offsets, do a full evaluation, repeat
 *     indefinitely, printing whenever a new minimum (or equal) is found.
 *     Better than the greedy+evolution in gen_crt for very large searches.
 *
 * Bit convention: 1 = candidate (BIT SET = still a potential prime).
 *   buf[i] has bit b set  iff  (2b) is NOT eliminated by primes 1..i.
 *   (This is the same convention as primeinterval.cpp, opposite gen_crt.)
 *
 * Output format: same as gen_crt.c — loadable by cpugapminer --crt-file.
 *
 * Build:
 *   gcc -O3 -std=c11 -Wall -o tools/gen_crt_exhaust tools/gen_crt_exhaust.c -lgmp -lm
 *
 * Usage:
 *   gen_crt_exhaust --ctr-primes N --ctr-merit M [--ctr-bits B]
 *                   [--ctr-file FILE] [--ctr-ivs IVALS]
 *
 *   --ctr-primes N   Number of CRT primes (2..38).  Primes: 3,5,7,...
 *                    NOTE: prime[0]=2 is skipped (sieve is odd-only).
 *                    The offsets are for primes[1..N] = 3,5,...
 *   --ctr-merit  M   Target merit.  Determines interval size:
 *                    gap_size = ceil(M * (256 + bits) * ln2).
 *                    (256 = block-hash bits; same formula as gen_crt.c)
 *   --ctr-bits   B   Shift/bits parameter (default 1024).
 *   --ctr-file   F   Output file (default: crt_exhaust.txt).
 *   --ctr-ivs    K   Save top-K solutions (default: 20).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <gmp.h>

/* ------------------------------------------------------------------ */
/* First 40 odd primes (index 0 = prime 3 = first CRT prime).         */
/* Index mirrors small_primes_cache[1..38] in the miner.              */
/* ------------------------------------------------------------------ */
static const int PRIMES[] = {
     3,  5,  7, 11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97,101,103,107,109,113,127,
   131,137,139,149,151,157,163,167,173,179
};
#define N_PRIMES_MAX 40

/* Exhaustive search is feasible up to ~8 primes (product of offsets ≤ 2*3*5*7*11*13*17*19 ~= 9.7M).
   For 9 primes (×23) the space is 223M — still doable overnight but slow.
   DEFAULT: exhaust ≤ 7 primes, random above. */
#define MAX_EXHAUST_PRIMES 7

/* ------------------------------------------------------------------ */
/* Layered sieve state                                                 */
/*                                                                     */
/* buf[i][b] = 1 iff odd number (2b) is NOT eliminated by primes      */
/*             PRIMES[0..i].  buf[0] = all-ones (base layer).         */
/* interval  = window width (number of even-spaced odd numbers).      */
/* ii[i]     = current offset for prime i.                            */
/* ------------------------------------------------------------------ */
/* Must hold interval = gap_size/2 + 1.
 * Worst case: merit=30, bits=1024 → gap≈26640 → interval≈13321.       */
#define MAX_INTERVAL 16384

typedef struct {
    uint8_t  buf[N_PRIMES_MAX + 1][MAX_INTERVAL]; /* layered sieve    */
    int      ii[N_PRIMES_MAX];   /* current offsets                   */
    int      n_primes;
    int      interval;           /* half of gap + 1 (bit positions)   */
    int      gap_size;
    long     min_cand;           /* best candidate count so far       */
    long     max_cand;
    long     iter;
} SearchState;

/* ------------------------------------------------------------------ */
/* Rebuild layers from_level..n_primes-1 using current ii[].          */
/* ------------------------------------------------------------------ */
static void rebuild_from(SearchState *S, int from_level) {
    int inter = S->interval;
    for (int i = from_level; i < S->n_primes; i++) {
        if (i == 0) {
            memset(S->buf[0], 1, (size_t)inter);  /* all candidates */
        } else {
            memcpy(S->buf[i], S->buf[i-1], (size_t)inter);
        }
        int p = PRIMES[i];
        int j = S->ii[i] % p;
        while (j < inter) { S->buf[i][j] = 0; j += p; }
    }
}

/* Count candidates at the final layer. */
static long count_candidates(const SearchState *S) {
    long cnt = 0;
    const uint8_t *b = S->buf[S->n_primes - 1];
    for (int j = 0; j < S->interval; j++) cnt += b[j];
    return cnt;
}

/* ------------------------------------------------------------------ */
/* CRT computation (GMP): find the smallest x such that               */
/*   x ≡ -ii[k]  (mod PRIMES[k])  for k=0..n_primes-1               */
/* then add gap_size/2 to center the window.                           */
/* ------------------------------------------------------------------ */
static void compute_crt(const int *ii, int n_primes, int gap_size,
                        char *out_str, size_t out_len) {
    mpz_t crt1, crt2, crt3;
    mpz_init_set_ui(crt1, 1);
    mpz_init_set_ui(crt2, 2);
    mpz_init(crt3);

    for (int a = 0; a < n_primes; a++) {
        unsigned long p = (unsigned long)PRIMES[a];
        unsigned long offset = (unsigned long)ii[a];
        /* Find x such that x ≡ -offset (mod p).
           Equivalent: find smallest crt1 ≥ current satisfying the congruence. */
        int found = 0;
        while (!found) {
            mpz_add_ui(crt3, crt1, 2 * offset);
            unsigned long r = mpz_tdiv_r_ui(crt3, crt3, p);
            if (r == 0) {
                found = 1;
            } else {
                mpz_add(crt1, crt1, crt2);
            }
        }
        mpz_mul_ui(crt2, crt2, p);
        mpz_mod(crt1, crt1, crt2);
    }

    mpz_add_ui(crt1, crt1, (unsigned long)(gap_size / 2));
    mpz_get_str(out_str, 10, crt1);
    (void)out_len;

    mpz_clear(crt1);
    mpz_clear(crt2);
    mpz_clear(crt3);
}

/* ------------------------------------------------------------------ */
/* Write solution in gen_crt.c output format.                         */
/* The file is opened in write (truncate) mode on every call so that  */
/* the output file always holds exactly ONE solution — the current    */
/* best.  This makes the file directly loadable by the miner.         */
/*                                                                    */
/* Offset encoding:                                                   */
/*   gen_crt_exhaust sieve marks position b as composite for prime p  */
/*   when b ≡ ii[k] (mod p).  The miner marks gap-sieve bit pos      */
/*   ≡ (offset_file + adj) % p (made odd) as composite, where        */
/*   adj = nAdd0 & 1.  Writing offset_file = (2*ii[k]) % p and       */
/*   including "2 1" (which forces adj=1) makes the miner mark        */
/*   pos ≡ ii[k] (mod p) — exactly matching this sieve.              */
/* ------------------------------------------------------------------ */
static void write_solution(const char *path, const int *ii, int n_primes,
                            long n_cand, int gap_size,
                            double merit, int shift) {
    char crt_str[256];
    compute_crt(ii, n_primes, gap_size, crt_str, sizeof(crt_str));

    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return; }

    fprintf(f, "# CRT sieve file generated by gen_crt_exhaust\n");
    /* n_primes +1: includes prime 2 (written below) as first entry.
       Prime 2 with offset 1 forces nAdd0 to be odd (adj=1) in the
       miner's CRT alignment, which is required for the odd-only sieve
       convention used by gen_crt_exhaust.  The offset for each odd
       prime p is written as (2*ii[k]) % p so that the miner's template
       marks positions pos ≡ ii[k] (mod p) — matching this sieve. */
    fprintf(f, "n_primes %d\n", n_primes + 1);
    fprintf(f, "merit %.2f\n", merit);
    fprintf(f, "shift %d\n", shift);
    fprintf(f, "gap_target %d\n", gap_size);
    fprintf(f, "n_candidates %ld\n", n_cand);
    fprintf(f, "2 1\n");  /* forces adj=1; skipped by template builder */
    for (int k = 0; k < n_primes; k++)
        fprintf(f, "%d %d\n", PRIMES[k], (2 * ii[k]) % PRIMES[k]);
    fprintf(f, "# CRT:%s\n", crt_str);
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Exhaustive search (small n_primes).                                 */
/* Odometer with incremental layer rebuild.                            */
/* ------------------------------------------------------------------ */
static void search_exhaustive(SearchState *S, const char *outfile,
                              double merit, int shift) {
    int n = S->n_primes;

    /* Initialise all offsets to 1 (skip 0: composite base). */
    for (int i = 0; i < n; i++) S->ii[i] = 1;
    rebuild_from(S, 0);

    long iter = 0, print_interval = 500000;

    /* ii[0] runs 1..PRIMES[0]-1 = 1..2. */
    while (S->ii[0] < PRIMES[0]) {
        long cnt = count_candidates(S);
        iter++;

        if (cnt < S->min_cand) {
            S->min_cand = cnt;
            printf("\rmin=%ld  ", cnt);
            for (int k=0;k<n;k++) printf("%d ",S->ii[k]);
            printf("  (iter %ld)\n", iter);
            /* Overwrite file with this new best (single-solution output). */
            write_solution(outfile, S->ii, n, cnt, S->gap_size, merit, shift);
        }
        if (cnt > S->max_cand) S->max_cand = cnt;

        if (iter % print_interval == 0) {
            printf("\r iter=%ld  min=%ld max=%ld   ", iter, S->min_cand, S->max_cand);
            for (int k=0;k<n;k++) printf("%d ",S->ii[k]);
            fflush(stdout);
        }

        /* Increment odometer from innermost level. */
        int level = n - 1;
        S->ii[level]++;
        while (level > 0 && S->ii[level] >= PRIMES[level]) {
            S->ii[level] = 1;  /* reset to 1 (not 0) */
            level--;
            S->ii[level]++;
        }
        /* Rebuild only from changed level. */
        rebuild_from(S, level);
    }

    printf("\nExhaustive done: %ld iterations, min=%ld max=%ld\n",
           iter, S->min_cand, S->max_cand);
}

/* ------------------------------------------------------------------ */
/* Random-restart search (large n_primes or indefinite run).           */
/* ------------------------------------------------------------------ */
static void search_random(SearchState *S, const char *outfile,
                          double merit, int shift,
                          long max_iter  /* 0 = run forever */) {
    int n = S->n_primes;
    unsigned rng = (unsigned)time(NULL);
    long iter = 0;

    printf("Random search: n_primes=%d interval=%d gap=%d\n",
           n, S->interval, S->gap_size);
    printf("Press Ctrl-C to stop (best solution saved to file on each new min).\n");

    while (!max_iter || iter < max_iter) {

        /* Randomise all offsets, skipping 0 (offset 0 → composite base). */
        for (int i = 0; i < n; i++) {
            rng = rng * 1664525u + 1013904223u;
            int p = PRIMES[i];
            S->ii[i] = 1 + (int)((rng >> 8) % (unsigned)(p - 1));
        }
        rebuild_from(S, 0);
        long cnt = count_candidates(S);
        iter++;

        if (cnt < S->min_cand) {
            S->min_cand = cnt;
            printf("\rmin=%ld  ", cnt);
            for (int k=0;k<n;k++) printf("%d ",S->ii[k]);
            printf("  (iter %ld)\n", iter);
            /* Overwrite file with this new best (single-solution output). */
            write_solution(outfile, S->ii, n, cnt, S->gap_size, merit, shift);
        }
        if (cnt > S->max_cand) S->max_cand = cnt;

        if (iter % 200000 == 0) {
            printf("\r iter=%ld  min=%ld max=%ld      ", iter, S->min_cand, S->max_cand);
            fflush(stdout);
        }
    }
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --ctr-primes N --ctr-merit M [--ctr-bits B]\n"
        "          [--ctr-file FILE] [--ctr-ivs K] [--ctr-exhaust]\n\n"
        "  --ctr-primes N   Number of CRT primes (1..%d).  Primes used: 3,5,7,...\n"
        "  --ctr-merit  M   Target merit (gap = M * (256+bits) * ln2).\n"
        "  --ctr-bits   B   Shift/bits parameter (default: 1024).\n"
        "  --ctr-file   F   Output file (default: crt_exhaust.txt).\n"
        "  --ctr-ivs    K   Save up to K solutions above min (not used here;\n"
        "                   all solutions within min+2 are saved).\n"
        "  --ctr-exhaust    Force exhaustive search even for large n_primes.\n"
        "  --ctr-random     Force random search even for small n_primes.\n"
        "\nAutomatic: exhaustive for n_primes <= %d, random otherwise.\n",
        prog, N_PRIMES_MAX, MAX_EXHAUST_PRIMES);
}

int main(int argc, char *argv[]) {
    int    n_primes  = 0;
    double merit     = 0.0;
    int    bits      = 1024;
    char   outfile[256] = "crt_exhaust.txt";
    int    force_exhaust = 0;
    int    force_random  = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--ctr-primes") && i+1 < argc)
            n_primes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ctr-merit") && i+1 < argc)
            merit = atof(argv[++i]);
        else if (!strcmp(argv[i], "--ctr-bits") && i+1 < argc)
            bits = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ctr-file") && i+1 < argc)
            snprintf(outfile, sizeof(outfile), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--ctr-ivs") && i+1 < argc)
            ++i; /* accepted but ignored; we save all within min+2 */
        else if (!strcmp(argv[i], "--ctr-exhaust"))
            force_exhaust = 1;
        else if (!strcmp(argv[i], "--ctr-random"))
            force_random = 1;
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]); return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (n_primes < 1 || n_primes > N_PRIMES_MAX) {
        fprintf(stderr, "error: --ctr-primes must be 1..%d\n", N_PRIMES_MAX);
        usage(argv[0]); return 1;
    }
    if (merit <= 0.0) {
        fprintf(stderr, "error: --ctr-merit must be > 0\n");
        usage(argv[0]); return 1;
    }

    /* gap_size = ceil(merit * (256 + bits) * ln(2)).
     * 256 = block-hash size in bits; the mined number has roughly
     * (256 + shift) bits, so ln(p) ≈ (256 + shift) × ln(2).  This
     * matches the formula in gen_crt.c (gap_size = ceil(merit*(256+sh)*ln2)). */
    int gap_size = (int)ceil(merit * (256.0 + (double)bits) * log(2.0));
    int interval = gap_size / 2 + 1;  /* bit positions for odd numbers */

    if (interval > MAX_INTERVAL) {
        fprintf(stderr, "error: interval=%d > MAX_INTERVAL=%d. "
                "Increase MAX_INTERVAL and recompile.\n",
                interval, MAX_INTERVAL);
        return 1;
    }

    /* Determine search mode. */
    int do_exhaust = (n_primes <= MAX_EXHAUST_PRIMES) && !force_random;
    if (force_exhaust) do_exhaust = 1;

    /* Compute search space size for informational output. */
    double space = 1.0;
    for (int i = 0; i < n_primes; i++)
        space *= (double)(PRIMES[i] - 1);  /* offset 0 excluded */

    fprintf(stderr, "gen_crt_exhaust\n");
    fprintf(stderr, "  primes    : %d  (", n_primes);
    for (int i = 0; i < n_primes && i < 6; i++)
        fprintf(stderr, "%d%s", PRIMES[i], (i < n_primes-1 && i < 5) ? "," : "");
    if (n_primes > 6) fprintf(stderr, ",...");
    fprintf(stderr, ")\n");
    fprintf(stderr, "  merit     : %.2f\n", merit);
    fprintf(stderr, "  bits      : %d\n", bits);
    fprintf(stderr, "  gap_size  : %d\n", gap_size);
    fprintf(stderr, "  interval  : %d  (bit positions)\n", interval);
    fprintf(stderr, "  search    : %s\n", do_exhaust ? "EXHAUSTIVE" : "RANDOM");
    if (do_exhaust)
        fprintf(stderr, "  space     : %.3g  combinations\n", space);
    fprintf(stderr, "  output    : %s\n", outfile);
    fprintf(stderr, "\n");

    /* Allocate and initialise search state. */
    SearchState *S = (SearchState *)calloc(1, sizeof(SearchState));
    if (!S) { perror("calloc"); return 1; }
    S->n_primes  = n_primes;
    S->interval  = interval;
    S->gap_size  = gap_size;
    S->min_cand  = interval + 1;  /* worse than any real value */
    S->max_cand  = 0;

    if (do_exhaust) {
        search_exhaustive(S, outfile, merit, bits);
    } else {
        search_random(S, outfile, merit, bits, 0);
    }
    free(S);
    return 0;
}
