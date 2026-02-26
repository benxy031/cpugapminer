/*
 * gen_crt -- Generate a CRT (Chinese Remainder Theorem) sieve file
 *
 * Computes all integers in [0, primorial) that are coprime to the
 * primorial of the first N primes, then writes them to a binary file
 * for use by the gap miner (--crt-file option).
 *
 * The miner uses this to replace the small-prime sieve phase with a
 * precomputed template, eliminating strided memory accesses for the
 * first N primes.
 *
 * Usage:
 *   gen_crt --primes 7 --output crt_7.bin
 *   gen_crt --primes 8 --output crt_8.bin
 *
 * Build:
 *   make gen_crt
 *
 * File format (little-endian):
 *   bytes  0- 3:  magic "CRT1"
 *   bytes  4- 7:  n_primes       (uint32_t)
 *   bytes  8-15:  primorial      (uint64_t)
 *   bytes 16-23:  n_candidates   (uint64_t)  -- coprime residues
 *   bytes 24...:  offsets[]      (uint32_t × n_candidates, sorted)
 *                 each offset is an ODD value in [1, primorial) coprime to primorial
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* First 14 primes (primorial of 14 primes = 614889782588491410 > 2^59) */
static const uint64_t PRIMES[] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43
};
#define MAX_PRIMES 14

/* ---- CRT file header (24 bytes) ---- */
struct crt_header {
    char     magic[4];       /* "CRT1" */
    uint32_t n_primes;
    uint64_t primorial;
    uint64_t n_candidates;
};

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  --primes N    Number of primes in the primorial (2..10, default 7)\n"
        "  --output FILE Output file path (default: crt.bin)\n"
        "  --info        Show statistics only, don't write file\n"
        "  --help        Show this help\n"
        "\n"
        "Recommended settings:\n"
        "  N=7  primorial=  510,510   template=32KB (L1)  survivors=18.1%%\n"
        "  N=8  primorial=9,699,690   template=606KB(L2)  survivors=17.1%%\n"
        "  N=9  primorial=223,092,870 template=14MB (L3)  survivors=16.4%%\n"
        "\n"
        "For sieve_size=20M:\n"
        "  N=7: 39 repetitions per window (ideal)\n"
        "  N=8:  2 repetitions per window (OK)\n"
        "  N=9:  0 repetitions -- primorial > sieve_size (not recommended)\n",
        prog);
}

int main(int argc, char **argv) {
    int n_primes = 7;
    const char *output = "crt.bin";
    int info_only = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--primes") && i + 1 < argc)
            n_primes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--output") && i + 1 < argc)
            output = argv[++i];
        else if (!strcmp(argv[i], "--info"))
            info_only = 1;
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]); return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]); return 1;
        }
    }

    if (n_primes < 2 || n_primes > 10) {
        fprintf(stderr, "Error: --primes must be 2..10 (primorial must fit in uint64 and "
                        "template must fit in memory)\n");
        return 1;
    }

    /* ---- Compute primorial ---- */
    uint64_t primorial = 1;
    printf("Primes:");
    for (int i = 0; i < n_primes; i++) {
        printf(" %llu", (unsigned long long)PRIMES[i]);
        primorial *= PRIMES[i];
    }
    printf("\nPrimorial: %llu\n", (unsigned long long)primorial);

    /* Euler totient ratio = product of (1 - 1/p) */
    double surv_ratio = 1.0;
    for (int i = 0; i < n_primes; i++)
        surv_ratio *= (1.0 - 1.0 / (double)PRIMES[i]);
    uint64_t expected = (uint64_t)(surv_ratio * (double)primorial + 0.5);
    printf("Survivor ratio: %.4f%%\n", surv_ratio * 100.0);
    printf("Expected survivors: %llu (Euler totient)\n",
           (unsigned long long)expected);

    /* Template size (odd-only bitmap) */
    size_t tmpl_bits = primorial / 2;
    size_t tmpl_bytes = (tmpl_bits + 7) / 8;
    printf("Odd-only template: %zu bits = %zu bytes", tmpl_bits, tmpl_bytes);
    if (tmpl_bytes < 64 * 1024)
        printf(" (fits in L1 cache)\n");
    else if (tmpl_bytes < 1024 * 1024)
        printf(" (fits in L2 cache)\n");
    else if (tmpl_bytes < 32 * 1024 * 1024)
        printf(" (fits in L3 cache)\n");
    else
        printf(" (WARNING: larger than typical L3)\n");

    /* Sieve window coverage */
    printf("Repetitions per 20M sieve window: %llu\n",
           (unsigned long long)(20000000ULL / primorial));

    /* ---- Sieve: mark composites ---- */
    printf("\nSieving %llu residues...\n", (unsigned long long)primorial);
    clock_t t0 = clock();

    /* Byte array: composite[x] = 1 means x shares a factor with primorial */
    uint8_t *composite = (uint8_t *)calloc(primorial, 1);
    if (!composite) {
        fprintf(stderr, "Error: cannot allocate %llu bytes for sieve\n",
                (unsigned long long)primorial);
        return 1;
    }

    composite[0] = 1; /* 0 is divisible by everything */
    for (int i = 0; i < n_primes; i++) {
        uint64_t p = PRIMES[i];
        for (uint64_t j = p; j < primorial; j += p)
            composite[j] = 1;
    }

    /* ---- Collect ODD coprime residues ---- */
    /* Count first */
    uint64_t n_candidates = 0;
    for (uint64_t x = 1; x < primorial; x += 2)
        if (!composite[x]) n_candidates++;

    printf("Odd coprime residues: %llu (of %llu odd values = %.2f%%)\n",
           (unsigned long long)n_candidates,
           (unsigned long long)(primorial / 2),
           100.0 * (double)n_candidates / (double)(primorial / 2));

    /* Collect into array */
    uint32_t *offsets = (uint32_t *)malloc(n_candidates * sizeof(uint32_t));
    if (!offsets) {
        fprintf(stderr, "Error: cannot allocate offset array\n");
        free(composite); return 1;
    }

    uint64_t k = 0;
    for (uint64_t x = 1; x < primorial; x += 2)
        if (!composite[x]) offsets[k++] = (uint32_t)x;

    free(composite);
    clock_t t1 = clock();
    printf("Sieve completed in %.2f s\n",
           (double)(t1 - t0) / CLOCKS_PER_SEC);

    /* ---- Gap analysis ---- */
    printf("\n--- Gap analysis (between consecutive coprime residues) ---\n");

    uint64_t max_gap = 0, max_gap_start = 0;
    double sum_gap = 0;
    uint64_t min_gap = primorial;

    /* Gaps between consecutive odd coprime residues */
    for (uint64_t i = 0; i + 1 < n_candidates; i++) {
        uint64_t gap = offsets[i + 1] - offsets[i];
        sum_gap += gap;
        if (gap > max_gap) { max_gap = gap; max_gap_start = offsets[i]; }
        if (gap < min_gap) min_gap = gap;
    }
    /* Wrap-around gap */
    uint64_t wrap = (primorial - offsets[n_candidates - 1]) + offsets[0];
    if (wrap > max_gap) { max_gap = wrap; max_gap_start = offsets[n_candidates - 1]; }
    if (wrap < min_gap) min_gap = wrap;

    printf("Minimum gap: %llu\n", (unsigned long long)min_gap);
    printf("Average gap: %.2f\n", (double)primorial / (double)n_candidates);
    printf("Maximum gap (Jacobsthal): %llu (starts at offset %llu)\n",
           (unsigned long long)max_gap, (unsigned long long)max_gap_start);

    /* Gap distribution histogram */
    uint64_t gap_bins[] = {2, 4, 6, 10, 20, 30, 50, 100, 200, 500, 0};
    printf("\nGap size distribution:\n");
    for (int b = 0; gap_bins[b]; b++) {
        uint64_t lo = (b == 0) ? 0 : gap_bins[b - 1];
        uint64_t hi = gap_bins[b];
        uint64_t cnt = 0;
        for (uint64_t i = 0; i + 1 < n_candidates; i++) {
            uint64_t g = offsets[i + 1] - offsets[i];
            if (g >= lo && g < hi) cnt++;
        }
        if (cnt > 0)
            printf("  [%3llu, %3llu):  %llu gaps (%.1f%%)\n",
                   (unsigned long long)lo, (unsigned long long)hi,
                   (unsigned long long)cnt,
                   100.0 * (double)cnt / (double)(n_candidates - 1));
    }
    {
        uint64_t lo = gap_bins[0];
        for (int b = 0; gap_bins[b]; b++) lo = gap_bins[b];
        uint64_t cnt = 0;
        for (uint64_t i = 0; i + 1 < n_candidates; i++) {
            uint64_t g = offsets[i + 1] - offsets[i];
            if (g >= lo) cnt++;
        }
        if (cnt > 0)
            printf("  [%3llu, inf):  %llu gaps (%.1f%%)\n",
                   (unsigned long long)lo, (unsigned long long)cnt,
                   100.0 * (double)cnt / (double)(n_candidates - 1));
    }

    /* ---- Recommendations ---- */
    printf("\n--- Mining recommendations ---\n");
    printf("For shift=37, target≈20.89:\n");
    double logbase37 = (256.0 + 37.0) * log(2.0);
    uint64_t needed37 = (uint64_t)(20.89 * logbase37);
    printf("  Needed gap for merit 20.89: %llu\n", (unsigned long long)needed37);
    printf("  Max primorial gap (Jacobsthal): %llu (%.1f%% of needed)\n",
           (unsigned long long)max_gap,
           100.0 * (double)max_gap / (double)needed37);
    printf("  CRT provides a \"head start\" of up to %llu composites\n",
           (unsigned long long)max_gap);
    printf("  Primary benefit: replaces small-prime sieve with fast template tiling\n");

    /* ---- Write file ---- */
    if (!info_only) {
        FILE *fp = fopen(output, "wb");
        if (!fp) {
            perror(output);
            free(offsets); return 1;
        }

        struct crt_header hdr;
        memcpy(hdr.magic, "CRT1", 4);
        hdr.n_primes    = (uint32_t)n_primes;
        hdr.primorial   = primorial;
        hdr.n_candidates = n_candidates;

        fwrite(&hdr, sizeof(hdr), 1, fp);
        fwrite(offsets, sizeof(uint32_t), n_candidates, fp);
        fclose(fp);

        size_t file_size = sizeof(hdr) + n_candidates * sizeof(uint32_t);
        printf("\nWrote %s\n", output);
        printf("  Header: %zu bytes\n", sizeof(hdr));
        printf("  Offsets: %llu × 4 bytes = %llu bytes\n",
               (unsigned long long)n_candidates,
               (unsigned long long)(n_candidates * sizeof(uint32_t)));
        printf("  Total: %zu bytes (%.1f KB)\n", file_size,
               (double)file_size / 1024.0);
    }

    free(offsets);
    printf("\nDone.\n");
    return 0;
}
