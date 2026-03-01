#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "compat_win32.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <gmp.h>
#ifndef M_LN2
#define M_LN2 0.693147180559945309417232121458
#endif
/* Forward declarations for 256-bit arithmetic helpers defined later */
static void     hash_to_256(const char *s, int is_hex, uint8_t out[32]);
static uint64_t uint256_mod_small(const uint8_t h[32], int shift, uint64_t p);
static double   uint256_log_approx(const uint8_t h[32], int shift);
static void     set_base_bn(const uint8_t h256[32], int shift);
static int      bn_candidate_is_prime(uint64_t offset);
#ifdef WITH_RPC
static int      build_mining_pass(const char *url, const char *user, const char *pass, int shift);
static int      assemble_mining_block(uint64_t nadd_val, char out_hex[16384]);
extern int      rpc_getwork_data(const char *url, const char *user, const char *pass, char data_out[161], uint64_t *ndiff_out);
#endif
#ifdef WITH_RPC
#include <curl/curl.h>
#include "stratum.h"
static stratum_ctx *g_stratum = NULL;   /* non-NULL when mining via stratum pool */
#endif
#define GPU_MAX_DEVS  8
static int             g_gpu_batch_size = 0;  /* --gpu-batch; 0 = use default (4096) */
#ifdef WITH_CUDA
#include "gpu_fermat.h"
#define GPU_MAX_BATCH (1 << 20)   /* 1M candidates per batch */
static gpu_fermat_ctx *g_gpu_ctx[GPU_MAX_DEVS];
static int             g_gpu_count = 0;
#endif

// logging helper (used in both RPC and non-RPC builds)
static FILE *log_fp = NULL;
static void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    if (log_fp) {
        va_list ap2;
        va_start(ap2, fmt);
        vfprintf(log_fp, fmt, ap2);
        fflush(log_fp);
        va_end(ap2);
    }
    fflush(stdout);
    va_end(ap);
}
/* write only to the log file (silent on console); no-op when no log file is open */
static void log_file_only(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void log_file_only(const char *fmt, ...) {
    if (!log_fp) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_fp, fmt, ap);
    fflush(log_fp);
    va_end(ap);
}
#include <openssl/hmac.h>
#include <pthread.h>
#ifndef _WIN32
#include <sys/time.h>
#endif

#ifdef WITH_RPC
// submit queue and RPC globals
#define SUBMIT_QUEUE_MAX 32

struct submit_job {
    char url[256];
    char user[128];
    char pass[128];
    char method[64];
    char hex[16384];   /* block hex, hopefully large enough for most submissions */
    char signature[128]; /* optional signature string */
    int retries;
};

static pthread_mutex_t sq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sq_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t sq_empty_cond = PTHREAD_COND_INITIALIZER; /* fired when queue drains to 0 */
static struct submit_job submit_queue[SUBMIT_QUEUE_MAX];
static int sq_head = 0, sq_tail = 0, sq_count = 0;
static int sq_running = 0;
static pthread_t sq_thread;

/* rpc timing/retry globals */
static uint64_t last_submit_ms = 0;
static int rpc_rate_ms = 0;
static int rpc_default_retries = 3;
#endif

// Default sieve prime COUNT matching GapMiner (--sieve-primes N = N primes).
// The VALUE limit is computed from the count via PNT upper bound after arg parsing.
#define DEFAULT_SIEVE_PRIME_COUNT 900000
static uint64_t cli_sieve_prime_limit = 0;   /* computed from count; 0 = not yet set */
static uint64_t cli_sieve_prime_count = DEFAULT_SIEVE_PRIME_COUNT;

// cache of small primes used for segmented sieving (allocated once)
static uint64_t *small_primes_cache = NULL;
static size_t small_primes_count = 0;
static size_t small_primes_cap = 0;
static pthread_once_t small_primes_once = PTHREAD_ONCE_INIT;

/* Trial-division pre-filter: primes just above the sieve prime limit.
   The sieve already eliminates factors <= cli_sieve_prime_limit; these extra
   primes catch remaining small-factor composites cheaply, before the expensive
   Miller-Rabin test.  Cost per candidate: ~TD_EXTRA_CNT × 5 ns.
   NOTE: With GMP's fast mpz_probab_prime_p (~7 µs for 284-bit), TD overhead
   exceeds the savings.  Benchmarked: TD=0 → 151K tests/s, TD=1024 → 113K/s.
   Set to 0 to disable; increase only if MR cost rises (e.g. more rounds). */
#define TD_EXTRA_CNT 0
static uint32_t td_extra_primes[TD_EXTRA_CNT];
static int      td_extra_count = 0;
static pthread_once_t td_extra_once = PTHREAD_ONCE_INIT;
/* forward declaration — populate_small_primes_cache defined below */
static void populate_small_primes_cache(void);

/* Populate td_extra_primes[] with the first TD_EXTRA_CNT primes above
   the sieve prime limit.  Called once (via pthread_once); requires
   small_primes_cache to already be populated. */
static void populate_td_extra_primes(void) {
    /* Ensure the main sieve cache is ready. */
    pthread_once(&small_primes_once, populate_small_primes_cache);
    if (!small_primes_cache) return;

    /* Segmented sieve over [lo, hi) to find primes just above the sieve limit. */
    uint64_t lo = (uint64_t)cli_sieve_prime_limit + 1;
    if ((lo & 1) == 0) lo++; /* start on odd */
    /* A window of 200 000 odd numbers (~11 000 primes) is more than enough. */
    uint64_t hi = lo + 400000ULL; /* covers ~22 000 primes */
    size_t   sz = (hi - lo) / 2 + 1;
    uint8_t *sieve = (uint8_t *)calloc(sz, 1);
    if (!sieve) return;

    for (size_t idx = 1; idx < small_primes_count; idx++) {
        uint64_t p = small_primes_cache[idx];
        if (p * p > hi) break;
        /* first odd multiple of p >= lo */
        uint64_t rem = lo % p;
        uint64_t start = rem ? lo + (p - rem) : lo;
        if ((start & 1) == 0) start += p;
        for (uint64_t j = start; j < hi; j += 2 * p)
            sieve[(j - lo) / 2] = 1;
    }
    td_extra_count = 0;
    for (uint64_t n = lo; n < hi && td_extra_count < TD_EXTRA_CNT; n += 2)
        if (!sieve[(n - lo) / 2])
            td_extra_primes[td_extra_count++] = (uint32_t)n;
    free(sieve);
}

static void populate_small_primes_cache(void) {
    /* Generate all primes up to cli_sieve_prime_limit (already set from
       COUNT via PNT upper bound before this function is called). */
    size_t maxp = (size_t)cli_sieve_prime_limit + 1;
    if (maxp < 100) maxp = 100;  /* sanity floor */
    unsigned char *is_small = calloc(maxp, 1);
    if (!is_small) { free(is_small); return; }
    small_primes_cap = 80000;
    small_primes_cache = malloc(sizeof(uint64_t) * small_primes_cap);
    if (!small_primes_cache) { free(is_small); small_primes_cache = NULL; small_primes_cap = 0; return; }
    small_primes_count = 0;
    /* include 2 so the cache can be used for primality tests */
    if (small_primes_count < small_primes_cap)
        small_primes_cache[small_primes_count++] = 2;
    for (uint64_t i = 3; i < maxp; i += 2) {
        if (!is_small[i]) {
            if (small_primes_count + 1 > small_primes_cap) {
                size_t ncap = small_primes_cap * 2;
                uint64_t *tmp = realloc(small_primes_cache, ncap * sizeof(uint64_t));
                if (tmp) { small_primes_cache = tmp; small_primes_cap = ncap; }
                else { break; }
            }
            small_primes_cache[small_primes_count++] = i;
            if (i * i < maxp) {
                for (uint64_t j = i * i; j < maxp; j += 2 * i) is_small[j] = 1;
            }
        }
    }
    free(is_small);
}

// helper returning current time in milliseconds since epoch
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* mining/statistics globals */
static volatile uint64_t stats_sieved = 0;        /* total numbers fed through sieve */
static volatile uint64_t stats_tested = 0;         /* total primality tests run */
static volatile uint64_t stats_gaps = 0;           /* qualifying gaps found */
static volatile uint64_t stats_pairs = 0;          /* total consecutive prime pairs scanned */
static volatile uint64_t stats_blocks = 0;         /* blocks built */
static volatile uint64_t stats_submits = 0;        /* shares submitted */
static volatile uint64_t stats_success = 0;        /* shares accepted */
static volatile uint64_t stats_crt_windows = 0;    /* CRT windows fully tested */
static volatile uint64_t stats_primes_found = 0;   /* primes found (for primes/window) */
static uint64_t stats_start_ms = 0;                /* time mining started */
static volatile double   g_mining_target = 20.0;   /* merit threshold for block-prob display */
static volatile double   stats_best_merit = 0.0;   /* best gap merit seen this session */
static volatile uint64_t stats_best_gap   = 0;     /* gap size for best merit */
static volatile uint64_t stats_gpu_flushes = 0;    /* GPU accumulator flushes */
static volatile uint64_t stats_gpu_batched = 0;    /* total candidates sent in GPU flushes */

/* ── Rolling rate window for responsive est ──
   Store snapshots every STATS_INTERVAL_MS; use the oldest snapshot
   to compute a sliding-window rate that responds within ~30s. */
#define RATE_RING_SLOTS 6           /* 6 × 5s = 30s sliding window */
static struct { uint64_t pairs; uint64_t ms; } rate_ring[RATE_RING_SLOTS];
static int rate_ring_idx = 0;
static int rate_ring_full = 0;

/* ══════════════════════════════════════════════════════════════════════
   CRT Producer-Consumer Heap  (gaplist)
   ══════════════════════════════════════════════════════════════════════
   Sieve threads produce CRT windows, push to a min-heap (keyed by
   survivor count — fewer survivors = larger expected gaps = higher
   priority).  Fermat threads pop the best windows and test them.

   The heap is bounded: when full, new items replace the worst (most
   survivors) entry if better, otherwise are discarded.  This keeps
   memory bounded while continuously improving heap quality.
   ══════════════════════════════════════════════════════════════════════ */

struct crt_work_item {
    mpz_t    base;        /* sieve base for Fermat testing (tls_base_mpz snapshot)  */
    mpz_t    nAdd;        /* nAdd for block assembly                                */
    uint64_t *survivors;  /* heap-allocated copy of sieve survivor offsets           */
    size_t   surv_cnt;    /* number of survivors (heap key: lower = better)          */
    uint32_t nonce;       /* nonce for block assembly                                */
    int      cand_odd;    /* whether CRT candidate was odd (for nAdd adjustment)    */
    double   logbase;     /* log(base) for merit calculation                         */
    uint64_t generation;  /* pass generation — discard stale items                   */
};

#define CRT_HEAP_CAP 4096
static struct crt_work_item *crt_heap[CRT_HEAP_CAP]; /* min-heap by surv_cnt */
static size_t          crt_heap_size = 0;
static pthread_mutex_t crt_heap_mtx  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  crt_heap_cv   = PTHREAD_COND_INITIALIZER;
static volatile uint64_t crt_heap_gen   = 0;  /* incremented on template change */
static volatile int    crt_fermat_threads = 0; /* number of fermat threads (0 = monolithic) */
static int             crt_fermat_explicit = 0; /* 1 if user passed --fermat-threads */
static volatile int    crt_heap_shutdown = 0;    /* 1 = all threads should exit */

/* Allocate a work item with mpz_t's initialized */
static struct crt_work_item *crt_work_alloc(void) {
    struct crt_work_item *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    mpz_init2(w->base, 1024);
    mpz_init2(w->nAdd, 1024);
    return w;
}

/* Free a work item */
static void crt_work_free(struct crt_work_item *w) {
    if (!w) return;
    mpz_clear(w->base);
    mpz_clear(w->nAdd);
    free(w->survivors);
    free(w);
}

/* ── Min-heap operations (by surv_cnt) ── */
static void crt_heap_sift_up(size_t i) {
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (crt_heap[parent]->surv_cnt <= crt_heap[i]->surv_cnt) break;
        struct crt_work_item *tmp = crt_heap[parent];
        crt_heap[parent] = crt_heap[i];
        crt_heap[i] = tmp;
        i = parent;
    }
}

static void crt_heap_sift_down(size_t i, size_t n) {
    while (1) {
        size_t smallest = i;
        size_t left = 2 * i + 1, right = 2 * i + 2;
        if (left < n && crt_heap[left]->surv_cnt < crt_heap[smallest]->surv_cnt)
            smallest = left;
        if (right < n && crt_heap[right]->surv_cnt < crt_heap[smallest]->surv_cnt)
            smallest = right;
        if (smallest == i) break;
        struct crt_work_item *tmp = crt_heap[smallest];
        crt_heap[smallest] = crt_heap[i];
        crt_heap[i] = tmp;
        i = smallest;
    }
}

/* Push a work item into the heap.
   If heap is full and item is better than the worst, replace worst.
   Otherwise discard the item.  Returns 1 if item was kept, 0 if discarded. */
static int crt_heap_push(struct crt_work_item *w) {
    pthread_mutex_lock(&crt_heap_mtx);
    if (crt_heap_size < CRT_HEAP_CAP) {
        /* Room available: insert */
        crt_heap[crt_heap_size] = w;
        crt_heap_sift_up(crt_heap_size);
        crt_heap_size++;
        pthread_cond_signal(&crt_heap_cv);
        pthread_mutex_unlock(&crt_heap_mtx);
        return 1;
    }
    /* Heap full: find the maximum element (worst) among leaves */
    size_t first_leaf = crt_heap_size / 2;
    size_t max_idx = first_leaf;
    for (size_t i = first_leaf + 1; i < crt_heap_size; i++) {
        if (crt_heap[i]->surv_cnt > crt_heap[max_idx]->surv_cnt)
            max_idx = i;
    }
    if (w->surv_cnt < crt_heap[max_idx]->surv_cnt) {
        /* New item is better — replace worst */
        crt_work_free(crt_heap[max_idx]);
        crt_heap[max_idx] = w;
        /* Restore heap: might need sift-up or sift-down */
        crt_heap_sift_up(max_idx);
        crt_heap_sift_down(max_idx, crt_heap_size);
        pthread_cond_signal(&crt_heap_cv);
        pthread_mutex_unlock(&crt_heap_mtx);
        return 1;
    }
    /* New item is worse — discard */
    pthread_mutex_unlock(&crt_heap_mtx);
    crt_work_free(w);
    return 0;
}

/* Pop the best (fewest survivors) work item from the heap.
   Blocks until an item is available or g_abort_pass is set.
   Returns NULL if g_abort_pass is set (caller should exit). */
static struct crt_work_item *crt_heap_pop(void) {
    pthread_mutex_lock(&crt_heap_mtx);
    while (crt_heap_size == 0 && !crt_heap_shutdown) {
        /* Wait with timeout so we can check shutdown periodically */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000L; /* 100ms */
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&crt_heap_cv, &crt_heap_mtx, &ts);
    }
    if (crt_heap_size == 0 || crt_heap_shutdown) {
        pthread_mutex_unlock(&crt_heap_mtx);
        return NULL;
    }
    /* Extract min (root) */
    struct crt_work_item *best = crt_heap[0];
    crt_heap_size--;
    if (crt_heap_size > 0) {
        crt_heap[0] = crt_heap[crt_heap_size];
        crt_heap_sift_down(0, crt_heap_size);
    }
    pthread_mutex_unlock(&crt_heap_mtx);
    return best;
}

/* Flush all items from the heap (called on template change) */
static void crt_heap_flush(void) {
    pthread_mutex_lock(&crt_heap_mtx);
    for (size_t i = 0; i < crt_heap_size; i++)
        crt_work_free(crt_heap[i]);
    crt_heap_size = 0;
    pthread_cond_broadcast(&crt_heap_cv); /* wake waiting fermat threads */
    pthread_mutex_unlock(&crt_heap_mtx);
}

/* Get current heap size (for stats display) */
static size_t crt_heap_count(void) {
    /* No lock needed — just an approximate display value */
    return crt_heap_size;
}

/* shared current-work state so any thread can detect a new block */
static char     g_prevhash[65]  = {0};
static pthread_mutex_t g_work_lock = PTHREAD_MUTEX_INITIALIZER;
/* set to 1 by thread-0 when a new block is detected; all workers break their
   adder loop and the main thread restarts the pass with fresh work */
static volatile int g_abort_pass = 0;

#ifdef WITH_RPC
/* Pre-built mining pass: set once per getwork fetch, read-only during a pass.
   The prime base h256 = SHA256d(hdr80 + nNonce, 84 bytes) byte-reversed.
   gapcoind saves the complete block (with wallet coinbase TX) in
   mapNewBlock[hashMerkleRoot] when getwork is called.  Submissions via
   getwork[data] allow gapcoind to look up that saved block and validate PoW. */
struct pass_state {
    uint8_t  h256[32];    /* prime base: SHA256d(hdr80+nNonce) byte-reversed   */
    uint8_t  hdr80[80];   /* 80-byte header from getwork (no nNonce field)     */
    uint32_t nonce;       /* nNonce value making sha_raw[31] >= 0x80           */
    uint16_t nshift;
    uint64_t ndiff;       /* nDifficulty from getwork response                 */
    char     prevhex[65]; /* previous block hash for change detection          */
    uint64_t height;      /* reserved (not available from getwork header)      */
};
static struct pass_state g_pass = {0};
#endif

/* by default the miner continues searching even after a valid block is
   submitted.  Historically `--keep-going` enabled this behavior, but it is now
   the default; use --stop-after-block to request the old behaviour. */
static volatile int keep_going = 1;    /* default == continue mining */
static volatile int debug_force = 0;    /* if nonzero, pretend any header meets target */
/* if nonzero the miner uses a lightweight Fermat test (bases 2 & 3) instead of
   the full deterministic Miller‑Rabin.  This is faster but may misclassify a
   tiny number of composites as primes; use with --fast-fermat. */
static volatile int use_fast_fermat = 0;
static volatile int no_primality = 0;   /* skip all probable‑prime filtering */
static volatile int selftest = 0;        /* run a quick internal test then exit */

/* Sampling stride for two-phase gap scanning.  In phase 1 only every Kth
   sieve-survivor is Fermat-tested ("sampled"); candidate gap regions (where
   consecutive sampled primes are ≥ target apart) are then fully verified
   in phase 2.  K=8 gives ~5× fewer total Fermat tests per window.
   K=1 disables sampling (test all survivors — the old behaviour).          */
#define DEFAULT_SAMPLE_STRIDE 8
static int cli_sample_stride = DEFAULT_SAMPLE_STRIDE;

/* ── CRT (Chinese Remainder Theorem) sieve support ──
   Supports two formats:
     1. Legacy binary (CRT1 magic) — template bitmap tiling for ≤10 primes
     2. Text format (gen_crt --calc-ctr) — optimised gap-solver offsets

   Mode 1 (template): tiles a precomputed composite bitmap into the sieve.
   Mode 2 (gap-solver): stores prime:offset pairs for CRT-aligned mining.  */
#define CRT_MODE_NONE     0   /* no CRT file loaded                     */
#define CRT_MODE_TEMPLATE 1   /* legacy binary, small primorial          */
#define CRT_MODE_SOLVER   2   /* text format, optimised gap offsets      */
static int            g_crt_mode        = CRT_MODE_NONE;

/* Shared CRT state (both modes) */
static int            g_crt_n_primes    = 0;      /* primes covered by CRT */
static uint64_t       g_crt_max_prime   = 0;      /* largest prime in CRT set */
static const char    *cli_crt_file      = NULL;

/* Mode 1 (template) state */
static uint8_t       *g_crt_template    = NULL;   /* odd-only composite bitmap */
static size_t         g_crt_period      = 0;      /* primorial/2 (template bits) */
static uint64_t       g_crt_primorial   = 0;
static size_t         g_crt_tmpl_bytes  = 0;      /* (period+7)/8 */

/* Mode 2 (gap-solver) state — from text CRT file */
static int           *g_crt_offsets     = NULL;    /* offset[i] for prime i     */
static int           *g_crt_prime_list  = NULL;    /* prime values from file    */
static int            g_crt_gap_target  = 0;       /* target gap size           */
static int            g_crt_n_candidates= 0;       /* uncovered positions       */
static double         g_crt_merit       = 0.0;     /* target merit from file    */
static int            g_crt_shift       = 0;       /* shift from CRT file       */
static mpz_t          g_crt_primorial_mpz;          /* GMP primorial (any size)  */
static int            g_crt_primorial_mpz_init = 0; /* 1 once mpz_init'd         */

/* Per-thread CRT base residue (base mod primorial), set in set_base_bn(). */
static __thread uint64_t tls_crt_base_residue = 0;

/* Load a legacy binary CRT file (CRT1 format, ≤10 primes).
   File format: 4-byte magic "CRT1", uint32 n_primes, uint64 primorial,
   uint64 n_candidates, then n_candidates × uint32 sorted odd offsets.      */
static int load_crt_binary_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { log_msg("CRT: cannot open %s\n", path); return 0; }

    struct { char magic[4]; uint32_t np; uint64_t prim; uint64_t ncand; } hdr;
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1 ||
        memcmp(hdr.magic, "CRT1", 4) != 0) {
        log_msg("CRT: invalid header in %s\n", path);
        fclose(fp); return 0;
    }
    if (hdr.prim == 0 || hdr.ncand == 0 || hdr.prim > 2000000000ULL) {
        log_msg("CRT: primorial %llu out of range\n",
                (unsigned long long)hdr.prim);
        fclose(fp); return 0;
    }

    uint32_t *offsets = (uint32_t *)malloc(hdr.ncand * sizeof(uint32_t));
    if (!offsets) { fclose(fp); return 0; }
    if (fread(offsets, sizeof(uint32_t), hdr.ncand, fp) != hdr.ncand) {
        log_msg("CRT: truncated file %s\n", path);
        free(offsets); fclose(fp); return 0;
    }
    fclose(fp);

    /* Build odd-only composite bitmap: bit j = 1 means (2j+1) is NOT
       coprime to primorial → composite.  Start all-1 then clear coprime. */
    g_crt_primorial  = hdr.prim;
    g_crt_n_primes   = (int)hdr.np;
    g_crt_period     = (size_t)(hdr.prim / 2);
    g_crt_tmpl_bytes = (g_crt_period + 7) / 8;
    g_crt_template   = (uint8_t *)malloc(g_crt_tmpl_bytes);
    if (!g_crt_template) {
        free(offsets); g_crt_primorial = 0; return 0;
    }
    memset(g_crt_template, 0xFF, g_crt_tmpl_bytes);

    for (uint64_t i = 0; i < hdr.ncand; i++) {
        uint32_t v = offsets[i];
        if (v < 1 || !(v & 1)) continue;
        size_t bit = (v - 1) / 2;
        if (bit < g_crt_period)
            g_crt_template[bit / 8] &= ~(1u << (bit & 7));
    }
    size_t tail_bits = g_crt_tmpl_bytes * 8 - g_crt_period;
    if (tail_bits > 0) {
        size_t last = g_crt_period;
        for (size_t b = 0; b < tail_bits; b++)
            g_crt_template[(last + b) / 8] |= (1u << ((last + b) & 7));
    }
    free(offsets);

    /* Determine the largest prime covered by CRT (the Nth prime). */
    {
        static const uint64_t first_primes[] =
            {2,3,5,7,11,13,17,19,23,29,31,37,41,43};
        g_crt_max_prime = (g_crt_n_primes > 0 &&
                           g_crt_n_primes <= 14)
                        ? first_primes[g_crt_n_primes - 1] : 0;
    }
    g_crt_mode = CRT_MODE_TEMPLATE;

    log_msg("CRT: loaded %s  (template mode)\n"
            "  primes=%d (up to %llu)  primorial=%llu  "
            "candidates=%llu  template=%zu bytes\n",
            path, g_crt_n_primes,
            (unsigned long long)g_crt_max_prime,
            (unsigned long long)g_crt_primorial,
            (unsigned long long)hdr.ncand,
            g_crt_tmpl_bytes);
    return 1;
}

/* Load a text CRT file (generated by gen_crt --calc-ctr).
   Format:
     # comment lines
     n_primes N
     merit M
     shift S
     gap_target G
     n_candidates C
     prime1 offset1
     prime2 offset2
     ...                                                                    */
static int load_crt_text_file(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) { log_msg("CRT: cannot open %s\n", path); return 0; }

    int n_primes = 0, gap_target = 0, n_cand = 0, shift = 0;
    double merit = 0.0;
    int primes_cap = 0;
    int *prime_list = NULL, *offset_list = NULL;
    int pair_count = 0;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        /* skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        /* try key-value header lines first */
        if (sscanf(line, "n_primes %d", &n_primes) == 1) continue;
        if (sscanf(line, "merit %lf", &merit) == 1) continue;
        if (sscanf(line, "shift %d", &shift) == 1) continue;
        if (sscanf(line, "gap_target %d", &gap_target) == 1) continue;
        if (sscanf(line, "n_candidates %d", &n_cand) == 1) continue;

        /* otherwise: prime offset pair */
        int p = 0, o = 0;
        if (sscanf(line, "%d %d", &p, &o) == 2 && p >= 2) {
            if (pair_count >= primes_cap) {
                primes_cap = primes_cap ? primes_cap * 2 : 64;
                prime_list  = (int *)realloc(prime_list,
                                             (size_t)primes_cap * sizeof(int));
                offset_list = (int *)realloc(offset_list,
                                             (size_t)primes_cap * sizeof(int));
                if (!prime_list || !offset_list) {
                    free(prime_list); free(offset_list);
                    fclose(fp); return 0;
                }
            }
            prime_list[pair_count]  = p;
            offset_list[pair_count] = o;
            pair_count++;
        }
    }
    fclose(fp);

    if (pair_count == 0 || pair_count != n_primes) {
        log_msg("CRT: text file %s: expected %d primes, found %d pairs\n",
                path, n_primes, pair_count);
        if (pair_count == 0) { free(prime_list); free(offset_list); return 0; }
        n_primes = pair_count;
    }

    /* store globals */
    g_crt_n_primes    = n_primes;
    /* Compute primorial = product of CRT primes with offset > 0.
       Primes with offset=0 make the candidate divisible by that prime
       (always composite), so they are excluded from the CRT system. */
    int skip_zero = 0;
    for (int i = 0; i < n_primes; i++)
        if (offset_list[i] == 0) skip_zero++;
    if (skip_zero > 0)
        log_msg("CRT: warning: %d prime(s) have offset=0 (candidate always "
                "composite) — skipping them in CRT\n", skip_zero);
    if (!g_crt_primorial_mpz_init) {
        mpz_init(g_crt_primorial_mpz);
        g_crt_primorial_mpz_init = 1;
    }
    mpz_set_ui(g_crt_primorial_mpz, 1);
    for (int i = 0; i < n_primes; i++) {
        if (offset_list[i] == 0) continue;  /* skip offset=0 primes */
        mpz_mul_ui(g_crt_primorial_mpz, g_crt_primorial_mpz,
                   (unsigned long)prime_list[i]);
    }

    g_crt_prime_list  = prime_list;
    g_crt_offsets     = offset_list;
    g_crt_gap_target  = gap_target;
    g_crt_n_candidates= n_cand;
    g_crt_merit       = merit;
    g_crt_shift       = shift;
    g_crt_max_prime   = (uint64_t)prime_list[n_primes - 1];
    g_crt_primorial   = 0;  /* only used for CRT_MODE_TEMPLATE */
    g_crt_mode        = CRT_MODE_SOLVER;

    double prim_log2 = (double)mpz_sizeinbase(g_crt_primorial_mpz, 2);
    log_msg("CRT: loaded %s  (gap-solver mode)\n"
            "  primes=%d (2..%d)  shift=%d  merit=%.2f\n"
            "  gap_target=%d  n_candidates=%d  (%.1f%% uncovered)\n"
            "  primorial ~2^%.0f  ctr-bits=%d\n",
            path, g_crt_n_primes, (int)g_crt_max_prime,
            g_crt_shift, g_crt_merit,
            g_crt_gap_target, g_crt_n_candidates,
            gap_target > 0 ? 100.0 * (double)n_cand / (double)gap_target : 0,
            prim_log2, shift - (int)prim_log2);
    return 1;
}

/* Auto-detect CRT file format and load accordingly. */
static int load_crt_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { log_msg("CRT: cannot open %s\n", path); return 0; }
    char magic[4] = {0};
    size_t rd = fread(magic, 1, 4, fp);
    fclose(fp);
    if (rd >= 4 && memcmp(magic, "CRT1", 4) == 0)
        return load_crt_binary_file(path);
    else
        return load_crt_text_file(path);
}

/* Tile the CRT template into the sieve bitmap with the correct rotation.
   start_bit is the template bit index corresponding to sieve position 0.
   seg_size  is the number of odd positions in the sieve window.

   The template period (g_crt_period = primorial/2) is typically NOT a
   multiple of 8, so byte-level memcpy tiling would drift by
   (g_crt_tmpl_bytes*8 - g_crt_period) bits per tile.
   Instead, we use a simple incrementing-counter approach that wraps at
   the exact bit period.  Cost: ~10M iterations for sieve_size=20M,
   <10ms — negligible vs Fermat testing at large shifts. */
static void tile_crt_template(uint8_t *sieve, size_t sieve_bytes,
                              size_t seg_size, size_t start_bit) {
    memset(sieve, 0, sieve_bytes);
    size_t t = start_bit % g_crt_period;
    for (size_t k = 0; k < seg_size; k++) {
        if (g_crt_template[t >> 3] & (1u << (t & 7)))
            sieve[k >> 3] |= (1u << (k & 7));
        if (++t >= g_crt_period) t = 0;
    }
}

/* Comparator for qsort of uint64_t arrays (fallback sort path). */
static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static void format_est(char *buf, size_t sz, double est_sec) {
    if (est_sec < 10.0)
        snprintf(buf, sz, "%.1fs", est_sec);
    else if (est_sec < 60.0)
        snprintf(buf, sz, "%.0fs", est_sec);
    else if (est_sec < 3600.0)
        snprintf(buf, sz, "%.1fm", est_sec / 60.0);
    else if (est_sec < 86400.0)
        snprintf(buf, sz, "%.1fh", est_sec / 3600.0);
    else
        snprintf(buf, sz, "%.1fd", est_sec / 86400.0);
}

static void print_stats(void) {
    uint64_t now = now_ms();
    double elapsed = stats_start_ms ? (double)(now - stats_start_ms) / 1000.0 : 0.0;
    double sieve_rate  = (elapsed > 0.001) ? (double)stats_sieved  / elapsed : 0.0;
    double test_rate   = (elapsed > 0.001) ? (double)stats_tested  / elapsed : 0.0;
    double gap_rate    = (elapsed > 0.001) ? (double)stats_gaps    / elapsed : 0.0;

    /* ── Compute pairs/s using 30-second sliding window ──
       Uses a ring buffer of snapshots.  The rolling rate responds
       within ~30s to throughput changes (template switch, thread
       ramp-up, load changes).  Falls back to cumulative rate if
       the ring isn't full yet (first 30s of mining). */
    int oldest = rate_ring_full ? rate_ring_idx : 0;
    uint64_t old_pairs = rate_ring[oldest].pairs;
    uint64_t old_ms    = rate_ring[oldest].ms;
    double   window_dt = (old_ms > 0 && now > old_ms)
                         ? (double)(now - old_ms) / 1000.0 : 0.0;
    double   window_dp = (double)(stats_pairs - old_pairs);
    double   pairs_rate = (window_dt > 0.5) ? window_dp / window_dt
                        : (elapsed > 0.001) ? (double)stats_pairs / elapsed
                        : 0.0;
    /* Advance ring */
    rate_ring[rate_ring_idx].pairs = stats_pairs;
    rate_ring[rate_ring_idx].ms    = now;
    rate_ring_idx = (rate_ring_idx + 1) % RATE_RING_SLOTS;
    if (rate_ring_idx == 0) rate_ring_full = 1;

    /* ── Block probability estimate ──
       Cramér–Granville heuristic: P(gap merit ≥ m) ≈ e^(-m) per
       consecutive prime pair.  This is the standard asymptotic
       probability for a random gap between consecutive primes near p.
       Est = 1 / (pairs/s × e^(-target)).  Uses the rolling 30s rate
       for responsiveness. */
    double target_m = g_mining_target;
    char est_buf[64] = "n/a";
    double prob_pair = (target_m > 0) ? exp(-target_m) : 0.0;
    if (pairs_rate > 0 && prob_pair > 0) {
        double est_sec = 1.0 / (pairs_rate * prob_pair);
        format_est(est_buf, sizeof(est_buf), est_sec);
    }

    log_msg("STATS: elapsed=%.1fs  sieved=%llu (%.0f/s)  tested=%llu (%.0f/s)  "
            "gaps=%llu (%.3f/s)  built=%llu  submitted=%llu  accepted=%llu  "
            "prob=%.2e/pair  est=%s (target=%.2f)",
            elapsed,
            (unsigned long long)stats_sieved,  sieve_rate,
            (unsigned long long)stats_tested,  test_rate,
            (unsigned long long)stats_gaps,    gap_rate,
            (unsigned long long)stats_blocks,
            (unsigned long long)stats_submits,
            (unsigned long long)stats_success,
            prob_pair, est_buf, target_m);

    /* ── CRT-specific stats ── */
    if (g_crt_mode == CRT_MODE_SOLVER) {
        uint64_t crt_w = stats_crt_windows;
        uint64_t crt_p = stats_primes_found;
        double win_rate = (elapsed > 0.001) ? (double)crt_w / elapsed : 0.0;
        double ppw = (crt_w > 0) ? (double)crt_p / (double)crt_w : 0.0;
        log_msg("  windows=%llu (%.1f/s)  primes/win=%.1f",
                (unsigned long long)crt_w, win_rate, ppw);
        if (crt_fermat_threads > 0)
            log_msg("  gaplist=%zu", crt_heap_count());
    }

    /* Best merit found this session */
    double bm = stats_best_merit;
    if (bm > 0.0)
        log_msg("  best=%.2f (gap=%llu)",
                bm, (unsigned long long)stats_best_gap);

#ifdef WITH_CUDA
    if (stats_gpu_flushes > 0) {
        double avg_batch = (double)stats_gpu_batched / (double)stats_gpu_flushes;
        log_msg("  gpu_batch=%.0f", avg_batch);
    }
#endif

#ifdef WITH_RPC
    if (g_stratum) {
        uint64_t s_acc, s_rej;
        stratum_get_stats(g_stratum, &s_acc, &s_rej);
        log_msg("  pool=%lu/%lu", (unsigned long)s_acc, (unsigned long)(s_acc + s_rej));
    }
#endif
    log_msg("\n");
}

/* ---------- periodic stats thread ----------
   Wakes every `stats_interval_ms` milliseconds and calls print_stats() so
   the user always sees fresh rates regardless of how long a single sieve
   call takes (which can be several seconds for large --sieve-size values). */
#define STATS_INTERVAL_MS 5000
static volatile int stats_thread_running = 0;
static pthread_t stats_thread;

static void *stats_thread_fn(void *arg) {
    (void)arg;
    while (stats_thread_running) {
        struct timespec ts = { STATS_INTERVAL_MS / 1000,
                               (long)(STATS_INTERVAL_MS % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        if (stats_thread_running) print_stats();
    }
    return NULL;
}

static void start_stats_thread(void) {
    stats_thread_running = 1;
    pthread_create(&stats_thread, NULL, stats_thread_fn, NULL);
}

static void stop_stats_thread(void) {
    stats_thread_running = 0;
    pthread_join(stats_thread, NULL);
}

// ------------------------------------------------------------------------------------------------
// Modular arithmetic
// ------------------------------------------------------------------------------------------------

/* (a * b) % mod, using __uint128_t to avoid overflow.  Kept for use outside
   the hot primality path (e.g. selftest, sieve helpers). */
static inline uint64_t modmul(uint64_t a, uint64_t b, uint64_t mod) {
    return (uint64_t)((__uint128_t)a * b % mod);
}

/* modular exponentiation: a^e % m  (non-Montgomery fallback, kept for
   reference / selftest; hot path now uses Montgomery strong_mrt) */
static uint64_t modpow(uint64_t a, uint64_t e, uint64_t m) __attribute__((unused));
static uint64_t modpow(uint64_t a, uint64_t e, uint64_t m) {
    uint64_t res = 1 % m;
    a %= m;
    while (e) {
        if (e & 1) res = modmul(res, a, m);
        a = modmul(a, a, m);
        e >>= 1;
    }
    return res;
}

/* ═══════════════════════════════════════════════════════════════
   Montgomery modular arithmetic — eliminates the hardware DIVQ
   instruction from every modmul in the hot primality path.

   On Intel Xeon E5 (and most x86-64):
     Regular modmul via __uint128_t % n : ~43 cycles  (1× MUL + 1× DIV)
     Montgomery mont_mul                : ~14 cycles  (2× MUL + adds)
   → ~3× faster per multiply, ~5-7× faster per primality test overall

   R = 2^64 (implicit),  n must be odd.
   ═══════════════════════════════════════════════════════════════ */

/* n_prime = -(n^{-1}) mod 2^64 for odd n.
   Newton lifting: each step doubles the number of correct bits.
   6 steps cover all 64 bits.  Satisfies  n * n_prime ≡ -1 (mod 2^64). */
static inline uint64_t mont_ninv(uint64_t n) {
    uint64_t x = 1;
    x *= 2 - n * x;   /* good mod 2^2  */
    x *= 2 - n * x;   /* good mod 2^4  */
    x *= 2 - n * x;   /* good mod 2^8  */
    x *= 2 - n * x;   /* good mod 2^16 */
    x *= 2 - n * x;   /* good mod 2^32 */
    x *= 2 - n * x;   /* good mod 2^64 */
    return -x;         /* n * (-x) ≡ -1 (mod 2^64) */
}

/* Montgomery product: a * b * R^{-1} mod n.
   Splits into explicit 64-bit halves so no 128-bit overflow occurs
   even when n > 2^63 (our mining range can reach ~2^63.5).
   Result is in [0, n). */
static inline uint64_t mont_mul(uint64_t a, uint64_t b,
                                uint64_t n, uint64_t np) {
    __uint128_t ab = (__uint128_t)a * b;
    uint64_t ab_lo = (uint64_t)ab;
    uint64_t ab_hi = (uint64_t)(ab >> 64);
    uint64_t m     = ab_lo * np;             /* low 64 bits; implicit mod 2^64 */
    __uint128_t mn = (__uint128_t)m * n;
    uint64_t mn_lo = (uint64_t)mn;
    uint64_t mn_hi = (uint64_t)(mn >> 64);
    uint64_t carry = (ab_lo + mn_lo) < ab_lo ? 1u : 0u;
    uint64_t u     = ab_hi + mn_hi + carry;
    return u >= n ? u - n : u;
}

/* R^2 mod n = 2^128 mod n.  Computed once per candidate via the cheap
   identity  2^64 mod n = (-(uint64_t)n) % n  and one __uint128_t square.
   Used to convert values into Montgomery form. */
static inline uint64_t mont_R2(uint64_t n) {
    uint64_t r = (-(uint64_t)n) % n;              /* 2^64 mod n */
    return (uint64_t)(((__uint128_t)r * r) % n);  /* 2^128 mod n */
}

/* Montgomery exponentiation: base^exp mod n (result in normal form).
   np = mont_ninv(n),  R2 = mont_R2(n).
   Available for callers that need a full modular exponentiation via
   Montgomery; the primality tests use strong_mrt directly. */
static uint64_t mont_pow(uint64_t base, uint64_t exp,
                         uint64_t n, uint64_t np, uint64_t R2) __attribute__((unused));
static uint64_t mont_pow(uint64_t base, uint64_t exp,
                         uint64_t n, uint64_t np, uint64_t R2) {
    uint64_t b = mont_mul(base % n, R2, n, np);  /* base → Montgomery form */
    uint64_t r = mont_mul(1,        R2, n, np);  /* 1    → Montgomery form */
    while (exp) {
        if (exp & 1) r = mont_mul(r, b, n, np);
        b = mont_mul(b, b, n, np);
        exp >>= 1;
    }
    return mont_mul(r, 1, n, np);  /* result ← normal form */
}

/* Strong (Miller-Rabin) pseudoprime test for base a modulo n.
   n-1 = d * 2^s  (d odd).  np and R2 are Montgomery constants.
   Returns 1 if n is a strong probable prime to base a, 0 if composite.
   Operates entirely in Montgomery form to keep all multiplications fast. */
static int strong_mrt(uint64_t n, uint64_t a,
                      uint64_t np, uint64_t R2,
                      uint64_t d, int s) {
    uint64_t one_m = mont_mul(1,     R2, n, np);  /* Mont(1)   = R mod n */
    uint64_t nm1_m = mont_mul(n - 1, R2, n, np);  /* Mont(n-1) */
    /* Compute a^d in Montgomery form */
    uint64_t b = mont_mul(a % n, R2, n, np);
    uint64_t x = one_m;
    uint64_t e = d;
    while (e) {
        if (e & 1) x = mont_mul(x, b, n, np);
        b = mont_mul(b, b, n, np);
        e >>= 1;
    }
    if (x == one_m || x == nm1_m) return 1;
    /* Square up to s-1 times looking for ≡ -1 (mod n) */
    for (int r = 1; r < s; r++) {
        x = mont_mul(x, x, n, np);
        if (x == nm1_m) return 1;
    }
    return 0;  /* definitely composite */
}

/* forward declaration for the fast primality test used in worker threads */
static int fast_fermat_test(uint64_t n);

/* Deterministic Miller-Rabin for 64-bit integers.
   Uses the 7-base set {2,325,9375,28178,450775,9780504,1795265022} proven
   sufficient for all n < 2^64, now accelerated with Montgomery arithmetic.
   The np/R2 precomputation is amortised over all 7 base tests. */
static int miller_rabin(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if (!(n & 1) || n % 3 == 0) return 0;
    static const uint64_t small[] = {5,7,11,13,17,19,23,29,31,37};
    for (size_t i = 0; i < sizeof(small)/sizeof(*small); ++i) {
        if (n == small[i]) return 1;
        if (n % small[i] == 0) return 0;
    }
    uint64_t d = n - 1; int s = 0;
    while (!(d & 1)) { d >>= 1; s++; }
    uint64_t np = mont_ninv(n);
    uint64_t R2 = mont_R2(n);
    static const uint64_t bases[] = {2,325,9375,28178,450775,9780504,1795265022};
    for (size_t i = 0; i < 7; i++) {
        uint64_t a = bases[i] % n;
        if (a == 0) continue;
        if (!strong_mrt(n, a, np, R2, d, s)) return 0;
    }
    return 1;
}

/* simple segmented odd-only sieve for [L,R).  The implementation now
   reuses thread-local buffers to avoid malloc/free overhead on every call.
   A parallel array of logarithms is also maintained so that the gap loop
   does not need to call log() repeatedly.  The returned pointers are owned
   by sieve_range and must **not** be freed by the caller; they will be
   released at program exit. */
static __thread uint64_t *tls_pr   = NULL;
static __thread size_t    tls_cap  = 0;
/* Reusable composite-bits bitmap per thread – avoids calloc/free on every sieve call */
static __thread uint8_t  *tls_bits     = NULL;
static __thread size_t    tls_bits_cap = 0;
/* Reusable sieve start-position array per thread */
static __thread uint64_t *tls_sp_start     = NULL;
static __thread size_t    tls_sp_start_cap = 0;

/* ── Cached base_mod_p array ──
   base_mod_p[i] = (h256 << shift) % small_primes_cache[i], precomputed ONCE
   per mining pass in set_base_bn().  The sieve used to call uint256_mod_small()
   for every prime × every window – that's ~78K calls per 262K window, each
   doing 32+shift iterations.  Now the sieve just reads from this array.
   Allocated once, grown as needed. */
static __thread uint64_t *tls_base_mod_p     = NULL;
static __thread size_t    tls_base_mod_p_cap = 0;
/* Flag: set to 1 once set_base_bn() has populated tls_base_mod_p for the
   current pass.  Reset to 0 at start of each new pass (set_base_bn call). */
static __thread int       tls_base_mod_p_ready = 0;

static void free_sieve_buffers(void) {
    free(tls_pr);
    free(tls_bits);
    free(tls_base_mod_p);
    free(tls_sp_start);
    tls_pr       = NULL;
    tls_bits     = NULL;
    tls_base_mod_p = NULL;
    tls_sp_start = NULL;
    tls_cap      = 0;
    tls_bits_cap = 0;
    tls_base_mod_p_cap = 0;
    tls_sp_start_cap = 0;
    tls_base_mod_p_ready = 0;
}

/* sieve_range: segmented odd-only sieve over RELATIVE offsets [L, R) from
   the big base = h256 << shift.  L and R are uint64_t nAdd offsets; the
   actual prime candidates are (h256<<shift)+L ..  (h256<<shift)+R.
   The returned pr[] array holds those same relative offsets.

   OPTIMIZATION: uses tls_base_mod_p[] (precomputed in set_base_bn) instead of
   calling uint256_mod_small() for every sieve prime on every window.  This
   eliminates ~78K × (32+shift) iterations per window. */
static uint64_t* sieve_range(uint64_t L, uint64_t R, size_t *out_count,
                             const uint8_t *h256, int shift) {
    if (L >= R) { *out_count = 0; return NULL; }
    /* L must be odd so that (even_base + L) is odd */
    if ((L & 1) == 0) L++;
    if ((R & 1) == 0) R++;
    uint64_t seg_size = (R - L) / 2 + 1;
    size_t bit_size = (seg_size + 7) / 8;
    /* Reuse thread-local bits buffer; grow only when needed (memset << calloc) */
    if (tls_bits_cap < bit_size) {
        free(tls_bits);
        tls_bits = malloc(bit_size + 64); /* +64 for safe 8-byte word reads at tail */
        if (!tls_bits) { tls_bits_cap = 0; *out_count = 0; return NULL; }
        tls_bits_cap = bit_size + 64;
    }
    uint8_t *bits = tls_bits;

    /* For big primes (256+shift bits), the sieve trial-division limit is
       bounded by the user-configured --sieve-primes (or default).         */
    uint64_t use_limit = (uint64_t)cli_sieve_prime_limit;
    pthread_once(&small_primes_once, populate_small_primes_cache);

    /* ── CRT fast-init path ──
       If a CRT template is loaded (mode=TEMPLATE), tile it into the bitmap
       instead of memset(0) + small-prime sieve.  The template already marks
       composites for the first g_crt_n_primes primes, so the sieve loop
       starts at the first prime AFTER those covered by CRT.
       Mode=SOLVER uses a different mining path entirely; the regular sieve
       just skips the CRT-covered primes and relies on the CRT alignment.  */
    int crt_skip_to = 0;   /* small_primes_cache index to start sieving from */
    if (g_crt_mode == CRT_MODE_TEMPLATE && g_crt_template && g_crt_primorial > 0) {
        /* Compute which template bit corresponds to sieve position 0.
           Sieve position j represents value (base + L + 2j).
           base+L is always odd (base even, L odd).
           residue = (base + L) mod primorial (odd).
           Template bit for odd value v is (v-1)/2.
           start = (residue - 1) / 2.                                      */
        uint64_t residue = (tls_crt_base_residue + L % g_crt_primorial)
                           % g_crt_primorial;
        /* Ensure residue is odd (it should be: base even + L odd = odd) */
        if (!(residue & 1)) residue = (residue + g_crt_primorial) | 1;
        size_t start_bit = (size_t)((residue - 1) / 2);
        tile_crt_template(bits, bit_size, seg_size, start_bit);
        /* Find the index in small_primes_cache just past the CRT primes.
           CRT covers primes up to g_crt_max_prime (e.g. 17 for 7 primes),
           NOT up to the primorial. */
        if (small_primes_cache && g_crt_max_prime > 0) {
            for (size_t idx = 0; idx < small_primes_count; ++idx) {
                if (small_primes_cache[idx] > g_crt_max_prime)
                    break;
                crt_skip_to = (int)(idx + 1);
            }
        }
    } else {
        memset(bits, 0, bit_size);
    }

    /* Mark composites: for each small prime p, find first offset ≡ 0 (mod p)
       and stride by 2p (odd-only sieve).

       Use cached base_mod_p[] when available (precomputed once per pass in
       set_base_bn), falling back to uint256_mod_small on the cold path.

       L1-CACHE-BLOCKING: Small primes (stride 2p < block_bytes×16) have
       many hits per window.  Instead of striding across the entire bitmap
       (~1 MB for 20 M sieve), we process the bitmap in L1-sized blocks
       (32 KB).  This keeps the working set warm in L1 and reduces cache
       misses by ~30×.  Large primes (≤ 1 hit per block) use a single pass
       since they don't cause cache pressure. */
    int have_cache = tls_base_mod_p_ready && tls_base_mod_p;

    /* L1-block size in BITS (=positions).  32 KB = 262144 bits. */
    #define SIEVE_BLOCK_BITS  (32768ULL * 8)
    /* Primes with stride 2p covering ≤ 2 hits per block use the
       straight-through path (no blocking benefit). */
    #define SIEVE_BLOCK_THRESH (SIEVE_BLOCK_BITS)

    if (small_primes_cache) {
        /* --- Phase 1: small primes, L1-cache-blocked --- */
        /* Find the split index: primes where 2p < SIEVE_BLOCK_THRESH.
           Start from crt_skip_to to skip primes already covered by CRT. */
        int sieve_start = crt_skip_to > 1 ? crt_skip_to : 1;
        size_t split_idx = small_primes_count;
        for (size_t idx = (size_t)sieve_start; idx < small_primes_count; ++idx) {
            uint64_t p = small_primes_cache[idx];
            if (p > use_limit) { split_idx = idx; break; }
            if (2 * p >= SIEVE_BLOCK_THRESH) { split_idx = idx; break; }
        }

        /* Precompute starting positions for small primes (skip CRT primes). */
        size_t sp_count = split_idx > (size_t)sieve_start
                        ? split_idx - (size_t)sieve_start : 0;
        if (sp_count > 0) {
            /* Reuse TLS buffer to avoid malloc/free every sieve call */
            if (tls_sp_start_cap < sp_count) {
                free(tls_sp_start);
                tls_sp_start = (uint64_t *)malloc(sp_count * sizeof(uint64_t));
                tls_sp_start_cap = sp_count;
            }
            uint64_t *sp_start = tls_sp_start;
            for (size_t i = 0; i < sp_count; i++) {
                size_t idx = i + (size_t)sieve_start;
                uint64_t p = small_primes_cache[idx];
                uint64_t base_mod_p;
                if (have_cache)
                    base_mod_p = tls_base_mod_p[idx];
                else
                    base_mod_p = h256 ? uint256_mod_small(h256, shift, p) : (L % p);
                uint64_t lrem = (base_mod_p + L % p) % p;
                uint64_t start = L + (lrem == 0 ? 0 : p - lrem);
                if ((start & 1) == 0) start += p;
                sp_start[i] = start;
            }

            /* Process bitmap in L1-sized blocks */
            for (uint64_t blk_pos = 0; blk_pos < seg_size; blk_pos += SIEVE_BLOCK_BITS) {
                uint64_t blk_end = blk_pos + SIEVE_BLOCK_BITS;
                if (blk_end > seg_size) blk_end = seg_size;
                /* Translate block bounds to absolute offsets */
                uint64_t blk_L = L + blk_pos * 2;
                uint64_t blk_R = L + blk_end * 2;
                if (blk_R > R) blk_R = R;

                for (size_t i = 0; i < sp_count; i++) {
                    uint64_t p = small_primes_cache[i + (size_t)sieve_start];
                    uint64_t stride = 2 * p;
                    uint64_t m = sp_start[i];
                    /* Advance start into this block if needed */
                    if (m < blk_L) {
                        uint64_t skip = (blk_L - m + stride - 1) / stride;
                        m += skip * stride;
                    }
                    for (; m < blk_R; m += stride) {
                        uint64_t pos = (m - L) / 2;
                        bits[pos >> 3] |= (uint8_t)(1u << (pos & 7));
                    }
                    sp_start[i] = m; /* carry into next block */
                }
            }
            /* sp_start is TLS-owned; no free needed */
        }

        /* --- Phase 2: large primes, single pass (no blocking needed) --- */
        for (size_t idx = split_idx; idx < small_primes_count; ++idx) {
            uint64_t p = small_primes_cache[idx];
            if (p > use_limit) break;
            uint64_t base_mod_p;
            if (have_cache)
                base_mod_p = tls_base_mod_p[idx];
            else
                base_mod_p = h256 ? uint256_mod_small(h256, shift, p) : (L % p);
            uint64_t lrem = (base_mod_p + L % p) % p;
            uint64_t start = L + (lrem == 0 ? 0 : p - lrem);
            if ((start & 1) == 0) start += p;
            for (uint64_t m = start; m < R; m += 2 * p) {
                uint64_t pos = (m - L) / 2;
                bits[pos >> 3] |= (uint8_t)(1u << (pos & 7));
            }
        }
    }

    /* ensure the tls_pr buffer is large enough */
    if (tls_cap < seg_size) {
        size_t newcap = seg_size;
        tls_pr = realloc(tls_pr, newcap * sizeof(uint64_t));
        if (!tls_pr) {
            *out_count = 0;
            return NULL;
        }
        tls_cap = newcap;
    }

    /* ── Vectorized extraction using 64-bit word scan + CTZ ──
     *
     * Instead of checking one bit at a time, we process 64 bits (128 odd
     * positions worth of data) per iteration.  For each 64-bit word of the
     * bitmap:
     *   • Complement: survivors are 0-bits → invert to get 1-bits for
     *     survivors.
     *   • Mask off any trailing bits beyond seg_size.
     *   • While the word is nonzero, extract lowest set bit with CTZ,
     *     emit the corresponding offset, clear the bit.
     *
     * On modern x86-64 with BMI1, __builtin_ctzll compiles to a single
     * TZCNT instruction (1 cycle, no branch).  This is ~8× fewer
     * iterations than the old per-bit scan for typical sieve densities. */
    size_t out_cnt = 0;
    size_t full_words = bit_size / 8;
    for (size_t wi = 0; wi < full_words; wi++) {
        uint64_t word;
        memcpy(&word, bits + wi * 8, 8);
        word = ~word;  /* invert: survivors (0-bits) become 1-bits */
        while (word) {
            int bit = __builtin_ctzll(word);
            uint64_t pos = (uint64_t)wi * 64 + (uint64_t)bit;
            if (pos < seg_size) {
                tls_pr[out_cnt++] = L + pos * 2;
            }
            word &= word - 1;  /* clear lowest set bit */
        }
    }
    /* Handle remaining bytes (< 8) at tail */
    size_t tail_start = full_words * 8;
    for (size_t bi = tail_start; bi < bit_size; bi++) {
        uint8_t byte = ~bits[bi];  /* invert */
        while (byte) {
            int bit = __builtin_ctz((unsigned)byte);
            uint64_t pos = (uint64_t)bi * 8 + (uint64_t)bit;
            if (pos < seg_size) {
                tls_pr[out_cnt++] = L + pos * 2;
            }
            byte &= (uint8_t)(byte - 1);
        }
    }
    *out_count = out_cnt;
    return tls_pr;
}

#ifdef WITH_RPC
// rpc_submit/rpc_call are provided by the C++ wrapper in `src/rpc_cwrap.cpp`
#ifdef __cplusplus
extern "C" {
#endif
int rpc_submit(const char *url, const char *user, const char *pass, const char *method, const char *hex);
char *rpc_call(const char *url, const char *user, const char *pass, const char *method, const char *params_json);
char *rpc_getblocktemplate(const char *url, const char *user, const char *pass);
#ifdef __cplusplus
}
#endif
#endif
#ifdef WITH_RPC
static void enqueue_job(const struct submit_job *job) {
    pthread_mutex_lock(&sq_lock);
    if (sq_count >= SUBMIT_QUEUE_MAX) {
        // drop oldest to make room
        sq_head = (sq_head + 1) % SUBMIT_QUEUE_MAX;
        sq_count--;
        fprintf(stderr, "submit queue full, dropping oldest job\n");
    }
    submit_queue[sq_tail] = *job;
    sq_tail = (sq_tail + 1) % SUBMIT_QUEUE_MAX;
    sq_count++;
    pthread_cond_signal(&sq_cond);
    pthread_mutex_unlock(&sq_lock);
}

static struct submit_job dequeue_job(void) {
    struct submit_job job;
    memset(&job,0,sizeof(job));
    pthread_mutex_lock(&sq_lock);
    while (sq_count == 0 && sq_running) pthread_cond_wait(&sq_cond, &sq_lock);
    if (sq_count > 0) {
        job = submit_queue[sq_head];
        sq_head = (sq_head + 1) % SUBMIT_QUEUE_MAX;
        sq_count--;
        if (sq_count == 0)
            pthread_cond_signal(&sq_empty_cond); /* notify sq_drain() */
    }
    pthread_mutex_unlock(&sq_lock);
    return job;
}

static void *submit_thread_fn(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&sq_lock);
        while (sq_count == 0 && sq_running) pthread_cond_wait(&sq_cond, &sq_lock);
        if (!sq_running && sq_count == 0) { pthread_mutex_unlock(&sq_lock); break; }
        pthread_mutex_unlock(&sq_lock);

        struct submit_job job = dequeue_job();
        if (!job.hex[0]) continue;

        // rate limiting
        uint64_t now = now_ms();
        if (last_submit_ms && now - last_submit_ms < (uint64_t)rpc_rate_ms) {
            uint64_t wait = (uint64_t)rpc_rate_ms - (now - last_submit_ms);
            struct timespec tsw; tsw.tv_sec = wait / 1000; tsw.tv_nsec = (wait % 1000) * 1000000;
            nanosleep(&tsw, NULL);
        }

        int attempt = 0;
        int ok = -1;
        while (attempt <= job.retries) {
            // The node `submitblock` expects params: ["<blockhex>"] — send raw block hex only
            ok = rpc_submit(job.url[0] ? job.url : NULL,
                            job.user[0] ? job.user : NULL,
                            job.pass[0] ? job.pass : NULL,
                            job.method[0] ? job.method : "submitblock",
                            job.hex);
            if (ok == 0) break;  /* accepted */
            if (ok > 0) break;   /* definitive rejection — no point retrying */
            /* ok < 0: transient network/connection error — retry with backoff */
            int backoff_ms = 250 * (1 << attempt);
            if (backoff_ms > 10000) backoff_ms = 10000;
            struct timespec ts; ts.tv_sec = backoff_ms / 1000; ts.tv_nsec = (backoff_ms % 1000) * 1000000;
            nanosleep(&ts, NULL);
            attempt++;
        }
        last_submit_ms = now_ms();
        if (ok == 0) {
            __sync_fetch_and_add(&stats_success, 1);
            log_msg(">>> ACCEPTED (async submit)\n");
        } else if (ok > 0) {
            /* Definitive rejection (result=false/string): the block is stale.
               Abort the current mining pass immediately and drain the queue
               so we don't keep retrying the same dead block. */
            log_msg(">>> REJECTED (stale block — aborting pass, fetching new template)\n");
            g_abort_pass = 1;
            pthread_mutex_lock(&sq_lock);
            sq_head = sq_tail = sq_count = 0;
            pthread_cond_signal(&sq_empty_cond); /* queue forcibly cleared */
            pthread_mutex_unlock(&sq_lock);
        } else {
            log_msg(">>> FAILED after %d attempts (connection error, async submit)\n", attempt);
        }
    }
    return NULL;
}

static int start_submit_thread(void) {
    sq_running = 1;
    if (pthread_create(&sq_thread, NULL, submit_thread_fn, NULL) != 0) {
        sq_running = 0;
        return -1;
    }
    return 0;
}

static void stop_submit_thread(void) {
    pthread_mutex_lock(&sq_lock);
    sq_running = 0;
    pthread_cond_signal(&sq_cond);
    pthread_mutex_unlock(&sq_lock);
    pthread_join(sq_thread, NULL);
}

/* Wait until the submit queue is empty.  Must be called before any
   build_mining_pass() invocation so that in-flight submissions finish
   against the current mapNewBlock entry before getwork() evicts it. */
static void sq_drain(void) {
    pthread_mutex_lock(&sq_lock);
    while (sq_count > 0)
        pthread_cond_wait(&sq_empty_cond, &sq_lock);
    pthread_mutex_unlock(&sq_lock);
}
#endif

// ----------------- encode_pow_header_binary -----------------
// Minimal binary encoding: sha256(header) || le64(p) || le64(q)
static void u64_to_le(uint64_t v, unsigned char out[8]) __attribute__((unused));
static void u64_to_le(uint64_t v, unsigned char out[8]) {
    for (int i=0;i<8;i++) out[i] = (unsigned char)(v & 0xff), v >>= 8;
}

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) __attribute__((unused));
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i=0;i<len;i++) {
        out[i*2] = hex[(bytes[i] >> 4) & 0xf];
        out[i*2+1] = hex[bytes[i] & 0xf];
    }
    out[len*2] = '\0';
}

// RPC-only helpers
#ifdef WITH_RPC
/* Produce a 32-byte OP_RETURN commitment for the coinbase: SHA256 of the
   hex-decoded prevhash bytes.  The actual Gapcoin PoW is validated via
   nShift/nAdd in the block header, not this field. */
static void encode_pow_header_binary(const char *prevhash_hex, char outhex[65]) {
    uint8_t prevbytes[32] = {0};
    hash_to_256(prevhash_hex, 1, prevbytes);
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(prevbytes, 32, md);
    bytes_to_hex(md, 32, outhex);
}

// HMAC-SHA256 of data with key, hex output (64 chars + NUL)
static void hmac_sha256_hex(const char *key, const char *data, char outhex[65]) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), key, key ? (int)strlen(key) : 0,
         (const unsigned char*)data, strlen(data), md, &md_len);
    bytes_to_hex(md, md_len, outhex);
    outhex[64] = '\0';
}
#endif
// Build coinbase tx with OP_RETURN payload (hex string). Returns serialized tx buffer (caller frees) and sets out_len.
static void write_u32_le(unsigned char **p, uint32_t v) {
    for (int i = 0; i < 4; ++i) { **p = (unsigned char)(v & 0xff); *p += 1; v >>= 8; }
}
static void write_u64_le(unsigned char **p, uint64_t v) {
    for (int i = 0; i < 8; ++i) { **p = (unsigned char)(v & 0xff); *p += 1; v >>= 8; }
}
static void write_byte(unsigned char **p, unsigned char b) { **p = b; *p += 1; }

// write push-data opcode(s) and data
static size_t push_opcode_size(size_t len) {
    if (len <= 75) return 1 + len;
    if (len <= 0xFF) return 2 + len; // OP_PUSHDATA1
    if (len <= 0xFFFF) return 3 + len; // OP_PUSHDATA2
    return 5 + len; // OP_PUSHDATA4
}
static void write_push_data(unsigned char **p, const unsigned char *data, size_t len) {
    if (len <= 75) {
        write_byte(p, (unsigned char)len);
    } else if (len <= 0xFF) {
        write_byte(p, 0x4c);
        write_byte(p, (unsigned char)len);
    } else if (len <= 0xFFFF) {
        write_byte(p, 0x4d);
        unsigned short le = (unsigned short)len;
        memcpy(*p, &le, 2); *p += 2;
    } else {
        write_byte(p, 0x4e);
        unsigned int le = (unsigned int)len;
        memcpy(*p, &le, 4); *p += 4;
    }
    if (len) { memcpy(*p, data, len); *p += len; }
}

// write CompactSize (Bitcoin varint) into buffer pointer
static void write_compact_size(unsigned char **p, uint64_t v) {
    if (v < 0xFD) {
        write_byte(p, (unsigned char)v);
    } else if (v <= 0xFFFF) {
        write_byte(p, 0xFD);
        unsigned short le = (unsigned short)v;
        memcpy(*p, &le, 2); *p += 2;
    } else if (v <= 0xFFFFFFFF) {
        write_byte(p, 0xFE);
        unsigned int le = (unsigned int)v;
        memcpy(*p, &le, 4); *p += 4;
    } else {
        write_byte(p, 0xFF);
        unsigned long long le = (unsigned long long)v;
        memcpy(*p, &le, 8); *p += 8;
    }
}

// Build a minimal coinbase tx with OP_RETURN. Returns serialized tx buffer (caller frees) and sets out_len.
// Build a minimal coinbase tx with OP_RETURN (or alternative). Returns serialized tx buffer (caller frees) and sets out_len.
static unsigned char *build_coinbase_tx_opreturn(const char *opdata_hex, uint64_t value_satoshis, uint64_t height, size_t *out_len) __attribute__((unused));
static unsigned char *build_coinbase_tx_opreturn(const char *opdata_hex, uint64_t value_satoshis, uint64_t height, size_t *out_len) {
    size_t hexlen = strlen(opdata_hex);
    size_t datalen = hexlen / 2;
    unsigned char *data = malloc(datalen);
    for (size_t i = 0; i < datalen; ++i) { unsigned int v = 0; sscanf(opdata_hex + 2*i, "%2x", &v); data[i] = (unsigned char)v; }

    // estimate size conservatively (use plenty of headroom)
    size_t cap = 8192;
    unsigned char *tx = calloc(1, cap);
    if (!tx) { free(data); *out_len = 0; return NULL; }
    unsigned char *p = tx;

    // version
    write_u32_le(&p, 1);
    // vin count
    write_byte(&p, 1);
    // prevout hash (32 bytes zero)
    for (int i = 0; i < 32; ++i) write_byte(&p, 0x00);
    // prevout index
    write_u32_le(&p, 0xFFFFFFFFu);
    // scriptSig (coinbase) - include block height per BIP34
    unsigned char height_buf[9]; size_t hb = 0;
    uint64_t h = height;
    while (h) { height_buf[hb++] = (unsigned char)(h & 0xff); h >>= 8; }
    if (hb == 0) { height_buf[hb++] = 0x00; }
    if (height_buf[hb-1] & 0x80) { height_buf[hb++] = 0x00; }
    // scriptSig bytes = [push(height)] [height_buf...] [push(extranonce)] [extranonce] [push(COINBASE_FLAGS)]
    size_t extranonce_len = 4;
    const unsigned char coinbase_flags[] = { '/', 'P', '2', 'S', 'H', '/' };
    size_t coinbase_flags_len = sizeof(coinbase_flags);
    size_t scriptsig_len = push_opcode_size(hb) + push_opcode_size(extranonce_len) + push_opcode_size(coinbase_flags_len);
    // write CompactSize for script length
    write_compact_size(&p, scriptsig_len);
    // push height
    write_push_data(&p, height_buf, hb);
    // push extranonce (zeros) to mimic miner coinbase
    unsigned char extranonce[4] = {0,0,0,0};
    write_push_data(&p, extranonce, extranonce_len);
    // push coinbase flags (e.g. "/P2SH/") to match node's coinbase template
    write_push_data(&p, coinbase_flags, coinbase_flags_len);
    // sequence
    write_u32_le(&p, 0xFFFFFFFFu);
    // vout count
    write_byte(&p, 1);
    // value (8 bytes little-endian)
    write_u64_le(&p, value_satoshis);
    // pk_script (OP_RETURN)
    // Use provided OP_RETURN data length (serialize full payload)
    size_t use_datalen = datalen;
    size_t pk_script_len = 1 + (use_datalen ? push_opcode_size(use_datalen) : 0); // OP_RETURN [+ push + data]
    write_compact_size(&p, pk_script_len);
    write_byte(&p, 0x6a);
    if (use_datalen) {
        write_push_data(&p, data, use_datalen);
    }
    // locktime
    write_u32_le(&p, 0);

    *out_len = p - tx;
    log_file_only("DEBUG coinbase details: scriptsig_len=%zu extranonce_len=%zu pk_script_len=%zu datalen=%zu tx_len=%zu\n",
            scriptsig_len, extranonce_len, pk_script_len, datalen, *out_len);
    free(data);
    return tx;
}

// Build a minimal coinbase tx without OP_RETURN (use single-byte scriptPubKey OP_TRUE)
static unsigned char *build_coinbase_tx_minimal(uint64_t value_satoshis, uint64_t height, size_t *out_len) __attribute__((unused));
static unsigned char *build_coinbase_tx_minimal(uint64_t value_satoshis, uint64_t height, size_t *out_len) {
    // estimate size conservatively
    size_t cap = 8192;
    unsigned char *tx = calloc(1, cap);
    if (!tx) { *out_len = 0; return NULL; }
    unsigned char *p = tx;

    // version
    write_u32_le(&p, 1);
    // vin count
    write_byte(&p, 1);
    // prevout hash (32 bytes zero)
    for (int i = 0; i < 32; ++i) write_byte(&p, 0x00);
    // prevout index
    write_u32_le(&p, 0xFFFFFFFFu);
    // scriptSig (coinbase) - include block height per BIP34
    unsigned char height_buf[9]; size_t hb = 0;
    uint64_t h = height;
    while (h) { height_buf[hb++] = (unsigned char)(h & 0xff); h >>= 8; }
    if (hb == 0) { height_buf[hb++] = 0x00; }
    if (height_buf[hb-1] & 0x80) { height_buf[hb++] = 0x00; }
    size_t extranonce_len = 4;
    const unsigned char coinbase_flags[] = { '/', 'P', '2', 'S', 'H', '/' };
    size_t coinbase_flags_len = sizeof(coinbase_flags);
    size_t scriptsig_len = push_opcode_size(hb) + push_opcode_size(extranonce_len) + push_opcode_size(coinbase_flags_len);
    write_compact_size(&p, scriptsig_len);
    write_push_data(&p, height_buf, hb);
    unsigned char extranonce[4] = {0,0,0,0};
    write_push_data(&p, extranonce, extranonce_len);
    write_push_data(&p, coinbase_flags, coinbase_flags_len);
    // sequence
    write_u32_le(&p, 0xFFFFFFFFu);
    // vout count
    write_byte(&p, 1);
    // value
    write_u64_le(&p, value_satoshis);
    // pk_script: single OP_TRUE (0x51)
    size_t pk_script_len = 1;
    write_compact_size(&p, pk_script_len);
    write_byte(&p, 0x51);
    // locktime
    write_u32_le(&p, 0);

    *out_len = p - tx;
    log_file_only("DEBUG coinbase minimal: scriptsig_len=%zu extranonce_len=%zu pk_script_len=%zu tx_len=%zu\n",
            scriptsig_len, extranonce_len, pk_script_len, *out_len);
    return tx;
}

static void double_sha256(const unsigned char *data, size_t len, unsigned char out[32]) __attribute__((unused));
static void double_sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    unsigned char tmp[32]; SHA256(data, len, tmp); SHA256(tmp, 32, out);
}

// Build a full block hex from the GBT JSON and our header payload (we place payload in coinbase OP_RETURN).
// This is a minimal assembler: it extracts previousblockhash, curtime, version if present, builds coinbase tx,
// computes merkle root and serializes header + tx count + txs, hex-encodes into outhex.
#ifdef WITH_RPC
static int build_block_from_gbt_and_payload(const char *gbt_json, const char *header_payload_hex,
                                             int nshift_val, uint64_t nadd_val,
                                             char outhex[16384]) {
    char prevhex[65] = {0};
    uint32_t curtime = (uint32_t)time(NULL);
    uint32_t version = 2;
    uint64_t ndifficulty = 0x0014d29966377819ULL; /* default difficulty */
    /* parse difficulty field (hex) from GBT - HexBits output is a hex string representing 8 bytes big-endian */
    const char *bts = strstr(gbt_json, "\"difficulty\"");
    if (bts) {
        const char *c = strchr(bts, ':');
        if (c) {
            const char *quote = strchr(c, '"');
            if (quote) {
                const char *q2 = strchr(quote+1, '"');
                if (q2) {
                    size_t len = q2 - (quote+1);
                    if (len > 0 && len < 32) {
                        char buf[32]; memcpy(buf, quote+1, len); buf[len] = '\0';
                        uint64_t v = 0;
                        for (size_t i = 0; i < len; ++i) {
                            char ch = buf[i]; int val = 0;
                            if (ch >= '0' && ch <= '9') val = ch - '0';
                            else if (ch >= 'a' && ch <= 'f') val = 10 + ch - 'a';
                            else if (ch >= 'A' && ch <= 'F') val = 10 + ch - 'A';
                            else continue;
                            v = (v << 4) | (uint64_t)val;
                        }
                        ndifficulty = v;
                    }
                }
            }
        }
    }
    const char *p = strstr(gbt_json, "\"previousblockhash\"");
    if (p) { const char *q = strchr(p, '"'); if (q) { q = strchr(q+1, '"'); if (q) { const char *r = strchr(q+1, '"'); if (r) { const char *s = strchr(r+1, '"'); if (s && s-r-1 < 65) strncpy(prevhex, r+1, s-(r+1)); } } } }
    const char *t = strstr(gbt_json, "\"curtime\""); if (t) { const char *c = strchr(t, ':'); if (c) curtime = (uint32_t)atoi(c+1); }
    const char *v = strstr(gbt_json, "\"version\""); if (v) { const char *c = strchr(v, ':'); if (c) version = (uint32_t)atoi(c+1); }

    uint64_t coinbase_value = 0;
    const char *cbv = strstr(gbt_json, "\"coinbasevalue\"");
    if (cbv) { const char *c = strchr(cbv, ':'); if (c) coinbase_value = (uint64_t)strtoull(c+1, NULL, 10); }
    if (!coinbase_value) coinbase_value = 0;
    uint64_t block_height = 0;
    const char *hb = strstr(gbt_json, "\"height\"");
    if (hb) { const char *c2 = strchr(hb, ':'); if (c2) block_height = (uint64_t)strtoull(c2+1, NULL, 10); }

    // build coinbase tx (include block height).
    // If the GBT contains a prebuilt "coinbasetxn" object use its "data" field
    // (preferred) otherwise build locally (with or without OP_RETURN payload).
    size_t coin_txlen;
    unsigned char *coin_tx = NULL;
    const char *cbtxn = strstr(gbt_json, "\"coinbasetxn\"");
    if (cbtxn) {
        const char *d = strstr(cbtxn, "\"data\"");
        if (d) {
            const char *col = strchr(d, ':');
            if (col) {
                const char *quote = strchr(col, '"');
                if (quote) {
                    const char *q2 = strchr(quote+1, '"');
                    if (q2) {
                        size_t hlen = q2 - (quote+1);
                        coin_txlen = hlen/2;
                        coin_tx = malloc(coin_txlen);
                        if (coin_tx) {
                            for (size_t i=0;i<coin_txlen;i++) { unsigned int v=0; sscanf(quote+1 + 2*i, "%2x", &v); coin_tx[i]=(unsigned char)v; }
                        }
                    }
                }
            }
        }
    }
    if (!coin_tx) {
        if (!header_payload_hex || header_payload_hex[0] == '\0') {
            coin_tx = build_coinbase_tx_minimal(coinbase_value, block_height, &coin_txlen);
        } else {
            coin_tx = build_coinbase_tx_opreturn(header_payload_hex, coinbase_value, block_height, &coin_txlen);
        }
    }
    if (!coin_tx) {
        log_msg("ERROR: failed to build coinbase tx (OOM?)\n");
        return 0;
    }
    log_file_only("GBT: version=%u curtime=%u prev=%s txlen=%zu coinbase_value=%llu height=%llu\n", version, curtime, prevhex[0]?prevhex:"(none)", coin_txlen, (unsigned long long)coinbase_value, (unsigned long long)block_height);
    // debug coinbase tx bytes
    char coin_hex_dbg[2048]; if (coin_txlen < 1024) { bytes_to_hex(coin_tx, coin_txlen, coin_hex_dbg); log_file_only("DEBUG coin_tx hex: %s\n", coin_hex_dbg); }

    // gather transactions listed in GBT (their raw "data" fields)
    const char *txs_start = strstr(gbt_json, "\"transactions\"");
    unsigned char **tx_bytes = NULL; size_t *tx_lens = NULL; size_t tx_count = 0;
    if (txs_start) {
        const char *arr = strchr(txs_start, '[');
        if (arr) {
            const char *end = strchr(arr, ']');
            if (!end) end = gbt_json + strlen(gbt_json);
            const char *cur = arr;
            while (cur && cur < end) {
                const char *d = strstr(cur, "\"data\"");
                if (!d || d > end) break;
                const char *col = strchr(d, ':'); if (!col) break;
                const char *quote = strchr(col, '"'); if (!quote) break;
                const char *q2 = strchr(quote+1, '"'); if (!q2) break;
                size_t hlen = q2 - (quote+1);
                char *hex = malloc(hlen+1);
                if (!hex) { log_msg("ERROR: malloc hex failed\n"); for (size_t j=0;j<tx_count;j++) free(tx_bytes[j]); free(tx_bytes); free(tx_lens); free(coin_tx); return 0; }
                memcpy(hex, quote+1, hlen); hex[hlen] = '\0';
                unsigned char *b = malloc(hlen/2);
                if (!b) { log_msg("ERROR: malloc tx bytes failed\n"); free(hex); for (size_t j=0;j<tx_count;j++) free(tx_bytes[j]); free(tx_bytes); free(tx_lens); free(coin_tx); return 0; }
                for (size_t i=0;i<hlen/2;i++) { unsigned int v=0; sscanf(hex+2*i, "%2x", &v); b[i]=(unsigned char)v; }
                tx_bytes = realloc(tx_bytes, (tx_count+1)*sizeof(unsigned char*));
                tx_lens = realloc(tx_lens, (tx_count+1)*sizeof(size_t));
                tx_bytes[tx_count] = b; tx_lens[tx_count] = hlen/2; tx_count++;
                free(hex);
                cur = q2+1;
            }
        }
    }

    // build vector of tx hashes (double sha256) starting with coinbase
    size_t total_txs = 1 + tx_count;
    unsigned char **txraws = malloc(total_txs * sizeof(unsigned char*));
    size_t *txraw_lens = malloc(total_txs * sizeof(size_t));
    txraws[0] = coin_tx; txraw_lens[0] = coin_txlen;
    for (size_t i=0;i<tx_count;i++) { txraws[1+i] = tx_bytes[i]; txraw_lens[1+i] = tx_lens[i]; }

    unsigned char **hashes = malloc(total_txs * sizeof(unsigned char*));
    for (size_t i=0;i<total_txs;i++) {
        hashes[i] = malloc(32);
        double_sha256(txraws[i], txraw_lens[i], hashes[i]);
    }

    // merkle tree
    size_t m = total_txs;
    unsigned char **layer = hashes;
    while (m > 1) {
        size_t pairs = (m + 1) / 2;
        unsigned char **next = malloc(pairs * sizeof(unsigned char*));
        for (size_t i=0;i<pairs;i++) next[i] = malloc(32);
        for (size_t i=0;i<pairs;i++) {
            unsigned char buf[64];
            unsigned char *left = layer[2*i];
            unsigned char *right = (2*i+1 < m) ? layer[2*i+1] : layer[2*i];
            memcpy(buf, left, 32); memcpy(buf+32, right, 32);
            unsigned char out[32]; double_sha256(buf, 64, out);
            memcpy(next[i], out, 32);
        }
        for (size_t i=0;i<m;i++) free(layer[i]);
        free(layer);
        layer = next; m = pairs;
    }
    unsigned char merkle_root[32]; memcpy(merkle_root, layer[0], 32);
    free(layer[0]); free(layer);

    // build header (Gapcoin header includes additional fields: nDifficulty (8 bytes), nShift and nAdd vector)
    unsigned char headerbin[96]; unsigned char *hp = headerbin;
    memset(headerbin, 0, sizeof(headerbin));
    memcpy(hp, &version, 4); hp += 4;
    unsigned char prevbin[32]; memset(prevbin, 0, 32);
    if (prevhex[0]) {
        for (int i=0;i<32;i++) { unsigned int v=0; sscanf(prevhex + i*2, "%2x", &v); prevbin[31-i] = (unsigned char)v; }
    }
    memcpy(hp, prevbin, 32); hp += 32;
    // header expects merkle root in little-endian (reverse byte order)
    for (int i=0;i<32;i++) hp[i] = merkle_root[31-i];
    hp += 32;
    memcpy(hp, &curtime, 4); hp += 4;
    // nDifficulty is 8 bytes in Gapcoin header; write ndifficulty little-endian
    uint64_t diff64 = ndifficulty;
    for (int i = 0; i < 8; ++i) { hp[i] = (unsigned char)(diff64 & 0xff); diff64 >>= 8; }
    hp += 8;
    uint32_t nonce = 0; memcpy(hp, &nonce, 4); hp += 4;
    // nShift (uint16_t) – must match the shift used to find the prime
    uint16_t nshift = (uint16_t)nshift_val;
    memcpy(hp, &nshift, 2); hp += 2;
    // nAdd: serialize as big-endian minimal byte array with CompactSize prefix.
    // For nadd=0 write a single 0x00 byte (length 1).
    {
        unsigned char nadd_bytes[8];
        int nadd_len;
        if (nadd_val == 0) {
            nadd_bytes[0] = 0;
            nadd_len = 1;
        } else {
            /* write little-endian first, then reverse to big-endian */
            nadd_len = 0;
            uint64_t tmp = nadd_val;
            while (tmp > 0) { nadd_bytes[nadd_len++] = (unsigned char)(tmp & 0xff); tmp >>= 8; }
            /* reverse in-place to get big-endian (BN_bn2bin order) */
            for (int _i = 0; _i < nadd_len / 2; _i++) {
                unsigned char _t = nadd_bytes[_i];
                nadd_bytes[_i] = nadd_bytes[nadd_len - 1 - _i];
                nadd_bytes[nadd_len - 1 - _i] = _t;
            }
        }
        write_compact_size(&hp, (uint64_t)nadd_len);
        memcpy(hp, nadd_bytes, nadd_len); hp += nadd_len;
    }
    /* Gapcoin header is variable length: 4+32+32+4+8+4+2+(CompactSize+nAdd_bytes)
       For nadd=0 that is 88 bytes (CompactSize=1 + 1 zero byte).
       For larger adders the nAdd field grows (1 byte per 8 additional bits). */
    size_t header_size = (size_t)(hp - headerbin);
    log_file_only("DEBUG header_size=%zu (expected 88)\n", header_size);

    // serialize full block: header + varint txcount + tx raw bytes
    size_t full_len = header_size + 1;
    for (size_t i=0;i<total_txs;i++) full_len += txraw_lens[i];
    unsigned char *full = malloc(full_len + 8);
    unsigned char *fp = full;
    memcpy(fp, headerbin, header_size); fp += header_size;
    // write CompactSize tx count and remember varint length
    unsigned char *fp_varint_start = fp;
    write_compact_size(&fp, total_txs);
    size_t varint_len = (size_t)(fp - fp_varint_start);
    for (size_t i=0;i<total_txs;i++) { memcpy(fp, txraws[i], txraw_lens[i]); fp += txraw_lens[i]; }

    // Sanity-check: parse first tx from the serialized block and verify coinbase prevout
    unsigned char *rp = full + header_size; // after header
    // read txcount varint
    uint64_t parsed_txcount = 0;
    if (*rp < 0xFD) { parsed_txcount = *rp; rp += 1; }
    else if (*rp == 0xFD) { parsed_txcount = rp[1] | (rp[2]<<8); rp += 3; }
    else { parsed_txcount = 0; }
    if (parsed_txcount == 0) {
        log_msg("ERROR: parsed txcount == 0\n");
        free(full);
        return 0;
    }
    // parse first tx version (4 bytes)
    if ((size_t)(rp - full) + 4 > full_len) { log_msg("ERROR: block too short for tx version\n"); free(full); return 0; }
    rp += 4; // skip version
    // vin count
    uint64_t vin_cnt = 0;
    if (*rp < 0xFD) { vin_cnt = *rp; rp += 1; }
    if (vin_cnt < 1) { log_msg("ERROR: vin count < 1: %llu\n", (unsigned long long)vin_cnt); free(full); return 0; }
    // prevout hash (32)
    if ((size_t)(rp - full) + 32 + 4 > full_len) { log_msg("ERROR: block too short for prevout\n"); free(full); return 0; }
    int allzero = 1;
    for (int i=0;i<32;i++) if (rp[i] != 0x00) { allzero = 0; break; }
    uint32_t prev_index = rp[32] | (rp[33]<<8) | (rp[34]<<16) | (rp[35]<<24);
    if (!allzero || prev_index != 0xFFFFFFFFu) {
        char debughex[512]; size_t show = (full_len < 128) ? full_len : 128; bytes_to_hex(full, show, debughex);
        log_msg("ERROR: first tx prevout mismatch: allzero=%d prev_index=0x%08x parsed_txcount=%llu\nblockprefix=%s\n",
                allzero, prev_index, (unsigned long long)parsed_txcount, debughex);
        free(full);
        return 0;
    }

    // Detailed debug: log header, txcount and first tx prefix for byte-for-byte comparison
    char tmphex[1024*4]; size_t dbg_len = full_len < 200 ? full_len : 200; bytes_to_hex(full, dbg_len, tmphex);
    char headerhex[200]; bytes_to_hex(headerbin, header_size, headerhex); headerhex[header_size*2]='\0';
    log_file_only("DEBUG block header hex: %s\n", headerhex);
    log_file_only("DEBUG txcount=%zu first_bytes=%s\n", (size_t)total_txs, tmphex + 160);

    // Verify that the coinbase tx bytes appear immediately after header + txcount varint
    if (txraw_lens[0] > 0) {
        unsigned char *coin_in_block = full + header_size + varint_len;
        if ((size_t)(coin_in_block - full) + txraw_lens[0] > full_len) {
            log_msg("ERROR: coinbase would overflow serialized block\n");
            for (size_t i=0;i<total_txs;i++) free(txraws[i]);
            free(txraws); free(txraw_lens); free(full);
            return 0;
        }
        if (memcmp(coin_in_block, txraws[0], txraw_lens[0]) != 0) {
            char coin_dbg[2048]; size_t show = txraw_lens[0] < 512 ? txraw_lens[0] : 512; bytes_to_hex(txraws[0], show, coin_dbg);
            char blk_dbg[2048]; size_t bshow = (full_len < 512) ? full_len : 512; bytes_to_hex(full, bshow, blk_dbg);
            log_msg("ERROR: coinbase bytes in block do not match built coinbase\ncoinbase_prefix=%s\nblock_prefix_at_header_plus_varint=%s\n", coin_dbg, blk_dbg + (header_size+varint_len)*2);
            for (size_t i=0;i<total_txs;i++) free(txraws[i]);
            free(txraws); free(txraw_lens); free(full);
            return 0;
        }
    }

    bytes_to_hex(full, full_len, outhex);

/* pow check helper can use header bytes already written above */

    /* Dump raw serialized block bytes and hex to /tmp for forensic comparison
       Filename includes timestamp, pid and a small random value. */
    {
        char binpath[256]; char hexpath[256];
        snprintf(binpath, sizeof(binpath), "%sgap_miner_block_%lu_%lu_%u.bin",
                 win_temp_dir(), (unsigned long)time(NULL), (unsigned long)getpid(), (unsigned)rand());
        snprintf(hexpath, sizeof(hexpath), "%sgap_miner_block_%lu_%lu_%u.hex",
                 win_temp_dir(), (unsigned long)time(NULL), (unsigned long)getpid(), (unsigned)rand());
        FILE *bf = fopen(binpath, "wb");
        if (bf) {
            fwrite(full, 1, full_len, bf);
            fclose(bf);
            log_file_only("WROTE raw block binary: %s (len=%zu)\n", binpath, full_len);
        } else {
            log_msg("FAILED to write raw block binary: %s\n", binpath);
        }
        FILE *hf = fopen(hexpath, "w");
        if (hf) {
            fprintf(hf, "%s", outhex);
            fclose(hf);
            log_file_only("WROTE raw block hex: %s (chars=%zu)\n", hexpath, strlen(outhex));
        } else {
            log_msg("FAILED to write raw block hex: %s\n", hexpath);
        }
    }

    for (size_t i=0;i<total_txs;i++) {
        free(txraws[i]);
    }
    free(txraws);
    free(txraw_lens);
    if (tx_bytes) free(tx_bytes);
    if (tx_lens) free(tx_lens);
    free(full);
    return 1;
}
#endif

#ifdef WITH_RPC
/* =========================================================================
 * Mining pass state: build_mining_pass() + assemble_mining_block()
 *
 * Protocol fix: gapcoind uses getwork not getblocktemplate+submitblock.
 * getwork (no params) returns an 80-byte header with gapcoind's own coinbase
 * TX already included; gapcoind saves the complete block in
 * mapNewBlock[hashMerkleRoot].  Submission via getwork[data] lets gapcoind
 * look up that saved block by merkle root and inject our nNonce+nShift+nAdd.
 *
 * build_mining_pass(): calls getwork → gets 80-byte header hex + nDifficulty,
 *   decodes header, finds nNonce so SHA256d(hdr80+nNonce)[31] >= 0x80
 *   (Gapcoin requires mpz_sizeinbase(hash,2) == 256), byte-reverses to h256
 *   (BN_bin2bn/uint256_mod_small expect h256[0] = MSB = sha_raw[31]).
 *
 * assemble_mining_block(): builds getwork submit payload:
 *   hdr80(80) + nNonce(4,LE) + nShift(2,LE) + nAdd(raw LE bytes, ≥ 1 byte)
 *   Total must be > 86 bytes (gapcoind requirement).
 * ========================================================================= */

static int build_mining_pass(const char *url, const char *user, const char *pass, int shift) {
    char data_hex[161] = {0};
    uint64_t ndiff = 0;
    if (!rpc_getwork_data(url, user, pass, data_hex, &ndiff)) return 0;
    /* decode 80-byte header from hex exactly as getwork returns it (wire
       order: little-endian fields).  No per-word swapping is needed for
       hashing or submission; gapcoind stores the raw wire header in
       mapNewBlock and expects submissions in the same byte order. */
    uint8_t hdr80[80];
    for (int i = 0; i < 80; i++) {
        unsigned int bv = 0;
        sscanf(data_hex + i*2, "%2x", &bv);
        hdr80[i] = (uint8_t)bv;
    }
    /* extract prevhex: bytes 4..35 of hdr80 are prevhash in LE wire order.
       Display as big-endian hex (byte-reversed) to match Bitcoin convention. */
    char prevhex[65] = {0};
    for (int i = 0; i < 32; i++)
        sprintf(prevhex + 2*i, "%02x", hdr80[4 + 31 - i]);
    /* find nNonce so SHA256d(hdr80+nNonce)[31] >= 0x80.
     * Bitcoin uint256: SHA256d_byte[k] = data[k]; ary_to_mpz(order=-1) treats data[31] as MSB.
     * BN_bin2bn/uint256_mod_small expect h256[0] = MSB → h256[k] = sha_raw[31-k].
     * Gapcoin requires mpz_sizeinbase(hash,2) == 256 → sha_raw[31] >= 0x80. */
    uint8_t hdr84[84], sha_raw[32], h256[32];
    uint32_t nonce = 0;
    for (;;) {
        memcpy(hdr84, hdr80, 80);
        memcpy(hdr84 + 80, &nonce, 4);  /* nNonce appended after 80-byte header */
        double_sha256(hdr84, 84, sha_raw);
        if (sha_raw[31] >= 0x80) break;
        if (++nonce == 0) break;
    }
    for (int k = 0; k < 32; k++) h256[k] = sha_raw[31-k];
    /* store in g_pass */
    memcpy(g_pass.h256,  h256,  32);
    memcpy(g_pass.hdr80, hdr80, 80);
    g_pass.nonce  = nonce;
    g_pass.nshift = (uint16_t)shift;
    g_pass.ndiff  = ndiff;
    strncpy(g_pass.prevhex, prevhex, 64);
    g_pass.prevhex[64] = '\0';
    g_pass.height = 0; /* not available from getwork header */
    log_file_only("build_mining_pass: nonce=%u ndiff=%llu h256[0..3]=%02x%02x%02x%02x prevhex=%.16s...\n",
                  nonce, (unsigned long long)ndiff,
                  h256[0], h256[1], h256[2], h256[3], prevhex);
    return 1;
}

static int assemble_mining_block(uint64_t nadd_val, char out_hex[16384]) {
    /* getwork submit format: hdr80(80) + nNonce(4,LE) + nShift(2,LE) + nAdd(raw LE, ≥ 1 byte)
     * gapcoind casts vchData to CBlock*; nNonce is at offset 80, nShift at 84,
     * nAdd starts at byte 86.  gapcoind requires vchData.size() > 86.
     * nAdd is raw little-endian bytes, NO compact-size prefix. */
    unsigned char buf[512];
    unsigned char *p = buf;
    memcpy(p, g_pass.hdr80,    80); p += 80;  /* header unchanged */
    memcpy(p, &g_pass.nonce,    4); p += 4;   /* nNonce LE (offset 80) */
    memcpy(p, &g_pass.nshift,   2); p += 2;   /* nShift LE (offset 84) */
    /* nAdd raw LE bytes, minimum 1 byte */
    unsigned char nb[8];
    int nl;
    if (nadd_val == 0) { nb[0] = 0; nl = 1; }
    else {
        nl = 0;
        uint64_t tmp = nadd_val;
        while (tmp > 0) { nb[nl++] = (unsigned char)(tmp & 0xff); tmp >>= 8; }
    }
    memcpy(p, nb, nl); p += nl;
    /* gapcoind requires vchData.size() > 86; pad with one zero byte if too short */
    if ((p - buf) <= 86) { *p++ = 0x00; }
    bytes_to_hex(buf, (size_t)(p - buf), out_hex);
    return 1;
}

/* Like assemble_mining_block but accepts a full mpz_t nAdd and an explicit
   nonce, so CRT mining at large shifts (512+) can submit properly. */
static int assemble_mining_block_mpz(uint32_t mining_nonce, mpz_t nadd_val,
                                     char out_hex[16384]) {
    unsigned char buf[1024]; /* enough for nAdd up to ~7400 bits */
    unsigned char *p = buf;
    memcpy(p, g_pass.hdr80,    80); p += 80;
    memcpy(p, &mining_nonce,    4); p += 4;
    memcpy(p, &g_pass.nshift,   2); p += 2;
    /* nAdd raw LE bytes */
    if (mpz_sgn(nadd_val) == 0) {
        *p++ = 0;
    } else {
        size_t count = 0;
        mpz_export(p, &count, -1, 1, 0, 0, nadd_val); /* LE byte order */
        p += count;
    }
    if ((p - buf) <= 86) { *p++ = 0x00; }
    bytes_to_hex(buf, (size_t)(p - buf), out_hex);
    return 1;
}

/* Build a mining pass from stratum work data.
   Same logic as build_mining_pass() but reads from the caller-provided
   data_hex/ndiff (obtained from the stratum client) instead of HTTP getwork. */
static int build_mining_pass_stratum(const char *data_hex, uint64_t ndiff, int shift) {
    /* decode 80-byte header from hex */
    uint8_t hdr80[80];
    for (int i = 0; i < 80; i++) {
        unsigned int bv = 0;
        sscanf(data_hex + i*2, "%2x", &bv);
        hdr80[i] = (uint8_t)bv;
    }
    /* extract prevhex: bytes 4..35 of hdr80 are prevhash in LE wire order.
       Display as big-endian hex (byte-reversed) to match Bitcoin convention. */
    char prevhex[65] = {0};
    for (int i = 0; i < 32; i++)
        sprintf(prevhex + 2*i, "%02x", hdr80[4 + 31 - i]);
    /* find nNonce so SHA256d(hdr80+nNonce)[31] >= 0x80 */
    uint8_t hdr84[84], sha_raw[32], h256[32];
    uint32_t nonce = 0;
    for (;;) {
        memcpy(hdr84, hdr80, 80);
        memcpy(hdr84 + 80, &nonce, 4);
        double_sha256(hdr84, 84, sha_raw);
        if (sha_raw[31] >= 0x80) break;
        if (++nonce == 0) break;
    }
    for (int k = 0; k < 32; k++) h256[k] = sha_raw[31-k];
    /* store in g_pass */
    memcpy(g_pass.h256,  h256,  32);
    memcpy(g_pass.hdr80, hdr80, 80);
    g_pass.nonce  = nonce;
    g_pass.nshift = (uint16_t)shift;
    g_pass.ndiff  = ndiff;
    strncpy(g_pass.prevhex, prevhex, 64);
    g_pass.prevhex[64] = '\0';
    g_pass.height = 0;
    log_file_only("build_mining_pass_stratum: nonce=%u ndiff=%llu h256[0..3]=%02x%02x%02x%02x prevhex=%.16s...\n",
                  nonce, (unsigned long long)ndiff,
                  h256[0], h256[1], h256[2], h256[3], prevhex);
    return 1;
}
#endif /* WITH_RPC — build_mining_pass / assemble_mining_block */

/* check whether the block should be forwarded to the node for PoW validation.
   Gapcoin uses prime-gap proof-of-work, not hash-based PoW; the real PoW check
   is performed by gapcoind on submitblock, so we always forward the block.
   debug_force is checked first for the --force-solution testing path. */
static int header_meets_target_hex(const char *blockhex) {
    (void)blockhex; /* the node decides; we never reject locally */
    return 1;
}

/* Convert a header string to a 256-bit (32-byte) big-endian integer.
   is_hex=1: decode up to 64 hex chars directly (prevhash from GBT).
   is_hex=0: SHA-256 the string and use the digest. */
static void hash_to_256(const char *s, int is_hex, uint8_t out[32]) {
    memset(out, 0, 32);
    if (is_hex) {
        size_t len = strlen(s);
        if (len > 64) len = 64;
        for (size_t i = 0; i < len / 2; i++) {
            char hi = s[2*i], lo = s[2*i+1];
            int vh = (hi>='0'&&hi<='9')?(hi-'0'):(hi>='a'&&hi<='f')?(10+hi-'a'):(10+hi-'A');
            int vl = (lo>='0'&&lo<='9')?(lo-'0'):(lo>='a'&&lo<='f')?(10+lo-'a'):(10+lo-'A');
            out[i] = (uint8_t)((vh << 4) | vl);
        }
    } else {
        unsigned char md[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)s, strlen(s), md);
        memcpy(out, md, 32);
    }
}

/* Compute (h << shift) % p  where h is a 32-byte big-endian integer and p
   fits in uint64_t.  Uses __uint128_t for intermediate reductions. */
static uint64_t uint256_mod_small(const uint8_t h[32], int shift, uint64_t p) {
    if (p <= 1) return 0;
    /* Step 1: h % p via schoolbook big-endian byte reduction */
    __uint128_t rem = 0;
    for (int i = 0; i < 32; i++)
        rem = (rem * 256 + h[i]) % p;
    /* Step 2: 2^shift % p via repeated doubling */
    __uint128_t pow2 = 1 % p;
    for (int i = 0; i < shift; i++)
        pow2 = pow2 * 2 % p;
    return (uint64_t)((__uint128_t)rem * pow2 % p);
}

/* Approximate log(h << shift) for merit calculation.
   h is big-endian 32 bytes (256-bit hash), prime = h*2^shift + nAdd.
   Since nAdd << h*2^shift, log(prime) ≈ log(h) + shift*log(2).
   We approximate log(h) using its 8 most-significant bytes. */
static double uint256_log_approx(const uint8_t h[32], int shift) {
    uint64_t leading = 0;
    for (int i = 0; i < 8; i++) leading = (leading << 8) | h[i];
    if (leading == 0) return (double)(192 + shift) * M_LN2;
    /* h ≈ leading * 2^192, so log(h<<shift) ≈ log(leading) + (192+shift)*ln2 */
    return log((double)leading) + (double)(192 + shift) * M_LN2;
}

/* Thread-local GMP state for 256+shift-bit primality testing.
   set_base_bn() precomputes base = h256 << shift once per mining pass.
   bn_candidate_is_prime() tests base + offset.

   ═══════════════════════════════════════════════════════════════════
   GMP REPLACEMENT: OpenSSL BN was the old backend.  GMP's mpz has
   hand-tuned x86-64 assembly (karatsuba, montgomery) that's 5-10×
   faster for 284-bit modular exponentiation.

   Key wins:
   • mpz_probab_prime_p: one function call, no alloc overhead
   • mpz_add_ui:  O(1) to update lowest limb (vs BN_copy+BN_add_word)
   • Assembly-level Montgomery mult in libgmp: ~8 cycles per limb-mul
     vs OpenSSL's generic C path at ~14-20 cycles
   ═══════════════════════════════════════════════════════════════════ */
static __thread mpz_t  tls_base_mpz;       /* base = h256 << shift     */
static __thread mpz_t  tls_cand_mpz;       /* candidate = base + offset */
static __thread mpz_t  tls_two_mpz;        /* constant 2 (Fermat base)  */
static __thread mpz_t  tls_exp_mpz;        /* n-1 exponent for Fermat   */
static __thread mpz_t  tls_res_mpz;        /* powm result               */
static __thread int    tls_gmp_inited = 0;  /* 0 until first init       */

static void ensure_gmp_tls(void) {
    if (__builtin_expect(!tls_gmp_inited, 0)) {
        /* Pre-allocate all mpz to 384 bits (6 limbs) — enough for 284-bit
           numbers, avoiding any internal reallocation during hot paths. */
        mpz_init2(tls_base_mpz, 384);
        mpz_init2(tls_cand_mpz, 384);
        mpz_init_set_ui(tls_two_mpz, 2);
        mpz_init2(tls_exp_mpz, 384);
        mpz_init2(tls_res_mpz, 384);
        tls_gmp_inited = 1;
    }
}

/* Thread-local TD residues: tls_td_residues[i] = (base << shift) % td_extra_primes[i].         Precomputed once per mining pass in set_base_bn(); used for cheap pre-filtering. */
static __thread uint32_t tls_td_residues[TD_EXTRA_CNT];

/* Compute tls_base_mpz = h256 << shift  (called once per worker pass).
   Also precomputes the TD residues for the extended trial-division table
   and the cached base_mod_p[] array for sieve_range. */
static void set_base_bn(const uint8_t h256[32], int shift) {
    ensure_gmp_tls();
    /* Import h256 (big-endian, MSB first) into GMP */
    mpz_import(tls_base_mpz, 32, 1, 1, 1, 0, h256);
    mpz_mul_2exp(tls_base_mpz, tls_base_mpz, (unsigned long)shift);

    /* ── Precompute CRT base residue once per pass ── */
    if (g_crt_mode == CRT_MODE_TEMPLATE && g_crt_primorial > 0)
        tls_crt_base_residue = mpz_fdiv_ui(tls_base_mpz,
                                           (unsigned long)g_crt_primorial);

    /* ── Precompute base_mod_p[] for ALL sieve primes ──
       This cache is read by sieve_range() on every window, eliminating
       ~78K calls to uint256_mod_small() per window.  The cost here is
       O(small_primes_count) 256-bit reductions = ~5ms once per pass
       vs ~5ms × 1000 windows = ~5 seconds in the old code. */
    pthread_once(&small_primes_once, populate_small_primes_cache);
    if (small_primes_cache && small_primes_count > 0) {
        if (tls_base_mod_p_cap < small_primes_count) {
            free(tls_base_mod_p);
            tls_base_mod_p_cap = small_primes_count + 64;
            tls_base_mod_p = malloc(tls_base_mod_p_cap * sizeof(uint64_t));
        }
        if (tls_base_mod_p) {
            for (size_t i = 0; i < small_primes_count; i++) {
                uint64_t p = small_primes_cache[i];
                tls_base_mod_p[i] = mpz_fdiv_ui(tls_base_mpz, (unsigned long)p);
            }
            tls_base_mod_p_ready = 1;
        }
    }

    /* Precompute TD residues for the extended trial-division table. */
    pthread_once(&td_extra_once, populate_td_extra_primes);
    for (int i = 0; i < td_extra_count; i++)
        tls_td_residues[i] = (uint32_t)mpz_fdiv_ui(tls_base_mpz,
                                                     (unsigned long)td_extra_primes[i]);
}


/* Return 1 if (tls_base_mpz + offset) is probably prime.
 *
 * Two paths:
 *  A. --fast-fermat: raw Fermat test via GMP's mpz_powm.
 *     Computes 2^(n-1) mod n and checks == 1.
 *     Bypasses mpz_probab_prime_p's internal trial-division (which is
 *     redundant — our candidates already survived a million-prime sieve).
 *  B. Full: mpz_probab_prime_p(n, 10) — 10 MR rounds.
 */
static int bn_candidate_is_prime(uint64_t offset) {
    /* --- Trial-division pre-filter (disabled when TD_EXTRA_CNT=0) --- */
    for (int i = 0; i < td_extra_count; i++) {
        uint32_t p   = td_extra_primes[i];
        uint32_t rem = (uint32_t)(((uint64_t)tls_td_residues[i]
                                   + (uint64_t)(offset % p)) % p);
        if (rem == 0) return 0;
    }

    ensure_gmp_tls();
    /* candidate = base + offset.  mpz_add_ui is O(1) for small offsets
       (only touches the lowest GMP limb). */
    mpz_set(tls_cand_mpz, tls_base_mpz);
    mpz_add_ui(tls_cand_mpz, tls_cand_mpz, (unsigned long)offset);

    if (use_fast_fermat) {
        /* Raw base-2 Fermat test: 2^(n-1) mod n == 1?
           Skips GMP's redundant internal trial-division (~700 primes
           up to 5000) that mpz_probab_prime_p does before MR.
           For sieve-filtered 284-bit candidates, this saves ~10-15%. */
        mpz_sub_ui(tls_exp_mpz, tls_cand_mpz, 1);
        mpz_powm(tls_res_mpz, tls_two_mpz, tls_exp_mpz, tls_cand_mpz);
        return mpz_cmp_ui(tls_res_mpz, 1) == 0;
    } else {
        /* Full probable-prime: 10 MR rounds (higher confidence than
           OpenSSL's BN_prime_checks ≈ 6, but still fast with GMP). */
        return mpz_probab_prime_p(tls_cand_mpz, 10) > 0;
    }
}

#ifdef WITH_CUDA
/* GPU batch primality filter.
   Takes the thread-local base (tls_base_mpz) and an array of uint64
   offsets.  Sends (base + offset[i]) for each i to the GPU for Fermat
   testing, then compacts the survivors in-place.
   Returns the new count (number of probable primes).  */
static size_t gpu_batch_filter(uint64_t *offsets, size_t cnt) {
    if (g_gpu_count == 0 || cnt == 0) return 0;

    /* Round-robin GPU selection by thread (tls_tid set per worker) */
    static __thread int tls_gpu_idx = -1;
    if (tls_gpu_idx < 0) {
        static volatile int gpu_rr = 0;
        tls_gpu_idx = __sync_fetch_and_add(&gpu_rr, 1) % g_gpu_count;
    }
    gpu_fermat_ctx *ctx = g_gpu_ctx[tls_gpu_idx];

    ensure_gmp_tls();
    /* Export base into GPU_NLIMBS LE limb array */
    uint64_t base_limbs[GPU_NLIMBS];
    memset(base_limbs, 0, sizeof(base_limbs));
    size_t nexp = 0;
    mpz_export(base_limbs, &nexp, -1, 8, 0, 0, tls_base_mpz);
    if (nexp > GPU_NLIMBS) {
        static int warned = 0;
        if (!warned) {
            fprintf(stderr, "gpu_batch_filter: candidate needs %zu limbs "
                    "but GPU_NLIMBS=%d — falling back to CPU.  "
                    "Rebuild with GPU_BITS=%zu or higher.\n",
                    nexp, GPU_NLIMBS, nexp * 64);
            warned = 1;
        }
        /* CPU fallback */
        size_t pf = 0;
        for (size_t j = 0; j < cnt; j++)
            if (bn_candidate_is_prime(offsets[j]))
                offsets[pf++] = offsets[j];
        return pf;
    }

    /* Allocate flat candidate buffer: cnt × GPU_NLIMBS limbs */
    size_t batch = cnt;
    if (batch > GPU_MAX_BATCH) batch = GPU_MAX_BATCH;
    uint64_t *cands = (uint64_t *)malloc(batch * GPU_NLIMBS * sizeof(uint64_t));
    uint8_t  *res   = (uint8_t  *)malloc(batch);
    if (!cands || !res) { free(cands); free(res); return 0; }

    size_t pf = 0;  /* prime-filtered count */
    size_t i = 0;
    while (i < cnt) {
        size_t chunk = cnt - i;
        if (chunk > batch) chunk = batch;
        /* Build candidate limbs: base + offset */
        for (size_t j = 0; j < chunk; j++) {
            uint64_t *dst = &cands[j * GPU_NLIMBS];
            /* copy base */
            for (int k = 0; k < GPU_NLIMBS; k++) dst[k] = base_limbs[k];
            /* add offset (single-precision add) */
            uint64_t carry = 0;
            dst[0] += offsets[i + j];
            carry = (dst[0] < offsets[i + j]);
            for (int k = 1; k < GPU_NLIMBS && carry; k++) {
                dst[k] += carry;
                carry = (dst[k] == 0);
            }
        }
        /* GPU test */
        int np = gpu_fermat_test_batch(ctx, cands, res, chunk);
        if (np < 0) {
            /* GPU error: fall back to CPU for remaining */
            for (size_t j = 0; j < chunk; j++)
                if (bn_candidate_is_prime(offsets[i + j]))
                    offsets[pf++] = offsets[i + j];
        } else {
            for (size_t j = 0; j < chunk; j++)
                if (res[j]) offsets[pf++] = offsets[i + j];
        }
        i += chunk;
    }
    free(cands);
    free(res);
    return pf;
}
#endif /* WITH_CUDA */

#ifdef WITH_CUDA
/* ── Scan gap results for one window ──
   After Fermat testing, scan consecutive prime survivors for qualifying
   gaps.  Updates global stats, logs gaps, submits qualifying blocks. */
static void scan_gap_results(uint64_t *primes, size_t prime_cnt,
                             double logbase, uint32_t nonce, int cand_odd,
                             mpz_srcptr nAdd, int shift_v, double target,
                             const char *rpc_url, const char *rpc_user,
                             const char *rpc_pass) {
    __sync_fetch_and_add(&stats_crt_windows, 1);
    __sync_fetch_and_add(&stats_primes_found, (uint64_t)prime_cnt);
    if (prime_cnt < 2) return;
    __sync_fetch_and_add(&stats_pairs, (uint64_t)(prime_cnt - 1));
    for (size_t i = 0; i + 1 < prime_cnt; i++) {
        uint64_t gap = primes[i + 1] - primes[i];
        double merit = (double)gap / logbase;
        if (merit > stats_best_merit) {
            stats_best_merit = merit;
            stats_best_gap   = gap;
        }
        if (merit < target) continue;
        __sync_fetch_and_add(&stats_gaps, 1);
        mpz_t nAdd_prime;
        mpz_init(nAdd_prime);
        mpz_set(nAdd_prime, nAdd);
        mpz_add_ui(nAdd_prime, nAdd_prime, primes[i]);
        if (cand_odd)
            mpz_sub_ui(nAdd_prime, nAdd_prime, 1);
        char nAdd_str[256];
        gmp_snprintf(nAdd_str, sizeof(nAdd_str), "%Zd", nAdd_prime);
        log_msg("\n>>> GAP FOUND\n"
                "    gap     = %llu\n"
                "    merit   = %.6f  (need >= %.2f)\n"
                "    nShift  = %d\n"
                "    nonce   = %u\n"
                "    nAdd    = %s\n",
                (unsigned long long)gap,
                merit, target, shift_v,
                (unsigned)nonce, nAdd_str);
#ifdef WITH_RPC
        if (rpc_url && !g_abort_pass) {
            pthread_mutex_lock(&sq_lock);
            int sq_busy = (sq_count > 0);
            pthread_mutex_unlock(&sq_lock);
            if (!sq_busy) {
                char blockhex[16384];
                memset(blockhex, 0, sizeof(blockhex));
                if (assemble_mining_block_mpz(nonce, nAdd_prime, blockhex)) {
                    __sync_fetch_and_add(&stats_blocks, 1);
                    log_file_only("Built blockhex: %s\n", blockhex);
                    if (header_meets_target_hex(blockhex)) {
                        log_msg(">>> SUBMITTING to node\n"
                                "    merit=%.6f  gap=%llu"
                                "  nShift=%d  nonce=%u\n",
                                merit, (unsigned long long)gap,
                                shift_v, (unsigned)nonce);
                        struct submit_job _job;
                        memset(&_job, 0, sizeof(_job));
                        strncpy(_job.url, rpc_url, sizeof(_job.url)-1);
                        strncpy(_job.user, rpc_user ? rpc_user : "",
                                sizeof(_job.user)-1);
                        strncpy(_job.pass, rpc_pass ? rpc_pass : "",
                                sizeof(_job.pass)-1);
                        strncpy(_job.method, "getwork",
                                sizeof(_job.method)-1);
                        memcpy(_job.hex, blockhex, sizeof(_job.hex));
                        _job.retries = rpc_default_retries;
                        __sync_fetch_and_add(&stats_submits, 1);
                        enqueue_job(&_job);
                        log_msg(">>> QUEUED for async submit"
                                " (mining continues)\n");
                        print_stats();
                    }
                } else {
                    log_msg("Failed to assemble block\n");
                }
            }
        }
#endif
        mpz_clear(nAdd_prime);
    }
}

/* ── GPU batch accumulator ──
   Collects candidates from multiple CRT windows into a single large
   buffer, then sends them all to the GPU in one kernel launch.
   Instead of ~800 candidates per window (tiny batch), we accumulate
   4096+ before flushing for much better GPU SM utilization. */

#define GPU_ACCUM_DEFAULT  4096

struct gpu_accum_win {
    size_t    cand_start;     /* index into flat cand_limbs buffer */
    size_t    cand_count;     /* survivors from this window */
    uint64_t *surv;           /* owned copy of survivor offsets */
    size_t    surv_cnt;
    uint32_t  nonce;
    int       cand_odd;
    double    logbase;
    double    target;
    int       shift;
    const char *rpc_url, *rpc_user, *rpc_pass;
    mpz_t     nAdd;           /* owned copy */
};

struct gpu_accum {
    uint64_t *limbs;           /* flat: total × GPU_NLIMBS uint64_t */
    size_t    total;           /* current accumulated candidate count */
    size_t    capacity;
    struct gpu_accum_win *wins;
    size_t    win_count;
    size_t    win_cap;
    uint8_t  *results;
    size_t    res_cap;
    int       threshold;       /* flush when total >= this */
    gpu_fermat_ctx *ctx;       /* assigned GPU context */
};

static __thread struct gpu_accum *tls_gpu_accum;

static struct gpu_accum *gpu_accum_create(gpu_fermat_ctx *ctx, int threshold) {
    struct gpu_accum *a = (struct gpu_accum *)calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->threshold = threshold > 0 ? threshold : GPU_ACCUM_DEFAULT;
    a->ctx = ctx;
    a->capacity = (size_t)a->threshold + 1024;
    a->limbs = (uint64_t *)malloc(a->capacity * GPU_NLIMBS * sizeof(uint64_t));
    a->win_cap = 256;
    a->wins = (struct gpu_accum_win *)malloc(a->win_cap * sizeof(a->wins[0]));
    a->res_cap = a->capacity;
    a->results = (uint8_t *)malloc(a->res_cap);
    if (!a->limbs || !a->wins || !a->results) {
        free(a->limbs); free(a->wins); free(a->results); free(a);
        return NULL;
    }
    return a;
}

static void gpu_accum_reset(struct gpu_accum *a) {
    for (size_t i = 0; i < a->win_count; i++) {
        free(a->wins[i].surv);
        mpz_clear(a->wins[i].nAdd);
    }
    a->total = 0;
    a->win_count = 0;
}

static void gpu_accum_destroy(struct gpu_accum *a) {
    if (!a) return;
    gpu_accum_reset(a);
    free(a->limbs);
    free(a->wins);
    free(a->results);
    free(a);
}

/* Add a window's survivors to the accumulator.
   Returns 1 if threshold reached (caller should call gpu_accum_flush). */
static int gpu_accum_add(struct gpu_accum *a,
                         const uint64_t base_limbs[GPU_NLIMBS],
                         const uint64_t *offsets, size_t cnt,
                         uint32_t nonce, int cand_odd,
                         double logbase, double target_v, int shift_v,
                         mpz_srcptr nAdd,
                         const char *rpc_url, const char *rpc_user,
                         const char *rpc_pass) {
    if (!a || cnt == 0) return 0;
    /* Grow limbs buffer if needed */
    if (a->total + cnt > a->capacity) {
        size_t new_cap = (a->total + cnt) * 2;
        uint64_t *nl = (uint64_t *)realloc(a->limbs,
            new_cap * GPU_NLIMBS * sizeof(uint64_t));
        if (!nl) return 0;
        a->limbs = nl;
        a->capacity = new_cap;
        if (new_cap > a->res_cap) {
            uint8_t *nr = (uint8_t *)realloc(a->results, new_cap);
            if (!nr) return 0;
            a->results = nr;
            a->res_cap = new_cap;
        }
    }
    /* Grow window array if needed */
    if (a->win_count >= a->win_cap) {
        size_t nwc = a->win_cap * 2;
        struct gpu_accum_win *nw = (struct gpu_accum_win *)realloc(
            a->wins, nwc * sizeof(a->wins[0]));
        if (!nw) return 0;
        a->wins = nw;
        a->win_cap = nwc;
    }
    /* Convert candidates: base + offset → limbs */
    for (size_t j = 0; j < cnt; j++) {
        uint64_t *dst = &a->limbs[(a->total + j) * GPU_NLIMBS];
        for (int k = 0; k < GPU_NLIMBS; k++) dst[k] = base_limbs[k];
        dst[0] += offsets[j];
        uint64_t carry = (dst[0] < offsets[j]);
        for (int k = 1; k < GPU_NLIMBS && carry; k++) {
            dst[k] += carry;
            carry = (dst[k] == 0);
        }
    }
    /* Record window metadata */
    struct gpu_accum_win *w = &a->wins[a->win_count];
    w->cand_start = a->total;
    w->cand_count = cnt;
    w->surv = (uint64_t *)malloc(cnt * sizeof(uint64_t));
    if (w->surv) memcpy(w->surv, offsets, cnt * sizeof(uint64_t));
    w->surv_cnt   = cnt;
    w->nonce      = nonce;
    w->cand_odd   = cand_odd;
    w->logbase    = logbase;
    w->target     = target_v;
    w->shift      = shift_v;
    w->rpc_url    = rpc_url;
    w->rpc_user   = rpc_user;
    w->rpc_pass   = rpc_pass;
    mpz_init(w->nAdd);
    mpz_set(w->nAdd, nAdd);
    a->total += cnt;
    a->win_count++;
    return (int)(a->total >= (size_t)a->threshold);
}

/* Flush: send all accumulated candidates to GPU, process results. */
static void gpu_accum_flush(struct gpu_accum *a) {
    if (!a || a->total == 0 || !a->ctx) return;
    /* GPU test entire accumulated batch */
    __sync_fetch_and_add(&stats_gpu_flushes, 1);
    __sync_fetch_and_add(&stats_gpu_batched, a->total);
    int np = gpu_fermat_test_batch(a->ctx, a->limbs, a->results, a->total);
    /* Distribute results to each window and scan gaps */
    for (size_t wi = 0; wi < a->win_count; wi++) {
        struct gpu_accum_win *w = &a->wins[wi];
        if (np < 0 || !w->surv) {
            /* GPU error: count the window, skip gap-scanning */
            __sync_fetch_and_add(&stats_crt_windows, 1);
            free(w->surv); w->surv = NULL;
            mpz_clear(w->nAdd);
            continue;
        }
        /* Compact survivors using GPU results */
        size_t pf = 0;
        for (size_t j = 0; j < w->cand_count; j++) {
            if (a->results[w->cand_start + j])
                w->surv[pf++] = w->surv[j];
        }
        scan_gap_results(w->surv, pf, w->logbase, w->nonce, w->cand_odd,
                         w->nAdd, w->shift, w->target,
                         w->rpc_url, w->rpc_user, w->rpc_pass);
        free(w->surv); w->surv = NULL;
        mpz_clear(w->nAdd);
    }
    a->total = 0;
    a->win_count = 0;
}
#endif /* WITH_CUDA — accumulator */

// Produce hex of SHA256(header) (useful as a simple header encoding)
static void sha256_hex(const char *s, char out[65]) __attribute__((unused));
static void sha256_hex(const char *s, char out[65]) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)s, strlen(s), md);
    static const char hex[] = "0123456789abcdef";
    for (int i=0;i<32;i++) {
        out[i*2] = hex[(md[i] >> 4) & 0xf];
        out[i*2+1] = hex[md[i] & 0xf];
    }
    out[64]='\0';
}
// Worker struct and function for threaded mining (file-scope)
struct worker_args {
    int tid;
    int nthreads;
    uint8_t  h256[32];  /* 256-bit base hash (big-endian) */
    int shift;
    int64_t adder_max;
    uint64_t sieve_size;
    double target;
    const char *header;
    const char *rpc_url;
    const char *rpc_user;
    const char *rpc_pass;
    const char *rpc_method;
    const char *rpc_sign_key;
    /* per-thread adder-space slice (set by main before spawning) */
    int64_t adder_base_offset; /* offset into [0, global_adder_max) */
    int     rpc_thread;        /* 1 for the thread that polls GBT   */
    int     crt_role;          /* 0=normal/sieve, 1=fermat consumer  */
};

/* ══════════════════════════════════════════════════════════════════════
   CRT Gap-Solver Mining Helpers
   ══════════════════════════════════════════════════════════════════════ */

/* Modular inverse of a mod m via extended GCD.  Requires gcd(a,m)=1. */
static uint64_t mod_inv_u64(uint64_t a, uint64_t m) {
    int64_t old_r = (int64_t)a, r = (int64_t)m;
    int64_t old_s = 1, s = 0;
    while (r != 0) {
        int64_t q = old_r / r;
        int64_t t;
        t = old_r - q * r; old_r = r; r = t;
        t = old_s - q * s; old_s = s; s = t;
    }
    return (uint64_t)((old_s % (int64_t)m + (int64_t)m) % (int64_t)m);
}

/* Compute the CRT-aligned starting nAdd modulo primorial.
 *
 * For each CRT prime p_i with gap offset o_i, the alignment constraint is:
 *    (base + nAdd + o_i) ≡ 0 (mod p_i)
 * i.e.  nAdd ≡ -(base + o_i) (mod p_i)
 *
 * This positions each CRT prime's composites INSIDE the gap starting at
 * base+nAdd, ensuring maximum gap coverage.  The CRT combines all
 * congruences into a unique solution modulo primorial.
 *
 * Must be called AFTER set_base_bn() (requires tls_base_mpz). */
static uint64_t crt_compute_alignment(void) __attribute__((unused));
static uint64_t crt_compute_alignment(void) {
    /* Use __uint128_t for intermediate values to avoid overflow.
       Final result < primorial < 2^64, so cast back is safe. */
    __uint128_t nAdd0 = 0;
    __uint128_t M = 1;

    for (int i = 0; i < g_crt_n_primes; i++) {
        uint64_t p = (uint64_t)g_crt_prime_list[i];
        uint64_t o = (uint64_t)g_crt_offsets[i];
        /* offset=0 means candidate ≡ 0 mod p (always composite).
           Skip these primes — they are also excluded from the primorial. */
        if (o == 0) continue;
        uint64_t base_mod_p = mpz_fdiv_ui(tls_base_mpz, (unsigned long)p);

        /* Target: nAdd ≡ -(base + o) mod p
           = (p - (base_mod_p + o) % p) % p */
        uint64_t sum = (base_mod_p + o % p) % p;
        uint64_t target_r = sum == 0 ? 0 : p - sum;

        /* Incremental CRT: solve nAdd0 + k*M ≡ target_r (mod p) */
        uint64_t curr_r  = (uint64_t)(nAdd0 % (__uint128_t)p);
        uint64_t diff    = (target_r + p - curr_r) % p;
        uint64_t M_mod_p = (uint64_t)(M % (__uint128_t)p);
        uint64_t inv     = mod_inv_u64(M_mod_p, p);
        uint64_t k       = (diff * inv) % p;

        nAdd0 += (__uint128_t)k * M;
        M     *= (__uint128_t)p;
    }

    return (uint64_t)nAdd0;
}

/* ── GMP-based CRT alignment (arbitrary-size primorials) ──
   Same algorithm as crt_compute_alignment() but with mpz_t arithmetic
   so it works for any number of CRT primes / any shift.
   Must be called AFTER set_base_bn() (requires tls_base_mpz). */
static void crt_compute_alignment_mpz(mpz_t result) {
    mpz_t nAdd0, M, tmp_p;
    mpz_inits(nAdd0, M, tmp_p, NULL);
    mpz_set_ui(nAdd0, 0);
    mpz_set_ui(M, 1);

    for (int i = 0; i < g_crt_n_primes; i++) {
        unsigned long p = (unsigned long)g_crt_prime_list[i];
        unsigned long o = (unsigned long)g_crt_offsets[i];
        /* offset=0 means candidate ≡ 0 mod p (always composite).
           Skip these primes — they are also excluded from the primorial. */
        if (o == 0) continue;
        unsigned long base_mod_p = mpz_fdiv_ui(tls_base_mpz, p);

        unsigned long sum = (base_mod_p + o % p) % p;
        unsigned long target_r = sum == 0 ? 0 : p - sum;

        unsigned long curr_r = mpz_fdiv_ui(nAdd0, p);
        unsigned long diff   = (target_r + p - curr_r) % p;
        unsigned long M_mod_p = mpz_fdiv_ui(M, p);

        /* inv = M_mod_p^(-1) mod p via GMP */
        mpz_set_ui(tmp_p, p);
        mpz_t tmp_inv;
        mpz_init(tmp_inv);
        mpz_set_ui(tmp_inv, M_mod_p);
        mpz_invert(tmp_inv, tmp_inv, tmp_p);
        unsigned long inv = mpz_get_ui(tmp_inv);
        mpz_clear(tmp_inv);

        unsigned long k = (diff * inv) % p;

        /* nAdd0 += k * M */
        mpz_set_ui(tmp_p, k);
        mpz_addmul(nAdd0, tmp_p, M);
        mpz_mul_ui(M, M, p);
    }

    mpz_set(result, nAdd0);
    mpz_clears(nAdd0, M, tmp_p, NULL);
}

/* Direct Fermat/MR primality test on a full mpz_t value (no base+offset).
   Skips the trial-division pre-filter (which uses residues from the
   current base, not from the candidate). */
static int __attribute__((unused)) bn_is_prime_mpz(mpz_t candidate) {
    ensure_gmp_tls();
    if (use_fast_fermat) {
        mpz_sub_ui(tls_exp_mpz, candidate, 1);
        mpz_powm(tls_res_mpz, tls_two_mpz, tls_exp_mpz, candidate);
        return mpz_cmp_ui(tls_res_mpz, 1) == 0;
    } else {
        return mpz_probab_prime_p(candidate, 10) > 0;
    }
}

/* Rebase the thread-local sieve/prime-test state so that future calls
   to sieve_range() and bn_candidate_is_prime() work relative to the
   given mpz_t base position (typically a confirmed CRT prime). */
static void rebase_for_gap_check(mpz_t new_base) {
    mpz_set(tls_base_mpz, new_base);
    /* Recompute sieve prime residues */
    pthread_once(&small_primes_once, populate_small_primes_cache);
    if (tls_base_mod_p && small_primes_cache) {
        for (size_t i = 0; i < small_primes_count; i++)
            tls_base_mod_p[i] = mpz_fdiv_ui(tls_base_mpz,
                                             (unsigned long)small_primes_cache[i]);
        tls_base_mod_p_ready = 1;
    }
    /* Recompute trial-division residues */
    for (int i = 0; i < td_extra_count; i++)
        tls_td_residues[i] = (uint32_t)mpz_fdiv_ui(tls_base_mpz,
                                        (unsigned long)td_extra_primes[i]);
}

// process a list of primes searching for gaps meeting the local threshold.
// This implements dcct’s skip-ahead optimization in a slightly different
// form: after fixing the current prime `prev` we compute the maximum gap
// (`maxlen = target_local * log(prev)`) that could still meet the merit
// threshold.  Rather than testing every subsequent prime, we first locate
// the first prime outside that window and then scan **forward** through the
// candidates inside the window until a qualifying `q` is found.  If none is
// found we jump the index ahead to the window end and continue.  The forward
// scan often terminates early, saving a lot of work when the sieve returns a
// dense cluster of primes.  When a gap is discovered we handle block
// construction/submission here exactly as the old code did.  The function
// returns 1 to signal the caller (single-thread mode or a worker) that a
// valid block has been found and `!keep_going` should cause termination.
/* scan_candidates: pr[] holds relative offsets (nAdd values) from the big
   base = h256<<shift.  logbase = log(base) (precomputed, constant across
   all candidates in this window).  nAdd = pr[i] directly. */
static int scan_candidates(uint64_t *pr, size_t cnt, double target_local,
                           double logbase, int shift_sc,
                           const char *header_local,
                           const char *rpc_url_local,
                           const char *rpc_user_local,
                           const char *rpc_pass_local,
                           const char *rpc_method_local,
                           const char *rpc_sign_key_local) {
    (void)header_local;     /* param kept for API compat; abort uses g_abort_pass */
    (void)rpc_method_local; /* method is always "getwork" now */
    if (cnt > 1) __sync_fetch_and_add(&stats_pairs, (uint64_t)(cnt - 1));
    for (size_t i = 0; i + 1 < cnt; i++) {
        uint64_t prev  = pr[i];       /* nAdd of gap start prime */
        uint64_t q     = pr[i + 1];   /* nAdd of gap end prime   */
        uint64_t gap   = q - prev;
        double merit   = (double)gap / logbase;
        /* Track best merit seen (lock-free: small races are harmless) */
        if (merit > stats_best_merit) {
            stats_best_merit = merit;
            stats_best_gap   = gap;
        }
        if (merit < target_local)
            continue;

        __sync_fetch_and_add(&stats_gaps, 1);
        /* nAdd = relative offset = prev (prime = base + nAdd). */
        uint64_t nadd_sc = prev;
        log_msg("\n>>> GAP FOUND\n"
                "    gap     = %llu\n"
                "    merit   = %.6f  (need >= %.2f)\n"
                "    nShift  = %d\n"
                "    nAdd    = %llu (0x%llx)\n",
                (unsigned long long)gap,
                merit, target_local,
                shift_sc,
                (unsigned long long)nadd_sc,
                (unsigned long long)nadd_sc);
#ifdef WITH_RPC
            if (rpc_url_local) {
                if (g_abort_pass) continue;
                char blockhex[16384]; memset(blockhex, 0, sizeof(blockhex));
                if (assemble_mining_block(nadd_sc, blockhex)) {
                    __sync_fetch_and_add(&stats_blocks, 1);
                    log_file_only("Built blockhex: %s\n", blockhex);
                    if (header_meets_target_hex(blockhex)) {
                        log_msg(">>> SUBMITTING  merit=%.6f  gap=%llu  nShift=%d  nAdd=%llu\n",
                                merit, (unsigned long long)gap,
                                shift_sc, (unsigned long long)nadd_sc);
                        __sync_fetch_and_add(&stats_submits, 1);
                        if (g_stratum) {
                            /* Submit via stratum (non-blocking) */
                            if (stratum_submit(g_stratum, blockhex)) {
                                log_msg(">>> SUBMITTED via stratum\n");
                            } else {
                                log_msg(">>> stratum submit FAILED\n");
                            }
                            print_stats();
                        } else {
                            /* Submit via HTTP RPC (async queue) */
                            if (rpc_sign_key_local) {
                                char sig[65];
                                hmac_sha256_hex(rpc_sign_key_local, blockhex, sig);
                                log_msg("    signature: %s\n", sig);
                            }
                            /* Only one submission per block round */
                            pthread_mutex_lock(&sq_lock);
                            int sq_busy = (sq_count > 0);
                            pthread_mutex_unlock(&sq_lock);
                            if (sq_busy) continue;
                            struct submit_job _job;
                            memset(&_job, 0, sizeof(_job));
                            strncpy(_job.url,    rpc_url_local,                     sizeof(_job.url)-1);
                            strncpy(_job.user,   rpc_user_local  ? rpc_user_local  : "", sizeof(_job.user)-1);
                            strncpy(_job.pass,   rpc_pass_local  ? rpc_pass_local  : "", sizeof(_job.pass)-1);
                            strncpy(_job.method, "getwork",                         sizeof(_job.method)-1);
                            memcpy(_job.hex, blockhex, sizeof(_job.hex));
                            _job.retries = rpc_default_retries;
                            enqueue_job(&_job);
                            log_msg(">>> QUEUED for async submit (mining continues)\n");
                            print_stats();
                        }
                        if (!keep_going) return 1;
                        else log_msg("continuing mining after success\n");
                    }
                } else {
                    log_msg("Failed to assemble getwork block\n");
                }
            }
#endif
    }   /* end for */
    return 0;
}

/* ---------- Pre-sieve pipeline (double-buffer) ----------
   Each worker thread has a companion "sieve helper" thread.  While the
   worker does primality tests + gap scan on window N, the helper is already
   sieving window N+nthreads into the OTHER buffer slot.  When primality
   finishes the next sieve result is ready immediately, eliminating the
   idle stall where one stage waited for the other.

   Two heap-allocated buffer slots ping-pong: helper always writes into
   bufs[fill_slot] while the worker reads bufs[1-fill_slot].  The helper
   uses its own thread-local sieve buffers (TLS is per-thread), so
   sieve_range is safe to call concurrently from both threads. */

struct presieve_buf {
    uint64_t *pr;
    size_t    cap;
    size_t    cnt;
    uint64_t  L, R;
};

/* Cooperative Fermat work-sharing: after the helper finishes sieving
   the next window, it joins the worker to test the CURRENT window's
   candidates.  Both threads pull from a shared atomic index.
   On an 8-thread CPU with 6 workers + 6 helpers, this uses the otherwise-
   idle HT siblings for useful work — effectively doubling Fermat throughput
   per worker without increasing thread count.                              */
struct coop_fermat {
    uint64_t       *pr;          /* shared candidate array (current window) */
    size_t          cnt;         /* total candidate count                   */
    volatile size_t next_idx;    /* atomic work index (fetch-and-add)       */
    uint64_t       *out;         /* helper's confirmed primes               */
    size_t          out_cnt;     /* number of primes found by helper        */
    size_t          out_cap;     /* capacity of out[]                       */
    volatile int    active;      /* 1 = work available for helper           */
    volatile int    helper_done; /* 1 = helper finished its Fermat batch    */
    volatile int    more_work;   /* 1 = worker will set up another phase    */
};

struct presieve_ctx {
    struct presieve_buf bufs[2]; /* ping-pong slots                     */
    int fill_slot;               /* helper writes into bufs[fill_slot]  */
    int state;                   /* 0=idle 1=sieving 2=ready 3=fermat-only -1=exit */
    pthread_mutex_t mu;
    pthread_cond_t  cv_go;       /* worker -> helper: new window ready  */
    pthread_cond_t  cv_done;     /* helper -> worker: result ready      */
    pthread_t thread;
    const uint8_t *h256;         /* 256-bit base hash (for sieve_range) */
    int            shift;        /* bit shift for prime size             */
    struct coop_fermat coop;     /* cooperative Fermat testing state     */
};

static void presieve_buf_ensure(struct presieve_buf *b, size_t need) {
    if (b->cap >= need) return;
    size_t nc = need + (need >> 1) + 64;
    b->pr  = realloc(b->pr, nc * sizeof(uint64_t));
    b->cap = nc;
}

/* Helper: assist with Fermat testing from the shared cooperative work queue.
   Called after the helper finishes sieving; runs until all candidates consumed.
   When more_work is set, the helper loops: after finishing one batch it spins
   on helper_done until the worker clears it (meaning a new batch is ready)
   or sets active=0 (meaning no more work).                                  */
static void coop_fermat_assist(struct presieve_ctx *ctx) {
    struct coop_fermat *co = &ctx->coop;
    if (!co->active) return;

    for (;;) {
        /* Process current batch of candidates */
        for (;;) {
            size_t idx = __sync_fetch_and_add(&co->next_idx, 1);
            if (idx >= co->cnt) break;
            if (bn_candidate_is_prime(co->pr[idx])) {
                /* Store confirmed prime in helper's private output buffer */
                if (co->out_cnt >= co->out_cap) {
                    size_t nc = co->out_cap ? co->out_cap * 2 : 256;
                    co->out = realloc(co->out, nc * sizeof(uint64_t));
                    co->out_cap = nc;
                }
                co->out[co->out_cnt++] = co->pr[idx];
            }
            /* Incremental stats: report every 4096 tests so the counter
               moves smoothly even with large sieve windows (33M+).     */
            if (((idx + 1) & 0xFFF) == 0)
                __sync_fetch_and_add(&stats_tested, 4096);
        }

        /* Signal worker: this batch is done, out[] is up to date. */
        __sync_synchronize();
        co->helper_done = 1;

        /* If no more phases expected, exit. */
        if (!co->more_work) break;

        /* Wait for worker to set up next phase (worker clears helper_done)
           or to deactivate us (worker sets active=0 then clears helper_done). */
        while (co->helper_done)
            __asm__ volatile("pause" ::: "memory");
        if (!co->active) break;
    }
}

static void *presieve_helper_fn(void *arg) {
    struct presieve_ctx *ctx = arg;
    /* Initialize helper's GMP TLS base to match the worker's.
       This is needed so bn_candidate_is_prime() works correctly
       when the helper assists with cooperative Fermat testing.    */
    set_base_bn(ctx->h256, ctx->shift);
    for (;;) {
        pthread_mutex_lock(&ctx->mu);
        while (ctx->state != 1 && ctx->state != 3 && ctx->state != -1)
            pthread_cond_wait(&ctx->cv_go, &ctx->mu);
        if (ctx->state == -1) { pthread_mutex_unlock(&ctx->mu); break; }

        int need_sieve = (ctx->state == 1);

        if (need_sieve) {
            int slot   = ctx->fill_slot;
            uint64_t L = ctx->bufs[slot].L;
            uint64_t R = ctx->bufs[slot].R;
            pthread_mutex_unlock(&ctx->mu);

            /* sieve using this helper's own TLS */
            size_t cnt = 0;
            uint64_t *pr_tls = sieve_range(L, R, &cnt, ctx->h256, ctx->shift);

            pthread_mutex_lock(&ctx->mu);
            struct presieve_buf *b = &ctx->bufs[slot];
            if (ctx->state != -1) {
                presieve_buf_ensure(b, cnt);
                if (cnt && pr_tls)
                    memcpy(b->pr, pr_tls, cnt * sizeof(uint64_t));
                b->cnt = cnt;
                ctx->state = 2;
                pthread_cond_signal(&ctx->cv_done);
            }
            __sync_fetch_and_add(&stats_sieved, (uint64_t)(R - L));
            pthread_mutex_unlock(&ctx->mu);
        } else {
            /* state=3: no sieving needed, just assist with Fermat */
            pthread_mutex_unlock(&ctx->mu);
        }

        /* Assist with Fermat testing on the current window.
           For state=1: helper finished sieving, now helps with Fermat.
           For state=3: helper skipped sieving, goes straight to Fermat. */
        coop_fermat_assist(ctx);
    }
    free_sieve_buffers(); /* release helper's TLS */
    if (tls_gmp_inited) {
        mpz_clear(tls_base_mpz);
        mpz_clear(tls_cand_mpz);
        mpz_clear(tls_two_mpz);
        mpz_clear(tls_exp_mpz);
        mpz_clear(tls_res_mpz);
        tls_gmp_inited = 0;
    }
    free(ctx->coop.out);  /* release coop output buffer */
    return NULL;
}

/* Compute the L/R range for window index widx. Returns 0 if empty. */
static int presieve_window(int64_t widx, uint64_t base,
                           uint64_t sieve_size, uint64_t adder_max,
                           uint64_t *out_L, uint64_t *out_R) {
    uint64_t L = base + (uint64_t)widx * sieve_size;
    if ((L & 1) == 0) L++;
    uint64_t R = L + sieve_size;
    uint64_t cap = base + adder_max;
    if (R > cap) R = cap;
    if (R <= L) return 0;
    *out_L = L; *out_R = R;
    return 1;
}

static void *worker_fn(void *arg) {
    struct worker_args *wa          = (struct worker_args*)arg;
    uint8_t  h256_local[32];
    memcpy(h256_local, wa->h256, 32);
    int      shift_local            = wa->shift;
    int64_t  adder_max_local        = wa->adder_max;
    uint64_t sieve_size_local       = wa->sieve_size;
    double   target_local           = wa->target;
    int64_t  adder_base_offset_local = wa->adder_base_offset;
    int      rpc_thread_local       = wa->rpc_thread;
    const char *header_local = NULL, *rpc_url_local = NULL, *rpc_user_local = NULL;
    const char *rpc_pass_local = NULL, *rpc_method_local = NULL, *rpc_sign_key_local = NULL;
#ifdef WITH_RPC
    header_local       = wa->header;
    rpc_url_local      = wa->rpc_url;
    rpc_user_local     = wa->rpc_user;
    rpc_pass_local     = wa->rpc_pass;
    rpc_method_local   = wa->rpc_method;
    rpc_sign_key_local = wa->rpc_sign_key;
#endif

    /* Precompute log(base) = log(h256 << shift) for merit calculation.      */
    double logbase = uint256_log_approx(h256_local, shift_local);
    /* Set thread-local base BIGNUM = h256 << shift for primality tests.     */
    set_base_bn(h256_local, shift_local);

    /* This thread covers adder offsets [rel_base, rel_base+adder_max_local) */
    uint64_t base       = (uint64_t)adder_base_offset_local;  /* relative from big base */
    int64_t  num_windows = ((int64_t)adder_max_local + (int64_t)sieve_size_local - 1)
                           / (int64_t)sieve_size_local;
    if (num_windows == 0) return NULL;

    /* ══════════════════════════════════════════════════════════════════
       CRT Gap-Solver Mining Path  (GMP / nonce-parallel)
       ══════════════════════════════════════════════════════════════════
       When CRT_MODE_SOLVER is active, skip the normal windowed sieve.
       Each thread iterates nonces independently (thread t starts at
       g_pass.nonce + 1 + tid, stepping by nthreads).  For every valid
       nonce (SHA256d[31] >= 0x80) the CRT alignment is computed and
       candidates nAdd0, nAdd0+primorial, nAdd0+2*primorial … < 2^shift
       are Fermat-tested.  Each confirmed prime triggers a small forward
       gap-check sieve to measure the gap and (optionally) submit.
       ══════════════════════════════════════════════════════════════════ */
    if (g_crt_mode == CRT_MODE_SOLVER && g_crt_primorial_mpz_init) {
#ifdef WITH_RPC
        int      tid_local     = wa->tid;
        int      gap_scan_max  = g_crt_gap_target * 2;
        if (gap_scan_max < 10000) gap_scan_max = 10000;

        /* crt_end = 2^shift  (upper bound for nAdd) */
        mpz_t crt_end;
        mpz_init(crt_end);
        mpz_ui_pow_ui(crt_end, 2, (unsigned long)shift_local);

        /* ═══════════════════════════════════════════════════════════
           FERMAT CONSUMER THREAD  (producer-consumer mode only)
           Pop the best sieved window from the heap, Fermat-test all
           survivors, scan consecutive prime pairs for qualifying gaps.
           ═══════════════════════════════════════════════════════════ */
        if (wa->crt_role == 1 && crt_fermat_threads > 0) {
            ensure_gmp_tls();

            while (keep_going && !g_abort_pass) {
                struct crt_work_item *w = crt_heap_pop();
                if (!w) break; /* abort or shutdown */

                /* Discard stale items from previous template */
                if (w->generation != crt_heap_gen) {
                    crt_work_free(w);
                    continue;
                }

                /* Set thread-local base for Fermat testing */
                mpz_set(tls_base_mpz, w->base);

                /* Fermat-test ALL survivors to find primes */
                size_t pf = 0;
#ifdef WITH_CUDA
                if (g_gpu_count > 0) {
                    pf = gpu_batch_filter(w->survivors, w->surv_cnt);
                    __sync_fetch_and_add(&stats_tested, (uint64_t)w->surv_cnt);
                } else
#endif
                {
                    for (size_t j = 0; j < w->surv_cnt; j++) {
                        __sync_fetch_and_add(&stats_tested, 1);
                        if (bn_candidate_is_prime(w->survivors[j]))
                            w->survivors[pf++] = w->survivors[j];
                    }
                }

                /* Scan consecutive prime pairs for qualifying gaps */
                __sync_fetch_and_add(&stats_crt_windows, 1);
                __sync_fetch_and_add(&stats_primes_found, (uint64_t)pf);
                if (pf >= 2) {
                    __sync_fetch_and_add(&stats_pairs, (uint64_t)(pf - 1));
                    for (size_t i = 0; i + 1 < pf; i++) {
                        uint64_t gap = w->survivors[i + 1] - w->survivors[i];
                        double merit = (double)gap / w->logbase;
                        if (merit > stats_best_merit) {
                            stats_best_merit = merit;
                            stats_best_gap   = gap;
                        }
                        if (merit < target_local) continue;

                        __sync_fetch_and_add(&stats_gaps, 1);

                        mpz_t nAdd_prime;
                        mpz_init(nAdd_prime);
                        mpz_set(nAdd_prime, w->nAdd);
                        mpz_add_ui(nAdd_prime, nAdd_prime, w->survivors[i]);
                        if (w->cand_odd)
                            mpz_sub_ui(nAdd_prime, nAdd_prime, 1);

                        char nAdd_str[256];
                        gmp_snprintf(nAdd_str, sizeof(nAdd_str), "%Zd",
                                     nAdd_prime);
                        log_msg("\n>>> GAP FOUND\n"
                                "    gap     = %llu\n"
                                "    merit   = %.6f  (need >= %.2f)\n"
                                "    nShift  = %d\n"
                                "    nonce   = %u\n"
                                "    nAdd    = %s\n",
                                (unsigned long long)gap,
                                merit, target_local,
                                shift_local,
                                (unsigned)w->nonce,
                                nAdd_str);

                        if (rpc_url_local && !g_abort_pass) {
                            pthread_mutex_lock(&sq_lock);
                            int sq_busy = (sq_count > 0);
                            pthread_mutex_unlock(&sq_lock);
                            if (!sq_busy) {
                                char blockhex[16384];
                                memset(blockhex, 0, sizeof(blockhex));
                                if (assemble_mining_block_mpz(w->nonce,
                                        nAdd_prime, blockhex)) {
                                    __sync_fetch_and_add(&stats_blocks, 1);
                                    log_file_only("Built blockhex: %s\n",
                                                  blockhex);
                                    if (header_meets_target_hex(blockhex)) {
                                        log_msg(">>> SUBMITTING to node\n"
                                                "    merit=%.6f  gap=%llu"
                                                "  nShift=%d  nonce=%u\n",
                                                merit,
                                                (unsigned long long)gap,
                                                shift_local,
                                                (unsigned)w->nonce);
                                        struct submit_job _job;
                                        memset(&_job, 0, sizeof(_job));
                                        strncpy(_job.url, rpc_url_local,
                                                sizeof(_job.url)-1);
                                        strncpy(_job.user,
                                                rpc_user_local ? rpc_user_local : "",
                                                sizeof(_job.user)-1);
                                        strncpy(_job.pass,
                                                rpc_pass_local ? rpc_pass_local : "",
                                                sizeof(_job.pass)-1);
                                        strncpy(_job.method, "getwork",
                                                sizeof(_job.method)-1);
                                        memcpy(_job.hex, blockhex,
                                               sizeof(_job.hex));
                                        _job.retries = rpc_default_retries;
                                        __sync_fetch_and_add(&stats_submits, 1);
                                        enqueue_job(&_job);
                                        log_msg(">>> QUEUED for async submit"
                                                " (mining continues)\n");
                                        print_stats();
                                    }
                                } else {
                                    log_msg("Failed to assemble block\n");
                                }
                            }
                        }

                        mpz_clear(nAdd_prime);
                    }
                }

                crt_work_free(w);
            } /* end fermat consumer loop */

            mpz_clear(crt_end);
            if (tls_gmp_inited) {
                mpz_clear(tls_base_mpz);
                mpz_clear(tls_cand_mpz);
                mpz_clear(tls_two_mpz);
                mpz_clear(tls_exp_mpz);
                mpz_clear(tls_res_mpz);
                tls_gmp_inited = 0;
            }
            return NULL;
        }

        /* ═══════════════════════════════════════════════════════════
           SIEVE PRODUCER THREAD (or monolithic if no fermat threads)
           Iterate nonces, CRT-align, sieve each window.
           — If crt_fermat_threads > 0: push sieved windows to heap.
           — If crt_fermat_threads == 0: test inline (original path).
           ═══════════════════════════════════════════════════════════ */
        {
            int n_sieve_threads = wa->nthreads - crt_fermat_threads;
            if (n_sieve_threads < 1) n_sieve_threads = 1;
            int nth_local = (crt_fermat_threads > 0) ? n_sieve_threads
                                                     : wa->nthreads;

            if (rpc_thread_local) {
                size_t prim_bits = mpz_sizeinbase(g_crt_primorial_mpz, 2);
                if (crt_fermat_threads > 0)
                    log_msg("CRT mining (%dT: %d sieve + %d fermat): "
                            "primorial~2^%zu  shift=%d  gap_scan=%d  heap=%d\n",
                            wa->nthreads, n_sieve_threads,
                            crt_fermat_threads,
                            prim_bits, shift_local, gap_scan_max,
                            CRT_HEAP_CAP);
                else
                    log_msg("CRT mining (%dT): primorial~2^%zu  shift=%d"
                            "  gap_scan=%d\n",
                            nth_local, prim_bits, shift_local, gap_scan_max);
            }

#ifdef WITH_RPC
            uint64_t gbt_last_ms = now_ms();
#endif

            uint32_t nonce_cur = g_pass.nonce + 1 + (uint32_t)tid_local;

            mpz_t nAdd, candidate, orig_base_crt;
            mpz_inits(nAdd, candidate, orig_base_crt, NULL);

            uint64_t *prim_mod_sieve = NULL;
            size_t    prim_mod_count = 0;

            while (keep_going && !g_abort_pass) {

#ifdef WITH_RPC
                /* Poll for new blocks every 5 s (rpc thread only) */
                if (rpc_thread_local && rpc_url_local) {
                    uint64_t now = now_ms();
                    if (now - gbt_last_ms >= 5000) {
                      if (g_stratum) {
                        /* ── stratum: check for pushed new-work ── */
                        char data_hex[161];
                        uint64_t ndiff;
                        if (stratum_poll_new_work(g_stratum, data_hex,
                                                  &ndiff)) {
                            log_msg("\n*** STRATUM NEW BLOCK ***\n\n");
                            build_mining_pass_stratum(data_hex, ndiff,
                                                     shift_local);
                            g_abort_pass = 1;
                            crt_heap_shutdown = 1;
                            pthread_cond_broadcast(&crt_heap_cv);
                            break;
                        }
                      } else {
                        char *resp = rpc_call(rpc_url_local, rpc_user_local,
                                              rpc_pass_local,
                                              "getbestblockhash", NULL);
                        if (resp) {
                            const char *q1 = strchr(resp, '"');
                            if (q1) q1 = strchr(q1+1, '"');
                            if (q1) q1 = strchr(q1+1, '"');
                            const char *q2 = q1 ? strchr(q1+1, '"') : NULL;
                            if (q1 && q2 && (q2-q1-1) == 64) {
                                char best[65];
                                memcpy(best, q1+1, 64); best[64] = '\0';
                                if (g_pass.prevhex[0] &&
                                    strcmp(best, g_pass.prevhex) != 0) {
                                    log_msg("\n*** NEW BLOCK  prevhash=%.16s..."
                                            "  mining on top ***\n\n", best);
                                    pthread_mutex_lock(&g_work_lock);
                                    strncpy(g_prevhash, best, 64);
                                    g_prevhash[64] = '\0';
                                    pthread_mutex_unlock(&g_work_lock);
                                    free(resp);
                                    g_abort_pass = 1;
                                    crt_heap_shutdown = 1;
                                    pthread_cond_broadcast(&crt_heap_cv);
                                    break;
                                }
                            }
                            free(resp);
                        }
                      }
                        gbt_last_ms = now_ms();
                    }
                }
#endif

                /* ── Compute SHA256d for this nonce ── */
                uint8_t hdr84[84], sha_raw[32], h256_nonce[32];
                memcpy(hdr84, g_pass.hdr80, 80);
                memcpy(hdr84 + 80, &nonce_cur, 4);
                double_sha256(hdr84, 84, sha_raw);

                if (sha_raw[31] < 0x80) {
                    nonce_cur += (uint32_t)nth_local;
                    if (nonce_cur < (uint32_t)nth_local) break;
                    continue;
                }

                for (int k = 0; k < 32; k++)
                    h256_nonce[k] = sha_raw[31 - k];

                set_base_bn(h256_nonce, shift_local);
                double logbase_nonce =
                    uint256_log_approx(h256_nonce, shift_local);

                crt_compute_alignment_mpz(nAdd);
                mpz_set(orig_base_crt, tls_base_mpz);

                if (!prim_mod_sieve && small_primes_cache &&
                    small_primes_count > 0) {
                    prim_mod_count = small_primes_count;
                    prim_mod_sieve = (uint64_t *)malloc(
                        prim_mod_count * sizeof(uint64_t));
                    if (prim_mod_sieve) {
                        for (size_t pi = 0; pi < prim_mod_count; pi++)
                            prim_mod_sieve[pi] = mpz_fdiv_ui(
                                g_crt_primorial_mpz,
                                (unsigned long)small_primes_cache[pi]);
                    }
                }

                mpz_add(candidate, orig_base_crt, nAdd);
                int cand_odd = mpz_odd_p(candidate);
                if (cand_odd) mpz_sub_ui(candidate, candidate, 1);
                rebase_for_gap_check(candidate);
                int crt_first_win = 1;

                while (mpz_cmp(nAdd, crt_end) < 0 &&
                       keep_going && !g_abort_pass) {

                    if (!crt_first_win) {
                        mpz_add(tls_base_mpz, tls_base_mpz,
                                g_crt_primorial_mpz);
                        if (prim_mod_sieve && tls_base_mod_p) {
                            for (size_t pi = 0; pi < prim_mod_count; pi++) {
                                tls_base_mod_p[pi] += prim_mod_sieve[pi];
                                if (tls_base_mod_p[pi] >=
                                    small_primes_cache[pi])
                                    tls_base_mod_p[pi] -=
                                        small_primes_cache[pi];
                            }
                        }
                    }
                    crt_first_win = 0;

                    uint64_t gap_L = 1;
                    uint64_t gap_R = (uint64_t)gap_scan_max;
                    size_t surv_cnt = 0;
                    uint64_t *surv = sieve_range(gap_L, gap_R,
                                                 &surv_cnt, NULL, 0);
                    __sync_fetch_and_add(&stats_sieved, gap_R - gap_L);

                    if (!surv || surv_cnt == 0) {
                        mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
                        continue;
                    }

                    /* ── Producer-consumer: push to heap ── */
                    if (crt_fermat_threads > 0) {
                        struct crt_work_item *w = crt_work_alloc();
                        if (w) {
                            mpz_set(w->base, tls_base_mpz);
                            mpz_set(w->nAdd, nAdd);
                            w->survivors = (uint64_t *)malloc(
                                surv_cnt * sizeof(uint64_t));
                            if (w->survivors)
                                memcpy(w->survivors, surv,
                                       surv_cnt * sizeof(uint64_t));
                            else
                                surv_cnt = 0;
                            w->surv_cnt   = surv_cnt;
                            w->nonce      = nonce_cur;
                            w->cand_odd   = cand_odd;
                            w->logbase    = logbase_nonce;
                            w->generation = crt_heap_gen;
                            crt_heap_push(w); /* may discard if worse */
                        }
                        mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
                        continue;
                    }

                    /* ── Monolithic: Fermat-test ── */
                    size_t pf = 0;
#ifdef WITH_CUDA
                    if (g_gpu_count > 0) {
                        /* Lazy-init thread-local GPU accumulator */
                        if (!tls_gpu_accum) {
                            static volatile int accum_rr = 0;
                            int gi = __sync_fetch_and_add(&accum_rr, 1)
                                     % g_gpu_count;
                            tls_gpu_accum = gpu_accum_create(
                                g_gpu_ctx[gi], g_gpu_batch_size);
                        }
                        if (tls_gpu_accum) {
                            ensure_gmp_tls();
                            uint64_t bl[GPU_NLIMBS];
                            memset(bl, 0, sizeof(bl));
                            size_t nexp = 0;
                            mpz_export(bl, &nexp, -1, 8, 0, 0,
                                       tls_base_mpz);
                            if (nexp <= (size_t)GPU_NLIMBS) {
                                __sync_fetch_and_add(&stats_tested,
                                    (uint64_t)surv_cnt);
                                if (gpu_accum_add(tls_gpu_accum, bl,
                                        surv, surv_cnt, nonce_cur,
                                        cand_odd, logbase_nonce,
                                        target_local, shift_local,
                                        nAdd, rpc_url_local,
                                        rpc_user_local, rpc_pass_local))
                                    gpu_accum_flush(tls_gpu_accum);
                                mpz_add(nAdd, nAdd,
                                        g_crt_primorial_mpz);
                                continue;
                            }
                            /* nexp > GPU_NLIMBS: fall through to CPU */
                        }
                        /* Accumulator unavailable: direct GPU batch */
                        pf = gpu_batch_filter(surv, surv_cnt);
                        __sync_fetch_and_add(&stats_tested,
                                             (uint64_t)surv_cnt);
                    } else
#endif
                    {
                        for (size_t j = 0; j < surv_cnt; j++) {
                            __sync_fetch_and_add(&stats_tested, 1);
                            if (bn_candidate_is_prime(surv[j]))
                                surv[pf++] = surv[j];
                        }
                    }

                    /* Gap processing (CPU path + GPU fallback) */
                    __sync_fetch_and_add(&stats_crt_windows, 1);
                    __sync_fetch_and_add(&stats_primes_found, (uint64_t)pf);
                    if (pf >= 2) {
                        __sync_fetch_and_add(&stats_pairs,
                                             (uint64_t)(pf - 1));
                        for (size_t i = 0; i + 1 < pf; i++) {
                            uint64_t gap = surv[i + 1] - surv[i];
                            double merit = (double)gap / logbase_nonce;
                            if (merit > stats_best_merit) {
                                stats_best_merit = merit;
                                stats_best_gap   = gap;
                            }
                            if (merit < target_local) continue;

                            __sync_fetch_and_add(&stats_gaps, 1);

                            mpz_t nAdd_prime;
                            mpz_init(nAdd_prime);
                            mpz_set(nAdd_prime, nAdd);
                            mpz_add_ui(nAdd_prime, nAdd_prime, surv[i]);
                            if (cand_odd)
                                mpz_sub_ui(nAdd_prime, nAdd_prime, 1);

                            char nAdd_str[256];
                            gmp_snprintf(nAdd_str, sizeof(nAdd_str),
                                         "%Zd", nAdd_prime);
                            log_msg("\n>>> GAP FOUND\n"
                                    "    gap     = %llu\n"
                                    "    merit   = %.6f  (need >= %.2f)\n"
                                    "    nShift  = %d\n"
                                    "    nonce   = %u\n"
                                    "    nAdd    = %s\n",
                                    (unsigned long long)gap,
                                    merit, target_local,
                                    shift_local,
                                    (unsigned)nonce_cur,
                                    nAdd_str);
                            if (rpc_url_local && !g_abort_pass) {
                                pthread_mutex_lock(&sq_lock);
                                int sq_busy = (sq_count > 0);
                                pthread_mutex_unlock(&sq_lock);
                                if (!sq_busy) {
                                    char blockhex[16384];
                                    memset(blockhex, 0, sizeof(blockhex));
                                    if (assemble_mining_block_mpz(nonce_cur,
                                            nAdd_prime, blockhex)) {
                                        __sync_fetch_and_add(&stats_blocks, 1);
                                        log_file_only("Built blockhex: %s\n",
                                                      blockhex);
                                        if (header_meets_target_hex(blockhex)) {
                                            log_msg(">>> SUBMITTING to node\n"
                                                    "    merit=%.6f  gap=%llu"
                                                    "  nShift=%d  nonce=%u\n",
                                                    merit,
                                                    (unsigned long long)gap,
                                                    shift_local,
                                                    (unsigned)nonce_cur);
                                            struct submit_job _job;
                                            memset(&_job, 0, sizeof(_job));
                                            strncpy(_job.url, rpc_url_local,
                                                    sizeof(_job.url)-1);
                                            strncpy(_job.user,
                                                    rpc_user_local ? rpc_user_local : "",
                                                    sizeof(_job.user)-1);
                                            strncpy(_job.pass,
                                                    rpc_pass_local ? rpc_pass_local : "",
                                                    sizeof(_job.pass)-1);
                                            strncpy(_job.method, "getwork",
                                                    sizeof(_job.method)-1);
                                            memcpy(_job.hex, blockhex,
                                                   sizeof(_job.hex));
                                            _job.retries = rpc_default_retries;
                                            __sync_fetch_and_add(&stats_submits, 1);
                                            enqueue_job(&_job);
                                            log_msg(">>> QUEUED for async submit"
                                                    " (mining continues)\n");
                                            print_stats();
                                        }
                                    } else {
                                        log_msg("Failed to assemble block\n");
                                    }
                                }
                            }
                            mpz_clear(nAdd_prime);
                        }
                    }

                    mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
                } /* end CRT candidate loop */
#ifdef WITH_CUDA
                /* Flush any remaining accumulated GPU windows */
                if (tls_gpu_accum && tls_gpu_accum->win_count > 0) {
                    if (g_abort_pass)
                        gpu_accum_reset(tls_gpu_accum);
                    else
                        gpu_accum_flush(tls_gpu_accum);
                }
#endif

                nonce_cur += (uint32_t)nth_local;
                if (nonce_cur < (uint32_t)nth_local) break;

            } /* end nonce loop */

            mpz_clears(nAdd, candidate, orig_base_crt, crt_end, NULL);
            free(prim_mod_sieve);
        }

        /* ── CRT cleanup ── */
#ifdef WITH_CUDA
        if (tls_gpu_accum) {
            gpu_accum_destroy(tls_gpu_accum);
            tls_gpu_accum = NULL;
        }
#endif
        free_sieve_buffers();
        if (tls_gmp_inited) {
            mpz_clear(tls_base_mpz);
            mpz_clear(tls_cand_mpz);
            mpz_clear(tls_two_mpz);
            mpz_clear(tls_exp_mpz);
            mpz_clear(tls_res_mpz);
            tls_gmp_inited = 0;
        }
        return NULL;
#else
        /* Non-RPC build: CRT-SOLVER requires nonce iteration (needs header).
           Fall through to normal sieve path. */
        (void)0;
#endif
    }
    /* ══════════════════════════════════════════════════════════════════ */

    /* Pre-sieve helper lives for the whole thread lifetime – no respawn
       between passes, eliminating teardown overhead between cycles.        */
    struct presieve_ctx psc;
    memset(&psc, 0, sizeof(psc));
    pthread_mutex_init(&psc.mu, NULL);
    pthread_cond_init(&psc.cv_go,   NULL);
    pthread_cond_init(&psc.cv_done, NULL);
    psc.state = 0; psc.fill_slot = 0;
    psc.h256  = h256_local;  /* helper needs h256/shift for sieve_range */
    psc.shift = shift_local;
    pthread_create(&psc.thread, NULL, presieve_helper_fn, &psc);

#ifdef WITH_RPC
    /* Initialise here (not as static=0) so the first poll fires 5 s after
       the worker STARTS, not immediately.  A static zero means now_ms()-0
       is always ≥ 5000, causing an instant getbestblockhash call on the
       very first window — before any gap is searched — which races with
       build_mining_pass and sets g_abort_pass=1, making built=0 forever. */
    uint64_t gbt_last_ms = now_ms();
#endif

    /* Outer loop: mine continuously (same slice, same header) until either
       - a new block is detected by the RPC poller (g_abort_pass = 1), or
       - SIGINT clears keep_going, or
       - stop-after-block mode: scan_candidates returns 1.                  */
    while (keep_going && !g_abort_pass) {
        /* ---- prime the pipeline: kick off window 0 ---- */
        {
            uint64_t L0, R0;
            if (presieve_window(0, base, sieve_size_local,
                                (uint64_t)adder_max_local, &L0, &R0)) {
                pthread_mutex_lock(&psc.mu);
                psc.bufs[0].L = L0; psc.bufs[0].R = R0;
                psc.fill_slot = 0; psc.state = 1;
                pthread_cond_signal(&psc.cv_go);
                pthread_mutex_unlock(&psc.mu);
            }
        }

        for (int64_t adder = 0; adder < num_windows; adder++) {
            if (g_abort_pass || !keep_going) break;

#ifdef WITH_RPC
            if (rpc_thread_local && rpc_url_local) {
                uint64_t now = now_ms();
                if (now - gbt_last_ms >= 5000) {
                    if (g_stratum) {
                        /* Stratum: check if pool pushed new work */
                        char sdata[161]; uint64_t sndiff = 0;
                        if (stratum_poll_new_work(g_stratum, sdata, &sndiff)) {
                            build_mining_pass_stratum(sdata, sndiff, shift_local);
                            log_msg("\n*** NEW BLOCK (stratum)  prevhash=%.16s...  mining on top ***\n\n",
                                    g_pass.prevhex);
                            pthread_mutex_lock(&g_work_lock);
                            strncpy(g_prevhash, g_pass.prevhex, 64); g_prevhash[64] = '\0';
                            pthread_mutex_unlock(&g_work_lock);
                            g_abort_pass = 1; break;
                        }
                    } else {
                    /* Use getbestblockhash — a pure read-only query that does NOT
                       touch mapNewBlock.  Calling getwork (no params) here would
                       invoke CreateNewBlock(), clear mapNewBlock, and invalidate
                       the merkle root our pending submission references, causing
                       every gap found after the 5s poll to return result=false. */
                    char *resp = rpc_call(rpc_url_local, rpc_user_local, rpc_pass_local,
                                         "getbestblockhash", NULL);
                    if (resp) {
                        /* response: {"result":"<64-hex>","error":null,...}
                           Three strchr jumps land q1 on the opening quote of
                           the hash value; q2 is its closing quote 64 chars on. */
                        const char *q1 = strchr(resp, '"');   /* " before result */
                        if (q1) q1 = strchr(q1+1, '"');       /* " after  result */
                        if (q1) q1 = strchr(q1+1, '"');       /* " opening hash  */
                        const char *q2 = q1 ? strchr(q1+1, '"') : NULL; /* " closing hash */
                        if (q1 && q2 && (q2-q1-1) == 64) {
                            char best[65];
                            memcpy(best, q1+1, 64); best[64] = '\0';
                            /* g_pass.prevhex is the parent of the block we mine;
                               if getbestblockhash differs, a new block landed */
                            if (g_pass.prevhex[0] &&
                                strcmp(best, g_pass.prevhex) != 0) {
                                log_msg("\n*** NEW BLOCK  prevhash=%.16s...  mining on top ***\n\n",
                                        best);
                                pthread_mutex_lock(&g_work_lock);
                                strncpy(g_prevhash, best, 64); g_prevhash[64] = '\0';
                                pthread_mutex_unlock(&g_work_lock);
                                free(resp);
                                g_abort_pass = 1; break;
                            }
                        }
                        free(resp);
                    }
                    } /* end !g_stratum */
                    gbt_last_ms = now_ms();
                }
            }
#endif

            /* Wait for helper to finish sieving the current window          */
            pthread_mutex_lock(&psc.mu);
            while (psc.state == 1)
                pthread_cond_wait(&psc.cv_done, &psc.mu);
            if (psc.state != 2) { pthread_mutex_unlock(&psc.mu); break; }

            int cur_slot = psc.fill_slot;
            size_t cnt   = psc.bufs[cur_slot].cnt;

            /* Kick off NEXT window before primality so they overlap         */
            int64_t next_win = adder + 1;
            if (next_win < num_windows && !g_abort_pass && keep_going) {
                int next_slot = 1 - cur_slot;
                uint64_t nL, nR;
                if (presieve_window(next_win, base, sieve_size_local,
                                    (uint64_t)adder_max_local, &nL, &nR)) {
                    psc.bufs[next_slot].L = nL;
                    psc.bufs[next_slot].R = nR;
                    psc.fill_slot = next_slot;
                    psc.state = 1;
                    pthread_cond_signal(&psc.cv_go);
                } else {
                    psc.state = 0;
                }
            } else if (!g_abort_pass && keep_going) {
                /* Last window of pass — no sieve work, but still enlist the
                   helper for Fermat testing (state=3).  Without this, the
                   helper would idle on every last window, which is 50% of all
                   windows when sieve-size is large (e.g. 33M / 268M = 8 wins
                   per pass, only 7 have cooperative Fermat otherwise).      */
                psc.state = 3;
                pthread_cond_signal(&psc.cv_go);
            } else {
                psc.state = 0;
            }

            /* cur_slot is exclusively ours; helper works on next_slot      */
            uint64_t *pr     = psc.bufs[cur_slot].pr;

            /* Cooperative Fermat: enable when the helper has work — either
               sieving next window (state=1) or fermat-only (state=3).
               The helper always calls coop_fermat_assist() after its main
               task, so it will pick up the shared atomic work queue.        */
            int helper_will_assist = (psc.state == 1 || psc.state == 3);

            size_t orig_cnt = cnt;
            size_t pf = 0;
            size_t worker_tested = 0;

            /* Decide up-front whether to use two-phase smart scanning.
               Pre-allocate phase-1 buffers BEFORE unlocking the mutex so
               the fallback path can still set up coop normally.             */
            int smart_K = cli_sample_stride;
            int use_smart = (smart_K > 1 && !no_primality
                             && cnt > (size_t)(smart_K * 4));

            size_t needed_gap = 0, p1_cnt = 0, p1_wcap = 0;
            uint64_t *p1_cands = NULL, *p1_wbuf = NULL;



            if (use_smart) {
                needed_gap = (size_t)(target_local * logbase);
                if (needed_gap < 2) needed_gap = 2;
                p1_cnt  = (cnt + (size_t)smart_K - 1) / (size_t)smart_K;
                p1_wcap = p1_cnt / 4 + 64;
                p1_cands = (uint64_t *)malloc(p1_cnt * sizeof(uint64_t));
                p1_wbuf  = (uint64_t *)malloc(p1_wcap * sizeof(uint64_t));
                if (!p1_cands || !p1_wbuf) {
                    free(p1_cands); free(p1_wbuf);
                    p1_cands = p1_wbuf = NULL;
                    use_smart = 0;               /* OOM → full test fallback */
                } else {
                    for (size_t s = 0, j = 0; j < cnt; j += (size_t)smart_K, s++)
                        p1_cands[s] = pr[j];
                }
            }

            /* --- set up cooperative Fermat and unlock mutex (once) ------- */
#ifdef WITH_CUDA
            /* When GPU handles Fermat, disable cooperative assist — the GPU
               replaces all CPU Fermat work.  Helper still sieves the next
               window but skips coop_fermat_assist (active=0).               */
            int gpu_fermat_path = (g_gpu_count > 0);
            if (gpu_fermat_path) {
                psc.coop.active      = 0;
                psc.coop.more_work   = 0;
                psc.coop.helper_done = 1;
                __sync_synchronize();
                pthread_mutex_unlock(&psc.mu);
            } else
#endif
            {
            if (use_smart) {
                psc.coop.pr        = p1_cands;
                psc.coop.cnt       = p1_cnt;
                psc.coop.next_idx  = 0;
                psc.coop.out_cnt   = 0;
                psc.coop.more_work = 1;          /* another batch follows   */
                psc.coop.helper_done = helper_will_assist ? 0 : 1;
                __sync_synchronize();
                psc.coop.active = (p1_cnt > 0 && helper_will_assist) ? 1 : 0;
            } else {
                psc.coop.pr        = pr;
                psc.coop.cnt       = cnt;
                psc.coop.next_idx  = 0;
                psc.coop.out_cnt   = 0;
                psc.coop.more_work = 0;
                psc.coop.helper_done = helper_will_assist ? 0 : 1;
                __sync_synchronize();
                psc.coop.active = (cnt > 0 && !no_primality
                                   && helper_will_assist) ? 1 : 0;
            }
            pthread_mutex_unlock(&psc.mu);       /* exactly once per window */
            }

            /* ============================================================= */
#ifdef WITH_CUDA
            if (gpu_fermat_path && !no_primality) {
            /* ======= GPU FERMAT PATH (non-CRT) ============================
               Send all candidates to the GPU in one batch.  No cooperative
               Fermat needed — the GPU replaces all CPU Fermat work.
               Smart-scan phases are handled via gpu_batch_filter calls.
               ==============================================================*/
                if (use_smart) {
                    /* --- Phase 1: GPU tests sampled candidates ----------- */
                    size_t sp = gpu_batch_filter(p1_cands, p1_cnt);
                    __sync_fetch_and_add(&stats_tested, (uint64_t)p1_cnt);

                    uint64_t *sampled_primes = p1_cands; /* reuse buffer */
                    size_t sp_cnt = sp;

                    /* --- Gap analysis: find candidate regions ------------ */
                    size_t v_alloc = cnt / 8 + 64;
                    uint64_t *verify = (uint64_t *)malloc(v_alloc * sizeof(uint64_t));
                    size_t v_cnt = 0;
                    size_t n_gap_regions = 0;
                    size_t gap_reg_cap = sp_cnt + 2;
                    uint64_t *gap_reg_lo = (uint64_t *)malloc(gap_reg_cap * sizeof(uint64_t));
                    uint64_t *gap_reg_hi = (uint64_t *)malloc(gap_reg_cap * sizeof(uint64_t));
                    if (verify && sp_cnt >= 1) {
                        #define GPU_COLLECT_REGION(lo_val, hi_val) do {        \
                            size_t _lo = 0, _hi = cnt;                        \
                            while (_lo < _hi) {                               \
                                size_t _m = _lo + (_hi - _lo) / 2;            \
                                if (pr[_m] <= (lo_val)) _lo = _m + 1;         \
                                else _hi = _m;                                \
                            }                                                 \
                            for (size_t _j = _lo;                             \
                                 _j < cnt && pr[_j] < (hi_val); _j++) {       \
                                if (_j % (size_t)smart_K == 0) continue;      \
                                if (v_cnt >= v_alloc) {                       \
                                    v_alloc *= 2;                             \
                                    verify = (uint64_t *)realloc(verify,      \
                                                v_alloc * sizeof(uint64_t));  \
                                }                                             \
                                verify[v_cnt++] = pr[_j];                     \
                            }                                                 \
                        } while (0)

                        if (cnt > 0 && sampled_primes[0] - pr[0] >= needed_gap) {
                            GPU_COLLECT_REGION(pr[0] - 1, sampled_primes[0]);
                            if (gap_reg_lo) { gap_reg_lo[n_gap_regions] = 0; gap_reg_hi[n_gap_regions] = sampled_primes[0]; n_gap_regions++; }
                        }
                        for (size_t i = 0; i + 1 < sp_cnt; i++) {
                            if (sampled_primes[i+1] - sampled_primes[i] >= needed_gap) {
                                GPU_COLLECT_REGION(sampled_primes[i], sampled_primes[i+1]);
                                if (gap_reg_lo) { gap_reg_lo[n_gap_regions] = sampled_primes[i]; gap_reg_hi[n_gap_regions] = sampled_primes[i+1]; n_gap_regions++; }
                            }
                        }
                        if (cnt > 0 && pr[cnt-1] - sampled_primes[sp_cnt-1] >= needed_gap) {
                            GPU_COLLECT_REGION(sampled_primes[sp_cnt-1], pr[cnt-1] + 1);
                            if (gap_reg_lo) { gap_reg_lo[n_gap_regions] = sampled_primes[sp_cnt-1]; gap_reg_hi[n_gap_regions] = UINT64_MAX; n_gap_regions++; }
                        }
                        #undef GPU_COLLECT_REGION
                    }

                    /* --- Phase 2: GPU tests verification candidates ------ */
                    pf = sp_cnt;
                    memcpy(pr, sampled_primes, sp_cnt * sizeof(uint64_t));
                    if (v_cnt > 0) {
                        size_t vp = gpu_batch_filter(verify, v_cnt);
                        for (size_t i = 0; i < vp; i++)
                            pr[pf++] = verify[i];
                    }
                    __sync_fetch_and_add(&stats_tested, (uint64_t)v_cnt);
                    if (pf > 1) qsort(pr, pf, sizeof(uint64_t), cmp_u64);
                    cnt = pf;

                    /* Scan verified gap regions */
                    {
                        int found_block = 0;
                        size_t region_pairs = 0;
                        for (size_t r = 0; r < n_gap_regions && gap_reg_lo; r++) {
                            size_t lo_idx = 0;
                            { size_t l = 0, h = cnt;
                              while (l < h) { size_t m = l+(h-l)/2; if (pr[m] < gap_reg_lo[r]) l=m+1; else h=m; }
                              lo_idx = l; }
                            size_t hi_idx = cnt;
                            { size_t l = 0, h = cnt;
                              while (l < h) { size_t m = l+(h-l)/2; if (pr[m] <= gap_reg_hi[r]) l=m+1; else h=m; }
                              hi_idx = l; }
                            size_t seg_cnt = (hi_idx > lo_idx) ? hi_idx - lo_idx : 0;
                            if (seg_cnt >= 2) {
                                region_pairs += seg_cnt - 1;
                                if (scan_candidates(pr + lo_idx, seg_cnt,
                                                    target_local, logbase,
                                                    shift_local, header_local,
                                                    rpc_url_local, rpc_user_local,
                                                    rpc_pass_local, rpc_method_local,
                                                    rpc_sign_key_local))
                                    found_block = 1;
                            }
                        }
                        if (sp_cnt > 0 && p1_cnt > 0) {
                            size_t est_full = (size_t)((double)orig_cnt
                                            * (double)sp_cnt / (double)p1_cnt);
                            if (est_full > 1 + region_pairs)
                                __sync_fetch_and_add(&stats_pairs,
                                                     (uint64_t)(est_full - 1 - region_pairs));
                        }
                        free(gap_reg_lo);
                        free(gap_reg_hi);
                        if (found_block) { free(p1_cands); free(p1_wbuf); free(verify); goto worker_done; }
                    }
                    free(p1_cands); p1_cands = NULL;
                    free(p1_wbuf);  p1_wbuf = NULL;
                    free(verify);
                } else {
                    /* GPU full test (non-smart) */
                    pf = gpu_batch_filter(pr, cnt);
                    __sync_fetch_and_add(&stats_tested, (uint64_t)cnt);
                    cnt = pf;
                }
            } else
#endif
            if (use_smart) {
            /* ======= TWO-PHASE SMART SCANNING =============================
               Phase 1: sample every Kth sieve survivor (cooperative).
               Gap analysis: find regions where consecutive sampled primes
                             are ≥ target gap apart.
               Phase 2: verify all un-sampled survivors inside those regions
                        (cooperative).
               Expected savings: ~5× fewer Fermat tests per window (K=8).
               ==============================================================*/

                /* --- Phase 1: worker tests sampled candidates ------------ */
                size_t p1_wn = 0;
                for (;;) {
                    size_t idx = __sync_fetch_and_add(&psc.coop.next_idx, 1);
                    if (idx >= p1_cnt) break;
                    if (bn_candidate_is_prime(p1_cands[idx])) {
                        if (p1_wn >= p1_wcap) {
                            p1_wcap *= 2;
                            p1_wbuf = (uint64_t *)realloc(p1_wbuf,
                                        p1_wcap * sizeof(uint64_t));
                        }
                        p1_wbuf[p1_wn++] = p1_cands[idx];
                    }
                    worker_tested++;
                    if ((worker_tested & 0xFFF) == 0)
                        __sync_fetch_and_add(&stats_tested, 4096);
                }
                /* Wait for helper to finish phase 1                         */
                if (helper_will_assist) {
                    while (!psc.coop.helper_done)
                        __asm__ volatile("pause" ::: "memory");
                }

                /* Merge phase-1 worker + helper primes → sampled_primes[]   */
                size_t p1_hn  = psc.coop.out_cnt;
                size_t sp_cnt = p1_wn + p1_hn;
                uint64_t *sampled_primes = (uint64_t *)malloc(
                        (sp_cnt ? sp_cnt : 1) * sizeof(uint64_t));
                if (sampled_primes) {
                    size_t wi = 0, hi = 0, mi = 0;
                    while (wi < p1_wn && hi < p1_hn) {
                        if (p1_wbuf[wi] <= psc.coop.out[hi])
                            sampled_primes[mi++] = p1_wbuf[wi++];
                        else
                            sampled_primes[mi++] = psc.coop.out[hi++];
                    }
                    while (wi < p1_wn)  sampled_primes[mi++] = p1_wbuf[wi++];
                    while (hi < p1_hn)  sampled_primes[mi++] = psc.coop.out[hi++];
                    sp_cnt = mi;
                } else {
                    sp_cnt = 0;   /* OOM – skip gap analysis */
                }
                free(p1_wbuf);  p1_wbuf = NULL;
                free(p1_cands); p1_cands = NULL;

                /* --- Gap analysis: find candidate regions in pr[] -------- */
                size_t v_alloc = cnt / 8 + 64;
                uint64_t *verify = (uint64_t *)malloc(v_alloc * sizeof(uint64_t));
                size_t v_cnt = 0;
                /* Track gap-region boundaries so scan_candidates is called
                   only on fully-verified segments (avoids fake best_merit
                   from gaps between sampled-only primes). */
                size_t n_gap_regions = 0;
                size_t gap_reg_cap = sp_cnt + 2;
                uint64_t *gap_reg_lo = (uint64_t *)malloc(gap_reg_cap * sizeof(uint64_t));
                uint64_t *gap_reg_hi = (uint64_t *)malloc(gap_reg_cap * sizeof(uint64_t));
                if (verify && sp_cnt >= 1) {
                    /* Collect un-sampled survivors in (lo_val, hi_val)       */
                    #define COLLECT_REGION(lo_val, hi_val) do {                \
                        size_t _lo = 0, _hi = cnt;                            \
                        while (_lo < _hi) {                                   \
                            size_t _m = _lo + (_hi - _lo) / 2;               \
                            if (pr[_m] <= (lo_val)) _lo = _m + 1;            \
                            else _hi = _m;                                    \
                        }                                                     \
                        for (size_t _j = _lo;                                 \
                             _j < cnt && pr[_j] < (hi_val); _j++) {           \
                            if (_j % (size_t)smart_K == 0) continue;          \
                            if (v_cnt >= v_alloc) {                           \
                                v_alloc *= 2;                                 \
                                verify = (uint64_t *)realloc(verify,          \
                                            v_alloc * sizeof(uint64_t));      \
                            }                                                 \
                            verify[v_cnt++] = pr[_j];                         \
                        }                                                     \
                    } while (0)

                    /* Left edge */
                    if (cnt > 0 && sampled_primes[0] - pr[0] >= needed_gap) {
                        COLLECT_REGION(pr[0] - 1, sampled_primes[0]);
                        if (gap_reg_lo) { gap_reg_lo[n_gap_regions] = 0; gap_reg_hi[n_gap_regions] = sampled_primes[0]; n_gap_regions++; }
                    }
                    /* Interior gaps */
                    for (size_t i = 0; i + 1 < sp_cnt; i++) {
                        if (sampled_primes[i+1] - sampled_primes[i] >= needed_gap) {
                            COLLECT_REGION(sampled_primes[i], sampled_primes[i+1]);
                            if (gap_reg_lo) { gap_reg_lo[n_gap_regions] = sampled_primes[i]; gap_reg_hi[n_gap_regions] = sampled_primes[i+1]; n_gap_regions++; }
                        }
                    }
                    /* Right edge */
                    if (cnt > 0 &&
                        pr[cnt-1] - sampled_primes[sp_cnt-1] >= needed_gap) {
                        COLLECT_REGION(sampled_primes[sp_cnt-1], pr[cnt-1] + 1);
                        if (gap_reg_lo) { gap_reg_lo[n_gap_regions] = sampled_primes[sp_cnt-1]; gap_reg_hi[n_gap_regions] = UINT64_MAX; n_gap_regions++; }
                    }

                    #undef COLLECT_REGION
                }

                /* --- Phase 2: verify survivors in candidate gaps --------- */
                size_t p2_wn = 0;
                uint64_t *p2_wbuf = NULL;

                if (v_cnt > 0) {
                    psc.coop.pr        = verify;
                    psc.coop.cnt       = v_cnt;
                    psc.coop.next_idx  = 0;
                    /* don't reset out_cnt — helper appends to same buffer   */
                    psc.coop.more_work = 0;          /* last phase           */
                    psc.coop.helper_done = helper_will_assist ? 0 : 1;
                    __sync_synchronize();
                    /* Worker clears helper_done → wakes helper from spin    */

                    size_t p2_wcap = v_cnt / 4 + 64;
                    p2_wbuf = (uint64_t *)malloc(p2_wcap * sizeof(uint64_t));

                    for (;;) {
                        size_t idx = __sync_fetch_and_add(&psc.coop.next_idx, 1);
                        if (idx >= v_cnt) break;
                        if (bn_candidate_is_prime(verify[idx])) {
                            if (p2_wbuf && p2_wn >= p2_wcap) {
                                p2_wcap *= 2;
                                p2_wbuf = (uint64_t *)realloc(p2_wbuf,
                                            p2_wcap * sizeof(uint64_t));
                            }
                            if (p2_wbuf) p2_wbuf[p2_wn++] = verify[idx];
                        }
                        worker_tested++;
                        if ((worker_tested & 0xFFF) == 0)
                            __sync_fetch_and_add(&stats_tested, 4096);
                    }
                    if (helper_will_assist) {
                        while (!psc.coop.helper_done)
                            __asm__ volatile("pause" ::: "memory");
                    }
                } else {
                    /* No candidate gaps — release helper now.               */
                    psc.coop.more_work = 0;
                    psc.coop.active    = 0;
                    __sync_synchronize();
                    if (helper_will_assist)
                        psc.coop.helper_done = 0;    /* wake → sees active=0 */
                }

                psc.coop.active = 0;
                __sync_synchronize();

                /* --- Final merge: all confirmed primes → pr[], sort ------ */
                pf = 0;
                for (size_t i = 0; i < sp_cnt; i++) pr[pf++] = sampled_primes[i];
                if (p2_wbuf)
                    for (size_t i = 0; i < p2_wn; i++) pr[pf++] = p2_wbuf[i];
                for (size_t i = p1_hn; i < psc.coop.out_cnt; i++)
                    pr[pf++] = psc.coop.out[i];
                if (pf > 1) qsort(pr, pf, sizeof(uint64_t), cmp_u64);
                cnt = pf;

                free(sampled_primes);
                free(verify);
                free(p2_wbuf);

                /* Flush stats */
                {
                    size_t total_tested = p1_cnt + v_cnt;
                    size_t reported = (worker_tested / 4096) * 4096;
                    size_t remainder = worker_tested - reported;
                    if (helper_will_assist) {
                        size_t htested = total_tested > worker_tested
                                         ? total_tested - worker_tested : 0;
                        size_t hreported = (htested / 4096) * 4096;
                        remainder += (htested - hreported);
                    } else {
                        remainder = total_tested - reported;
                    }
                    if (remainder > 0)
                        __sync_fetch_and_add(&stats_tested, (uint64_t)remainder);
                }

                /* Scan ONLY fully-verified gap regions for qualifying gaps
                   and best-merit tracking.  Scanning the full merged array
                   would inflate best_merit with fake gaps between sampled-
                   only primes (merit ≈ target by construction of needed_gap
                   — explaining the suspicious best≈target on every run). */
                {
                    int found_block = 0;
                    size_t region_pairs = 0;
                    for (size_t r = 0; r < n_gap_regions && gap_reg_lo; r++) {
                        /* Binary search for first prime >= gap_reg_lo[r] */
                        size_t lo_idx = 0;
                        { size_t l = 0, h = cnt;
                          while (l < h) { size_t m = l+(h-l)/2; if (pr[m] < gap_reg_lo[r]) l=m+1; else h=m; }
                          lo_idx = l; }
                        /* Binary search for first prime > gap_reg_hi[r] */
                        size_t hi_idx = cnt;
                        { size_t l = 0, h = cnt;
                          while (l < h) { size_t m = l+(h-l)/2; if (pr[m] <= gap_reg_hi[r]) l=m+1; else h=m; }
                          hi_idx = l; }
                        size_t seg_cnt = (hi_idx > lo_idx) ? hi_idx - lo_idx : 0;
                        if (seg_cnt >= 2) {
                            region_pairs += seg_cnt - 1;
                            if (scan_candidates(pr + lo_idx, seg_cnt,
                                                target_local, logbase,
                                                shift_local, header_local,
                                                rpc_url_local, rpc_user_local,
                                                rpc_pass_local, rpc_method_local,
                                                rpc_sign_key_local))
                                found_block = 1;
                        }
                    }
                    /* Compensate stats_pairs for ETA: estimate full-scan pairs
                       from phase-1 sample rate, subtract pairs already counted
                       by scan_candidates in the verified regions above. */
                    if (sp_cnt > 0 && p1_cnt > 0) {
                        size_t est_full = (size_t)((double)orig_cnt
                                        * (double)sp_cnt / (double)p1_cnt);
                        if (est_full > 1 + region_pairs)
                            __sync_fetch_and_add(&stats_pairs,
                                                 (uint64_t)(est_full - 1 - region_pairs));
                    }
                    free(gap_reg_lo);
                    free(gap_reg_hi);
                    if (found_block) goto worker_done;
                }

            /* ============================================================= */
            } else if (!no_primality) {
            /* ======= FULL TEST (original path) ============================
               Test every sieve survivor cooperatively.  Used when
               --sample-stride 1 or as OOM fallback.
               ==============================================================*/
                for (;;) {
                    size_t idx = __sync_fetch_and_add(&psc.coop.next_idx, 1);
                    if (idx >= cnt) break;
                    if (bn_candidate_is_prime(pr[idx]))
                        pr[pf++] = pr[idx];
                    worker_tested++;
                    if ((worker_tested & 0xFFF) == 0)
                        __sync_fetch_and_add(&stats_tested, 4096);
                }
                psc.coop.active = 0;
                __sync_synchronize();

                if (helper_will_assist) {
                    while (!psc.coop.helper_done)
                        __asm__ volatile("pause" ::: "memory");

                    size_t wn = pf, hn = psc.coop.out_cnt;
                    if (hn > 0) {
                        uint64_t *wtmp = (uint64_t *)malloc(wn * sizeof(uint64_t));
                        if (wtmp) {
                            memcpy(wtmp, pr, wn * sizeof(uint64_t));
                            size_t wi = 0, hi = 0, mi = 0;
                            while (wi < wn && hi < hn) {
                                if (wtmp[wi] <= psc.coop.out[hi])
                                    pr[mi++] = wtmp[wi++];
                                else
                                    pr[mi++] = psc.coop.out[hi++];
                            }
                            while (wi < wn) pr[mi++] = wtmp[wi++];
                            while (hi < hn) pr[mi++] = psc.coop.out[hi++];
                            pf = mi;
                            free(wtmp);
                        } else {
                            for (size_t i = 0; i < hn; i++)
                                pr[pf++] = psc.coop.out[i];
                            qsort(pr, pf, sizeof(uint64_t), cmp_u64);
                        }
                    }
                }
                {   /* Flush stats */
                    size_t reported = (worker_tested / 4096) * 4096;
                    size_t remainder = worker_tested - reported;
                    if (helper_will_assist) {
                        size_t htested = orig_cnt > worker_tested
                                         ? orig_cnt - worker_tested : 0;
                        size_t hreported = (htested / 4096) * 4096;
                        remainder += (htested - hreported);
                    } else {
                        remainder = orig_cnt - reported;
                    }
                    if (remainder > 0)
                        __sync_fetch_and_add(&stats_tested, (uint64_t)remainder);
                }
                cnt = pf;

            /* ============================================================= */
            } else {
                /* no_primality: skip all testing */
                psc.coop.active = 0;
                pf = cnt;
                __sync_fetch_and_add(&stats_tested, (uint64_t)orig_cnt);
            }

            /* Smart-scan path handles gap scanning internally (region-based).
               Only run scan_candidates for full-test and no_primality. */
            if (!use_smart && cnt >= 2) {
                if (scan_candidates(pr, cnt, target_local, logbase,
                                    shift_local,
                                    header_local,
                                    rpc_url_local, rpc_user_local, rpc_pass_local,
                                    rpc_method_local, rpc_sign_key_local))
                    goto worker_done; /* stop-after-block: exit immediately */
            }
        } /* end window loop */
        /* Pass complete without abort: loop back and mine the same slice */
    } /* end continuous mining outer loop */

worker_done:
    /* Shut down helper */
    pthread_mutex_lock(&psc.mu);
    psc.state = -1;
    pthread_cond_signal(&psc.cv_go);
    pthread_mutex_unlock(&psc.mu);
    pthread_join(psc.thread, NULL);

    free(psc.bufs[0].pr);
    free(psc.bufs[1].pr);
    pthread_mutex_destroy(&psc.mu);
    pthread_cond_destroy(&psc.cv_go);
    pthread_cond_destroy(&psc.cv_done);

    /* Release this worker's own TLS sieve buffers and GMP state.
       Without this, every pass (new block) leaks ~103 MB per worker:
       tls_pr (~80 MB) + tls_base_mod_p (~22 MB) + tls_bits (~1.25 MB).
       With 14 threads that's ~1.45 GB leaked per block, causing OOM. */
#ifdef WITH_CUDA
    if (tls_gpu_accum) {
        gpu_accum_destroy(tls_gpu_accum);
        tls_gpu_accum = NULL;
    }
#endif
    free_sieve_buffers();
    if (tls_gmp_inited) {
        mpz_clear(tls_base_mpz);
        mpz_clear(tls_cand_mpz);
        mpz_clear(tls_two_mpz);
        mpz_clear(tls_exp_mpz);
        mpz_clear(tls_res_mpz);
        tls_gmp_inited = 0;
    }
    return NULL;
}




/* Fast probable-prime test used in the --fast-fermat hot path.

   Replaces two-base Fermat with Montgomery-accelerated strong
   (Miller-Rabin style) pseudoprime tests for bases 2 and 3.

   Why this is faster than the old Fermat:
   ┌────────────────────────────────────────────────────────┐
   │ Old: modpow(2,n-1,n) + modpow(3,n-1,n)                │
   │   = 2 × ~95 mulmod × ~43 cycles  ≈  8 170 cycles      │
   │                                                        │
   │ New: strong_mrt(2) + strong_mrt(3) with Montgomery     │
   │   = 2 × (d_bits + s squarings) × ~14 cycles           │
   │   ≈  2 × 63 × 14  ≈  1 760 cycles   (~5× faster)      │
   │                                                        │
   │ BONUS: strong test also catches Carmichael numbers     │
   │ → fewer false positives reaching scan_candidates       │
   └────────────────────────────────────────────────────────┘

   Bases {2,3}: no known 64-bit pseudoprimes for this pair below
   3.2 × 10^18, well beyond our mining range.  Effectively
   deterministic for sieve survivors in the Gapcoin prime space. */
static int fast_fermat_test(uint64_t n) {
    if (n < 4)  return n >= 2;   /* 2 and 3 are prime */
    if (!(n & 1)) return 0;      /* even → composite  */
    /* Factor out trailing zeros from n-1: n-1 = d << s */
    uint64_t d = n - 1;  int s = 0;
    while (!(d & 1)) { d >>= 1; s++; }
    /* Precompute Montgomery constants once; reused for both base tests */
    uint64_t np = mont_ninv(n);
    uint64_t R2 = mont_R2(n);
    if (!strong_mrt(n, 2, np, R2, d, s)) return 0;
    if (!strong_mrt(n, 3, np, R2, d, s)) return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s [options]\n", argv[0]);
        printf("  -o, --host HOST       node hostname or IP  (default: 127.0.0.1)\n");
        printf("  -p, --port PORT       node RPC port        (default: 31397)\n");
        printf("      --stratum H:P     stratum pool host:port (e.g. gap.suprnova.cc:4234)\n");
        printf("  -u, --user USER       pool/RPC username (e.g. worker.1)\n");
        printf("      --pass PASS       pool/RPC password\n");
        printf("      --rpc-url URL     full RPC URL (overrides --host/--port)\n");
        printf("  -s, --shift N         prime size shift      (default: 20)\n");
        printf("      --sieve-size S    sieve size            (default: 33554432)\n");
        printf("      --sieve-primes N  number of sieve primes (GapMiner-compatible)\n");
        printf("                        N primes -> largest ~ N*ln(N); default = 900000\n");
        printf("      --target T        minimum merit         (default: 20.0)\n");
        printf("      --threads N       worker threads        (default: 1)\n");
        printf("      --adder-max M     adder upper bound     (default: 2^shift)\n");
        printf("      --fast-fermat     fast primality (fewer Miller-Rabin rounds)\n");
        printf("      --sample-stride K smart scan: test every Kth survivor (default: 8, 1=off)\n");
        printf("      --crt-file FILE   load CRT sieve file (binary template or text gap-solver)\n");
        printf("      --fermat-threads N  number of Fermat testing threads for CRT producer-consumer\n");
        printf("                          default: auto = threads-1 for CRT solver with threads>=3\n");
        printf("      --keep-going      continue after block found (default on)\n");
        printf("      --stop-after-block  exit after first valid block\n");
        printf("      --log-file FILE   append messages to FILE\n");
        printf("      --header TEXT     override prime base (rarely needed)\n");
        printf("      --rpc-rate MS     getwork poll interval ms  (default: 5000)\n");
        printf("      --rpc-retries N   submit retries\n");
        printf("      --cuda [DEV,...]  use CUDA GPU(s) for Fermat testing (e.g. --cuda 0,1)\n");
        printf("      --gpu-batch N     accumulate N candidates before GPU flush (default: 4096)\n");
        return 1;
    }
    const char *header = NULL;
    int is_hex = 0;
    int shift = 20;
    /* adder_max is the exclusive upper bound on adder values.  if the user
       does not supply one it will be set automatically to 2^shift (so adders
       0..2^shift-1 are tried). */
    int64_t adder_max = -1;
    /* ensure adder_max does not exceed 2^shift to prevent reuse of work
       (p = sha256(header) << shift + adder must be unique per header). */
    uint64_t sieve_size = 33554432;
    double target = 20.0;
    int target_explicit = 0;  /* set to 1 if user passes --target */
    int cli_sieve_explicit = 0; /* set to 1 if user passes --sieve-primes */
    const char *rpc_url = NULL, *rpc_user = NULL, *rpc_pass = NULL, *rpc_method = "getwork";
    const char *stratum_arg = NULL; /* "host:port" for stratum pool connection */
    const char *rpc_sign_key = NULL;
    const char *rpc_host = NULL;
    int rpc_port = 0;
    const char *log_file = NULL;
    unsigned int cli_rpc_rate = 0;
    int cli_rpc_retries = -1;
    int build_only = 0;
    int no_opreturn = 0;
    int num_threads = 1;
    int use_cuda = 0;
    int cuda_devices[GPU_MAX_DEVS];
    int cuda_ndevs = 0;
    (void)cuda_devices; (void)cuda_ndevs;  /* suppress warning when WITH_CUDA not set */
    uint64_t build_p = 0, build_q = 0;
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i],"--header") && i+1<argc) header = argv[++i];
        else if (!strcmp(argv[i],"--hash-hex")) is_hex = 1;
        else if (!strcmp(argv[i],"--shift") && i+1<argc) shift = atoi(argv[++i]);
        else if (!strcmp(argv[i],"-s") && i+1<argc) shift = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--adder-max") && i+1<argc) adder_max = (int64_t)atoll(argv[++i]);
        else if (!strcmp(argv[i],"--sieve-size") && i+1<argc) sieve_size = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i],"--sieve-primes") && i+1<argc) {
            cli_sieve_prime_count = strtoull(argv[++i], NULL, 10);
            cli_sieve_explicit = 1;
            /* Limit is computed from count after arg parsing (PNT upper bound). */
        }
        else if (!strcmp(argv[i],"--target") && i+1<argc) { target = atof(argv[++i]); target_explicit = 1; }
        else if ((!strcmp(argv[i],"-o") || !strcmp(argv[i],"--host")) && i+1<argc) rpc_host = argv[++i];
        else if ((!strcmp(argv[i],"-p") || !strcmp(argv[i],"--port")) && i+1<argc) rpc_port = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--stratum") && i+1<argc) stratum_arg = argv[++i];
        else if (!strcmp(argv[i],"--rpc-url") && i+1<argc) rpc_url = argv[++i];
        else if ((!strcmp(argv[i],"-u") || !strcmp(argv[i],"--user") || !strcmp(argv[i],"--rpc-user")) && i+1<argc) rpc_user = argv[++i];
        else if ((!strcmp(argv[i],"--pass") || !strcmp(argv[i],"--rpc-pass")) && i+1<argc) rpc_pass = argv[++i];
        else if (!strcmp(argv[i],"--rpc-method") && i+1<argc) rpc_method = argv[++i];
        else if (!strcmp(argv[i],"--rpc-rate") && i+1<argc) cli_rpc_rate = (unsigned int)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--rpc-retries") && i+1<argc) cli_rpc_retries = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--rpc-sign-key") && i+1<argc) rpc_sign_key = argv[++i];
        else if (!strcmp(argv[i],"--log-file") && i+1<argc) log_file = argv[++i];
        else if (!strcmp(argv[i],"--build-only")) build_only = 1;
        else if (!strcmp(argv[i],"--no-opreturn")) no_opreturn = 1;
        else if (!strcmp(argv[i],"--force-solution")) debug_force = 1;
        else if (!strcmp(argv[i],"--fast-fermat")) use_fast_fermat = 1;
        else if (!strcmp(argv[i],"--cuda")) {
            use_cuda = 1;
            if (i+1 < argc && argv[i+1][0] != '-') {
                /* Parse comma-separated device list: --cuda 0,1 or --cuda 0 */
                char *devarg = argv[++i];
                char *tok = strtok(devarg, ",");
                while (tok && cuda_ndevs < GPU_MAX_DEVS) {
                    cuda_devices[cuda_ndevs++] = atoi(tok);
                    tok = strtok(NULL, ",");
                }
            }
            if (cuda_ndevs == 0) cuda_devices[cuda_ndevs++] = 0;
        }
        else if (!strcmp(argv[i],"--gpu-batch") && i+1<argc) {
            g_gpu_batch_size = atoi(argv[++i]);
            if (g_gpu_batch_size < 64) g_gpu_batch_size = 64;
        }
        else if (!strcmp(argv[i],"--no-primality")) no_primality = 1;
        else if (!strcmp(argv[i],"--selftest")) selftest = 1;
        else if (!strcmp(argv[i],"--threads") && i+1<argc) num_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--sample-stride") && i+1<argc) {
            cli_sample_stride = atoi(argv[++i]);
            if (cli_sample_stride < 1) cli_sample_stride = 1;
        }
        else if (!strcmp(argv[i],"--crt-file") && i+1<argc)
            cli_crt_file = argv[++i];
        else if ((!strcmp(argv[i],"--fermat-threads") || !strcmp(argv[i],"-d")) && i+1<argc) {
            crt_fermat_threads = atoi(argv[++i]);
            crt_fermat_explicit = 1;
        }
        else if (!strcmp(argv[i],"--p") && i+1<argc) build_p = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i],"--q") && i+1<argc) build_q = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i],"--keep-going")) {
            /* explicit, mostly for documentation; behavior is already on by
               default */
            keep_going = 1;
        } else if (!strcmp(argv[i],"--stop-after-block")) {
            /* new flag to disable continuation and exit when a solution is
               found */
            keep_going = 0;
        }
    }
    /* Build rpc_url from --host / --port if not given explicitly.
       Defaults: host=127.0.0.1, port=31397 (Gapcoin mainnet). */
    static char rpc_url_buf[256];
    if (!rpc_url && !stratum_arg && (rpc_host || rpc_port)) {
        const char *h = rpc_host ? rpc_host : "127.0.0.1";
        int         p = rpc_port ? rpc_port : 31397;
        snprintf(rpc_url_buf, sizeof(rpc_url_buf), "http://%s:%d/", h, p);
        rpc_url = rpc_url_buf;
    }
    /* ── Stratum pool connection ── */
#ifdef WITH_RPC
    static char stratum_host_buf[256];
    static char stratum_port_buf[16];
    if (stratum_arg) {
        /* Parse "host:port" */
        const char *colon = strrchr(stratum_arg, ':');
        if (!colon || colon == stratum_arg) {
            fprintf(stderr, "--stratum requires host:port format (e.g. gap.suprnova.cc:4234)\n");
            return 2;
        }
        size_t hlen = (size_t)(colon - stratum_arg);
        if (hlen >= sizeof(stratum_host_buf)) hlen = sizeof(stratum_host_buf) - 1;
        memcpy(stratum_host_buf, stratum_arg, hlen);
        stratum_host_buf[hlen] = '\0';
        strncpy(stratum_port_buf, colon + 1, sizeof(stratum_port_buf) - 1);
        stratum_port_buf[sizeof(stratum_port_buf) - 1] = '\0';
        if (!rpc_user) {
            fprintf(stderr, "--user required for stratum (pool worker name)\n");
            return 2;
        }
        log_msg("stratum: connecting to %s:%s as %s\n",
                stratum_host_buf, stratum_port_buf, rpc_user);
        g_stratum = stratum_connect(stratum_host_buf, stratum_port_buf,
                                    rpc_user, rpc_pass ? rpc_pass : "",
                                    (uint16_t)shift);
        if (!g_stratum) {
            fprintf(stderr, "Failed to connect to stratum pool %s:%s\n",
                    stratum_host_buf, stratum_port_buf);
            return 3;
        }
        /* Set rpc_url to a sentinel so RPC-guarded code paths activate.
           Actual communication goes through g_stratum, not HTTP. */
        rpc_url = "stratum";
    }
#else
    if (stratum_arg) {
        fprintf(stderr, "--stratum requires building with WITH_RPC=1\n");
        return 2;
    }
#endif
    if (adder_max < 0) {
        /* no explicit value supplied – use full allowed range */
        if (shift <= 62)
            adder_max = (int64_t)1 << shift;
        else
            adder_max = INT64_MAX; /* cap: 2^shift too large for int64_t */
        log_msg("auto adder_max=%lld (2^shift=%d)\n", (long long)adder_max, shift);
    }
    if (shift <= 62 && adder_max > ((int64_t)1 << shift)) {
        fprintf(stderr, "--adder-max (%lld) must be at most 2^shift (%lld)\n", (long long)adder_max, (long long)((int64_t)1 << shift));
        return 2;
    }

    /* Compute sieve prime VALUE limit from COUNT using PNT upper bound:
       p_n < n × (ln(n) + ln(ln(n))) for n >= 6.
       Both the default (900000) and any explicit --sieve-primes go through
       this path so semantics always match GapMiner. */
    if (cli_sieve_prime_limit == 0 && cli_sieve_prime_count >= 6) {
        double n = (double)cli_sieve_prime_count;
        double upper = n * (log(n) + log(log(n)));
        cli_sieve_prime_limit = (uint64_t)(upper * 1.05); /* 5% safety margin */
    } else if (cli_sieve_prime_limit == 0) {
        cli_sieve_prime_limit = 100;
    }

    /* Load CRT sieve template if requested. */
    if (cli_crt_file) {
        if (!load_crt_file(cli_crt_file)) {
            log_msg("Warning: CRT file load failed, continuing without CRT\n");
        }
    }

    /* ── CRT sieve-primes auto-tuning ──
       In CRT mode (gap-solver) the sieve filters the forward gap-check
       window (~11K positions at merit 22, shift 512).  Each additional
       composite eliminated by the sieve saves one Fermat test (~500 µs
       at shift 512).  The marginal sieve cost is tiny (ns per prime per
       position), so more sieve primes pay for themselves up to ~5M.
       Only adjust if the user didn't pass --sieve-primes explicitly. */
    if (g_crt_mode == CRT_MODE_SOLVER && !cli_sieve_explicit) {
        uint64_t new_count;
#ifdef WITH_CUDA
        if (use_cuda) {
            /* GPU Fermat: keep sieve primes low to feed larger batches.
               At 500K primes the gap-check sieve is still effective
               (same primes/win as 3M) but survivors per window are ~3×
               higher, keeping GPU occupancy near 100%.  */
            if (shift >= 384)
                new_count = 500000;
            else
                new_count = DEFAULT_SIEVE_PRIME_COUNT;
        } else
#endif
        {
        if (shift >= 768)
            new_count = 5000000;   /* ~86M limit */
        else if (shift >= 384)
            new_count = 3000000;   /* ~52M limit */
        else if (shift >= 128)
            new_count = 2000000;   /* ~35M limit */
        else
            new_count = DEFAULT_SIEVE_PRIME_COUNT;
        }
        if (new_count != cli_sieve_prime_count) {
            log_msg("CRT auto-tune: sieve-primes %llu -> %llu (shift=%d%s)\n",
                    (unsigned long long)cli_sieve_prime_count,
                    (unsigned long long)new_count, shift,
#ifdef WITH_CUDA
                    use_cuda ? ", cuda" : ""
#else
                    ""
#endif
                    );
            cli_sieve_prime_count = new_count;
            /* Recompute the value limit from the new count. */
            double n = (double)cli_sieve_prime_count;
            double upper = n * (log(n) + log(log(n)));
            cli_sieve_prime_limit = (uint64_t)(upper * 1.05);
        }
    }

    /* Auto-detect fermat threads for CRT solver producer-consumer mode.
       At high shifts (>= 256) the sieve is <1ms while Fermat testing
       takes ~270ms per window, so the sieve is <0.1% of work.  Dedicating
       a thread to sieving wastes CPU — monolithic is better (every thread
       does sieve+fermat on its own work).  Default: monolithic (0).
       Producer-consumer is only enabled with explicit --fermat-threads N.
       Setting --fermat-threads 0 explicitly also selects monolithic. */
    if (g_crt_mode == CRT_MODE_SOLVER && !crt_fermat_explicit &&
        crt_fermat_threads == 0) {
        /* Default: monolithic — all threads sieve+fermat independently */
        log_msg("CRT mode: monolithic (all %d threads sieve+fermat)\n",
                num_threads);
        log_msg("  use --fermat-threads N to enable producer-consumer\n");
    }
    if (crt_fermat_threads > 0 && crt_fermat_threads >= num_threads) {
        crt_fermat_threads = num_threads - 1;
        log_msg("clamped fermat-threads=%d (need at least 1 sieve thread)\n",
                crt_fermat_threads);
    }

    /* ── CUDA GPU initialization ── */
#ifdef WITH_CUDA
    if (use_cuda) {
        for (int gi = 0; gi < cuda_ndevs; gi++) {
            g_gpu_ctx[g_gpu_count] = gpu_fermat_init(cuda_devices[gi], GPU_MAX_BATCH);
            if (!g_gpu_ctx[g_gpu_count]) {
                fprintf(stderr, "CUDA init failed (device %d). Skipping.\n",
                        cuda_devices[gi]);
            } else {
                log_msg("CUDA: using %s (device %d) for Fermat testing\n",
                        gpu_fermat_device_name(g_gpu_ctx[g_gpu_count]),
                        cuda_devices[gi]);
                g_gpu_count++;
            }
        }
        if (g_gpu_count == 0) {
            fprintf(stderr, "No CUDA devices initialized. Falling back to CPU.\n");
            use_cuda = 0;
        }
    }
#else
    if (use_cuda) {
        fprintf(stderr, "--cuda requires building with WITH_CUDA=1\n");
        return 2;
    }
#endif

    if (selftest) {
        log_msg("selftest: verifying primality routines\n");
        uint64_t tests[] = {2,3,4,17,18,19,20,0};
        for (int ii = 0; tests[ii]; ii++) {
            uint64_t v = tests[ii];
            int ff = fast_fermat_test(v);
            int mr = miller_rabin(v);
            log_msg("  %llu -> fast=%d mr=%d\n", (unsigned long long)v, ff, mr);
        }
        return 0;
    }
    if (!header) {
#ifdef WITH_RPC
        if (rpc_url && !g_stratum) {
            /* fetch template and use previousblockhash as header seed */
            char *gbt = rpc_getblocktemplate(rpc_url, rpc_user, rpc_pass);
            if (gbt) {
                const char *p = strstr(gbt, "\"previousblockhash\"");
                if (p) {
                    const char *colon = strchr(p, ':');
                    if (colon) {
                        const char *start = colon + 1;
                        /* skip whitespace and opening quote */
                        while (*start && (*start == ' ' || *start == '"')) start++;
                        const char *end = strchr(start, '"');
                        if (end && end > start) {
                            size_t len = end - start;
                            header = malloc(len+1);
                            memcpy((char*)header, start, len);
                            ((char*)header)[len] = '\0';
                            if (header[0]) {
                                is_hex = 1; /* GBT prevhash is always a 64-char hex string */
                                log_msg("auto-header from GBT = %s\n", header);
                            } else
                                log_msg("auto-header from GBT came back empty\n");
                        }
                    }
                }
                free(gbt);
            }
        }
        if (!header && !g_stratum) {
            fprintf(stderr, "--header required (or provide --rpc-url or --stratum for automatic header)\n");
            return 2;
        }
#else
        fprintf(stderr, "--header required\n");
        return 2;
#endif
    }
    /* Auto-detect hex header: 64 hex chars → raw 256-bit prevhash, not a SHA-256 seed */
    if (!is_hex && header && strlen(header) == 64) {
        int all_hex = 1;
        for (int _i = 0; _i < 64 && all_hex; _i++) {
            char _c = header[_i];
            if (!((_c>='0'&&_c<='9')||(_c>='a'&&_c<='f')||(_c>='A'&&_c<='F'))) all_hex = 0;
        }
        if (all_hex) is_hex = 1;
    }
    uint8_t h256[32];
    if (header)
        hash_to_256(header, is_hex, h256);
    else
        memset(h256, 0, 32);  /* stratum: will be overwritten by build_mining_pass_stratum */
#ifdef WITH_RPC
    /* Correct the prime base: use SHA256d(84-byte block header) not prevhash.
       Without this, nAdd is prime for base=prevhash but NOT for base=block.GetHash(),
       so gapcoind rejects every submission.  build_mining_pass() assembles the
       84-byte header, double-SHA256s it, and byte-reverses to match Gapcoin's
       ary_to_mpz(order=-1) convention (data[31]=MSB → h256[0]=MSB). */
    if (rpc_url) {
        int got_work = 0;
        if (g_stratum) {
            /* Stratum: wait for first work from pool */
            char sdata[161]; uint64_t sndiff = 0;
            if (stratum_get_work(g_stratum, sdata, &sndiff)) {
                got_work = build_mining_pass_stratum(sdata, sndiff, shift);
            }
        } else {
            got_work = build_mining_pass(rpc_url, rpc_user, rpc_pass, shift);
        }
        if (got_work) {
            memcpy(h256, g_pass.h256, 32);
            if (g_pass.prevhex[0]) {
                pthread_mutex_lock(&g_work_lock);
                strncpy(g_prevhash, g_pass.prevhex, 64);
                g_prevhash[64] = '\0';
                pthread_mutex_unlock(&g_work_lock);
            }
            /* Derive target merit from network difficulty (nDifficulty).
             * Gapcoin encodes difficulty as fixed-point with 48 fractional bits:
             *   merit = nDifficulty / 2^48
             * Use this as the minimum merit threshold unless the user
             * explicitly set --target to override it. */
            if (!target_explicit && g_pass.ndiff > 0) {
                double net_merit = (double)g_pass.ndiff / (double)(1ULL << 48);
                target = net_merit;
                g_mining_target = target;
                log_msg("network difficulty: %.4f merit (nDifficulty=%llu)\n",
                        net_merit, (unsigned long long)g_pass.ndiff);
            }
        }
    }
#endif
    g_mining_target = target;   /* publish for print_stats block-prob display */
    atexit(print_stats);
    /* free thread-local sieve buffers when the process exits */
    atexit(free_sieve_buffers);
    /* Windows: initialise Winsock2 (no-op on POSIX) */
    win_wsa_init();
    if (log_file) {
        log_fp = fopen(log_file, "a");
        if (!log_fp) fprintf(stderr, "Failed to open log file %s\n", log_file);
    }
    stats_start_ms = now_ms();
    start_stats_thread();
    /* Trigger sieve cache population so we can log its stats. */
    pthread_once(&small_primes_once, populate_small_primes_cache);
    log_msg("C miner starting (shift=%d sieve=%llu sieve-primes=%zu [up to %llu])\n",
            shift, (unsigned long long)sieve_size,
            small_primes_count,
            small_primes_count > 0 ? (unsigned long long)small_primes_cache[small_primes_count-1] : 0ULL);
    if (keep_going)
        log_msg("default behaviour: will continue mining after finding a valid block\n");
    else
        log_msg("miner configured to exit when a valid block is found\n");
    if (use_fast_fermat)
        log_msg("fast Fermat: GMP mpz_powm base-2 (--fast-fermat)\n");

#ifndef WITH_RPC
    /* suppress unused-but-set warnings when built without RPC */
    (void)cli_rpc_rate; (void)cli_rpc_retries; (void)build_only; (void)no_opreturn;
    (void)build_p; (void)build_q; (void)rpc_url; (void)rpc_user; (void)rpc_pass; (void)rpc_method; (void)rpc_sign_key;
#endif

    /* worker definitions moved to file-scope */


#ifdef WITH_RPC
    if (cli_rpc_rate) rpc_rate_ms = cli_rpc_rate;
    if (cli_rpc_retries >= 0) rpc_default_retries = cli_rpc_retries;
    if (rpc_url && !g_stratum) start_submit_thread();
#ifdef WITH_RPC
    if (build_only) {
        if (!rpc_url) {
            log_msg("--build-only requires --rpc-url to fetch GBT and (optionally) submit\n");
            stop_stats_thread();
            return 2;
        }
        char *gbt = rpc_getblocktemplate(rpc_url, rpc_user, rpc_pass);
        if (!gbt) { log_msg("Failed to fetch GBT\n"); stop_stats_thread(); return 2; }
        char blockhex[16384]; memset(blockhex,0,sizeof(blockhex));
        char payload_hex[197] = {0};
        if (!no_opreturn) {
            if (build_p == 0 && build_q == 0) { log_msg("--build-only requires --p and --q when not using --no-opreturn\n"); free(gbt); stop_stats_thread(); return 2; }
            encode_pow_header_binary(header, payload_hex);
        }
        /* --p is interpreted as nAdd directly (prime = h256<<shift + nAdd). */
        uint64_t build_nadd = (uint64_t)build_p;
        if (build_block_from_gbt_and_payload(gbt, payload_hex, shift, build_nadd, blockhex)) {
            log_msg("Built blockhex: %s\n", blockhex);
            if (rpc_url) {
                log_msg("Submitting built block via RPC...\n");
                int rc = rpc_submit(rpc_url, rpc_user, rpc_pass, "submitblock", blockhex);
                log_msg("rpc_submit returned %d\n", rc);
            }
        } else {
            log_msg("Failed to build block from GBT\n");
        }
        free(gbt);
        stop_stats_thread();
        return 0;
    }
#endif
#endif
    if (num_threads <= 1) {
        do {
            int64_t num_windows = ((int64_t)adder_max + (int64_t)sieve_size - 1) / (int64_t)sieve_size;
            double logbase = uint256_log_approx(h256, shift);
            set_base_bn(h256, shift);

            /* ── CRT gap-solver path (single-threaded, GMP/nonce) ── */
            if (g_crt_mode == CRT_MODE_SOLVER && g_crt_primorial_mpz_init) {
#ifdef WITH_RPC
                int gap_scan_max = g_crt_gap_target * 2;
                if (gap_scan_max < 10000) gap_scan_max = 10000;

                mpz_t crt_end, nAdd_st, cand_st, orig_base_st;
                mpz_inits(crt_end, nAdd_st, cand_st, orig_base_st, NULL);
                mpz_ui_pow_ui(crt_end, 2, (unsigned long)shift);

                /* Precompute primorial % p for incremental rebase. */
                uint64_t *st_prim_mod = NULL;
                size_t    st_prim_cnt = 0;

                static int st_crt_logged = 0;
                if (!st_crt_logged) {
                    size_t prim_bits = mpz_sizeinbase(g_crt_primorial_mpz, 2);
                    log_msg("CRT mining (1T): primorial~2^%zu  shift=%d  gap_scan=%d\n",
                            prim_bits, shift, gap_scan_max);
                    st_crt_logged = 1;
                }

                uint32_t nonce_st = g_pass.nonce + 1;

                while (keep_going && !g_abort_pass) {
                    /* SHA256d for this nonce */
                    uint8_t hdr84_st[84], sha_raw_st[32], h256_st[32];
                    memcpy(hdr84_st, g_pass.hdr80, 80);
                    memcpy(hdr84_st + 80, &nonce_st, 4);
                    double_sha256(hdr84_st, 84, sha_raw_st);

                    if (sha_raw_st[31] < 0x80) { nonce_st++; continue; }

                    for (int k = 0; k < 32; k++) h256_st[k] = sha_raw_st[31 - k];
                    set_base_bn(h256_st, shift);
                    double logbase_st = uint256_log_approx(h256_st, shift);

                    crt_compute_alignment_mpz(nAdd_st);

                    /* Save original base; lazy-init primorial mod cache. */
                    mpz_set(orig_base_st, tls_base_mpz);
                    if (!st_prim_mod && small_primes_cache &&
                        small_primes_count > 0) {
                        st_prim_cnt = small_primes_count;
                        st_prim_mod = (uint64_t *)malloc(
                            st_prim_cnt * sizeof(uint64_t));
                        if (st_prim_mod) {
                            for (size_t pi = 0; pi < st_prim_cnt; pi++)
                                st_prim_mod[pi] = mpz_fdiv_ui(
                                    g_crt_primorial_mpz,
                                    (unsigned long)small_primes_cache[pi]);
                        }
                    }

                    /* First window: full rebase. */
                    mpz_add(cand_st, orig_base_st, nAdd_st);
                    int st_odd = mpz_odd_p(cand_st);
                    if (st_odd) mpz_sub_ui(cand_st, cand_st, 1);
                    rebase_for_gap_check(cand_st);
                    int st_first_win = 1;

                    while (mpz_cmp(nAdd_st, crt_end) < 0 && keep_going && !g_abort_pass) {
                        if (!st_first_win) {
                            /* Incremental rebase */
                            mpz_add(tls_base_mpz, tls_base_mpz,
                                    g_crt_primorial_mpz);
                            if (st_prim_mod && tls_base_mod_p) {
                                for (size_t pi = 0; pi < st_prim_cnt; pi++) {
                                    tls_base_mod_p[pi] += st_prim_mod[pi];
                                    if (tls_base_mod_p[pi] >=
                                        small_primes_cache[pi])
                                        tls_base_mod_p[pi] -=
                                            small_primes_cache[pi];
                                }
                            }
                        }
                        st_first_win = 0;

                        uint64_t gap_L = 1;
                        uint64_t gap_R = (uint64_t)gap_scan_max;
                        size_t surv_cnt = 0;
                        uint64_t *surv = sieve_range(gap_L, gap_R,
                                                     &surv_cnt, NULL, 0);
                        __sync_fetch_and_add(&stats_sieved, gap_R - gap_L);

                        if (!surv || surv_cnt == 0) {
                            mpz_add(nAdd_st, nAdd_st, g_crt_primorial_mpz);
                            continue;
                        }

                        /* Fermat-test ALL survivors */
                        size_t pf = 0;
#ifdef WITH_CUDA
                        if (g_gpu_count > 0) {
                            /* Lazy-init thread-local GPU accumulator */
                            if (!tls_gpu_accum) {
                                static volatile int st_accum_rr = 0;
                                int gi = __sync_fetch_and_add(&st_accum_rr, 1)
                                         % g_gpu_count;
                                tls_gpu_accum = gpu_accum_create(
                                    g_gpu_ctx[gi], g_gpu_batch_size);
                            }
                            if (tls_gpu_accum) {
                                ensure_gmp_tls();
                                uint64_t bl[GPU_NLIMBS];
                                memset(bl, 0, sizeof(bl));
                                size_t nexp = 0;
                                mpz_export(bl, &nexp, -1, 8, 0, 0,
                                           tls_base_mpz);
                                if (nexp <= (size_t)GPU_NLIMBS) {
                                    __sync_fetch_and_add(&stats_tested,
                                        (uint64_t)surv_cnt);
                                    if (gpu_accum_add(tls_gpu_accum, bl,
                                            surv, surv_cnt, nonce_st,
                                            st_odd, logbase_st,
                                            target, shift,
                                            nAdd_st, rpc_url,
                                            rpc_user, rpc_pass))
                                        gpu_accum_flush(tls_gpu_accum);
                                    mpz_add(nAdd_st, nAdd_st,
                                            g_crt_primorial_mpz);
                                    continue;
                                }
                            }
                            /* Fallback: direct GPU batch */
                            pf = gpu_batch_filter(surv, surv_cnt);
                            __sync_fetch_and_add(&stats_tested, (uint64_t)surv_cnt);
                        } else
#endif
                        {
                            for (size_t j = 0; j < surv_cnt; j++) {
                                __sync_fetch_and_add(&stats_tested, 1);
                                if (bn_candidate_is_prime(surv[j]))
                                    surv[pf++] = surv[j];
                            }
                        }

                        /* Scan consecutive primes for qualifying gaps */
                        __sync_fetch_and_add(&stats_crt_windows, 1);
                        __sync_fetch_and_add(&stats_primes_found, (uint64_t)pf);
                        if (pf >= 2) {
                            __sync_fetch_and_add(&stats_pairs,
                                                 (uint64_t)(pf - 1));
                            for (size_t i = 0; i + 1 < pf; i++) {
                                uint64_t gap = surv[i + 1] - surv[i];
                                double merit = (double)gap / logbase_st;
                                if (merit > stats_best_merit) {
                                    stats_best_merit = merit;
                                    stats_best_gap   = gap;
                                }
                                if (merit < target) continue;

                                __sync_fetch_and_add(&stats_gaps, 1);

                                mpz_t nAdd_p;
                                mpz_init(nAdd_p);
                                mpz_set(nAdd_p, nAdd_st);
                                mpz_add_ui(nAdd_p, nAdd_p, surv[i]);
                                if (st_odd)
                                    mpz_sub_ui(nAdd_p, nAdd_p, 1);

                                char nAdd_s[256];
                                gmp_snprintf(nAdd_s, sizeof(nAdd_s),
                                             "%Zd", nAdd_p);
                                log_msg("\n>>> GAP FOUND\n"
                                        "    gap     = %llu\n"
                                        "    merit   = %.6f  (need >= %.2f)\n"
                                        "    nShift  = %d\n"
                                        "    nonce   = %u\n"
                                        "    nAdd    = %s\n",
                                        (unsigned long long)gap,
                                        merit, target, shift,
                                        (unsigned)nonce_st, nAdd_s);
#ifdef WITH_RPC
                                if (rpc_url && !g_abort_pass) {
                                    char blockhex[16384];
                                    memset(blockhex, 0, sizeof(blockhex));
                                    if (assemble_mining_block_mpz(nonce_st,
                                            nAdd_p, blockhex)) {
                                        __sync_fetch_and_add(&stats_blocks, 1);
                                        log_file_only("Built blockhex: %s\n",
                                                      blockhex);
                                        if (header_meets_target_hex(blockhex)) {
                                            log_msg(">>> SUBMITTING to node\n");
                                            struct submit_job _job;
                                            memset(&_job, 0, sizeof(_job));
                                            strncpy(_job.url, rpc_url,
                                                    sizeof(_job.url)-1);
                                            strncpy(_job.user,
                                                    rpc_user ? rpc_user : "",
                                                    sizeof(_job.user)-1);
                                            strncpy(_job.pass,
                                                    rpc_pass ? rpc_pass : "",
                                                    sizeof(_job.pass)-1);
                                            strncpy(_job.method, "getwork",
                                                    sizeof(_job.method)-1);
                                            memcpy(_job.hex, blockhex,
                                                   sizeof(_job.hex));
                                            _job.retries = rpc_default_retries;
                                            __sync_fetch_and_add(&stats_submits,
                                                                 1);
                                            enqueue_job(&_job);
                                            log_msg(">>> QUEUED for async submit"
                                                    "\n");
                                            print_stats();
                                        }
                                    }
                                }
#endif
                                mpz_clear(nAdd_p);
                            }
                        }

                        mpz_add(nAdd_st, nAdd_st, g_crt_primorial_mpz);
                    } /* end CRT candidate loop */
#ifdef WITH_CUDA
                    /* Flush remaining accumulated GPU windows */
                    if (tls_gpu_accum && tls_gpu_accum->win_count > 0) {
                        if (g_abort_pass)
                            gpu_accum_reset(tls_gpu_accum);
                        else
                            gpu_accum_flush(tls_gpu_accum);
                    }
#endif

                    nonce_st++;
                } /* end nonce loop */

                mpz_clears(crt_end, nAdd_st, cand_st, orig_base_st, NULL);
                free(st_prim_mod);
                goto st_rpc_poll;
#endif /* WITH_RPC — CRT-SOLVER single-thread */
            }

            for (int64_t adder=0; adder<num_windows; ++adder) {
                /* L, R are relative offsets from h256<<shift (= nAdd range) */
                uint64_t L = (uint64_t)adder * sieve_size;
                if ((L & 1) == 0) L++;
                uint64_t R = L + sieve_size;
                if (R > (uint64_t)adder_max) R = (uint64_t)adder_max;
                if (R <= L) continue;
                size_t cnt=0;
                uint64_t *pr = sieve_range(L, R, &cnt, h256, shift);
                __sync_fetch_and_add(&stats_sieved, (uint64_t)(R - L));
                /* primality – compact pr[] in-place using big-prime BN test */
                size_t pf = 0;
                size_t orig_cnt_st = cnt;
                int smart_K_st = cli_sample_stride;
                int use_smart_st = (smart_K_st > 1 && !no_primality
                                    && cnt > (size_t)(smart_K_st * 4));

                if (use_smart_st) {
                    /* --- Phase 1: sample every Kth survivor --------------- */
                    size_t p1n = (cnt + (size_t)smart_K_st - 1) / (size_t)smart_K_st;
                    uint64_t *sampled = (uint64_t *)malloc(p1n * sizeof(uint64_t));
                    if (!sampled) { use_smart_st = 0; goto st_full; }

                    size_t sp = 0;
                    /* Build phase-1 candidate array */
                    uint64_t *p1_arr = (uint64_t *)malloc(p1n * sizeof(uint64_t));
                    if (p1_arr) {
                        for (size_t j = 0, k = 0; j < cnt; j += (size_t)smart_K_st)
                            p1_arr[k++] = pr[j];
                    }
#ifdef WITH_CUDA
                    if (g_gpu_count > 0 && p1_arr) {
                        sp = gpu_batch_filter(p1_arr, p1n);
                        memcpy(sampled, p1_arr, sp * sizeof(uint64_t));
                    } else
#endif
                    {
                        for (size_t j = 0; j < cnt; j += (size_t)smart_K_st) {
                            if (bn_candidate_is_prime(pr[j]))
                                sampled[sp++] = pr[j];
                        }
                    }
                    free(p1_arr);
                    __sync_fetch_and_add(&stats_tested, (uint64_t)p1n);

                    size_t needed = (size_t)(target * logbase);
                    if (needed < 2) needed = 2;

                    /* --- Collect verification candidates ------------------ */
                    size_t v_alloc = cnt / 4 + 64, v_cnt = 0;
                    uint64_t *verify = (uint64_t *)malloc(v_alloc * sizeof(uint64_t));
                    if (!verify) { free(sampled); use_smart_st = 0; goto st_full; }

                    #define COLLECT_ST(lo_val, hi_val) do {                      \
                        size_t _lo = 0, _hi = cnt;                              \
                        while (_lo < _hi) {                                     \
                            size_t _m = _lo + (_hi - _lo) / 2;                  \
                            if (pr[_m] <= (lo_val)) _lo = _m + 1;              \
                            else _hi = _m;                                      \
                        }                                                       \
                        for (size_t _j = _lo;                                   \
                             _j < cnt && pr[_j] < (hi_val); _j++) {             \
                            if (_j % (size_t)smart_K_st == 0) continue;         \
                            if (v_cnt >= v_alloc) {                             \
                                v_alloc *= 2;                                   \
                                verify = (uint64_t *)realloc(verify,            \
                                            v_alloc * sizeof(uint64_t));        \
                            }                                                   \
                            verify[v_cnt++] = pr[_j];                           \
                        }                                                       \
                    } while (0)

                    /* Track gap-region boundaries (same fix as cooperative path) */
                    size_t n_greg_st = 0;
                    size_t greg_cap_st = sp + 2;
                    uint64_t *greg_lo_st = (uint64_t *)malloc(greg_cap_st * sizeof(uint64_t));
                    uint64_t *greg_hi_st = (uint64_t *)malloc(greg_cap_st * sizeof(uint64_t));

                    if (sp > 0 && cnt > 0 && sampled[0] - pr[0] >= needed) {
                        COLLECT_ST(pr[0] - 1, sampled[0]);
                        if (greg_lo_st) { greg_lo_st[n_greg_st] = 0; greg_hi_st[n_greg_st] = sampled[0]; n_greg_st++; }
                    }
                    for (size_t i = 0; i + 1 < sp; i++) {
                        if (sampled[i+1] - sampled[i] >= needed) {
                            COLLECT_ST(sampled[i], sampled[i+1]);
                            if (greg_lo_st) { greg_lo_st[n_greg_st] = sampled[i]; greg_hi_st[n_greg_st] = sampled[i+1]; n_greg_st++; }
                        }
                    }
                    if (sp > 0 && cnt > 0 &&
                        pr[cnt-1] - sampled[sp-1] >= needed) {
                        COLLECT_ST(sampled[sp-1], pr[cnt-1] + 1);
                        if (greg_lo_st) { greg_lo_st[n_greg_st] = sampled[sp-1]; greg_hi_st[n_greg_st] = UINT64_MAX; n_greg_st++; }
                    }
                    #undef COLLECT_ST

                    /* --- Phase 2: test verification candidates ------------ */
                    pf = sp;
                    memcpy(pr, sampled, sp * sizeof(uint64_t));
#ifdef WITH_CUDA
                    if (g_gpu_count > 0 && v_cnt > 0) {
                        size_t vp = gpu_batch_filter(verify, v_cnt);
                        for (size_t i = 0; i < vp; i++)
                            pr[pf++] = verify[i];
                    } else
#endif
                    {
                        for (size_t i = 0; i < v_cnt; i++) {
                            if (bn_candidate_is_prime(verify[i]))
                                pr[pf++] = verify[i];
                        }
                    }
                    __sync_fetch_and_add(&stats_tested, (uint64_t)v_cnt);
                    if (pf > 1) qsort(pr, pf, sizeof(uint64_t), cmp_u64);
                    cnt = pf;

                    /* Scan only fully-verified gap regions (same fix as cooperative path) */
                    {
                        size_t region_pairs_st = 0;
                        for (size_t r = 0; r < n_greg_st && greg_lo_st; r++) {
                            size_t lo_idx = 0;
                            { size_t l = 0, h = cnt;
                              while (l < h) { size_t m = l+(h-l)/2; if (pr[m] < greg_lo_st[r]) l=m+1; else h=m; }
                              lo_idx = l; }
                            size_t hi_idx = cnt;
                            { size_t l = 0, h = cnt;
                              while (l < h) { size_t m = l+(h-l)/2; if (pr[m] <= greg_hi_st[r]) l=m+1; else h=m; }
                              hi_idx = l; }
                            size_t seg_cnt = (hi_idx > lo_idx) ? hi_idx - lo_idx : 0;
                            if (seg_cnt >= 2) {
                                region_pairs_st += seg_cnt - 1;
                                if (scan_candidates(pr + lo_idx, seg_cnt,
                                                   target, logbase, shift,
                                                   header, rpc_url, rpc_user,
                                                   rpc_pass, rpc_method,
                                                   rpc_sign_key))
                                    return 0;
                            }
                        }
                        /* ETA pair compensation */
                        if (sp > 0 && p1n > 0) {
                            size_t est_full = (size_t)((double)orig_cnt_st
                                            * (double)sp / (double)p1n);
                            if (est_full > 1 + region_pairs_st)
                                __sync_fetch_and_add(&stats_pairs,
                                                     (uint64_t)(est_full - 1 - region_pairs_st));
                        }
                    }
                    free(greg_lo_st);
                    free(greg_hi_st);
                    free(sampled);
                    free(verify);
                } else {
                st_full:
                    if (!no_primality) {
                        size_t test_cnt = cnt;
#ifdef WITH_CUDA
                        if (g_gpu_count > 0) {
                            pf = gpu_batch_filter(pr, cnt);
                        } else
#endif
                        {
                            for (size_t i = 0; i < cnt; i++) {
                                if (bn_candidate_is_prime(pr[i])) pr[pf++] = pr[i];
                            }
                        }
                        __sync_fetch_and_add(&stats_tested, (uint64_t)test_cnt);
                        cnt = pf;
                    } else {
                        pf = cnt;
                        __sync_fetch_and_add(&stats_tested, (uint64_t)cnt);
                    }
                }
                /* Smart-scan handles gap scanning via regions above;
                   only run full-array scan for full-test / no_primality. */
                if (!use_smart_st && cnt>=2) {
                    if (scan_candidates(pr, cnt, target, logbase,
                                       shift, header,
                                       rpc_url, rpc_user, rpc_pass,
                                       rpc_method, rpc_sign_key)) {
                        return 0;
                    }
                }
            }
        st_rpc_poll:
            if (keep_going && rpc_url) {
#ifdef WITH_RPC
              if (g_stratum) {
                char sdata[161]; uint64_t sndiff;
                if (stratum_poll_new_work(g_stratum, sdata, &sndiff)) {
                    build_mining_pass_stratum(sdata, sndiff, shift);
                    memcpy(h256, g_pass.h256, 32);
                    free((char*)header);
                    header = strdup(g_pass.prevhex);
                    if (!g_abort_pass)
                        log_msg("\n*** STRATUM NEW BLOCK ***\n\n");
                    g_abort_pass = 1;
                }
              } else {
                sq_drain();
                if (build_mining_pass(rpc_url, rpc_user, rpc_pass, shift)) {
                    memcpy(h256, g_pass.h256, 32);
                    if (g_pass.prevhex[0] && strcmp(g_pass.prevhex, header ? header : "") != 0) {
                        free((char*)header);
                        header = strdup(g_pass.prevhex);
                        if (!g_abort_pass)
                            log_msg("\n*** NEW BLOCK  prevhash=%.16s...  mining on top ***\n\n", g_pass.prevhex);
                        pthread_mutex_lock(&g_work_lock);
                        strncpy(g_prevhash, g_pass.prevhex, 64); g_prevhash[64] = '\0';
                        pthread_mutex_unlock(&g_work_lock);
                        g_abort_pass = 1;
                    }
                }
              }
#endif
            }
        } while (keep_going);
    } else {
        do {
            g_abort_pass = 0;
            /* Flush stale heap items from previous pass and bump generation */
            if (crt_fermat_threads > 0) {
                crt_heap_shutdown = 0;
                crt_heap_flush();
                __sync_fetch_and_add(&crt_heap_gen, 1);
            }
            pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
            struct worker_args *wargs = malloc(sizeof(struct worker_args) * num_threads);
            /* Partition the adder range evenly across threads so every core
               has its own non-overlapping slice to search.  With the old
               stride-by-nthreads design, thread i only touched windows
               i, i+N, i+2N, ... so if num_windows < N most threads were idle.
               Now thread t covers [(t*adder_max/N), ((t+1)*adder_max/N)) and
               loops over those windows continuously until a new block arrives. */
            int64_t slice = adder_max / (int64_t)num_threads;
            if (slice < 1) slice = 1;
            /* Assign CRT roles: first (num_threads - crt_fermat_threads) are
               sieve producers (role=0), rest are fermat consumers (role=1).
               Sieve threads get sequential tids 0..n_sieve-1 for nonce
               distribution; fermat threads don't iterate nonces. */
            int n_sieve = num_threads - crt_fermat_threads;
            if (n_sieve < 1) n_sieve = 1;
            for (int t = 0; t < num_threads; t++) {
                int64_t off  = (int64_t)t * slice;
                int64_t sz   = (t == num_threads - 1) ? (adder_max - off) : slice;
                wargs[t].tid               = t;
                wargs[t].nthreads          = num_threads;
                wargs[t].rpc_thread        = (t == 0) ? 1 : 0;
                wargs[t].adder_base_offset = off;
                wargs[t].adder_max         = sz;
                memcpy(wargs[t].h256, h256, 32);
                wargs[t].shift             = shift;
                wargs[t].sieve_size        = sieve_size;
                wargs[t].target            = target;
                wargs[t].header            = header;
                wargs[t].rpc_url           = rpc_url;
                wargs[t].rpc_user          = rpc_user;
                wargs[t].rpc_pass          = rpc_pass;
                wargs[t].rpc_method        = rpc_method;
                wargs[t].rpc_sign_key      = rpc_sign_key;
                /* CRT role: sieve threads are 0..n_sieve-1, fermat are the rest */
                wargs[t].crt_role = (crt_fermat_threads > 0 && t >= n_sieve) ? 1 : 0;
                pthread_create(&threads[t], NULL, worker_fn, &wargs[t]);
            }
            for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);
            free(threads);
            free(wargs);

            if (keep_going && rpc_url) {
#ifdef WITH_RPC
              if (g_stratum) {
                char sdata[161]; uint64_t sndiff;
                if (stratum_poll_new_work(g_stratum, sdata, &sndiff)) {
                    build_mining_pass_stratum(sdata, sndiff, shift);
                    memcpy(h256, g_pass.h256, 32);
                    free((char*)header);
                    header = strdup(g_pass.prevhex);
                    if (!g_abort_pass)
                        log_msg("\n*** STRATUM NEW BLOCK ***\n\n");
                }
              } else {
                /* Drain submit queue before getwork to keep mapNewBlock consistent. */
                sq_drain();
                if (build_mining_pass(rpc_url, rpc_user, rpc_pass, shift)) {
                    memcpy(h256, g_pass.h256, 32);
                    if (g_pass.prevhex[0] && strcmp(g_pass.prevhex, header ? header : "") != 0) {
                        free((char*)header);
                        header = strdup(g_pass.prevhex);
                        if (!g_abort_pass)
                            log_msg("\n*** NEW BLOCK  prevhash=%.16s...  mining on top ***\n\n", g_pass.prevhex);
                        pthread_mutex_lock(&g_work_lock);
                        strncpy(g_prevhash, g_pass.prevhex, 64); g_prevhash[64] = '\0';
                        pthread_mutex_unlock(&g_work_lock);
                    }
                }
              }
#endif
            }
        } while (keep_going);
    }
#ifdef WITH_RPC
    if (rpc_url && !g_stratum) stop_submit_thread();
    if (g_stratum) stratum_disconnect(g_stratum);
#endif
#ifdef WITH_CUDA
    for (int gi = 0; gi < g_gpu_count; gi++)
        gpu_fermat_destroy(g_gpu_ctx[gi]);
#endif
    stop_stats_thread();
    if (!keep_going) {
        printf("Done, no qualifying gaps found in tried adders.\n");
        return 0;
    }
    /* if keep_going was true we only get here when the main loop breaks (e.g.
       after a successful exit triggered by debug_force or a signal).  fall
       through to return 0 normally. */
    return 0;
}
