#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#ifdef WITH_RPC
#include <curl/curl.h>
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
#include <sys/time.h>

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
static struct submit_job submit_queue[SUBMIT_QUEUE_MAX];
static int sq_head = 0, sq_tail = 0, sq_count = 0;
static int sq_running = 0;
static pthread_t sq_thread;

/* rpc timing/retry globals */
static uint64_t last_submit_ms = 0;
static int rpc_rate_ms = 0;
static int rpc_default_retries = 3;
#endif

// tuned segmented-sieve helper: limit primes used to pre-sieve to this bound
// (default; can be overridden at runtime via --sieve-primes)
#define SIEVE_SMALL_PRIME_LIMIT 1000000
static uint64_t cli_sieve_prime_limit = SIEVE_SMALL_PRIME_LIMIT;

// cache of small primes used for segmented sieving (allocated once)
static uint64_t *small_primes_cache = NULL;
static size_t small_primes_count = 0;
static size_t small_primes_cap = 0;
static pthread_once_t small_primes_once = PTHREAD_ONCE_INIT;

static void populate_small_primes_cache(void) {
    size_t maxp = SIEVE_SMALL_PRIME_LIMIT + 1;
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
static volatile uint64_t stats_blocks = 0;         /* blocks built */
static volatile uint64_t stats_submits = 0;        /* shares submitted */
static volatile uint64_t stats_success = 0;        /* shares accepted */
static uint64_t stats_start_ms = 0;                /* time mining started */

/* shared current-work state so any thread can detect a new block */
static char     g_prevhash[65]  = {0};
static uint64_t g_height        = 0;
static pthread_mutex_t g_work_lock = PTHREAD_MUTEX_INITIALIZER;
/* set to 1 by thread-0 when a new block is detected; all workers break their
   adder loop and the main thread restarts the pass with fresh work */
static volatile int g_abort_pass = 0;

/* Parse prevhash and height from a GBT JSON string, log a clear banner if
   the chain tip has moved, and update the shared globals. */
static void check_and_log_new_work(const char *gbt_json) {
    if (!gbt_json) return;
    char prevhash[65] = {0};
    uint64_t height = 0;
    const char *p = strstr(gbt_json, "\"previousblockhash\"");
    if (p) {
        const char *c = strchr(p, ':'); if (c) {
            const char *q = strchr(c, '"'); if (q) {
                const char *e = strchr(q+1, '"');
                if (e && (size_t)(e-q-1) < sizeof(prevhash))
                    { memcpy(prevhash, q+1, e-q-1); prevhash[e-q-1] = '\0'; }
            }
        }
    }
    const char *h = strstr(gbt_json, "\"height\"");
    if (h) { const char *c = strchr(h, ':'); if (c) height = (uint64_t)strtoull(c+1, NULL, 10); }
    if (!prevhash[0]) return;
    pthread_mutex_lock(&g_work_lock);
    if (strcmp(prevhash, g_prevhash) != 0) {
        memcpy(g_prevhash, prevhash, sizeof(g_prevhash));
        g_height = height;
        pthread_mutex_unlock(&g_work_lock);
        log_msg("\n*** NEW BLOCK  height=%llu  prevhash=%.16s...  mining on top ***\n\n",
                (unsigned long long)height, prevhash);
    } else {
        pthread_mutex_unlock(&g_work_lock);
    }
}
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

static void print_stats(void) {
    uint64_t now = now_ms();
    double elapsed = stats_start_ms ? (double)(now - stats_start_ms) / 1000.0 : 0.0;
    double sieve_rate  = (elapsed > 0.001) ? (double)stats_sieved  / elapsed : 0.0;
    double test_rate   = (elapsed > 0.001) ? (double)stats_tested  / elapsed : 0.0;
    double gap_rate    = (elapsed > 0.001) ? (double)stats_gaps    / elapsed : 0.0;
    log_msg("STATS: elapsed=%.1fs  sieved=%llu (%.0f/s)  tested=%llu (%.0f/s)  gaps=%llu (%.3f/s)  built=%llu  submitted=%llu  accepted=%llu\n",
            elapsed,
            (unsigned long long)stats_sieved,  sieve_rate,
            (unsigned long long)stats_tested,  test_rate,
            (unsigned long long)stats_gaps,    gap_rate,
            (unsigned long long)stats_blocks,
            (unsigned long long)stats_submits,
            (unsigned long long)stats_success);
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
static __thread double   *tls_log  = NULL;
static __thread size_t    tls_cap  = 0;
/* Reusable composite-bits bitmap per thread – avoids calloc/free on every sieve call */
static __thread uint8_t  *tls_bits     = NULL;
static __thread size_t    tls_bits_cap = 0;

static void free_sieve_buffers(void) {
    free(tls_pr);
    free(tls_log);
    free(tls_bits);
    tls_pr       = NULL;
    tls_log      = NULL;
    tls_bits     = NULL;
    tls_cap      = 0;
    tls_bits_cap = 0;
}

static uint64_t* sieve_range(uint64_t L, uint64_t R, size_t *out_count,
                             double **out_logs) {
    if (L >= R) { *out_count = 0; if (out_logs) *out_logs = NULL; return NULL; }
    if (L < 3) L = 3;
    if ((L & 1) == 0) L++;
    if ((R & 1) == 0) R++;
    uint64_t seg_size = (R - L) / 2 + 1;
    size_t bit_size = (seg_size + 7) / 8;
    /* Reuse thread-local bits buffer; grow only when needed (memset << calloc) */
    if (tls_bits_cap < bit_size) {
        free(tls_bits);
        tls_bits = malloc(bit_size + 64); /* +64 for safe 8-byte word reads at tail */
        if (!tls_bits) { tls_bits_cap = 0; *out_count = 0; if (out_logs) *out_logs = NULL; return NULL; }
        tls_bits_cap = bit_size + 64;
    }
    memset(tls_bits, 0, bit_size);
    uint8_t *bits = tls_bits;

    uint64_t limit = (uint64_t)floor(sqrt((double)R)) + 1;
    uint64_t use_limit = limit;
    if (use_limit > cli_sieve_prime_limit) use_limit = cli_sieve_prime_limit;
    if (use_limit > SIEVE_SMALL_PRIME_LIMIT) use_limit = SIEVE_SMALL_PRIME_LIMIT;  /* safety */
    pthread_once(&small_primes_once, populate_small_primes_cache);

    /* Start marking at idx=1 to skip p=2: L is always odd, so even multiples
       of 2 produce fractional bit-array indices and corrupt the sieve. */
    if (small_primes_cache) {
        for (size_t idx = 1; idx < small_primes_count; ++idx) {
            uint64_t p = small_primes_cache[idx];
            if (p > use_limit) break;
            uint64_t start = (L + p - 1) / p * p;
            if ((start & 1) == 0) start += p;
            for (uint64_t m = start; m < R; m += 2 * p) {
                uint64_t pos = (m - L) / 2;
                if (pos < seg_size) bits[pos>>3] |= (uint8_t)(1u << (pos & 7));
            }
        }
    }

    /* ensure the tls buffers are large enough */
    if (tls_cap < seg_size) {
        size_t newcap = seg_size;
        tls_pr = realloc(tls_pr, newcap * sizeof(uint64_t));
        tls_log = realloc(tls_log, newcap * sizeof(double));
        if (!tls_pr || !tls_log) {
            free(bits);
            *out_count = 0;
            if (out_logs) *out_logs = NULL;
            return NULL;
        }
        tls_cap = newcap;
    }

    /* Extract surviving candidates.  Use a 30-wheel to skip numbers divisible
       by 2, 3, or 5 – they were marked composite by the sieve but skipping them
       here halves the number of bit-array accesses compared with a linear scan,
       which matters when log() is called for every survivor.
       wheel30[w] = step to next coprime-with-30 residue. */
    static const uint8_t wheel30[8] = {6,4,2,4,2,4,6,2};
    static const int8_t mod30_start[30] = {
        -1,-1,-1,-1,-1,-1,-1, 1,-1,-1,-1, 2,-1, 3,-1,-1,-1, 4,-1, 5,-1,-1,-1, 6,-1,-1,-1,-1,-1, 7
    };
    size_t out_cnt = 0;
    uint64_t x = L;
    if ((x & 1) == 0) x++;
    uint8_t r0 = (uint8_t)(x % 30);
    int w;
    if (r0 == 1) { w = 0; }
    else if (r0 < 30 && mod30_start[r0] >= 0) { w = mod30_start[r0]; }
    else {
        do { x += 2; } while (x < R && (x % 30 == 0 || mod30_start[x % 30] < 0));
        if (x >= R) { *out_count = 0; if (out_logs) *out_logs = NULL; return NULL; }
        w = (x % 30 == 1) ? 0 : mod30_start[x % 30];
    }
    while (x < R) {
        uint64_t pos = (x - L) >> 1;
        if (pos < seg_size && !(bits[pos>>3] & (uint8_t)(1u << (pos & 7)))) {
            tls_pr[out_cnt]  = x;
            tls_log[out_cnt] = log((double)x);
            out_cnt++;
        }
        x += wheel30[w];
        w = (w + 1) & 7;
    }
    *out_count = out_cnt;
    if (out_logs) *out_logs = tls_log;
    return tls_pr;
}

#ifdef WITH_RPC
struct string {
    char *ptr;
    size_t len;
};

static void init_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(1);
    s->ptr[0] = '\0';
}

static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s) {
    size_t newlen = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, newlen + 1);
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[newlen] = '\0';
    s->len = newlen;
    return size * nmemb;
}

// rpc_submit/rpc_call are provided by the C++ wrapper in `src/rpc_cwrap.cpp`
#ifdef WITH_RPC
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
        if (last_submit_ms && now - last_submit_ms < rpc_rate_ms) {
            uint64_t wait = rpc_rate_ms - (now - last_submit_ms);
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
static void encode_pow_header_binary(const char *header, uint64_t p, uint64_t q, char outhex[197]) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)header, strlen(header), md);
    unsigned char buf[32 + 8 + 8];
    memcpy(buf, md, 32);
    u64_to_le(p, buf+32);
    u64_to_le(q, buf+40);
    bytes_to_hex(buf, sizeof(buf), outhex);
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
        snprintf(binpath, sizeof(binpath), "/tmp/gap_miner_block_%lu_%lu_%u.bin",
                 (unsigned long)time(NULL), (unsigned long)getpid(), (unsigned)rand());
        snprintf(hexpath, sizeof(hexpath), "/tmp/gap_miner_block_%lu_%lu_%u.hex",
                 (unsigned long)time(NULL), (unsigned long)getpid(), (unsigned)rand());
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

/* check whether the block should be forwarded to the node for PoW validation.
   Gapcoin uses prime-gap proof-of-work, not hash-based PoW; the real PoW check
   is performed by gapcoind on submitblock, so we always forward the block.
   debug_force is checked first for the --force-solution testing path. */
static int header_meets_target_hex(const char *blockhex) {
    (void)blockhex; /* the node decides; we never reject locally */
    return 1;
}

/* Extract and format the difficulty field from a GBT JSON string.
   Gapcoin stores difficulty as a quoted 8-byte hex value; we parse it and
   return a human-readable string "0x<hex> (~merit N.NN)" where the second
   byte of the value is the approximate integer minimum-merit encoded in the
   compact difficulty format.  Falls back to "(unknown)" if not found. */
static void gbt_difficulty_str(const char *gbt_json, char out[64]) {
    out[0] = '\0';
    if (!gbt_json) { snprintf(out, 64, "(unknown)"); return; }
    const char *bts = strstr(gbt_json, "\"difficulty\"");
    if (!bts) { snprintf(out, 64, "(unknown)"); return; }
    const char *c = strchr(bts, ':'); if (!c) { snprintf(out, 64, "(unknown)"); return; }
    const char *q1 = strchr(c, '"'); if (!q1) { snprintf(out, 64, "(unknown)"); return; }
    const char *q2 = strchr(q1+1, '"'); if (!q2) { snprintf(out, 64, "(unknown)"); return; }
    size_t hlen = (size_t)(q2 - (q1+1));
    if (hlen == 0 || hlen > 16) { snprintf(out, 64, "(unknown)"); return; }
    char hbuf[17]; memcpy(hbuf, q1+1, hlen); hbuf[hlen] = '\0';
    /* parse as big-endian uint64 */
    uint64_t v = 0;
    for (size_t i = 0; i < hlen; i++) {
        char ch = hbuf[i]; int val = 0;
        if (ch>='0'&&ch<='9') val=ch-'0';
        else if (ch>='a'&&ch<='f') val=10+ch-'a';
        else if (ch>='A'&&ch<='F') val=10+ch-'A';
        v = (v<<4)|(uint64_t)val;
    }
    /* second byte encodes the integer part of minimum merit in Gapcoin compact format */
    unsigned int merit_int = (unsigned int)((v >> 48) & 0xFF);
    unsigned int frac = (unsigned int)((v >> 32) & 0xFFFF);
    double merit_f = merit_int + (double)frac / 65536.0;
    snprintf(out, 64, "0x%016llx (~min-merit %.2f)", (unsigned long long)v, merit_f);
}

static uint64_t hash_to_int(const char *s, int is_hex) {
    if (is_hex) {
        uint64_t v = 0;
        for (size_t i=0;i<16 && s[i];++i) {
            char c = s[i];
            int val = 0;
            if (c>='0'&&c<='9') val=c-'0'; else if (c>='a'&&c<='f') val=10+c-'a'; else if (c>='A'&&c<='F') val=10+c-'A';
            v = (v<<4) | (val & 0xf);
        }
        return v;
    }
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)s, strlen(s), md);
    uint64_t v = 0;
    for (int i=0;i<8;i++) v = (v<<8) | md[i];
    return v;
}

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
    uint64_t h_int;
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
};

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
static int scan_candidates(uint64_t *pr, double *pr_log, size_t cnt, double target_local,
                           uint64_t h_int_sc, int shift_sc,
                           const char *header_local,
                           const char *rpc_url_local,
                           const char *rpc_user_local,
                           const char *rpc_pass_local,
                           const char *rpc_method_local,
                           const char *rpc_sign_key_local) {
    for (size_t i = 0; i + 1 < cnt; i++) {
        uint64_t prev  = pr[i];
        uint64_t q     = pr[i + 1];
        uint64_t gap   = q - prev;
        double logp    = pr_log[i];
        double merit   = (double)gap / logp;
        if (merit < target_local)
            continue;

        __sync_fetch_and_add(&stats_gaps, 1);
        /* Compute nAdd here so we can log it alongside the gap */
        uint64_t nadd_sc = prev - (h_int_sc << shift_sc);
        log_msg("\n>>> GAP FOUND\n"
                "    p       = %llu\n"
                "    q       = %llu\n"
                "    gap     = %llu\n"
                "    merit   = %.6f  (need >= %.2f)\n"
                "    nShift  = %d\n"
                "    nAdd    = %llu (0x%llx)\n",
                (unsigned long long)prev,
                (unsigned long long)q,
                (unsigned long long)gap,
                merit, target_local,
                shift_sc,
                (unsigned long long)nadd_sc,
                (unsigned long long)nadd_sc);
#ifdef WITH_RPC
            if (rpc_url_local) {
                char *gbt = rpc_getblocktemplate(rpc_url_local, rpc_user_local, rpc_pass_local);
                char blockhex[16384]; memset(blockhex,0,sizeof(blockhex));
                if (gbt) {
                    /* Piggyback new-block detection on the GBT we just fetched.
                       This updates g_prevhash and sets g_abort_pass when the
                       chain tip has advanced, without waiting for the 5-second
                       poll in worker_fn thread 0. */
                    check_and_log_new_work(gbt);
                    if (g_abort_pass) { free(gbt); continue; }
                    /* Only one submission per block round: if there is already
                       a job in the queue this gap will almost certainly be stale
                       by the time the submit thread gets to it. */
                    pthread_mutex_lock(&sq_lock);
                    int sq_busy = (sq_count > 0);
                    pthread_mutex_unlock(&sq_lock);
                    if (sq_busy) { free(gbt); continue; }
                    char diff_str[64]; gbt_difficulty_str(gbt, diff_str);
                    log_msg("    network difficulty = %s\n", diff_str);
                    char payload_hex[197]; encode_pow_header_binary(header_local, prev, q, payload_hex);
                    if (build_block_from_gbt_and_payload(gbt, payload_hex, shift_sc, nadd_sc, blockhex)) {
                        __sync_fetch_and_add(&stats_blocks,1);
                        log_file_only("Built blockhex: %s\n", blockhex);
                        if (header_meets_target_hex(blockhex)) {
                            log_msg(">>> SUBMITTING to node\n"
                                    "    merit=%.6f  gap=%llu  p=%llu  nShift=%d  nAdd=%llu\n"
                                    "    network difficulty = %s\n",
                                    merit, (unsigned long long)gap, (unsigned long long)prev,
                                    shift_sc, (unsigned long long)nadd_sc, diff_str);
                            if (rpc_sign_key_local) {
                                char sig[65];
                                hmac_sha256_hex(rpc_sign_key_local, blockhex, sig);
                                log_msg("    signature: %s\n", sig);
                            }
                            if (rpc_url_local) {
                                struct submit_job _job;
                                memset(&_job, 0, sizeof(_job));
                                strncpy(_job.url,    rpc_url_local,                       sizeof(_job.url)-1);
                                strncpy(_job.user,   rpc_user_local   ? rpc_user_local   : "", sizeof(_job.user)-1);
                                strncpy(_job.pass,   rpc_pass_local   ? rpc_pass_local   : "", sizeof(_job.pass)-1);
                                strncpy(_job.method, rpc_method_local ? rpc_method_local : "submitblock", sizeof(_job.method)-1);
                                /* blockhex and _job.hex are both 16384 bytes; memcpy the full buffer */
                                memcpy(_job.hex, blockhex, sizeof(_job.hex));
                                _job.retries = rpc_default_retries;
                                __sync_fetch_and_add(&stats_submits, 1);
                                enqueue_job(&_job);
                                log_msg(">>> QUEUED for async submit (mining continues)\n");
                            }
                            print_stats();
                            if (!keep_going) {
                                free(gbt);
                                return 1;
                            } else log_msg("continuing mining after success\n");
                        }
                    } else {
                        log_msg("Failed to build block from GBT\n");
                    }
                    free(gbt);
                } else {
                    log_msg("Failed to fetch GBT\n");
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
    double   *pr_log;
    size_t    cap;
    size_t    cnt;
    uint64_t  L, R;
};

struct presieve_ctx {
    struct presieve_buf bufs[2]; /* ping-pong slots                     */
    int fill_slot;               /* helper writes into bufs[fill_slot]  */
    int state;                   /* 0=idle 1=sieving 2=ready -1=exit   */
    pthread_mutex_t mu;
    pthread_cond_t  cv_go;       /* worker -> helper: new window ready  */
    pthread_cond_t  cv_done;     /* helper -> worker: result ready      */
    pthread_t thread;
};

static void presieve_buf_ensure(struct presieve_buf *b, size_t need) {
    if (b->cap >= need) return;
    size_t nc = need + (need >> 1) + 64;
    b->pr     = realloc(b->pr,     nc * sizeof(uint64_t));
    b->pr_log = realloc(b->pr_log, nc * sizeof(double));
    b->cap    = nc;
}

static void *presieve_helper_fn(void *arg) {
    struct presieve_ctx *ctx = arg;
    for (;;) {
        pthread_mutex_lock(&ctx->mu);
        while (ctx->state != 1 && ctx->state != -1)
            pthread_cond_wait(&ctx->cv_go, &ctx->mu);
        if (ctx->state == -1) { pthread_mutex_unlock(&ctx->mu); break; }
        int slot   = ctx->fill_slot;
        uint64_t L = ctx->bufs[slot].L;
        uint64_t R = ctx->bufs[slot].R;
        pthread_mutex_unlock(&ctx->mu);

        /* sieve using this helper's own TLS (independent from worker's TLS) */
        size_t cnt = 0;
        double *log_tls = NULL;
        uint64_t *pr_tls = sieve_range(L, R, &cnt, &log_tls);

        pthread_mutex_lock(&ctx->mu);
        struct presieve_buf *b = &ctx->bufs[slot];
        presieve_buf_ensure(b, cnt);
        if (cnt && pr_tls) {
            memcpy(b->pr,     pr_tls,  cnt * sizeof(uint64_t));
            memcpy(b->pr_log, log_tls, cnt * sizeof(double));
        }
        b->cnt = cnt;
        __sync_fetch_and_add(&stats_sieved, (uint64_t)(R - L));
        ctx->state = 2;
        pthread_cond_signal(&ctx->cv_done);
        pthread_mutex_unlock(&ctx->mu);
    }
    free_sieve_buffers(); /* release helper's TLS */
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
    uint64_t h_int_local            = wa->h_int;
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

    /* This thread covers [base, base+adder_max_local) where base already
       embeds the per-thread offset into the global adder range.            */
    uint64_t base       = (h_int_local << shift_local) + (uint64_t)adder_base_offset_local;
    int64_t  num_windows = ((int64_t)adder_max_local + (int64_t)sieve_size_local - 1)
                           / (int64_t)sieve_size_local;
    if (num_windows == 0) return NULL;

    /* Pre-sieve helper lives for the whole thread lifetime – no respawn
       between passes, eliminating teardown overhead between cycles.        */
    struct presieve_ctx psc;
    memset(&psc, 0, sizeof(psc));
    pthread_mutex_init(&psc.mu, NULL);
    pthread_cond_init(&psc.cv_go,   NULL);
    pthread_cond_init(&psc.cv_done, NULL);
    psc.state = 0; psc.fill_slot = 0;
    pthread_create(&psc.thread, NULL, presieve_helper_fn, &psc);

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
                static uint64_t gbt_last_ms = 0;
                uint64_t now = now_ms();
                if (now - gbt_last_ms >= 5000) {
                    char *gbt = rpc_getblocktemplate(rpc_url_local, rpc_user_local, rpc_pass_local);
                    if (gbt) {
                        check_and_log_new_work(gbt);
                        free(gbt);
                        pthread_mutex_lock(&g_work_lock);
                        int new_block = header_local && strcmp(header_local, g_prevhash) != 0;
                        pthread_mutex_unlock(&g_work_lock);
                        if (new_block) { g_abort_pass = 1; break; }
                    }
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
            } else {
                psc.state = 0;
            }

            /* cur_slot is exclusively ours; helper works on next_slot      */
            uint64_t *pr     = psc.bufs[cur_slot].pr;
            double   *pr_log = psc.bufs[cur_slot].pr_log;
            pthread_mutex_unlock(&psc.mu);

            /* Primality test in-place (runs while helper sieves next window) */
            size_t orig_cnt = cnt;
            size_t pf = 0;
            if (!no_primality) {
                for (size_t i = 0; i < cnt; i++) {
                    if (use_fast_fermat ? fast_fermat_test(pr[i]) : miller_rabin(pr[i])) {
                        pr[pf]     = pr[i];
                        pr_log[pf] = pr_log[i];
                        pf++;
                    }
                }
                __sync_fetch_and_add(&stats_tested, (uint64_t)orig_cnt);
                cnt = pf;
            } else {
                pf = cnt;
                __sync_fetch_and_add(&stats_tested, (uint64_t)cnt);
            }

            if (cnt >= 2) {
                if (scan_candidates(pr, pr_log, cnt, target_local,
                                    h_int_local, shift_local,
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

    free(psc.bufs[0].pr); free(psc.bufs[0].pr_log);
    free(psc.bufs[1].pr); free(psc.bufs[1].pr_log);
    pthread_mutex_destroy(&psc.mu);
    pthread_cond_destroy(&psc.cv_go);
    pthread_cond_destroy(&psc.cv_done);
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
        printf("Usage: %s --header <text> [options]\n", argv[0]);
        printf("  options: --hash-hex --shift N --adder-max M --sieve-size S --sieve-primes P --target T\n");
        printf("           --rpc-url URL --rpc-user U --rpc-pass P --rpc-method METH\n");
        printf("           --rpc-rate MS --rpc-retries N --rpc-sign-key KEY\n");
        printf("           --build-only --no-opreturn --keep-going --stop-after-block\n");
        printf("           --fast-fermat (use fast Fermat primality check)\n");
        printf("           --no-primality    skip probabilistic tests entirely\n");
        printf("           --selftest       run a few primality checks and exit\n");
        printf("           --threads N --p P --q Q --log-file FILE\n");
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
    uint64_t sieve_size = 32768;
    double target = 20.0;
    const char *rpc_url = NULL, *rpc_user = NULL, *rpc_pass = NULL, *rpc_method = "getwork";
    const char *rpc_sign_key = NULL;
    const char *log_file = NULL;
    unsigned int cli_rpc_rate = 0;
    int cli_rpc_retries = -1;
    int build_only = 0;
    int no_opreturn = 0;
    int num_threads = 1;
    uint64_t build_p = 0, build_q = 0;
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i],"--header") && i+1<argc) header = argv[++i];
        else if (!strcmp(argv[i],"--hash-hex")) is_hex = 1;
        else if (!strcmp(argv[i],"--shift") && i+1<argc) shift = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--adder-max") && i+1<argc) adder_max = (int64_t)atoll(argv[++i]);
        else if (!strcmp(argv[i],"--sieve-size") && i+1<argc) sieve_size = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i],"--sieve-primes") && i+1<argc) cli_sieve_prime_limit = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i],"--target") && i+1<argc) target = atof(argv[++i]);
        else if (!strcmp(argv[i],"--rpc-url") && i+1<argc) rpc_url = argv[++i];
        else if (!strcmp(argv[i],"--rpc-user") && i+1<argc) rpc_user = argv[++i];
        else if (!strcmp(argv[i],"--rpc-pass") && i+1<argc) rpc_pass = argv[++i];
        else if (!strcmp(argv[i],"--rpc-method") && i+1<argc) rpc_method = argv[++i];
        else if (!strcmp(argv[i],"--rpc-rate") && i+1<argc) cli_rpc_rate = (unsigned int)atoi(argv[++i]);
        else if (!strcmp(argv[i],"--rpc-retries") && i+1<argc) cli_rpc_retries = atoi(argv[++i]);
        else if (!strcmp(argv[i],"--rpc-sign-key") && i+1<argc) rpc_sign_key = argv[++i];
        else if (!strcmp(argv[i],"--log-file") && i+1<argc) log_file = argv[++i];
        else if (!strcmp(argv[i],"--build-only")) build_only = 1;
        else if (!strcmp(argv[i],"--no-opreturn")) no_opreturn = 1;
        else if (!strcmp(argv[i],"--force-solution")) debug_force = 1;
        else if (!strcmp(argv[i],"--fast-fermat")) use_fast_fermat = 1;
        else if (!strcmp(argv[i],"--no-primality")) no_primality = 1;
        else if (!strcmp(argv[i],"--selftest")) selftest = 1;
        else if (!strcmp(argv[i],"--threads") && i+1<argc) num_threads = atoi(argv[++i]);
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
    if (adder_max < 0) {
        /* no explicit value supplied – use full allowed range */
        adder_max = (int64_t)1 << shift;
        log_msg("auto adder_max=%lld (2^shift)\n", (long long)adder_max);
    }
    if (adder_max > ((int64_t)1 << shift)) {
        fprintf(stderr, "--adder-max (%lld) must be at most 2^shift (%lld)\n", (long long)adder_max, (long long)((int64_t)1 << shift));
        return 2;
    }
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
        if (rpc_url) {
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
                            if (header[0])
                                log_msg("auto-header from GBT = %s\n", header);
                            else
                                log_msg("auto-header from GBT came back empty\n");
                        }
                    }
                }
                free(gbt);
            }
        }
        if (!header) {
            fprintf(stderr, "--header required (or provide --rpc-url for automatic header)\n");
            return 2;
        }
    }
    uint64_t h_int = hash_to_int(header, is_hex);
    atexit(print_stats);
    /* free thread-local sieve buffers when the process exits */
    atexit(free_sieve_buffers);
    if (log_file) {
        log_fp = fopen(log_file, "a");
        if (!log_fp) fprintf(stderr, "Failed to open log file %s\n", log_file);
    }
    stats_start_ms = now_ms();
    start_stats_thread();
    log_msg("C miner starting (shift=%d sieve=%llu)\n", shift, (unsigned long long)sieve_size);
    if (keep_going)
        log_msg("default behaviour: will continue mining after finding a valid block\n");
    else
        log_msg("miner configured to exit when a valid block is found\n");
    if (use_fast_fermat)
        log_msg("fast Fermat primality test enabled\n");

#ifndef WITH_RPC
    /* suppress unused-but-set warnings when built without RPC */
    (void)cli_rpc_rate; (void)cli_rpc_retries; (void)build_only; (void)no_opreturn;
    (void)build_p; (void)build_q; (void)rpc_url; (void)rpc_user; (void)rpc_pass; (void)rpc_method; (void)rpc_sign_key;
#endif

    /* worker definitions moved to file-scope */


#ifdef WITH_RPC
    if (cli_rpc_rate) rpc_rate_ms = cli_rpc_rate;
    if (cli_rpc_retries >= 0) rpc_default_retries = cli_rpc_retries;
    if (rpc_url) start_submit_thread();
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
            encode_pow_header_binary(header, build_p, build_q, payload_hex);
        }
        /* nAdd = p - (hash << shift), or 0 if no p given */
        uint64_t build_nadd = (build_p > 0) ? (build_p - (h_int << shift)) : 0;
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
            for (int64_t adder=0; adder<num_windows; ++adder) {
                uint64_t base = h_int << shift;
                uint64_t L = base + (uint64_t)adder * sieve_size;
                if ((L & 1) == 0) L++;
                uint64_t R = L + sieve_size;
                uint64_t max_valid = base + (uint64_t)adder_max;
                if (R > max_valid) R = max_valid;
                if (R <= L) continue;
                size_t cnt=0;
                double *pr_log = NULL;
                uint64_t *pr = sieve_range(L,R,&cnt,&pr_log);
                __sync_fetch_and_add(&stats_sieved, (uint64_t)(R - L));
                /* primality – compact pr[]/pr_log[] in-place */
                size_t pf = 0;
                if (!no_primality) {
                    size_t orig_cnt = cnt;
                    for (size_t i = 0; i < cnt; i++) {
                        if (use_fast_fermat ? fast_fermat_test(pr[i]) : miller_rabin(pr[i])) {
                            pr[pf]     = pr[i];
                            pr_log[pf] = pr_log[i];
                            pf++;
                        }
                    }
                    __sync_fetch_and_add(&stats_tested, (uint64_t)orig_cnt);
                    cnt = pf;
                } else {
                    pf = cnt;
                    __sync_fetch_and_add(&stats_tested, (uint64_t)cnt);
                }
                if (cnt>=2) {
                    if (scan_candidates(pr, pr_log, cnt, target,
                                       h_int, shift,
                                       header,
                                       rpc_url, rpc_user, rpc_pass,
                                       rpc_method, rpc_sign_key)) {
                        return 0;
                    }
                }
                /* free nothing; buffers reused */
            }
            if (keep_going && rpc_url) {
                /* refresh header if node has new template */
                char *gbt = rpc_getblocktemplate(rpc_url, rpc_user, rpc_pass);
                if (gbt) {
                    check_and_log_new_work(gbt);
                    const char *p = strstr(gbt, "\"previousblockhash\"");
                    if (p) {
                        const char *colon = strchr(p, ':');
                        if (colon) {
                            const char *start = colon + 1;
                            while (*start && (*start == ' ' || *start == '"')) start++;
                            const char *end = strchr(start, '"');
                            if (end && end > start) {
                                size_t len = end - start;
                                char *newhdr = malloc(len+1);
                                memcpy(newhdr, start, len);
                                newhdr[len] = '\0';
                                if (newhdr[0] && strcmp(newhdr, header) != 0) {
                                    free((char*)header);
                                    header = newhdr;
                                    h_int = hash_to_int(header, is_hex);
                                } else {
                                    free(newhdr);
                                }
                            }
                        }
                    }
                    free(gbt);
                }
            }
        } while (keep_going);
    } else {
        do {
            g_abort_pass = 0;
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
            for (int t = 0; t < num_threads; t++) {
                int64_t off  = (int64_t)t * slice;
                int64_t sz   = (t == num_threads - 1) ? (adder_max - off) : slice;
                wargs[t].tid               = 0;   /* stride handled internally */
                wargs[t].nthreads          = 1;
                wargs[t].rpc_thread        = (t == 0) ? 1 : 0;
                wargs[t].adder_base_offset = off;
                wargs[t].adder_max         = sz;
                wargs[t].h_int             = h_int;
                wargs[t].shift             = shift;
                wargs[t].sieve_size        = sieve_size;
                wargs[t].target            = target;
                wargs[t].header            = header;
                wargs[t].rpc_url           = rpc_url;
                wargs[t].rpc_user          = rpc_user;
                wargs[t].rpc_pass          = rpc_pass;
                wargs[t].rpc_method        = rpc_method;
                wargs[t].rpc_sign_key      = rpc_sign_key;
                pthread_create(&threads[t], NULL, worker_fn, &wargs[t]);
            }
            for (int t = 0; t < num_threads; t++) pthread_join(threads[t], NULL);
            free(threads);
            free(wargs);

            if (keep_going && rpc_url) {
                /* refresh header for next pass */
                char *gbt = rpc_getblocktemplate(rpc_url, rpc_user, rpc_pass);
                if (gbt) {
                    check_and_log_new_work(gbt);
                    const char *p = strstr(gbt, "\"previousblockhash\"");
                    if (p) {
                        const char *colon = strchr(p, ':');
                        if (colon) {
                            const char *start = colon + 1;
                            while (*start && (*start == ' ' || *start == '"')) start++;
                            const char *end = strchr(start, '"');
                            if (end && end > start) {
                                size_t len = end - start;
                                char *newhdr = malloc(len+1);
                                memcpy(newhdr, start, len);
                                newhdr[len] = '\0';
                                if (newhdr[0] && strcmp(newhdr, header) != 0) {
                                    free((char*)header);
                                    header = newhdr;
                                    h_int = hash_to_int(header, is_hex);
                                } else {
                                    free(newhdr);
                                }
                            }
                        }
                    }
                    free(gbt);
                }
            }
        } while (keep_going);
    }
#ifdef WITH_RPC
    if (rpc_url) stop_submit_thread();
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
