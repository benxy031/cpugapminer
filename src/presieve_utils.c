#include "presieve_utils.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>

#ifdef WITH_CUDA
#ifndef WITH_CRT_GPU_CONSUMER
#include "gpu_sieve.h"
#include "stats.h"
#include <cuda_runtime.h>

#define GPU_SIEVE_MAX_DEVS 32
#define GPU_SIEVE_POOL_MAX_PER_DEVICE 4

/* Shared GPU sieve context pool, bounded per selected device.
    A full gpu_sieve_ctx_t is memory-heavy (~100 MB at current prime caps), so
    per-thread contexts exhaust VRAM. A single shared context per device is safe
    but over-serializes the sieve. Use a small fixed pool per device to recover
    some concurrency while keeping VRAM bounded. */
static gpu_sieve_ctx_t g_gpu_sieve_ctx[GPU_SIEVE_MAX_DEVS][GPU_SIEVE_POOL_MAX_PER_DEVICE];
static pthread_mutex_t g_gpu_sieve_pool_mu[GPU_SIEVE_MAX_DEVS];
static pthread_cond_t  g_gpu_sieve_pool_cv[GPU_SIEVE_MAX_DEVS];
static int             g_gpu_sieve_ctx_initialized[GPU_SIEVE_MAX_DEVS][GPU_SIEVE_POOL_MAX_PER_DEVICE];
static int             g_gpu_sieve_ctx_in_use[GPU_SIEVE_MAX_DEVS][GPU_SIEVE_POOL_MAX_PER_DEVICE];
static int             g_gpu_sieve_pool_size[GPU_SIEVE_MAX_DEVS];
static __thread int    tls_gpu_sieve_ctx_index = -1;
static __thread int    tls_gpu_sieve_slot = -1;

/* Thread-local compact survivor buffer; filled by gpu_sieve_mark_segment_batch
 * when the inner gpu_sieve_mark_batch returns 1 (compact mode). */
static __thread uint32_t *tls_surv_buf     = NULL;
static __thread uint32_t  tls_surv_count   = 0;
static __thread size_t    tls_surv_buf_cap = 0; /* in entries */

/* Parameters captured at gpu_sieve_init() time; used for lazy per-thread alloc. */
static size_t g_gpu_seg_cap    = 0;
static size_t g_gpu_primes_cap = 0;
static int    g_gpu_init_done  = 0;   /* startup init called */
static int    g_gpu_sieve_devices[GPU_SIEVE_MAX_DEVS];
static int    g_gpu_sieve_num_devices = 0;
static int    g_gpu_sieve_target_pool = 2;
static volatile int g_gpu_sieve_rr = 0;

/* Global runtime flag: 1 = try to use GPU sieve, 0 = use CPU presieve only */
int g_gpu_sieve_enable = 1;  /* default: enabled if WITH_CUDA && !WITH_CRT_GPU_CONSUMER */

#endif /* !WITH_CRT_GPU_CONSUMER */
#endif /* WITH_CUDA */

int presieve_buf_ensure(struct presieve_buf *b, size_t need) {
    if (b->cap >= need) return 0;
    size_t nc = need + (need >> 1) + 64;
    uint64_t *tmp = realloc(b->pr, nc * sizeof(uint64_t));
    if (!tmp) return -1;
    b->pr = tmp;
    b->cap = nc;
    return 0;
}

int presieve_window(int64_t widx, uint64_t base,
                    uint64_t sieve_size, uint64_t adder_max,
                    uint64_t *out_L, uint64_t *out_R) {
    uint64_t L = base + (uint64_t)widx * sieve_size;
    if ((L & 1) == 0) L++;
    uint64_t R = L + sieve_size;
    uint64_t cap = base + adder_max;
    if (R > cap) R = cap;
    if (R <= L) return 0;
    *out_L = L;
    *out_R = R;
    return 1;
}

#ifdef WITH_CUDA
#ifndef WITH_CRT_GPU_CONSUMER

/* GPU sieve wrapper (monolithic CRT mode only) */

int gpu_sieve_init(size_t seg_cap, size_t primes_cap) {
        if (g_gpu_sieve_target_pool < 1 || g_gpu_sieve_target_pool > GPU_SIEVE_POOL_MAX_PER_DEVICE) {
            const char *pool_env = getenv("GPU_SIEVE_POOL");
            int cfg = 2;
            if (pool_env && *pool_env) {
                int parsed = atoi(pool_env);
                if (parsed >= 1 && parsed <= GPU_SIEVE_POOL_MAX_PER_DEVICE)
                    cfg = parsed;
            }
            g_gpu_sieve_target_pool = cfg;
        }

    if (!g_gpu_sieve_enable)
        return -1;
    if (g_gpu_init_done)
        return 0;

    if (g_gpu_sieve_num_devices <= 0) {
        int dev_count = 0;
        cudaError_t cerr = cudaGetDeviceCount(&dev_count);
        if (cerr != cudaSuccess || dev_count <= 0)
            return -1;
        if (dev_count > GPU_SIEVE_MAX_DEVS)
            dev_count = GPU_SIEVE_MAX_DEVS;
        for (int i = 0; i < dev_count; i++)
            g_gpu_sieve_devices[i] = i;
        g_gpu_sieve_num_devices = dev_count;
    }

    /* Stash capacity params for lazy per-thread context allocation. */
    g_gpu_seg_cap    = seg_cap;
    g_gpu_primes_cap = primes_cap;

    for (int i = 0; i < g_gpu_sieve_num_devices; i++) {
        int pool_count = 0;
        pthread_mutex_init(&g_gpu_sieve_pool_mu[i], NULL);
        pthread_cond_init(&g_gpu_sieve_pool_cv[i], NULL);
        for (int k = 0; k < g_gpu_sieve_target_pool; k++) {
            memset(&g_gpu_sieve_ctx[i][k], 0, sizeof(g_gpu_sieve_ctx[i][k]));
            if (gpu_sieve_ctx_alloc(&g_gpu_sieve_ctx[i][k], g_gpu_seg_cap,
                                    g_gpu_primes_cap, g_gpu_sieve_devices[i]) != 0) {
                break;
            }
            g_gpu_sieve_ctx_initialized[i][k] = 1;
            g_gpu_sieve_ctx_in_use[i][k] = 0;
            pool_count++;
        }
        if (pool_count <= 0) {
            for (int j = 0; j <= i; j++) {
                for (int k = 0; k < g_gpu_sieve_target_pool; k++) {
                    if (g_gpu_sieve_ctx_initialized[j][k]) {
                        gpu_sieve_ctx_free(&g_gpu_sieve_ctx[j][k]);
                        g_gpu_sieve_ctx_initialized[j][k] = 0;
                        g_gpu_sieve_ctx_in_use[j][k] = 0;
                    }
                }
                g_gpu_sieve_pool_size[j] = 0;
                pthread_cond_destroy(&g_gpu_sieve_pool_cv[j]);
                pthread_mutex_destroy(&g_gpu_sieve_pool_mu[j]);
            }
            g_gpu_sieve_num_devices = 0;
            return -1;
        }
        g_gpu_sieve_pool_size[i] = pool_count;
    }

    g_gpu_init_done  = 1;
    return 0;
}

int gpu_sieve_set_devices(const int *device_ids, int n_devices) {
    if (!device_ids || n_devices <= 0) {
        g_gpu_sieve_num_devices = 0;
        return 0;
    }

    if (n_devices > GPU_SIEVE_MAX_DEVS)
        n_devices = GPU_SIEVE_MAX_DEVS;

    int dev_count = 0;
    cudaError_t cerr = cudaGetDeviceCount(&dev_count);
    if (cerr != cudaSuccess || dev_count <= 0)
        return -1;

    int out = 0;
    for (int i = 0; i < n_devices; i++) {
        int id = device_ids[i];
        if (id < 0 || id >= dev_count)
            continue;
        int dup = 0;
        for (int j = 0; j < out; j++) {
            if (g_gpu_sieve_devices[j] == id) { dup = 1; break; }
        }
        if (!dup)
            g_gpu_sieve_devices[out++] = id;
    }

    if (out <= 0)
        return -1;

    g_gpu_sieve_num_devices = out;
    g_gpu_sieve_rr = 0;
    return 0;
}

int gpu_sieve_get_devices(int *out_device_ids, int max_ids) {
    int n = g_gpu_sieve_num_devices;
    if (!out_device_ids || max_ids <= 0)
        return n;
    if (n > max_ids)
        n = max_ids;
    for (int i = 0; i < n; i++)
        out_device_ids[i] = g_gpu_sieve_devices[i];
    return n;
}

int gpu_sieve_mark_segment_batch(
    uint8_t *h_bits,
    size_t bit_len,
    size_t segment_len,
    const uint64_t *h_primes,
    const uint64_t *h_base_mod_p,
    uint64_t base_mod_p_version,
    uint64_t L,
    uint64_t R,
    int n_primes
)
{
    if (!g_gpu_init_done || !g_gpu_sieve_enable || !h_bits || !h_primes || !h_base_mod_p || n_primes <= 0)
        return -1;

    if (g_gpu_sieve_num_devices <= 0)
        return -1;

    if (tls_gpu_sieve_ctx_index < 0) {
        int rr = __sync_fetch_and_add(&g_gpu_sieve_rr, 1);
        if (rr < 0) rr = -rr;
        tls_gpu_sieve_ctx_index = rr % g_gpu_sieve_num_devices;
        tls_gpu_sieve_slot = -1;
    }

    int idx = tls_gpu_sieve_ctx_index;
    if (idx < 0 || idx >= g_gpu_sieve_num_devices || g_gpu_sieve_pool_size[idx] <= 0)
        return -1;

    pthread_mutex_lock(&g_gpu_sieve_pool_mu[idx]);
    int slot = -1;

    /* Sticky slot: prefer the previously-used context to reduce churn and cache misses. */
    if (tls_gpu_sieve_slot >= 0 && tls_gpu_sieve_slot < g_gpu_sieve_pool_size[idx] &&
        g_gpu_sieve_ctx_initialized[idx][tls_gpu_sieve_slot] &&
        !g_gpu_sieve_ctx_in_use[idx][tls_gpu_sieve_slot]) {
        g_gpu_sieve_ctx_in_use[idx][tls_gpu_sieve_slot] = 1;
        slot = tls_gpu_sieve_slot;
    }

    for (;;) {
        if (slot < 0) {
            for (int k = 0; k < g_gpu_sieve_pool_size[idx]; k++) {
                if (g_gpu_sieve_ctx_initialized[idx][k] && !g_gpu_sieve_ctx_in_use[idx][k]) {
                    g_gpu_sieve_ctx_in_use[idx][k] = 1;
                    slot = k;
                    break;
                }
            }
        }
        if (slot >= 0)
            break;
        pthread_cond_wait(&g_gpu_sieve_pool_cv[idx], &g_gpu_sieve_pool_mu[idx]);
    }
    pthread_mutex_unlock(&g_gpu_sieve_pool_mu[idx]);
    tls_gpu_sieve_slot = slot;

    int rc = gpu_sieve_mark_batch(
        &g_gpu_sieve_ctx[idx][slot],
        h_bits,
        bit_len,
        segment_len,
        h_primes,
        h_base_mod_p,
        base_mod_p_version,
        L, R,
        n_primes
    );

    if (rc == 0 || rc == 1) {
        __sync_fetch_and_add(&stats_gpu_sieve_us_base_upload, g_gpu_sieve_ctx[idx][slot].last_us_base_upload);
        __sync_fetch_and_add(&stats_gpu_sieve_us_compute_k0,  g_gpu_sieve_ctx[idx][slot].last_us_compute_k0);
        __sync_fetch_and_add(&stats_gpu_sieve_us_mark,        g_gpu_sieve_ctx[idx][slot].last_us_mark);
        __sync_fetch_and_add(&stats_gpu_sieve_us_pack,        g_gpu_sieve_ctx[idx][slot].last_us_pack);
        __sync_fetch_and_add(&stats_gpu_sieve_us_bits_dl,     g_gpu_sieve_ctx[idx][slot].last_us_bits_dl);
    }

    /* Compact mode (rc == 1): copy survivors to TLS buffer before releasing ctx */
    if (rc == 1) {
        __sync_fetch_and_add(&stats_gpu_sieve_surv_calls, 1);
        uint32_t sc = g_gpu_sieve_ctx[idx][slot].last_surv_count;
        tls_surv_count = 0;
        if (sc > 0) {
            if (tls_surv_buf_cap < sc) {
                free(tls_surv_buf);
                tls_surv_buf = (uint32_t *)malloc((size_t)sc * sizeof(uint32_t));
                tls_surv_buf_cap = tls_surv_buf ? sc : 0;
            }
            if (tls_surv_buf && g_gpu_sieve_ctx[idx][slot].h_surv_pinned) {
                memcpy(tls_surv_buf, g_gpu_sieve_ctx[idx][slot].h_surv_pinned,
                       (size_t)sc * sizeof(uint32_t));
                tls_surv_count = sc;
            } else {
                rc = 0; /* copy failed; treat as bitmap mode (h_bits may be stale) */
            }
        }
    } else {
        tls_surv_count = 0;
    }

    pthread_mutex_lock(&g_gpu_sieve_pool_mu[idx]);
    g_gpu_sieve_ctx_in_use[idx][slot] = 0;
    pthread_cond_signal(&g_gpu_sieve_pool_cv[idx]);
    pthread_mutex_unlock(&g_gpu_sieve_pool_mu[idx]);
    return rc;
}

const uint32_t *gpu_sieve_last_survivors(uint32_t *count_out)
{
    if (count_out)
        *count_out = tls_surv_count;
    if (!tls_surv_buf || tls_surv_count == 0)
        return NULL;
    return tls_surv_buf;
}

void gpu_sieve_cleanup(void) {
    for (int i = 0; i < g_gpu_sieve_num_devices; i++) {
        for (int k = 0; k < g_gpu_sieve_pool_size[i]; k++) {
            if (g_gpu_sieve_ctx_initialized[i][k]) {
                gpu_sieve_ctx_free(&g_gpu_sieve_ctx[i][k]);
                g_gpu_sieve_ctx_initialized[i][k] = 0;
                g_gpu_sieve_ctx_in_use[i][k] = 0;
            }
        }
        g_gpu_sieve_pool_size[i] = 0;
        pthread_cond_destroy(&g_gpu_sieve_pool_cv[i]);
        pthread_mutex_destroy(&g_gpu_sieve_pool_mu[i]);
    }
    g_gpu_init_done = 0;
    g_gpu_sieve_num_devices = 0;
}

#endif /* !WITH_CRT_GPU_CONSUMER */
#endif /* WITH_CUDA */
