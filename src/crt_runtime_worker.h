#ifndef CRT_RUNTIME_WORKER_H
#define CRT_RUNTIME_WORKER_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <gmp.h>

#include "crt_runtime.h"

#if !defined(WITH_GPU_FERMAT) && (defined(WITH_CUDA) || defined(WITH_OPENCL))
#define WITH_GPU_FERMAT 1
#endif
#ifdef WITH_GPU_FERMAT
#include "gpu_fermat.h"
#endif

struct gpu_accum;
struct crt_work_item;

struct worker_args {
    int tid;
    int nthreads;
    uint8_t  h256[32];  /* 256-bit base hash (big-endian) */
    int shift;
    int64_t adder_max;
    uint64_t sieve_size;
    double target;
    double scan_target;
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

struct crt_runtime_worker_ctx {
    int force_monolithic;

    _Atomic int *keep_going;
    _Atomic int *g_abort_pass;

    volatile int *use_crt_gpu_consumer;
    volatile int *use_crt_gap_scan_adaptive;
    volatile int *crt_fermat_threads;

    int *g_crt_gap_target;
    int *g_crt_gap_scan_mode;
    uint64_t *g_crt_gap_scan_floor;
    volatile int *g_crt_gap_scan_runtime_logged;
    struct crt_gap_scan_adapt_cfg *g_crt_gap_scan_adapt_cfg;
    mpz_srcptr g_crt_primorial_mpz;

    int *rpc_tip_poll_ms;
    void *g_stratum;
    pthread_mutex_t *g_work_lock;
    char *g_prevhash;

#ifdef WITH_GPU_FERMAT
    int *g_gpu_count;
    int *g_gpu_batch_size;
    int *g_gpu_device_ids;
    int *g_gpu_active_limbs_global;
#endif

    int *tls_gmp_inited;
    mpz_ptr tls_base_mpz;
    mpz_ptr tls_cand_mpz;
    mpz_ptr tls_two_mpz;
    mpz_ptr tls_exp_mpz;
    mpz_ptr tls_res_mpz;
    mpz_ptr tls_mr_d;
    mpz_ptr tls_mr_x;
    mpz_ptr tls_mr_nm1;
    uint64_t **tls_base_mod_p;
#ifdef WITH_GPU_FERMAT
    struct gpu_accum **tls_gpu_accum;
#endif

    void (*log_msg)(const char *fmt, ...);
    uint64_t (*now_ms)(void);
    void (*set_base_bn)(const uint8_t h256[32], int shift);
    double (*compute_cramer_score)(const uint64_t *surv, size_t n,
                                   double logbase, uint64_t needed_gap);
    int (*rpc_tip_changed)(const char *url, const char *user,
                           const char *pass, const char *prevhex,
                           char best_out[65]);
    int (*build_mining_pass_stratum)(const char *data_hex,
                                     uint64_t ndiff,
                                     int shift);
    void (*pass_state_copy_prevhex)(char out[65]);
    void (*pass_state_snapshot_nonce_hdr80)(uint32_t *nonce_out,
                                            uint8_t hdr80_out[80]);

    void (*ensure_gmp_tls)(void);
    size_t (*crt_bkscan_and_submit)(
        uint64_t *surv, size_t surv_cnt,
        double logbase, double target, int shift_v,
        uint32_t nonce, int cand_odd, mpz_srcptr nAdd,
        const char *rpc_url, const char *rpc_user,
        const char *rpc_pass,
        size_t *out_primes_found,
        size_t *out_qual_pairs);
    void (*prime_cache_invalidate_base)(void);
    void (*crt_filter_init_residues)(void);
    void (*crt_filter_step_residues)(void);
    uint64_t *(*sieve_range)(uint64_t L, uint64_t R,
                             size_t *out_count,
                             const uint8_t *h256,
                             int shift);
    void (*crt_compute_alignment_mpz)(mpz_t result);
    void (*rebase_for_gap_check)(mpz_t new_base);
    void (*crt_score_roll_observe)(double score,
                                   uint64_t surv_cnt,
                                   uint64_t primes_found,
                                   uint64_t qual_pairs);

#ifdef WITH_GPU_FERMAT
    size_t (*gpu_batch_filter)(uint64_t *offsets, size_t cnt);
    struct gpu_accum *(*gpu_accum_create)(gpu_fermat_ctx *ctx,
                                          int threshold);
    int (*gpu_accum_add)(struct gpu_accum *a,
                         const uint64_t base_limbs[GPU_NLIMBS],
                         const uint64_t *offsets, size_t cnt,
                         double cramer_score,
                         uint32_t nonce, int cand_odd,
                         double logbase, double target_v, int shift_v,
                         mpz_srcptr base_mpz,
                         mpz_srcptr nAdd,
                         const char *rpc_url, const char *rpc_user,
                         const char *rpc_pass);
    void (*gpu_accum_flush)(struct gpu_accum *a);
    void (*gpu_accum_collect)(struct gpu_accum *a);
    void (*gpu_accum_reset)(struct gpu_accum *a);
    int (*gpu_accum_get_stride)(const struct gpu_accum *a);
    void (*gpu_accum_set_owns_ctx)(struct gpu_accum *a, int owns_ctx);
#endif
};

void crt_runtime_run_solver_producer_loop(
    const struct crt_runtime_worker_ctx *ctx,
    const struct worker_args *wa,
    int tid_local,
    int shift_local,
    double target_local,
    int rpc_thread_local,
    const char *rpc_url_local,
    const char *rpc_user_local,
    const char *rpc_pass_local,
    uint64_t gap_scan_cfg,
    mpz_t crt_end);

int crt_runtime_try_run_consumer_loop(
    const struct crt_runtime_worker_ctx *ctx,
    const struct worker_args *wa,
    mpz_t crt_end,
    double target_local,
    int shift_local,
    const char *rpc_url_local,
    const char *rpc_user_local,
    const char *rpc_pass_local);

int crt_runtime_gpu_process_mono_window(
    const struct crt_runtime_worker_ctx *ctx,
    uint64_t *surv,
    size_t surv_cnt,
    uint32_t nonce_cur,
    int cand_odd,
    double logbase_nonce,
    double target_local,
    int shift_local,
    mpz_t nAdd,
    const char *rpc_url_local,
    const char *rpc_user_local,
    const char *rpc_pass_local);

int crt_runtime_gpu_process_consumer_item(
    const struct crt_runtime_worker_ctx *ctx,
    struct crt_work_item *w,
    double target_local,
    int shift_local,
    const char *rpc_url_local,
    const char *rpc_user_local,
    const char *rpc_pass_local);

void crt_runtime_gpu_drain_tls_accum(
    const struct crt_runtime_worker_ctx *ctx);

#endif
