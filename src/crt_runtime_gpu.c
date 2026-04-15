#include "crt_runtime_worker.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>

#include "crt_heap.h"
#include "stats.h"

#ifdef WITH_GPU_FERMAT

#ifndef GPU_ACCUM_DEFAULT
#define GPU_ACCUM_DEFAULT 4096
#endif

static int g_mono_accum_rr = 0;
static int g_cons_accum_rr = 0;

static struct gpu_accum *crt_runtime_gpu_try_init_accum(
        const struct crt_runtime_worker_ctx *ctx,
        int *rr_counter) {
    if (!ctx || !ctx->tls_gpu_accum || !ctx->g_gpu_count ||
        !ctx->g_gpu_batch_size || !ctx->g_gpu_device_ids ||
        !ctx->gpu_accum_create || !ctx->gpu_accum_set_owns_ctx)
        return NULL;

    if (*ctx->g_gpu_count <= 0)
        return NULL;

    struct gpu_accum *acc = *ctx->tls_gpu_accum;
    if (acc)
        return acc;

    int gi = __sync_fetch_and_add(rr_counter, 1) % *ctx->g_gpu_count;
    int batch_size = *ctx->g_gpu_batch_size > 0
                     ? *ctx->g_gpu_batch_size
                     : GPU_ACCUM_DEFAULT;
    size_t batch_cap = (size_t)batch_size + 4096;

    gpu_fermat_ctx *per_ctx = gpu_fermat_init(ctx->g_gpu_device_ids[gi],
                                              batch_cap);
    if (per_ctx && ctx->g_gpu_active_limbs_global &&
        *ctx->g_gpu_active_limbs_global > 0) {
        gpu_fermat_set_limbs(per_ctx, *ctx->g_gpu_active_limbs_global);
    }

    acc = ctx->gpu_accum_create(per_ctx, batch_size);
    if (acc) {
        ctx->gpu_accum_set_owns_ctx(acc, 1);
        *ctx->tls_gpu_accum = acc;
        return acc;
    }

    if (per_ctx)
        gpu_fermat_destroy(per_ctx);
    return NULL;
}

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
        const char *rpc_pass_local) {
    if (!ctx || !ctx->g_gpu_count || *ctx->g_gpu_count <= 0 ||
        !ctx->ensure_gmp_tls || !ctx->gpu_accum_add ||
        !ctx->gpu_accum_flush || !ctx->gpu_accum_get_stride ||
        !ctx->gpu_batch_filter || !ctx->tls_base_mpz)
        return 0;

    struct gpu_accum *acc = crt_runtime_gpu_try_init_accum(ctx,
                                                           &g_mono_accum_rr);

    if (acc) {
        ctx->ensure_gmp_tls();
        int gpu_al = ctx->gpu_accum_get_stride(acc);
        uint64_t bl[GPU_NLIMBS];
        memset(bl, 0, (size_t)gpu_al * sizeof(uint64_t));
        size_t nexp = 0;
        mpz_export(bl, &nexp, -1, 8, 0, 0, ctx->tls_base_mpz);

        if (nexp <= (size_t)GPU_NLIMBS) {
            __sync_fetch_and_add(&stats_tested, (uint64_t)surv_cnt);
            __sync_fetch_and_add(&stats_crt_solver_mono_gpu_tests,
                                 (uint64_t)surv_cnt);

            int add_rc = ctx->gpu_accum_add(
                acc, bl,
                surv, surv_cnt, 0.0,
                nonce_cur,
                cand_odd, logbase_nonce,
                target_local, shift_local,
                ctx->tls_base_mpz,
                nAdd, rpc_url_local,
                rpc_user_local, rpc_pass_local);

            if (add_rc == 2) {
                ctx->gpu_accum_flush(acc);
                add_rc = ctx->gpu_accum_add(
                    acc, bl,
                    surv, surv_cnt, 0.0,
                    nonce_cur,
                    cand_odd, logbase_nonce,
                    target_local, shift_local,
                    ctx->tls_base_mpz,
                    nAdd, rpc_url_local,
                    rpc_user_local, rpc_pass_local);
            }
            if (add_rc == 1)
                ctx->gpu_accum_flush(acc);

            mpz_add(nAdd, nAdd, ctx->g_crt_primorial_mpz);
            return 1;
        }
        /* Limb overflow: fall through to direct batch path. */
    }

    size_t pf = ctx->gpu_batch_filter(surv, surv_cnt);
    __sync_fetch_and_add(&stats_tested, (uint64_t)surv_cnt);
    __sync_fetch_and_add(&stats_crt_solver_mono_gpu_tests,
                         (uint64_t)surv_cnt);
    __sync_fetch_and_add(&stats_crt_windows, 1);
    __sync_fetch_and_add(&stats_primes_found, (uint64_t)pf);
    if (pf >= 2)
        __sync_fetch_and_add(&stats_pairs, (uint64_t)(pf - 1));

    mpz_add(nAdd, nAdd, ctx->g_crt_primorial_mpz);
    return 1;
}

int crt_runtime_gpu_process_consumer_item(
        const struct crt_runtime_worker_ctx *ctx,
        struct crt_work_item *w,
        double target_local,
        int shift_local,
        const char *rpc_url_local,
        const char *rpc_user_local,
        const char *rpc_pass_local) {
    if (!ctx || !w || !ctx->use_crt_gpu_consumer ||
        !*ctx->use_crt_gpu_consumer || !ctx->g_gpu_count ||
        *ctx->g_gpu_count <= 0 || !ctx->gpu_accum_add ||
        !ctx->gpu_accum_flush || !ctx->gpu_accum_get_stride)
        return 0;

    struct gpu_accum *acc = crt_runtime_gpu_try_init_accum(ctx,
                                                           &g_cons_accum_rr);
    if (!acc)
        return 0;

    int gpu_al = ctx->gpu_accum_get_stride(acc);
    uint64_t bl[GPU_NLIMBS];
    memset(bl, 0, (size_t)gpu_al * sizeof(uint64_t));
    size_t nexp = 0;
    mpz_export(bl, &nexp, -1, 8, 0, 0, w->base);
    if (nexp > (size_t)GPU_NLIMBS)
        return 0;

    __sync_fetch_and_add(&stats_tested, (uint64_t)w->surv_cnt);
    __sync_fetch_and_add(&stats_crt_solver_consumer_gpu_tests,
                         (uint64_t)w->surv_cnt);

    int add_rc = ctx->gpu_accum_add(
        acc, bl,
        w->survivors, w->surv_cnt,
        w->cramer_score,
        w->nonce, w->cand_odd,
        w->logbase, target_local,
        shift_local,
        w->base,
        w->nAdd, rpc_url_local,
        rpc_user_local, rpc_pass_local);

    if (add_rc == 2) {
        ctx->gpu_accum_flush(acc);
        add_rc = ctx->gpu_accum_add(
            acc, bl,
            w->survivors, w->surv_cnt,
            w->cramer_score,
            w->nonce, w->cand_odd,
            w->logbase, target_local,
            shift_local,
            w->base,
            w->nAdd, rpc_url_local,
            rpc_user_local, rpc_pass_local);
    }
    if (add_rc == 1)
        ctx->gpu_accum_flush(acc);

    crt_work_free(w);
    return 1;
}

void crt_runtime_gpu_drain_tls_accum(
        const struct crt_runtime_worker_ctx *ctx) {
    if (!ctx || !ctx->tls_gpu_accum || !*ctx->tls_gpu_accum ||
        !ctx->gpu_accum_flush || !ctx->gpu_accum_collect ||
        !ctx->gpu_accum_reset || !ctx->g_abort_pass)
        return;

    struct gpu_accum *acc = *ctx->tls_gpu_accum;
    if (atomic_load(ctx->g_abort_pass)) {
        ctx->gpu_accum_reset(acc);
    } else {
        ctx->gpu_accum_flush(acc);
        ctx->gpu_accum_collect(acc);
    }
}

#else

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
        const char *rpc_pass_local) {
    (void)ctx;
    (void)surv;
    (void)surv_cnt;
    (void)nonce_cur;
    (void)cand_odd;
    (void)logbase_nonce;
    (void)target_local;
    (void)shift_local;
    (void)nAdd;
    (void)rpc_url_local;
    (void)rpc_user_local;
    (void)rpc_pass_local;
    return 0;
}

int crt_runtime_gpu_process_consumer_item(
        const struct crt_runtime_worker_ctx *ctx,
        struct crt_work_item *w,
        double target_local,
        int shift_local,
        const char *rpc_url_local,
        const char *rpc_user_local,
        const char *rpc_pass_local) {
    (void)ctx;
    (void)w;
    (void)target_local;
    (void)shift_local;
    (void)rpc_url_local;
    (void)rpc_user_local;
    (void)rpc_pass_local;
    return 0;
}

void crt_runtime_gpu_drain_tls_accum(
        const struct crt_runtime_worker_ctx *ctx) {
    (void)ctx;
}

#endif
