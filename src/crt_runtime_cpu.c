#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "crt_runtime_worker.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "compat_win32.h"
#include "block_utils.h"
#include "crt_gap_scan.h"
#include "crt_heap.h"
#include "gap_scan.h"
#include "primality_utils.h"
#include "sieve_cache.h"
#include "stats.h"
#include "uint256_utils.h"

#ifdef WITH_RPC
#include "stratum.h"
#endif

#ifndef GPU_ACCUM_DEFAULT
#define GPU_ACCUM_DEFAULT 4096
#endif

#define keep_going (*ctx->keep_going)
#define g_abort_pass (*ctx->g_abort_pass)
#define use_crt_gpu_consumer (*ctx->use_crt_gpu_consumer)
#define use_crt_gap_scan_adaptive (*ctx->use_crt_gap_scan_adaptive)
#define crt_fermat_threads (*ctx->crt_fermat_threads)
#define g_crt_gap_target (*ctx->g_crt_gap_target)
#define g_crt_gap_scan_mode (*ctx->g_crt_gap_scan_mode)
#define g_crt_gap_scan_floor (*ctx->g_crt_gap_scan_floor)
#define g_crt_gap_scan_runtime_logged (*ctx->g_crt_gap_scan_runtime_logged)
#define g_crt_gap_scan_adapt_cfg (*ctx->g_crt_gap_scan_adapt_cfg)
#define g_crt_primorial_mpz (ctx->g_crt_primorial_mpz)
#define rpc_tip_poll_ms (*ctx->rpc_tip_poll_ms)
#ifdef WITH_RPC
#define g_stratum ((stratum_ctx *)ctx->g_stratum)
#endif
#define g_work_lock (*ctx->g_work_lock)
#define g_prevhash (ctx->g_prevhash)
#define tls_gmp_inited (*ctx->tls_gmp_inited)
#define tls_base_mpz (ctx->tls_base_mpz)
#define tls_cand_mpz (ctx->tls_cand_mpz)
#define tls_two_mpz (ctx->tls_two_mpz)
#define tls_exp_mpz (ctx->tls_exp_mpz)
#define tls_res_mpz (ctx->tls_res_mpz)
#define tls_mr_d (ctx->tls_mr_d)
#define tls_mr_x (ctx->tls_mr_x)
#define tls_mr_nm1 (ctx->tls_mr_nm1)
#define tls_base_mod_p (*ctx->tls_base_mod_p)
#define log_msg (ctx->log_msg)
#define now_ms (ctx->now_ms)
#define set_base_bn (ctx->set_base_bn)
#define compute_cramer_score (ctx->compute_cramer_score)
#define rpc_tip_changed (ctx->rpc_tip_changed)
#define build_mining_pass_stratum (ctx->build_mining_pass_stratum)
#define pass_state_copy_prevhex (ctx->pass_state_copy_prevhex)
#define pass_state_snapshot_nonce_hdr80 (ctx->pass_state_snapshot_nonce_hdr80)
#define ensure_gmp_tls (ctx->ensure_gmp_tls)
#define crt_bkscan_and_submit (ctx->crt_bkscan_and_submit)
#define prime_cache_invalidate_base (ctx->prime_cache_invalidate_base)
#define crt_filter_init_residues (ctx->crt_filter_init_residues)
#define crt_filter_step_residues (ctx->crt_filter_step_residues)
#define sieve_range (ctx->sieve_range)
#define crt_compute_alignment_mpz (ctx->crt_compute_alignment_mpz)
#define rebase_for_gap_check (ctx->rebase_for_gap_check)
#define crt_score_roll_observe (ctx->crt_score_roll_observe)

static inline int crt_runtime_effective_fermat_threads(
        const struct crt_runtime_worker_ctx *ctx) {
    if (ctx && ctx->force_monolithic)
        return 0;
    return crt_fermat_threads;
}

static inline void crt_runtime_cleanup_tls_gmp(
    const struct crt_runtime_worker_ctx *ctx) {
    if (tls_gmp_inited) {
        mpz_clear(tls_base_mpz);
        mpz_clear(tls_cand_mpz);
        mpz_clear(tls_two_mpz);
        mpz_clear(tls_exp_mpz);
        mpz_clear(tls_res_mpz);
        mpz_clear(tls_mr_d);
        mpz_clear(tls_mr_x);
        mpz_clear(tls_mr_nm1);
        tls_gmp_inited = 0;
    }
}

struct crt_runtime_nonce_prepare {
    double logbase_nonce;
    uint64_t gap_scan_nonce;
};

static int crt_runtime_prepare_solver_nonce(
        uint32_t nonce_cur,
        const uint8_t hdr80_for_nonce[80],
        int shift_local,
        double target_local,
    struct crt_runtime_nonce_prepare *out,
    const struct crt_runtime_worker_ctx *ctx) {
    if (!out)
        return 0;

    uint8_t hdr84[84], sha_raw[32], h256_nonce[32];
    memcpy(hdr84, hdr80_for_nonce, 80);
    memcpy(hdr84 + 80, &nonce_cur, 4);
    double_sha256(hdr84, 84, sha_raw);

    if (sha_raw[31] < 0x80)
        return 0;

    for (int k = 0; k < 32; k++)
        h256_nonce[k] = sha_raw[31 - k];

    set_base_bn(h256_nonce, shift_local);
    out->logbase_nonce = uint256_log_approx(h256_nonce, shift_local);

    /* Skip nonces where the maximum achievable merit is below target.
     * The largest gap detectable in a CRT window is bounded by gap_target;
     * if gap_target / logbase_nonce < target, no gap in this window can
     * ever reach target merit, so the nonce is worthless. */
    if (g_crt_gap_target > 0 &&
        (double)g_crt_gap_target / out->logbase_nonce < target_local)
        return 0;

    uint64_t gap_scan_base = crt_gap_scan_for_nonce(
        target_local, out->logbase_nonce,
        (uint64_t)g_crt_gap_target, g_crt_gap_scan_mode,
        g_crt_gap_scan_floor);
    out->gap_scan_nonce = gap_scan_base;

    if (crt_fermat_threads > 0 && use_crt_gap_scan_adaptive) {
        uint64_t adaptive_cap = (gap_scan_base <= UINT64_MAX / 2ULL)
            ? (gap_scan_base * 2ULL)
            : UINT64_MAX;
        out->gap_scan_nonce = crt_runtime_adaptive_gap_scan_window(
            gap_scan_base,
            g_crt_gap_scan_floor,
            adaptive_cap,
            (uint64_t)crt_heap_count(),
            (uint64_t)crt_heap_cap,
            stats_crt_heap_push_ok,
            stats_crt_heap_push_replace,
            stats_crt_heap_push_drop,
            stats_crt_heap_pop_ok,
            stats_crt_heap_waits,
            &g_crt_gap_scan_adapt_cfg);
    }

    if (__sync_bool_compare_and_swap(
            &g_crt_gap_scan_runtime_logged, 0, 1)) {
        double raw_scan = target_local * out->logbase_nonce;
        if (g_crt_gap_scan_mode == CRT_GAP_SCAN_ORIGINAL) {
            log_msg("CRT gap-scan runtime: first nonce window=%llu "
                    "(raw=%.0f, cap=%d)\n",
                    (unsigned long long)out->gap_scan_nonce,
                    raw_scan, g_crt_gap_target);
        } else if (g_crt_gap_scan_mode == CRT_GAP_SCAN_ORIG_FLOOR) {
            log_msg("CRT gap-scan runtime: first nonce window=%llu "
                    "(raw=%.0f, floor=%llu)\n",
                    (unsigned long long)out->gap_scan_nonce,
                    raw_scan,
                    (unsigned long long)g_crt_gap_scan_floor);
        }
        if (out->gap_scan_nonce != gap_scan_base) {
            log_msg("CRT gap-scan runtime adaptive: base=%llu adjusted=%llu\n",
                    (unsigned long long)gap_scan_base,
                    (unsigned long long)out->gap_scan_nonce);
        }
    }

    return 1;
}

static void crt_runtime_process_solver_window(
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
        const char *rpc_pass_local,
        const struct crt_runtime_worker_ctx *ctx) {
    if (!surv || surv_cnt == 0) {
        mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
        return;
    }

    /* Producer-consumer path: score and queue windows for consumers. */
    if (crt_runtime_effective_fermat_threads(ctx) > 0) {
        __sync_fetch_and_add(&stats_crt_solver_prod_windows_generated, 1);

        uint64_t needed_gap_cs = (uint64_t)(target_local * logbase_nonce);
        if (needed_gap_cs < 2) needed_gap_cs = 2;

        if (surv_cnt < 2 ||
            surv[surv_cnt - 1] - surv[0] < needed_gap_cs) {
            __sync_fetch_and_add(
                &stats_crt_solver_prod_prefilter_span_drop, 1);
            mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
            return;
        }

        {
            uint64_t span_cs = surv[surv_cnt - 1] - surv[0];
            if (crt_runtime_should_drop_density(
                    (uint64_t)surv_cnt,
                    span_cs,
                    needed_gap_cs,
                    (uint64_t)crt_heap_count(),
                    (uint64_t)crt_heap_cap,
                    1.15)) {
                __sync_fetch_and_add(
                    &stats_crt_solver_prod_prefilter_density_drop, 1);
                mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
                return;
            }
        }

        double cs = compute_cramer_score(surv, surv_cnt,
                                         logbase_nonce,
                                         needed_gap_cs);
        __sync_fetch_and_add(&stats_cramer_scored, 1);
        __sync_fetch_and_add(&stats_cramer_score_sum_e9,
            (uint64_t)(cs * 1e9));

        double heap_worst_sc = crt_heap_worst_score_advisory();
        if (heap_worst_sc >= 0.0 && cs <= heap_worst_sc) {
            __sync_fetch_and_add(&stats_crt_heap_push_drop, 1);
            __sync_fetch_and_add(&stats_cramer_heap_skip, 1);
            struct timespec bt = {0, 200000L}; /* 200 us */
            nanosleep(&bt, NULL);
            mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
            return;
        }

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
            w->surv_cnt    = surv_cnt;
            w->cramer_score = cs;
            w->nonce       = nonce_cur;
            w->cand_odd    = cand_odd;
            w->logbase     = logbase_nonce;
            w->generation  = crt_heap_gen;
            if (crt_heap_push(w)) {
                __sync_fetch_and_add(
                    &stats_crt_solver_prod_windows_enqueued, 1);
            } else {
                struct timespec bt = {0, 200000L}; /* 200 us */
                nanosleep(&bt, NULL);
            }
        }
        mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
        return;
    }

    /* Monolithic path: evaluate this window inline. */
    {
        uint64_t ng = (uint64_t)(target_local * logbase_nonce);
        if (ng < 2) ng = 2;
        if (surv_cnt < 2 || surv[surv_cnt - 1] - surv[0] < ng) {
            __sync_fetch_and_add(&stats_cramer_skipped, 1);
            mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
            return;
        }
    }

#ifdef WITH_GPU_FERMAT
    if (crt_runtime_gpu_process_mono_window(
            ctx,
            surv,
            surv_cnt,
            nonce_cur,
            cand_odd,
            logbase_nonce,
            target_local,
            shift_local,
            nAdd,
            rpc_url_local,
            rpc_user_local,
            rpc_pass_local)) {
        return;
    }
#endif
    {
        size_t cpu_tests = crt_bkscan_and_submit(
            surv, surv_cnt,
            logbase_nonce, target_local,
            shift_local, nonce_cur,
            cand_odd, nAdd,
            rpc_url_local, rpc_user_local,
            rpc_pass_local,
            NULL, NULL);
        __sync_fetch_and_add(&stats_crt_solver_mono_cpu_tests,
                             (uint64_t)cpu_tests);
    }

    mpz_add(nAdd, nAdd, g_crt_primorial_mpz);
}

struct crt_runtime_nonce_step_result {
    uint32_t next_nonce;
    int overflow;
};

static struct crt_runtime_nonce_step_result
crt_runtime_run_solver_nonce_step(
        uint32_t nonce_cur,
        int nth_local,
        int shift_local,
        double target_local,
        int rpc_thread_local,
        const uint8_t hdr80_for_nonce[80],
        const char *rpc_url_local,
        const char *rpc_user_local,
        const char *rpc_pass_local,
        uint64_t *gbt_last_ms,
        mpz_t nAdd,
        mpz_t candidate,
        mpz_t orig_base_crt,
        mpz_t crt_end,
        uint64_t **prim_mod_sieve,
        size_t *prim_mod_count,
        const struct crt_runtime_worker_ctx *ctx) {
    struct crt_runtime_nonce_step_result out = {
        .next_nonce = nonce_cur,
        .overflow = 0,
    };

#ifdef WITH_RPC
    if (rpc_thread_local && rpc_url_local && gbt_last_ms) {
        uint64_t now = now_ms();
        if (now - *gbt_last_ms >= (uint64_t)rpc_tip_poll_ms) {
            if (g_stratum) {
                char data_hex[161];
                uint64_t ndiff;
                if (stratum_poll_new_work(g_stratum, data_hex, &ndiff)) {
                    log_msg("\n*** STRATUM NEW BLOCK ***\n\n");
                    build_mining_pass_stratum(data_hex, ndiff,
                                             shift_local);
                    g_abort_pass = 1;
                    crt_heap_signal_shutdown();
                }
            } else {
                char best[65];
                char prevhex_snap[65];
                pass_state_copy_prevhex(prevhex_snap);
                if (rpc_tip_changed(rpc_url_local, rpc_user_local,
                                    rpc_pass_local, prevhex_snap, best)) {
                    log_msg("\n*** NEW BLOCK  prevhash=%.16s..."
                            "  mining on top ***\n\n", best);
                    pthread_mutex_lock(&g_work_lock);
                    strncpy(g_prevhash, best, 64);
                    g_prevhash[64] = '\0';
                    pthread_mutex_unlock(&g_work_lock);
                    g_abort_pass = 1;
                    crt_heap_signal_shutdown();
                }
            }
            *gbt_last_ms = now_ms();
        }
    }
#else
    (void)rpc_thread_local;
    (void)rpc_url_local;
    (void)rpc_user_local;
    (void)rpc_pass_local;
    (void)gbt_last_ms;
#endif

    if (!keep_going || g_abort_pass)
        goto advance_nonce;

    {
        struct crt_runtime_nonce_prepare nonce_prep;
        if (!crt_runtime_prepare_solver_nonce(
                nonce_cur, hdr80_for_nonce,
                shift_local, target_local,
                &nonce_prep,
                ctx)) {
            goto advance_nonce;
        }

        double logbase_nonce = nonce_prep.logbase_nonce;
        uint64_t gap_scan_nonce = nonce_prep.gap_scan_nonce;

        crt_compute_alignment_mpz(nAdd);
        mpz_set(orig_base_crt, tls_base_mpz);

        if (prim_mod_sieve && prim_mod_count &&
            !*prim_mod_sieve && small_primes_cache &&
            small_primes_count > 0) {
            *prim_mod_count = small_primes_count;
            *prim_mod_sieve = (uint64_t *)malloc(
                (*prim_mod_count) * sizeof(uint64_t));
            if (*prim_mod_sieve) {
                for (size_t pi = 0; pi < *prim_mod_count; pi++) {
                    (*prim_mod_sieve)[pi] = mpz_fdiv_ui(
                        g_crt_primorial_mpz,
                        (unsigned long)small_primes_cache[pi]);
                }
            }
        }

        mpz_add(candidate, orig_base_crt, nAdd);
        int cand_odd = mpz_odd_p(candidate);
        if (cand_odd)
            mpz_sub_ui(candidate, candidate, 1);
        rebase_for_gap_check(candidate);

        crt_filter_init_residues();
        int crt_first_win = 1;

        while (mpz_cmp(nAdd, crt_end) < 0 &&
               keep_going && !g_abort_pass) {
#ifdef WITH_RPC
            if (rpc_thread_local && rpc_url_local && gbt_last_ms) {
                uint64_t now = now_ms();
                if (now - *gbt_last_ms >= (uint64_t)rpc_tip_poll_ms) {
                    if (g_stratum) {
                        char data_hex_w[161];
                        uint64_t ndiff_w;
                        if (stratum_poll_new_work(g_stratum,
                                                  data_hex_w,
                                                  &ndiff_w)) {
                            log_msg("\n*** STRATUM NEW BLOCK ***\n\n");
                            build_mining_pass_stratum(data_hex_w,
                                                      ndiff_w,
                                                      shift_local);
                            g_abort_pass = 1;
                            crt_heap_signal_shutdown();
                            break;
                        }
                    } else {
                        char best_w[65];
                        char prevhex_snap_w[65];
                        pass_state_copy_prevhex(prevhex_snap_w);
                        if (rpc_tip_changed(rpc_url_local,
                                            rpc_user_local,
                                            rpc_pass_local,
                                            prevhex_snap_w,
                                            best_w)) {
                            log_msg("\n*** NEW BLOCK  prevhash=%.16s..."
                                    "  mining on top ***\n\n", best_w);
                            pthread_mutex_lock(&g_work_lock);
                            strncpy(g_prevhash, best_w, 64);
                            g_prevhash[64] = '\0';
                            pthread_mutex_unlock(&g_work_lock);
                            g_abort_pass = 1;
                            crt_heap_signal_shutdown();
                            break;
                        }
                    }
                    *gbt_last_ms = now_ms();
                }
            }
            if (g_abort_pass)
                break;
#endif

            if (!crt_first_win) {
                mpz_add(tls_base_mpz, tls_base_mpz,
                        g_crt_primorial_mpz);
                prime_cache_invalidate_base();
                if (prim_mod_sieve && *prim_mod_sieve && prim_mod_count &&
                    tls_base_mod_p) {
                    for (size_t pi = 0; pi < *prim_mod_count; pi++) {
                        tls_base_mod_p[pi] += (*prim_mod_sieve)[pi];
                        if (tls_base_mod_p[pi] >=
                            small_primes_cache[pi]) {
                            tls_base_mod_p[pi] -=
                                small_primes_cache[pi];
                        }
                    }
                }
                /* crt_filter_step_residues() is now a no-op for CRT solver
                   mode: the advance is merged into sieve_range's phase-3
                   loop so both the bitmap mark and the residue step happen
                   in a single pass over the 129K-entry filter table. */
                crt_filter_step_residues();
            }
            crt_first_win = 0;

            uint64_t gap_L = 1;
            uint64_t gap_R = gap_scan_nonce;
            size_t surv_cnt = 0;
            uint64_t *surv = sieve_range(gap_L, gap_R,
                                         &surv_cnt, NULL, 0);
            __sync_fetch_and_add(&stats_sieved, gap_R - gap_L);

            crt_runtime_process_solver_window(
                surv, surv_cnt,
                nonce_cur, cand_odd,
                logbase_nonce,
                target_local, shift_local,
                nAdd,
                rpc_url_local, rpc_user_local, rpc_pass_local,
                ctx);
        }
    }

advance_nonce:
    out.next_nonce = nonce_cur + (uint32_t)nth_local;
    out.overflow = (out.next_nonce < (uint32_t)nth_local);
    return out;
}

void crt_runtime_cpu_run_solver_producer_loop(
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
        mpz_t crt_end) {
    int eff_fermat_threads = crt_runtime_effective_fermat_threads(ctx);
    int n_sieve_threads = wa->nthreads - eff_fermat_threads;
    if (n_sieve_threads < 1)
        n_sieve_threads = 1;
    int nth_local = (eff_fermat_threads > 0)
                        ? n_sieve_threads
                        : wa->nthreads;

    if (rpc_thread_local) {
        size_t prim_bits = mpz_sizeinbase(g_crt_primorial_mpz, 2);
        size_t crt_seg = (size_t)gap_scan_cfg / 2;
        size_t crt_bytes = (crt_seg + 7) / 8;
        if (eff_fermat_threads > 0) {
            log_msg("CRT mining (%dT: %d sieve + %d fermat): "
                    "primorial~2^%lu  shift=%d  gap_scan_tmpl=%llu  "
                    "sieve_bitmap=%zu bytes (%.1f KB)  heap=%d\n",
                    wa->nthreads, n_sieve_threads,
                eff_fermat_threads,
                    (unsigned long)prim_bits, shift_local,
                    (unsigned long long)gap_scan_cfg,
                    crt_bytes, (double)crt_bytes / 1024.0,
                    (int)crt_heap_cap);
        } else {
            log_msg("CRT mining (%dT): primorial~2^%lu  shift=%d"
                    "  gap_scan_tmpl=%llu  sieve_bitmap=%zu bytes (%.1f KB)\n",
                    nth_local, (unsigned long)prim_bits, shift_local,
                    (unsigned long long)gap_scan_cfg,
                    crt_bytes, (double)crt_bytes / 1024.0);
        }
    }

    uint64_t *gbt_last_ms_ptr = NULL;
#ifdef WITH_RPC
    uint64_t gbt_last_ms = now_ms();
    gbt_last_ms_ptr = &gbt_last_ms;
#endif

    uint32_t pass_nonce = 0;
    uint8_t hdr80_for_nonce[80];
#ifdef WITH_RPC
    pass_state_snapshot_nonce_hdr80(&pass_nonce, hdr80_for_nonce);
#else
    memset(hdr80_for_nonce, 0, sizeof(hdr80_for_nonce));
#endif
    uint32_t nonce_cur = pass_nonce + 1 + (uint32_t)tid_local;

    mpz_t nAdd, candidate, orig_base_crt;
    mpz_inits(nAdd, candidate, orig_base_crt, NULL);

    uint64_t *prim_mod_sieve = NULL;
    size_t prim_mod_count = 0;

    while (keep_going && !g_abort_pass) {
        struct crt_runtime_nonce_step_result step_res =
            crt_runtime_run_solver_nonce_step(
                nonce_cur,
                nth_local,
                shift_local,
                target_local,
                rpc_thread_local,
                hdr80_for_nonce,
                rpc_url_local,
                rpc_user_local,
                rpc_pass_local,
                gbt_last_ms_ptr,
                nAdd,
                candidate,
                orig_base_crt,
                crt_end,
                &prim_mod_sieve,
                &prim_mod_count,
                ctx);
        nonce_cur = step_res.next_nonce;
        if (step_res.overflow)
            break;
    }

    crt_runtime_gpu_drain_tls_accum(ctx);

    mpz_clears(nAdd, candidate, orig_base_crt, NULL);
    free(prim_mod_sieve);
}

int crt_runtime_cpu_try_run_consumer_loop(
    const struct crt_runtime_worker_ctx *ctx,
        const struct worker_args *wa,
        mpz_t crt_end,
        double target_local,
        int shift_local,
        const char *rpc_url_local,
        const char *rpc_user_local,
        const char *rpc_pass_local) {
    if (!(wa->crt_role == 1 && crt_fermat_threads > 0))
        return 0;

    ensure_gmp_tls();

    while (keep_going && !g_abort_pass) {
        struct crt_work_item *w = crt_heap_pop();
        if (!w) break; /* abort or shutdown */

        /* Discard stale items from previous template */
        if (w->generation != crt_heap_gen) {
            __sync_fetch_and_add(&stats_crt_stale_drop, 1);
            crt_work_free(w);
            continue;
        }

        __sync_fetch_and_add(&stats_crt_consumer_windows, 1);

#ifdef WITH_GPU_FERMAT
        if (crt_runtime_gpu_process_consumer_item(
                ctx,
                w,
                target_local,
                shift_local,
                rpc_url_local,
                rpc_user_local,
                rpc_pass_local)) {
            continue;
        }
#endif

                /* Rebase all primality-side caches (prime cache + TD residues)
                     to this window's base before CPU boundary testing. */
                rebase_for_gap_check(w->base);

        /* Backward-scan: sample + skip-ahead instead of testing
           100% of survivors.  ~10-20x fewer Fermat tests. */
        {
            size_t w_primes = 0, w_qual = 0;
            size_t cpu_tests = crt_bkscan_and_submit(
                w->survivors, w->surv_cnt,
                w->logbase, target_local,
                shift_local, w->nonce,
                w->cand_odd, w->nAdd,
                rpc_url_local, rpc_user_local,
                rpc_pass_local,
                &w_primes, &w_qual);
            __sync_fetch_and_add(&stats_crt_solver_consumer_cpu_tests,
                                 (uint64_t)cpu_tests);
            crt_score_roll_observe(w->cramer_score,
                                   (uint64_t)w->surv_cnt,
                                   (uint64_t)w_primes,
                                   (uint64_t)w_qual);
        }

        crt_work_free(w);
    }

    crt_runtime_gpu_drain_tls_accum(ctx);

    mpz_clear(crt_end);
    crt_runtime_cleanup_tls_gmp(ctx);
    return 1;
}
