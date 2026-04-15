#include "crt_runtime_worker.h"
#include "crt_runtime_cpu.h"

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
    mpz_t crt_end) {
    crt_runtime_cpu_run_solver_producer_loop(
        ctx,
        wa,
        tid_local,
        shift_local,
        target_local,
        rpc_thread_local,
        rpc_url_local,
        rpc_user_local,
        rpc_pass_local,
        gap_scan_cfg,
        crt_end);
}

int crt_runtime_try_run_consumer_loop(
    const struct crt_runtime_worker_ctx *ctx,
    const struct worker_args *wa,
    mpz_t crt_end,
    double target_local,
    int shift_local,
    const char *rpc_url_local,
    const char *rpc_user_local,
    const char *rpc_pass_local) {
    return crt_runtime_cpu_try_run_consumer_loop(
        ctx,
        wa,
        crt_end,
        target_local,
        shift_local,
        rpc_url_local,
        rpc_user_local,
        rpc_pass_local);
}
