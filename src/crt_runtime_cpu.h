#ifndef CRT_RUNTIME_CPU_H
#define CRT_RUNTIME_CPU_H

#include <stdint.h>
#include <gmp.h>

struct worker_args;
struct crt_runtime_worker_ctx;

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
    mpz_t crt_end);

int crt_runtime_cpu_try_run_consumer_loop(
    const struct crt_runtime_worker_ctx *ctx,
    const struct worker_args *wa,
    mpz_t crt_end,
    double target_local,
    int shift_local,
    const char *rpc_url_local,
    const char *rpc_user_local,
    const char *rpc_pass_local);

#endif
