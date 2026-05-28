/*
 * tools/bench_cgbn/bench_fermat.cu
 *
 * Benchmark: 768-bit base-2 Fermat primality test using NVIDIA CGBN
 *   https://github.com/NVlabs/CGBN  (header-only, NVlabs official)
 *
 * Goal: compare CGBN multi-thread approach vs the project's gpu_fermat.cu
 *       Baseline: ~474,000 candidates/s on RTX 3060 (sm_86, 1 thread/candidate,
 *                 255 registers/thread, ~8 warps/SM)
 *
 * Two methods tested at TPI = 4, 8, 16, 32:
 *   A) cgbn_modular_power  — generic built-in, uses Montgomery internally
 *   B) square + double     — binary exp where "double" = add+cond-sub (free
 *                            for base=2 vs full mont_mul); mirrors gpu_fermat.cu
 *
 * Build: see Makefile (auto-clones CGBN if not present)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>           /* must come before cgbn.h so __GMP_H__ is defined */
#include <cuda_runtime.h>
#include "cgbn/cgbn.h"

/* ---- compile-time constants ---- */
#define BITS     768
#define N_LIMBS  (BITS / 32)      /* 24 uint32_t limbs */
#define KCOUNT   200000           /* instances per benchmark run */
#define NRUNS    5                /* timing repetitions */
#define TPBLOCK  128              /* threads per block */

/* ---- per-instance layout ---- */
typedef struct {
    cgbn_mem_t<BITS> modulus;    /* N: 768-bit odd number */
    uint32_t         passed;     /* 1 = Fermat test passed */
} instance_t;

/* ---- error helpers ---- */
#define CUDA_CHECK(e) \
    do { cudaError_t _r=(e); if (_r!=cudaSuccess) { \
        fprintf(stderr,"CUDA: %s  [%s:%d]\n", \
                cudaGetErrorString(_r),__FILE__,__LINE__); exit(1); } } while(0)

#define CGBN_CHECK(r) \
    do { if (cgbn_error_report_check(r)) { \
        fprintf(stderr,"CGBN error: %s\n",cgbn_error_string(r)); exit(1); } } while(0)

/* ---- CGBN parameter structs (one per TPI value) ---- */
/* CGBN constraint: BITS % (32*TPI) == 0  AND  limbs_per_thread <= TPI/2
 * For BITS=768:
 *   TPI=4:  6 limbs/thread > TPI/2=2  →  dlimbs_algs_multi (NOT IMPLEMENTED)
 *   TPI=8:  3 limbs/thread <= TPI/2=4  →  dlimbs_algs_half  (WORKS)
 *   TPI=16: 1.5 limbs/thread (non-integer, INVALID)
 *   TPI=32: 0.75 limbs/thread (non-integer, INVALID)
 * Only TPI=8 is valid for 768-bit Fermat with CGBN. */
template<uint32_t tpi>
struct Params {
    static const uint32_t TPB           = TPBLOCK;
    static const uint32_t MAX_ROTATION  = 4;
    static const uint32_t SHM_LIMIT     = 0;
    static const bool     CONSTANT_TIME = false;
    static const uint32_t TPI           = tpi;
};

/* ================================================================
 * Kernel A: cgbn_modular_power  (generic built-in)
 * ================================================================ */
template<uint32_t tpi>
__global__ void k_modpow(cgbn_error_report_t *rpt, instance_t *inst, uint32_t n)
{
    int32_t id = (int32_t)((blockIdx.x * blockDim.x + threadIdx.x) / tpi);
    if ((uint32_t)id >= n) return;

    typedef cgbn_context_t<tpi, Params<tpi>> ctx_t;
    typedef cgbn_env_t<ctx_t, BITS>          env_t;
    typedef typename env_t::cgbn_t           bn_t;

    ctx_t ctx(cgbn_report_monitor, rpt, (uint32_t)id);
    env_t env(ctx);
    bn_t  N, e, base, r;

    cgbn_load    (env, N,    &inst[id].modulus);
    cgbn_sub_ui32(env, e,    N, 1);       /* e = N-1  */
    cgbn_set_ui32(env, base, 2);          /* base = 2 */
    cgbn_modular_power(env, r, base, e, N);
    inst[id].passed = cgbn_equals_ui32(env, r, 1);
}

/* ================================================================
 * Kernel B: square + double  (base=2 optimised, binary exponentiation)
 *
 * For base=2, "multiply by base" in Montgomery space is just:
 *     r = (r + r) >= N  ?  (r+r)-N  :  (r+r)
 * This is an add + compare + conditional sub — much cheaper than a
 * full cgbn_mont_mul.  Same trick used in gpu_fermat.cu.
 * ================================================================ */
template<uint32_t tpi>
__global__ void k_sqrdbl(cgbn_error_report_t *rpt, instance_t *inst, uint32_t n)
{
    int32_t id = (int32_t)((blockIdx.x * blockDim.x + threadIdx.x) / tpi);
    if ((uint32_t)id >= n) return;

    typedef cgbn_context_t<tpi, Params<tpi>> ctx_t;
    typedef cgbn_env_t<ctx_t, BITS>          env_t;
    typedef typename env_t::cgbn_t           bn_t;

    ctx_t    ctx(cgbn_report_monitor, rpt, (uint32_t)id);
    env_t    env(ctx);
    bn_t     N, e, r, t, base;
    uint32_t np0;
    int32_t  pos;

    cgbn_load    (env, N, &inst[id].modulus);
    cgbn_sub_ui32(env, e, N, 1);          /* e = N - 1 */

    /* r = Montgomery form of 2  (= 2·R mod N)
     * Use separate 'base' variable to avoid aliased cgbn_bn2mont output. */
    cgbn_set_ui32(env, base, 2);
    np0 = cgbn_bn2mont(env, r, base, N);

    /* start from the bit below the leading 1-bit of e */
    pos = (BITS - 1) - (int32_t)cgbn_clz(env, e) - 1;

    while (pos >= 0) {
        /* square */
        cgbn_mont_sqr(env, r, r, N, np0);
        /* fwmont_mul lazily reduces to [0,2N); add+cond_sub needs r in [0,N) */
        if (cgbn_compare(env, r, N) >= 0)
            cgbn_sub(env, r, r, N);

        /* if bit is 1: double via add+cond_sub */
        if (cgbn_extract_bits_ui32(env, e, (uint32_t)pos, 1)) {
            uint32_t carry = cgbn_add(env, t, r, r);
            if (carry || cgbn_compare(env, t, N) >= 0)
                cgbn_sub(env, r, t, N);
            else
                cgbn_set(env, r, t);
        }
        pos--;
    }

    cgbn_mont2bn(env, r, r, N, np0);
    inst[id].passed = cgbn_equals_ui32(env, r, 1);
}

/* ================================================================
 * k_trace: trace first few iterations for instance 0, thread 0 of group 0
 * ================================================================ */
template<uint32_t tpi>
__global__ void k_trace(cgbn_error_report_t *rpt, instance_t *inst)
{
    int32_t id = (int32_t)((blockIdx.x * blockDim.x + threadIdx.x) / tpi);
    if (id != 0) return;

    typedef cgbn_context_t<tpi, Params<tpi>> ctx_t;
    typedef cgbn_env_t<ctx_t, BITS>          env_t;
    typedef typename env_t::cgbn_t           bn_t;

    ctx_t ctx(cgbn_report_monitor, rpt, 0u);
    env_t env(ctx);
    bn_t  N, e, r, t, base;
    uint32_t np0;

    cgbn_load    (env, N, &inst[0].modulus);
    cgbn_sub_ui32(env, e, N, 1);
    cgbn_set_ui32(env, base, 2);
    np0 = cgbn_bn2mont(env, r, base, N);

    /* Print bn2mont(2) lowest 32 bits from thread 0 of the group */
    int32_t group_thread = threadIdx.x & (tpi - 1);
    if (group_thread == 0)
        printf("bn2mont(2) r[0]=%08x  np0=%08x\n",
               cgbn_get_ui32(env, r), np0);

    int32_t pos = (BITS - 1) - (int32_t)cgbn_clz(env, e) - 1;
    if (group_thread == 0)
        printf("starting pos=%d\n", pos);

    int iters = 0;
    while (pos >= 0 && iters < 5) {
        cgbn_mont_sqr(env, r, r, N, np0);

        uint32_t bit = cgbn_extract_bits_ui32(env, e, (uint32_t)pos, 1);
        if (group_thread == 0)
            printf("iter=%d pos=%d bit=%u r[0]_after_sqr=%08x\n",
                   iters, pos, bit, cgbn_get_ui32(env, r));

        if (bit) {
            uint32_t carry = cgbn_add(env, t, r, r);
            int32_t  cmp   = cgbn_compare(env, t, N);
            if (group_thread == 0)
                printf("  carry=%u cmp=%d t[0]=%08x\n",
                       carry, cmp, cgbn_get_ui32(env, t));
            if (carry || cmp >= 0)
                cgbn_sub(env, r, t, N);
            else
                cgbn_set(env, r, t);
            if (group_thread == 0)
                printf("  r[0]_after_dbl=%08x\n", cgbn_get_ui32(env, r));
        }
        pos--;
        iters++;
    }
}

/* ================================================================
 * generate_instances: random 768-bit odd numbers
 * ================================================================ */
static void generate_instances(instance_t *dst, uint32_t count)
{
    uint32_t seed = 0xdeadbeef;
    for (uint32_t i = 0; i < count; i++) {
        for (uint32_t j = 0; j < N_LIMBS; j++) {
            seed = seed * 1664525u + 1013904223u;   /* simple LCG */
            dst[i].modulus._limbs[j] = seed;
        }
        dst[i].modulus._limbs[0]         |= 1u;           /* must be odd   */
        dst[i].modulus._limbs[N_LIMBS-1] |= 0x80000000u;  /* 768-bit MSB   */
        dst[i].passed = 0;
    }
}

/* ================================================================
 * bench_one<tpi, sqrdbl>
 *   sqrdbl=false → kernel A (cgbn_modular_power)
 *   sqrdbl=true  → kernel B (square+double)
 * ================================================================ */
template<uint32_t tpi, bool sqrdbl>
static void bench_one(const char *label,
                      instance_t *cpu, instance_t *gpu,
                      cgbn_error_report_t *report)
{
    const int ipb    = TPBLOCK / (int)tpi;
    const int blocks = (KCOUNT + ipb - 1) / ipb;

    /* print register usage */
    cudaFuncAttributes attr;
    if (sqrdbl)
        CUDA_CHECK(cudaFuncGetAttributes(&attr, k_sqrdbl<tpi>));
    else
        CUDA_CHECK(cudaFuncGetAttributes(&attr, k_modpow<tpi>));
    int regs         = attr.numRegs;
    int thds_per_sm  = (regs > 0) ? (65536 / regs) : 2048;
    if (thds_per_sm > 2048) thds_per_sm = 2048;
    int warps_per_sm = thds_per_sm / 32;
    int cands_per_sm = thds_per_sm / (int)tpi;

    /* warm-up pass */
    if (sqrdbl)
        k_sqrdbl<tpi><<<blocks, TPBLOCK>>>(report, gpu, KCOUNT);
    else
        k_modpow<tpi><<<blocks, TPBLOCK>>>(report, gpu, KCOUNT);
    CUDA_CHECK(cudaDeviceSynchronize());
    CGBN_CHECK(report);

    /* timed passes */
    cudaEvent_t ev0, ev1;
    CUDA_CHECK(cudaEventCreate(&ev0));
    CUDA_CHECK(cudaEventCreate(&ev1));
    double total = 0.0;
    for (int r = 0; r < NRUNS; r++) {
        float ms;
        CUDA_CHECK(cudaEventRecord(ev0));
        if (sqrdbl)
            k_sqrdbl<tpi><<<blocks, TPBLOCK>>>(report, gpu, KCOUNT);
        else
            k_modpow<tpi><<<blocks, TPBLOCK>>>(report, gpu, KCOUNT);
        CUDA_CHECK(cudaEventRecord(ev1));
        CUDA_CHECK(cudaEventSynchronize(ev1));
        CUDA_CHECK(cudaEventElapsedTime(&ms, ev0, ev1));
        total += (double)ms;
    }
    CUDA_CHECK(cudaEventDestroy(ev0));
    CUDA_CHECK(cudaEventDestroy(ev1));

    double avg  = total / NRUNS;
    double tput = (double)KCOUNT / (avg / 1000.0);

    /* copy back to count passed (sanity check) */
    CUDA_CHECK(cudaMemcpy(cpu, gpu,
                          sizeof(instance_t) * KCOUNT, cudaMemcpyDeviceToHost));
    int passed = 0;
    for (int i = 0; i < KCOUNT; i++) passed += (int)cpu[i].passed;

    printf("  %-12s TPI=%2u  regs=%3d  warps/SM=%2d  cands/SM=%3d  "
           "%9.0f /s  (%.1f ms  passed=%d)\n",
           label, tpi, regs, warps_per_sm, cands_per_sm,
           tput, avg, passed);
}

/* ================================================================
 * main
 * ================================================================ */
int main(void)
{
    /* device info */
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    printf("Device : %s  sm_%d%d  %d SMs  %d regs/SM  max %d warps/SM\n",
           prop.name, prop.major, prop.minor,
           prop.multiProcessorCount, prop.regsPerMultiprocessor,
           prop.maxThreadsPerMultiProcessor / 32);
    printf("Test   : %d instances, %d runs, %d-bit base-2 Fermat\n\n",
           KCOUNT, NRUNS, BITS);
    printf("Baseline: gpu_fermat.cu on RTX 3060 ~474,000 /s  "
           "(255 regs, 8 warps/SM, ~257 cands/SM)\n");
    printf("%-78s\n\n", "------------------------------------------------------------------------------");

    /* allocate shared instances */
    instance_t *cpu = (instance_t *)malloc(sizeof(instance_t) * KCOUNT);
    instance_t *gpu;
    cgbn_error_report_t *report;

    if (!cpu) { fprintf(stderr, "OOM\n"); return 1; }
    generate_instances(cpu, KCOUNT);

    CUDA_CHECK(cudaMalloc(&gpu, sizeof(instance_t) * KCOUNT));
    CUDA_CHECK(cudaMemcpy(gpu, cpu,
                          sizeof(instance_t) * KCOUNT, cudaMemcpyHostToDevice));
    CUDA_CHECK(cgbn_error_report_alloc(&report));

    /* ---- Trace: print first few iterations for instance 0 ---- */
    /* NOTE: k_trace has a known deadlock (cgbn_get_ui32 inside thread-0 guard).
     * Disabled until the trace kernel is fixed.
    printf("=== TRACE: first 5 iters for instance 0 ===\n");
    k_trace<8><<<1, TPBLOCK>>>(report, gpu);
    CUDA_CHECK(cudaDeviceSynchronize());
    CGBN_CHECK(report);
    printf("\n");
    */

    /* Only TPI=8 is valid for 768-bit (see constraint comments above) */

    /* ---- Method A: cgbn_modular_power ---- */
    printf("=== A: cgbn_modular_power (generic built-in) ===\n");
    bench_one<8, false>("modpow", cpu, gpu, report);

    /* ---- Method B: square + double ---- */
    printf("\n=== B: square+double (base=2, binary exp, doubling=add+cond.sub) ===\n");
    bench_one<8, true>("sqr+dbl", cpu, gpu, report);

    /* cleanup */
    CUDA_CHECK(cudaFree(gpu));
    CUDA_CHECK(cgbn_error_report_free(report));
    free(cpu);

    printf("\n");
    printf("Result > ~474,000/s  →  worth integrating into gpu_fermat.cu\n");
    printf("Best candidate: lowest TPI that still beats baseline\n");
    return 0;
}
