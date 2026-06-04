/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * test_vs_modpow.cu – verify that add+cond_sub doubling gives the same
 * Fermat pass count as cgbn_modular_power on 200k random 768-bit candidates.
 *
 * Build: nvcc -arch=sm_86 -O3 -std=c++14 -Icgbn/include -lgmp -o test_vs_modpow test_vs_modpow.cu
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>           /* must come before cgbn.h so __GMP_H__ is defined */
#include <cuda_runtime.h>
#include "cgbn/cgbn.h"

#define BITS    768
#define NLIMBS  (BITS / 32)
#define KCOUNT  200000
#define TPBLOCK 128

#define CUDA_CHECK(e) do { cudaError_t _r=(e); if(_r!=cudaSuccess){ \
    fprintf(stderr,"CUDA %s [%s:%d]\n",cudaGetErrorString(_r),__FILE__,__LINE__); \
    exit(1);} } while(0)
#define CGBN_CHECK(r) do { if(cgbn_error_report_check(r)){ \
    fprintf(stderr,"CGBN: %s\n",cgbn_error_string(r)); exit(1);} } while(0)

typedef struct {
    cgbn_mem_t<BITS> modulus;
    uint32_t         passed_sqrdbl;   /* add+cond_sub result */
    uint32_t         passed_modpow;   /* cgbn_modular_power result */
} inst_t;

template<uint32_t tpi>
struct Params {
    static const uint32_t TPB           = TPBLOCK;
    static const uint32_t MAX_ROTATION  = 4;
    static const uint32_t SHM_LIMIT     = 0;
    static const bool     CONSTANT_TIME = false;
    static const uint32_t TPI           = tpi;
};

/* Method A: cgbn_modular_power */
template<uint32_t tpi>
__global__ void k_modpow(cgbn_error_report_t *rpt, inst_t *inst, uint32_t n)
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
    cgbn_sub_ui32(env, e,    N, 1);
    cgbn_set_ui32(env, base, 2);
    cgbn_modular_power(env, r, base, e, N);
    inst[id].passed_modpow = cgbn_equals_ui32(env, r, 1);
}

/* Method B: square+double with add+cond_sub */
template<uint32_t tpi>
__global__ void k_sqrdbl(cgbn_error_report_t *rpt, inst_t *inst, uint32_t n)
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
    cgbn_sub_ui32(env, e, N, 1);
    cgbn_set_ui32(env, base, 2);
    np0 = cgbn_bn2mont(env, r, base, N);
    pos = (BITS - 1) - (int32_t)cgbn_clz(env, e) - 1;

    while (pos >= 0) {
        cgbn_mont_sqr(env, r, r, N, np0);
        /* Explicit reduction: fwmont_mul lazy-reduces to [0,2N);
           add+cond_sub doubling requires r in [0,N). */
        if (cgbn_compare(env, r, N) >= 0)
            cgbn_sub(env, r, r, N);
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
    inst[id].passed_sqrdbl = cgbn_equals_ui32(env, r, 1);
}

static void generate_instances(inst_t *dst, uint32_t count)
{
    uint32_t seed = 0xdeadbeef;
    for (uint32_t i = 0; i < count; i++) {
        for (uint32_t j = 0; j < NLIMBS; j++) {
            seed = seed * 1664525u + 1013904223u;
            dst[i].modulus._limbs[j] = seed;
        }
        dst[i].modulus._limbs[0]         |= 1u;
        dst[i].modulus._limbs[NLIMBS-1]  |= 0x80000000u;
        dst[i].passed_sqrdbl = dst[i].passed_modpow = 0;
    }
}

int main(void)
{
    const int ipb    = TPBLOCK / 8;
    const int blocks = (KCOUNT + ipb - 1) / ipb;

    inst_t *cpu = (inst_t *)malloc(sizeof(inst_t) * KCOUNT);
    inst_t *gpu;
    cgbn_error_report_t *report;

    generate_instances(cpu, KCOUNT);

    CUDA_CHECK(cudaMalloc(&gpu, sizeof(inst_t) * KCOUNT));
    CUDA_CHECK(cudaMemcpy(gpu, cpu, sizeof(inst_t) * KCOUNT, cudaMemcpyHostToDevice));
    CUDA_CHECK(cgbn_error_report_alloc(&report));

    /* Run modpow */
    k_modpow<8><<<blocks, TPBLOCK>>>(report, gpu, KCOUNT);
    CUDA_CHECK(cudaDeviceSynchronize());
    CGBN_CHECK(report);

    /* Run sqrdbl (add+cond_sub) */
    k_sqrdbl<8><<<blocks, TPBLOCK>>>(report, gpu, KCOUNT);
    CUDA_CHECK(cudaDeviceSynchronize());
    CGBN_CHECK(report);

    CUDA_CHECK(cudaMemcpy(cpu, gpu, sizeof(inst_t) * KCOUNT, cudaMemcpyDeviceToHost));

    /* CPU reference check: use GMP to compute 2^(N-1) mod N */
    mpz_t n_mpz, r_mpz, two;
    mpz_init(n_mpz);
    mpz_init(r_mpz);
    mpz_init_set_ui(two, 2);

    int passed_sqrdbl = 0, passed_modpow = 0, passed_cpu = 0;
    int disagree_sq_vs_mp = 0, disagree_sq_vs_cpu = 0, disagree_mp_vs_cpu = 0;
    for (int i = 0; i < KCOUNT; i++) {
        /* Load N from limbs (little-endian uint32) */
        mpz_import(n_mpz, NLIMBS, -1, 4, 0, 0, cpu[i].modulus._limbs);
        /* e = N - 1 */
        mpz_t e_mpz;
        mpz_init(e_mpz);
        mpz_sub_ui(e_mpz, n_mpz, 1);
        /* r = 2^e mod N */
        mpz_powm(r_mpz, two, e_mpz, n_mpz);
        mpz_clear(e_mpz);
        int cpu_pass = (mpz_cmp_ui(r_mpz, 1) == 0) ? 1 : 0;

        passed_modpow  += (int)cpu[i].passed_modpow;
        passed_sqrdbl  += (int)cpu[i].passed_sqrdbl;
        passed_cpu     += cpu_pass;
        if (cpu[i].passed_modpow != cpu[i].passed_sqrdbl)
            disagree_sq_vs_mp++;
        if ((int)cpu[i].passed_sqrdbl != cpu_pass)
            disagree_sq_vs_cpu++;
        if ((int)cpu[i].passed_modpow != cpu_pass)
            disagree_mp_vs_cpu++;
    }
    mpz_clear(n_mpz); mpz_clear(r_mpz); mpz_clear(two);

    printf("cpu_ref: passed=%d\n", passed_cpu);
    printf("modpow:  passed=%d  disagree_vs_cpu=%d\n", passed_modpow, disagree_mp_vs_cpu);
    printf("sqrdbl:  passed=%d  disagree_vs_cpu=%d\n", passed_sqrdbl, disagree_sq_vs_cpu);
    printf("sqrdbl vs modpow disagree=%d\n", disagree_sq_vs_mp);

    free(cpu);
    CUDA_CHECK(cudaFree(gpu));
    cgbn_error_report_free(report);
    return 0;
}
