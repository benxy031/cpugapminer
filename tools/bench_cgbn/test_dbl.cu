/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * test_dbl.cu – minimal test for CGBN add+cond_sub doubling correctness.
 *
 * Runs with exactly 1 CGBN group (8 threads, TPI=8) on 1 instance.
 * Tests whether (r+r) with conditional subtract gives the same result
 * as cgbn_mont_mul(r, mont_two) for each step of the binary exp.
 *
 * Build: nvcc -arch=sm_86 -O3 -std=c++14 -Icgbn/include -lgmp -o test_dbl test_dbl.cu
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>
#include <cuda_runtime.h>
#include "cgbn/cgbn.h"

#define BITS    768
#define NLIMBS  (BITS / 32)

#define CUDA_CHECK(e) do { \
    cudaError_t _r=(e); if(_r!=cudaSuccess){ \
    fprintf(stderr,"CUDA %s [%s:%d]\n",cudaGetErrorString(_r),__FILE__,__LINE__); \
    exit(1);} } while(0)

#define CGBN_CHECK(r) do { if(cgbn_error_report_check(r)){ \
    fprintf(stderr,"CGBN: %s\n",cgbn_error_string(r)); exit(1);} } while(0)

typedef struct {
    cgbn_mem_t<BITS> modulus;
    uint32_t         passed_dbl;   /* result of add+cond_sub exp */
    uint32_t         passed_mul;   /* result of mont_mul exp */
    int32_t          diverge_pos;  /* pos where they first differ (-1 = never) */
} inst_t;

template<uint32_t tpi>
struct Params {
    static const uint32_t TPB           = 32;  /* full warp = 4 groups × TPI=8 */
    static const uint32_t MAX_ROTATION  = 4;
    static const uint32_t SHM_LIMIT     = 0;
    static const bool     CONSTANT_TIME = false;
    static const uint32_t TPI           = tpi;
};

/* ============================================================
 * k_compare: runs both methods in lockstep, reports first divergence.
 * Launch with 32 threads (4 groups × TPI=8) — a complete warp.
 * All 4 groups operate on their own instances; only group 0 prints.
 * ============================================================ */
__global__ void k_compare(cgbn_error_report_t *rpt, inst_t *inst, uint32_t n)
{
    typedef cgbn_context_t<8, Params<8>> ctx_t;
    typedef cgbn_env_t<ctx_t, BITS>      env_t;
    typedef env_t::cgbn_t                bn_t;

    int32_t id = (int32_t)((blockIdx.x * blockDim.x + threadIdx.x) / 8);
    if ((uint32_t)id >= n) return;

    ctx_t ctx(cgbn_report_monitor, rpt, (uint32_t)id);
    env_t env(ctx);
    bn_t  N, e, r1, r2, t, base, mont_two;
    uint32_t np0;

    cgbn_load    (env, N,    &inst[id].modulus);
    cgbn_sub_ui32(env, e,    N, 1);
    cgbn_set_ui32(env, base, 2);
    np0 = cgbn_bn2mont(env, r1, base, N);
    cgbn_set(env, r2,       r1);     /* both start at mont(2) */
    cgbn_set(env, mont_two, r1);     /* save mont(2) for mul path */

    int32_t pos = (BITS - 1) - (int32_t)cgbn_clz(env, e) - 1;
    int32_t diverge = -1;
    int32_t gt = threadIdx.x & 7;   /* group thread (0..7) */

    {
        uint32_t r1_init = cgbn_get_ui32(env, r1);   /* all 8 threads participate */
        if (id == 0 && gt == 0)
            printf("Starting pos=%d  np0=%08x  r[0]=%08x\n", pos, np0, r1_init);
    }

    while (pos >= 0) {
        uint32_t bit = cgbn_extract_bits_ui32(env, e, (uint32_t)pos, 1);

        /* --- Trace state BEFORE any operation at the divergence position --- */
        if ((pos == 764 || pos == 763) && id == 0) {
            uint32_t rv = cgbn_get_ui32(env, r1);   /* r1==r2 here (no diverge yet) */
            uint32_t rv2 = cgbn_get_ui32(env, r2);
            uint32_t nv = cgbn_get_ui32(env, N);
            if (gt == 0)
                printf("[pos=%d] bit=%u  r1[0]=%08x r2[0]=%08x N[0]=%08x\n", pos, bit, rv, rv2, nv);
        }

        /* --- Method 1: add + cond_sub --- */
        cgbn_mont_sqr(env, r1, r1, N, np0);

        if (pos == 764 && id == 0 && bit) {
            uint32_t r1s = cgbn_get_ui32(env, r1);
            if (gt == 0) printf("[pos=764] after_sqr r1[0]=%08x\n", r1s);

            uint32_t carry = cgbn_add(env, t, r1, r1);
            int32_t  cmp   = cgbn_compare(env, t, N);
            uint32_t tv    = cgbn_get_ui32(env, t);
            /* MSB limbs to see if t actually > N */
            uint32_t t23   = cgbn_extract_bits_ui32(env, t, 736, 32);
            uint32_t N23   = cgbn_extract_bits_ui32(env, N, 736, 32);
            uint32_t t22   = cgbn_extract_bits_ui32(env, t, 704, 32);
            uint32_t N22   = cgbn_extract_bits_ui32(env, N, 704, 32);
            uint32_t r1_23 = cgbn_extract_bits_ui32(env, r1, 736, 32);
            uint32_t r1_22 = cgbn_extract_bits_ui32(env, r1, 704, 32);
            if (gt == 0)
                printf("[pos=764] carry=%u cmp=%d t[0]=%08x\n"
                       "          r1[23]=%08x t[23]=%08x N[23]=%08x\n"
                       "          r1[22]=%08x t[22]=%08x N[22]=%08x\n",
                       carry, cmp, tv,
                       r1_23, t23, N23,
                       r1_22, t22, N22);

            if (carry || cmp >= 0)
                cgbn_sub(env, r1, t, N);
            else
                cgbn_set(env, r1, t);

            uint32_t r1f = cgbn_get_ui32(env, r1);
            if (gt == 0) printf("[pos=764] r1_after_dbl[0]=%08x\n", r1f);
        } else if (bit) {
            uint32_t carry = cgbn_add(env, t, r1, r1);
            if (carry || cgbn_compare(env, t, N) >= 0)
                cgbn_sub(env, r1, t, N);
            else
                cgbn_set(env, r1, t);
        }

        /* --- Method 2: mont_mul --- */
        cgbn_mont_sqr(env, r2, r2, N, np0);
        if (bit) {
            cgbn_mont_mul(env, r2, r2, mont_two, N, np0);
            if ((pos == 764 || pos == 763) && id == 0) {
                uint32_t r2f  = cgbn_get_ui32(env, r2);
                uint32_t r2_23 = cgbn_extract_bits_ui32(env, r2, 736, 32);
                uint32_t r1f  = cgbn_get_ui32(env, r1);
                uint32_t r1_23 = cgbn_extract_bits_ui32(env, r1, 736, 32);
                if (gt == 0)
                    printf("[pos=%d] r1[0]=%08x r1[23]=%08x  r2[0]=%08x r2[23]=%08x\n",
                           pos, r1f, r1_23, r2f, r2_23);
            }
        } else if ((pos == 764 || pos == 763) && id == 0) {
            /* print r2 after squaring only (no doubling) — check full reconvergence */
            uint32_t r2sq_0  = cgbn_get_ui32(env, r2);
            uint32_t r1sq_0  = cgbn_get_ui32(env, r1);
            uint32_t r2sq_23 = cgbn_extract_bits_ui32(env, r2, 736, 32);
            uint32_t r1sq_23 = cgbn_extract_bits_ui32(env, r1, 736, 32);
            uint32_t r2sq_12 = cgbn_extract_bits_ui32(env, r2, 384, 32);
            uint32_t r1sq_12 = cgbn_extract_bits_ui32(env, r1, 384, 32);
            if (gt == 0)
                printf("[pos=%d] after_sqr_only:\n"
                       "  r1[0]=%08x r1[23]=%08x r1[12]=%08x\n"
                       "  r2[0]=%08x r2[23]=%08x r2[12]=%08x\n",
                       pos, r1sq_0, r1sq_23, r1sq_12, r2sq_0, r2sq_23, r2sq_12);
        }

        /* --- Check divergence: call cgbn_get_ui32 from ALL 8 threads --- */
        if (diverge < 0 && cgbn_compare(env, r1, r2) != 0) {
            diverge = pos;
            /* MUST call these OUTSIDE the gt==0 guard — they need all 8 threads */
            uint32_t r1_low = cgbn_get_ui32(env, r1);
            uint32_t r2_low = cgbn_get_ui32(env, r2);
            if (id == 0 && gt == 0)
                printf("DIVERGE at pos=%d bit=%u  r1[0]=%08x  r2[0]=%08x\n",
                       pos, bit, r1_low, r2_low);
        }
        pos--;
    }

    cgbn_mont2bn(env, r1, r1, N, np0);
    cgbn_mont2bn(env, r2, r2, N, np0);

    inst[id].passed_dbl  = cgbn_equals_ui32(env, r1, 1);
    inst[id].passed_mul  = cgbn_equals_ui32(env, r2, 1);
    inst[id].diverge_pos = diverge;

    if (id == 0 && gt == 0)
        printf("Final: passed_dbl=%u  passed_mul=%u  diverge_pos=%d\n",
               inst[id].passed_dbl, inst[id].passed_mul, diverge);
}

int main(void)
{
    /* generate 4 instances (same seed as bench_fermat.cu) — fills 1 full warp */
    const int NINST = 4;
    inst_t *cpu = (inst_t *)malloc(sizeof(inst_t) * NINST);
    uint32_t seed = 0xdeadbeef;
    for (int i = 0; i < NINST; i++) {
        for (uint32_t j = 0; j < NLIMBS; j++) {
            seed = seed * 1664525u + 1013904223u;
            cpu[i].modulus._limbs[j] = seed;
        }
        cpu[i].modulus._limbs[0]         |= 1u;
        cpu[i].modulus._limbs[NLIMBS-1]  |= 0x80000000u;
        cpu[i].passed_dbl = cpu[i].passed_mul = 0;
        cpu[i].diverge_pos = -1;
    }

    printf("N[0][0]=%08x N[0][23]=%08x\n",
           cpu[0].modulus._limbs[0], cpu[0].modulus._limbs[NLIMBS-1]);

    inst_t *gpu;
    cgbn_error_report_t *rpt;
    CUDA_CHECK(cudaMalloc(&gpu, sizeof(inst_t) * NINST));
    CUDA_CHECK(cudaMemcpy(gpu, cpu, sizeof(inst_t) * NINST, cudaMemcpyHostToDevice));
    CUDA_CHECK(cgbn_error_report_alloc(&rpt));

    /* launch 1 block of 32 threads = 4 CGBN groups (complete warp) */
    k_compare<<<1, 32>>>(rpt, gpu, NINST);
    CUDA_CHECK(cudaDeviceSynchronize());
    CGBN_CHECK(rpt);

    CUDA_CHECK(cudaMemcpy(cpu, gpu, sizeof(inst_t) * NINST, cudaMemcpyDeviceToHost));
    printf("CPU-side inst[0]: passed_dbl=%u  passed_mul=%u  diverge_pos=%d\n",
           cpu[0].passed_dbl, cpu[0].passed_mul, cpu[0].diverge_pos);

    free(cpu);
    CUDA_CHECK(cudaFree(gpu));
    cgbn_error_report_free(rpt);
    return 0;
}
