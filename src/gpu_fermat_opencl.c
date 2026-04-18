/* gpu_fermat_opencl.c -- OpenCL backend for batch Fermat testing.
 *
 * This backend mirrors the gpu_fermat API used by CUDA path:
 * - two slots (0/1) for submit/collect pipelining
 * - AL-specialized kernel dispatch (5/6/8/10/12/16/NL), similar to CUDA
 *
 * Notes:
 * - Kernel is correctness-first and currently less tuned than CUDA.
 * - active_limbs is honored at runtime and mapped to nearest kernel.
 */

#include "gpu_fermat.h"

#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 120
#endif

#include <CL/cl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OCL_LOCAL_SIZE 128

enum {
    KIDX_AL5 = 0,
    KIDX_AL6,
    KIDX_AL8,
    KIDX_AL10,
    KIDX_AL12,
    KIDX_AL16,
    KIDX_ALNL,
    KIDX_COUNT
};

struct gpu_fermat_ctx {
    int platform_id;
    int device_id;
    size_t max_batch;
    int active_limbs;

    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_program program;
    cl_kernel kernels[KIDX_COUNT];
    cl_command_queue queue[2];

    cl_mem d_cands[2];
    cl_mem d_results[2];
    uint8_t *h_results[2];
    cl_event done_event[2];
    int done_event_valid[2];
    size_t pending[2];

    char dev_name[256];
    pthread_mutex_t slot_mu[2];
    int slot_mu_inited[2];
    pthread_cond_t slot_cv[2];
    int slot_cv_inited[2];
};

static const char *g_kernel_src =
"#if __OPENCL_VERSION__ < 120\n"
"#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable\n"
"#endif\n"
"#ifndef GPU_NLIMBS\n"
"#define GPU_NLIMBS 16\n"
"#endif\n"
"#define NL GPU_NLIMBS\n"
"\n"
"__attribute__((always_inline))\n"
"static inline ulong compute_ninv(ulong n0)\n"
"{\n"
"    ulong x = 1;\n"
"    for (int i = 0; i < 6; i++)\n"
"        x *= (ulong)2 - n0 * x;\n"
"    return ~x + 1;\n"
"}\n"
"\n"
/* ── Per-AL specialized helpers: gte, sub, moddbl, compute_rmodn, montmul ── */
"#define DEFINE_GTE(S, AV) \\\n"
"__attribute__((always_inline)) \\\n"
"static inline int gte_##S(const __private ulong *a, \\\n"
"                          const __private ulong *b) \\\n"
"{ \\\n"
"    for (int i = (AV) - 1; i >= 0; i--) { \\\n"
"        if (a[i] > b[i]) return 1; \\\n"
"        if (a[i] < b[i]) return 0; \\\n"
"    } \\\n"
"    return 1; \\\n"
"}\n"
"\n"
"#define DEFINE_SUB(S, AV) \\\n"
"__attribute__((always_inline)) \\\n"
"static inline void sub_##S(__private ulong *r, \\\n"
"    const __private ulong *a, const __private ulong *b) \\\n"
"{ \\\n"
"    ulong borrow = 0; \\\n"
"    for (int i = 0; i < (AV); i++) { \\\n"
"        ulong ai = a[i], bi = b[i]; \\\n"
"        ulong d = ai - bi; \\\n"
"        ulong b1 = (ai < bi); \\\n"
"        ulong d2 = d - borrow; \\\n"
"        ulong b2 = (d < borrow); \\\n"
"        r[i] = d2; \\\n"
"        borrow = b1 + b2; \\\n"
"    } \\\n"
"}\n"
"\n"
"#define DEFINE_MODDBL(S, AV) \\\n"
"__attribute__((always_inline)) \\\n"
"static inline void moddbl_##S(__private ulong *a, \\\n"
"                               const __private ulong *n) \\\n"
"{ \\\n"
"    ulong carry = 0; \\\n"
"    for (int i = 0; i < (AV); i++) { \\\n"
"        ulong v = a[i]; \\\n"
"        a[i] = (v << 1) | carry; \\\n"
"        carry = v >> 63; \\\n"
"    } \\\n"
"    if (carry || gte_##S(a, n)) \\\n"
"        sub_##S(a, a, n); \\\n"
"}\n"
"\n"
"#define DEFINE_RMODN(S, AV) \\\n"
"static inline void compute_rmodn_##S(__private ulong *r, \\\n"
"                                      const __private ulong *n) \\\n"
"{ \\\n"
"    int top_limb = (AV) - 1; \\\n"
"    while (top_limb > 0 && n[top_limb] == 0ul) top_limb--; \\\n"
"    int top_bit_in_limb = 63 - (int)clz(n[top_limb]); \\\n"
"    int topbit = top_limb * 64 + top_bit_in_limb; \\\n"
"    for (int i = 0; i < (AV); i++) r[i] = 0ul; \\\n"
"    r[top_limb] = 1ul << top_bit_in_limb; \\\n"
"    sub_##S(r, r, n); \\\n"
"    int remaining = 64 * (AV) - 1 - topbit; \\\n"
"    for (int i = 0; i < remaining; i++) \\\n"
"        moddbl_##S(r, n); \\\n"
"}\n"
"\n"
/* montmul with mac inlined — no &t[j] so t[] stays in registers */
"#define DEFINE_MONTMUL(S, AV) \\\n"
"__attribute__((always_inline)) \\\n"
"static inline void montmul_##S(__private ulong *r, \\\n"
"    const __private ulong *a, const __private ulong *b, \\\n"
"    const __private ulong *n, ulong ninv) \\\n"
"{ \\\n"
"    ulong tbuf[2 * (AV) + 4]; \\\n"
"    for (int i = 0; i < (int)(2 * (AV) + 4); i++) tbuf[i] = 0; \\\n"
"    __private ulong *t = tbuf; \\\n"
"    for (int i = 0; i < (AV); i++) { \\\n"
"        ulong c = 0; \\\n"
"        for (int j = 0; j < (AV); j++) { \\\n"
"            ulong _lo = a[i] * b[j]; \\\n"
"            ulong _hi = mul_hi(a[i], b[j]); \\\n"
"            _lo += c; _hi += (_lo < c); \\\n"
"            ulong _pv = t[j]; t[j] = _pv + _lo; \\\n"
"            _hi += (t[j] < _pv); c = _hi; \\\n"
"        } \\\n"
"        ulong old = t[(AV)]; \\\n"
"        t[(AV)] += c; \\\n"
"        t[(AV) + 1] += (t[(AV)] < old); \\\n"
"        ulong m = t[0] * ninv; \\\n"
"        c = 0; \\\n"
"        for (int j = 0; j < (AV); j++) { \\\n"
"            ulong _lo = m * n[j]; \\\n"
"            ulong _hi = mul_hi(m, n[j]); \\\n"
"            _lo += c; _hi += (_lo < c); \\\n"
"            ulong _pv = t[j]; t[j] = _pv + _lo; \\\n"
"            _hi += (t[j] < _pv); c = _hi; \\\n"
"        } \\\n"
"        old = t[(AV)]; \\\n"
"        t[(AV)] += c; \\\n"
"        t[(AV) + 1] += (t[(AV)] < old); \\\n"
"        t++; \\\n"
"        t[(AV) + 1] = 0; \\\n"
"    } \\\n"
"    if (t[(AV)] || gte_##S(t, n)) \\\n"
"        sub_##S(r, t, n); \\\n"
"    else \\\n"
"        for (int i = 0; i < (AV); i++) r[i] = t[i]; \\\n"
"}\n"
"\n"
/* Instantiate all helpers + montmul for each AL */
"#if NL >= 5\n"
"DEFINE_GTE(5, 5) DEFINE_SUB(5, 5) DEFINE_MODDBL(5, 5)\n"
"DEFINE_RMODN(5, 5) DEFINE_MONTMUL(5, 5)\n"
"#endif\n"
"#if NL >= 6\n"
"DEFINE_GTE(6, 6) DEFINE_SUB(6, 6) DEFINE_MODDBL(6, 6)\n"
"DEFINE_RMODN(6, 6) DEFINE_MONTMUL(6, 6)\n"
"#endif\n"
"#if NL >= 8\n"
"DEFINE_GTE(8, 8) DEFINE_SUB(8, 8) DEFINE_MODDBL(8, 8)\n"
"DEFINE_RMODN(8, 8) DEFINE_MONTMUL(8, 8)\n"
"#endif\n"
"#if NL >= 10\n"
"DEFINE_GTE(10, 10) DEFINE_SUB(10, 10) DEFINE_MODDBL(10, 10)\n"
"DEFINE_RMODN(10, 10) DEFINE_MONTMUL(10, 10)\n"
"#endif\n"
"#if NL >= 12\n"
"DEFINE_GTE(12, 12) DEFINE_SUB(12, 12) DEFINE_MODDBL(12, 12)\n"
"DEFINE_RMODN(12, 12) DEFINE_MONTMUL(12, 12)\n"
"#endif\n"
"#if NL >= 16\n"
"DEFINE_GTE(16, 16) DEFINE_SUB(16, 16) DEFINE_MODDBL(16, 16)\n"
"DEFINE_RMODN(16, 16) DEFINE_MONTMUL(16, 16)\n"
"#endif\n"
"DEFINE_GTE(NL, NL) DEFINE_SUB(NL, NL) DEFINE_MODDBL(NL, NL)\n"
"DEFINE_RMODN(NL, NL) DEFINE_MONTMUL(NL, NL)\n"
"\n"
/* Fermat kernel: 4-bit left-to-right sliding-window exponentiation.
 * Precomputes win[k] = base^(2k+1) for k=0..7 (8 odd powers).
 * Reduces montmul count ~25% vs binary square-and-multiply. */
"#define DEFINE_FERMAT_KERNEL(KNAME, AL) \\\n"
"__kernel void KNAME(__global const ulong *cands, \\\n"
"                    __global uchar *results, \\\n"
"                    uint count, uint stride) { \\\n"
"    uint idx = get_global_id(0); \\\n"
"    if (idx >= count) return; \\\n"
"    __private ulong n[(AL)]; \\\n"
"    __private ulong base_m[(AL)]; \\\n"
"    __private ulong e[(AL)]; \\\n"
"    __private ulong res[(AL)]; \\\n"
"    __private ulong bsq[(AL)]; \\\n"
"    __private ulong win[8 * (AL)]; \\\n"
"    uint base_off = idx * stride; \\\n"
"    for (int i = 0; i < (AL); i++) n[i] = cands[base_off + i]; \\\n"
"    if ((n[0] & 1ul) == 0ul) { results[idx] = (uchar)0; return; } \\\n"
"    ulong ninv = compute_ninv(n[0]); \\\n"
"    compute_rmodn_##AL(base_m, n); \\\n"
"    moddbl_##AL(base_m, n); \\\n"
"    for (int i = 0; i < (AL); i++) win[i] = base_m[i]; \\\n"
"    montmul_##AL(bsq, base_m, base_m, n, ninv); \\\n"
"    for (int k = 1; k < 8; k++) \\\n"
"        montmul_##AL(win + k*(AL), win + (k-1)*(AL), bsq, n, ninv); \\\n"
"    for (int i = 0; i < (AL); i++) e[i] = n[i]; \\\n"
"    e[0] -= 1ul; \\\n"
"    int top = (AL) - 1; \\\n"
"    while (top > 0 && e[top] == 0ul) top--; \\\n"
"    int msb_e = top * 64 + 63 - (int)clz((ulong)e[top]); \\\n"
"    for (int i = 0; i < (AL); i++) res[i] = base_m[i]; \\\n"
"    int bit = msb_e - 1; \\\n"
"    while (bit >= 0) { \\\n"
"        if (bit < 3) { \\\n"
"            montmul_##AL(res, res, res, n, ninv); \\\n"
"            if ((e[bit >> 6] >> (bit & 63)) & 1ul) \\\n"
"                montmul_##AL(res, res, base_m, n, ninv); \\\n"
"            bit--; \\\n"
"        } else { \\\n"
"            int lm = (bit - 3) >> 6; \\\n"
"            int off = (bit - 3) & 63; \\\n"
"            uint w = (uint)(e[lm] >> off) & 0xFu; \\\n"
"            if (off > 60 && lm + 1 < (AL)) \\\n"
"                w |= (uint)(e[lm + 1] << (64 - off)) & 0xFu; \\\n"
"            if (w == 0u) { \\\n"
"                montmul_##AL(res, res, res, n, ninv); \\\n"
"                montmul_##AL(res, res, res, n, ninv); \\\n"
"                montmul_##AL(res, res, res, n, ninv); \\\n"
"                montmul_##AL(res, res, res, n, ninv); \\\n"
"            } else { \\\n"
"                int z = (int)ctz(w); \\\n"
"                int sq = 4 - z; \\\n"
"                for (int s = 0; s < sq; s++) \\\n"
"                    montmul_##AL(res, res, res, n, ninv); \\\n"
"                montmul_##AL(res, res, win + ((w >> z) >> 1) * (AL), n, ninv); \\\n"
"                for (int s = 0; s < z; s++) \\\n"
"                    montmul_##AL(res, res, res, n, ninv); \\\n"
"            } \\\n"
"            bit -= 4; \\\n"
"        } \\\n"
"    } \\\n"
"    for (int i = 0; i < (AL); i++) bsq[i] = 0ul; \\\n"
"    bsq[0] = 1ul; \\\n"
"    montmul_##AL(res, res, bsq, n, ninv); \\\n"
"    int ok = (res[0] == 1ul); \\\n"
"    for (int i = 1; i < (AL); i++) ok &= (res[i] == 0ul); \\\n"
"    results[idx] = ok ? (uchar)1 : (uchar)0; \\\n"
"}\n"
"\n"
"#if NL >= 5\n"
"DEFINE_FERMAT_KERNEL(fermat_kernel_al5, 5)\n"
"#endif\n"
"#if NL >= 6\n"
"DEFINE_FERMAT_KERNEL(fermat_kernel_al6, 6)\n"
"#endif\n"
"#if NL >= 8\n"
"DEFINE_FERMAT_KERNEL(fermat_kernel_al8, 8)\n"
"#endif\n"
"#if NL >= 10\n"
"DEFINE_FERMAT_KERNEL(fermat_kernel_al10, 10)\n"
"#endif\n"
"#if NL >= 12\n"
"DEFINE_FERMAT_KERNEL(fermat_kernel_al12, 12)\n"
"#endif\n"
"#if NL >= 16\n"
"DEFINE_FERMAT_KERNEL(fermat_kernel_al16, 16)\n"
"#endif\n"
"DEFINE_FERMAT_KERNEL(fermat_kernel_nl, NL)\n";

static int parse_env_platform(void)
{
    const char *s = getenv("GAP_OPENCL_PLATFORM");
    if (!s || !*s) return 0;
    int p = atoi(s);
    return (p < 0) ? 0 : p;
}

static __inline int kernel_index_for_al(int al)
{
#if GPU_NLIMBS >= 5
    if (al <= 5) return KIDX_AL5;
#endif
#if GPU_NLIMBS >= 6
    if (al <= 6) return KIDX_AL6;
#endif
#if GPU_NLIMBS >= 8
    if (al <= 8) return KIDX_AL8;
#endif
#if GPU_NLIMBS >= 10
    if (al <= 10) return KIDX_AL10;
#endif
#if GPU_NLIMBS >= 12
    if (al <= 12) return KIDX_AL12;
#endif
#if GPU_NLIMBS >= 16
    if (al <= 16) return KIDX_AL16;
#endif
    return KIDX_ALNL;
}

static __inline size_t local_size_for_al(int al, size_t preferred_mul)
{
    size_t wave = preferred_mul ? preferred_mul : 32;
    if (al <= 10) return wave * 2;
    return wave;
}

static void destroy_partial(gpu_fermat_ctx *ctx)
{
    if (!ctx) return;
    for (int s = 0; s < 2; s++) {
        if (ctx->done_event_valid[s] && ctx->done_event[s]) {
            clReleaseEvent(ctx->done_event[s]);
            ctx->done_event[s] = NULL;
            ctx->done_event_valid[s] = 0;
        }
        if (ctx->d_cands[s]) clReleaseMemObject(ctx->d_cands[s]);
        if (ctx->d_results[s]) clReleaseMemObject(ctx->d_results[s]);
        if (ctx->queue[s]) clReleaseCommandQueue(ctx->queue[s]);
        free(ctx->h_results[s]);
        if (ctx->slot_mu_inited[s]) {
            if (ctx->slot_cv_inited[s]) {
                pthread_cond_destroy(&ctx->slot_cv[s]);
                ctx->slot_cv_inited[s] = 0;
            }
            pthread_mutex_destroy(&ctx->slot_mu[s]);
            ctx->slot_mu_inited[s] = 0;
        }
    }
    for (int i = 0; i < KIDX_COUNT; i++) {
        if (ctx->kernels[i]) clReleaseKernel(ctx->kernels[i]);
    }
    if (ctx->program) clReleaseProgram(ctx->program);
    if (ctx->context) clReleaseContext(ctx->context);
}

gpu_fermat_ctx *gpu_fermat_init(int device_id, size_t max_batch)
{
    cl_int err;
    cl_uint nplat = 0;
    int platform_id = parse_env_platform();

    gpu_fermat_ctx *ctx = (gpu_fermat_ctx *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    for (int s = 0; s < 2; s++) {
        if (pthread_mutex_init(&ctx->slot_mu[s], NULL) != 0) {
            destroy_partial(ctx);
            free(ctx);
            return NULL;
        }
        ctx->slot_mu_inited[s] = 1;
        if (pthread_cond_init(&ctx->slot_cv[s], NULL) != 0) {
            destroy_partial(ctx);
            free(ctx);
            return NULL;
        }
        ctx->slot_cv_inited[s] = 1;
    }

    err = clGetPlatformIDs(0, NULL, &nplat);
    if (err != CL_SUCCESS || nplat == 0) {
        fprintf(stderr, "opencl: no platforms found (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }
    if ((cl_uint)platform_id >= nplat) {
        fprintf(stderr, "opencl: platform index %d out of range (0..%u)\n",
                platform_id, (unsigned)(nplat - 1));
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }

    cl_platform_id *plats = (cl_platform_id *)malloc((size_t)nplat * sizeof(*plats));
    if (!plats) {
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }
    err = clGetPlatformIDs(nplat, plats, NULL);
    if (err != CL_SUCCESS) {
        free(plats);
        fprintf(stderr, "opencl: clGetPlatformIDs failed (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }
    ctx->platform = plats[platform_id];
    free(plats);

    cl_uint ndev = 0;
    err = clGetDeviceIDs(ctx->platform, CL_DEVICE_TYPE_GPU, 0, NULL, &ndev);
    if (err != CL_SUCCESS || ndev == 0) {
        fprintf(stderr, "opencl: no GPU devices on platform %d (err=%d)\n",
                platform_id, (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }
    if ((cl_uint)device_id >= ndev) {
        fprintf(stderr, "opencl: device index %d out of range (0..%u)\n",
                device_id, (unsigned)(ndev - 1));
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }

    cl_device_id *devs = (cl_device_id *)malloc((size_t)ndev * sizeof(*devs));
    if (!devs) {
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }
    err = clGetDeviceIDs(ctx->platform, CL_DEVICE_TYPE_GPU, ndev, devs, NULL);
    if (err != CL_SUCCESS) {
        free(devs);
        fprintf(stderr, "opencl: clGetDeviceIDs failed (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }
    ctx->device = devs[device_id];
    free(devs);

    memset(ctx->dev_name, 0, sizeof(ctx->dev_name));
    (void)clGetDeviceInfo(ctx->device, CL_DEVICE_NAME, sizeof(ctx->dev_name),
                          ctx->dev_name, NULL);

    ctx->context = clCreateContext(NULL, 1, &ctx->device, NULL, NULL, &err);
    if (err != CL_SUCCESS || !ctx->context) {
        fprintf(stderr, "opencl: clCreateContext failed (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }

#if CL_TARGET_OPENCL_VERSION >= 200
    ctx->queue[0] = clCreateCommandQueueWithProperties(ctx->context, ctx->device, 0, &err);
#else
    ctx->queue[0] = clCreateCommandQueue(ctx->context, ctx->device, 0, &err);
#endif
    if (err != CL_SUCCESS || !ctx->queue[0]) {
        fprintf(stderr, "opencl: clCreateCommandQueue[0] failed (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }
#if CL_TARGET_OPENCL_VERSION >= 200
    ctx->queue[1] = clCreateCommandQueueWithProperties(ctx->context, ctx->device, 0, &err);
#else
    ctx->queue[1] = clCreateCommandQueue(ctx->context, ctx->device, 0, &err);
#endif
    if (err != CL_SUCCESS || !ctx->queue[1]) {
        fprintf(stderr, "opencl: clCreateCommandQueue[1] failed (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }

    const char *src = g_kernel_src;
    size_t src_len = strlen(g_kernel_src);
    ctx->program = clCreateProgramWithSource(ctx->context, 1, &src, &src_len, &err);
    if (err != CL_SUCCESS || !ctx->program) {
        fprintf(stderr, "opencl: clCreateProgramWithSource failed (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }

    char build_opts[128];
    snprintf(build_opts, sizeof(build_opts), "-D GPU_NLIMBS=%d", GPU_NLIMBS);
    err = clBuildProgram(ctx->program, 1, &ctx->device, build_opts, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_sz = 0;
        clGetProgramBuildInfo(ctx->program, ctx->device, CL_PROGRAM_BUILD_LOG,
                              0, NULL, &log_sz);
        char *blog = (char *)malloc(log_sz + 1);
        if (blog) {
            clGetProgramBuildInfo(ctx->program, ctx->device, CL_PROGRAM_BUILD_LOG,
                                  log_sz, blog, NULL);
            blog[log_sz] = '\0';
            fprintf(stderr, "opencl: program build failed (err=%d)\n%s\n",
                    (int)err, blog);
            free(blog);
        } else {
            fprintf(stderr, "opencl: program build failed (err=%d)\n", (int)err);
        }
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }

    /* Optional AL-specialized kernels plus mandatory NL fallback. */
#if GPU_NLIMBS >= 5
    ctx->kernels[KIDX_AL5] = clCreateKernel(ctx->program, "fermat_kernel_al5", &err);
    if (err != CL_SUCCESS) ctx->kernels[KIDX_AL5] = NULL;
#endif
#if GPU_NLIMBS >= 6
    ctx->kernels[KIDX_AL6] = clCreateKernel(ctx->program, "fermat_kernel_al6", &err);
    if (err != CL_SUCCESS) ctx->kernels[KIDX_AL6] = NULL;
#endif
#if GPU_NLIMBS >= 8
    ctx->kernels[KIDX_AL8] = clCreateKernel(ctx->program, "fermat_kernel_al8", &err);
    if (err != CL_SUCCESS) ctx->kernels[KIDX_AL8] = NULL;
#endif
#if GPU_NLIMBS >= 10
    ctx->kernels[KIDX_AL10] = clCreateKernel(ctx->program, "fermat_kernel_al10", &err);
    if (err != CL_SUCCESS) ctx->kernels[KIDX_AL10] = NULL;
#endif
#if GPU_NLIMBS >= 12
    ctx->kernels[KIDX_AL12] = clCreateKernel(ctx->program, "fermat_kernel_al12", &err);
    if (err != CL_SUCCESS) ctx->kernels[KIDX_AL12] = NULL;
#endif
#if GPU_NLIMBS >= 16
    ctx->kernels[KIDX_AL16] = clCreateKernel(ctx->program, "fermat_kernel_al16", &err);
    if (err != CL_SUCCESS) ctx->kernels[KIDX_AL16] = NULL;
#endif
    ctx->kernels[KIDX_ALNL] = clCreateKernel(ctx->program, "fermat_kernel_nl", &err);
    if (err != CL_SUCCESS || !ctx->kernels[KIDX_ALNL]) {
        fprintf(stderr, "opencl: clCreateKernel fallback failed (err=%d)\n", (int)err);
        destroy_partial(ctx);
        free(ctx);
        return NULL;
    }

    size_t cands_bytes = max_batch * GPU_NLIMBS * sizeof(uint64_t);
    for (int s = 0; s < 2; s++) {
        ctx->d_cands[s] = clCreateBuffer(ctx->context, CL_MEM_READ_ONLY,
                                         cands_bytes, NULL, &err);
        if (err != CL_SUCCESS || !ctx->d_cands[s]) {
            fprintf(stderr, "opencl: clCreateBuffer cands[%d] failed (err=%d)\n", s, (int)err);
            destroy_partial(ctx);
            free(ctx);
            return NULL;
        }
        ctx->d_results[s] = clCreateBuffer(ctx->context, CL_MEM_WRITE_ONLY,
                                           max_batch, NULL, &err);
        if (err != CL_SUCCESS || !ctx->d_results[s]) {
            fprintf(stderr, "opencl: clCreateBuffer results[%d] failed (err=%d)\n", s, (int)err);
            destroy_partial(ctx);
            free(ctx);
            return NULL;
        }
        ctx->h_results[s] = (uint8_t *)malloc(max_batch);
        if (!ctx->h_results[s]) {
            destroy_partial(ctx);
            free(ctx);
            return NULL;
        }
        ctx->pending[s] = 0;
    }

    ctx->platform_id = platform_id;
    ctx->device_id = device_id;
    ctx->max_batch = max_batch;
    ctx->active_limbs = GPU_NLIMBS;

    return ctx;
}

int gpu_fermat_submit(gpu_fermat_ctx *ctx, int slot,
                      const uint64_t *candidates, size_t count)
{
    if (!ctx || !candidates || count == 0) return -1;
    if (slot < 0 || slot > 1) return -1;
    if (count > ctx->max_batch) count = ctx->max_batch;

    pthread_mutex_lock(&ctx->slot_mu[slot]);
    while (ctx->pending[slot] != 0)
        pthread_cond_wait(&ctx->slot_cv[slot], &ctx->slot_mu[slot]);

    if (ctx->done_event_valid[slot] && ctx->done_event[slot]) {
        clReleaseEvent(ctx->done_event[slot]);
        ctx->done_event[slot] = NULL;
        ctx->done_event_valid[slot] = 0;
    }

    int al = __atomic_load_n(&ctx->active_limbs, __ATOMIC_RELAXED);
    if (al < 1) al = GPU_NLIMBS;
    if (al > GPU_NLIMBS) al = GPU_NLIMBS;
    int stride = al;

    cl_int err;
    cl_event read_event = NULL;
    size_t cands_bytes = count * (size_t)stride * sizeof(uint64_t);
    err = clEnqueueWriteBuffer(ctx->queue[slot], ctx->d_cands[slot], CL_FALSE,
                               0, cands_bytes, candidates, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        goto fail;
    }
    int kidx = kernel_index_for_al(al);
    cl_kernel k = ctx->kernels[kidx] ? ctx->kernels[kidx] : ctx->kernels[KIDX_ALNL];
    cl_uint ncount = (cl_uint)count;
    cl_uint nstride = (cl_uint)stride;

    err  = clSetKernelArg(k, 0, sizeof(cl_mem), &ctx->d_cands[slot]);
    err |= clSetKernelArg(k, 1, sizeof(cl_mem), &ctx->d_results[slot]);
    err |= clSetKernelArg(k, 2, sizeof(cl_uint), &ncount);
    err |= clSetKernelArg(k, 3, sizeof(cl_uint), &nstride);
    if (err != CL_SUCCESS) {
        goto fail;
    }

    size_t preferred_mul = 0;
    (void)clGetKernelWorkGroupInfo(k, ctx->device,
                                   CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE,
                                   sizeof(preferred_mul), &preferred_mul, NULL);
    size_t local = local_size_for_al(al, preferred_mul);
    size_t max_wg = 0;
    if (clGetKernelWorkGroupInfo(k, ctx->device, CL_KERNEL_WORK_GROUP_SIZE,
                                 sizeof(max_wg), &max_wg, NULL) == CL_SUCCESS) {
        if (max_wg > 0 && local > max_wg) local = max_wg;
    }
    if (preferred_mul > 0 && local > preferred_mul)
        local = (local / preferred_mul) * preferred_mul;
    if (local < 1) local = 1;
    size_t global = ((count + local - 1) / local) * local;
    err = clEnqueueNDRangeKernel(ctx->queue[slot], k, 1,
                                 NULL, &global, &local, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        goto fail;
    }

    err = clEnqueueReadBuffer(ctx->queue[slot], ctx->d_results[slot], CL_FALSE,
                              0, count, ctx->h_results[slot], 0, NULL, &read_event);
    if (err != CL_SUCCESS) {
        goto fail;
    }

    err = clFlush(ctx->queue[slot]);
    if (err != CL_SUCCESS) {
        goto fail;
    }

    ctx->done_event[slot] = read_event;
    ctx->done_event_valid[slot] = 1;
    ctx->pending[slot] = count;
    pthread_mutex_unlock(&ctx->slot_mu[slot]);
    return 0;

fail:
    if (read_event) clReleaseEvent(read_event);
    pthread_mutex_unlock(&ctx->slot_mu[slot]);
    return -1;
}

int gpu_fermat_collect(gpu_fermat_ctx *ctx, int slot,
                       uint8_t *results, size_t count)
{
    if (!ctx || !results) return -1;
    if (slot < 0 || slot > 1) return -1;

    pthread_mutex_lock(&ctx->slot_mu[slot]);
    if (ctx->pending[slot] == 0) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return 0;
    }

    size_t n = ctx->pending[slot];
    if (count < n) n = count;

    cl_int err;
    if (ctx->done_event_valid[slot] && ctx->done_event[slot]) {
        err = clWaitForEvents(1, &ctx->done_event[slot]);
        clReleaseEvent(ctx->done_event[slot]);
        ctx->done_event[slot] = NULL;
        ctx->done_event_valid[slot] = 0;
    } else {
        /* Fallback path for robustness if submit failed before event record. */
        err = clFinish(ctx->queue[slot]);
    }
    if (err != CL_SUCCESS) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    memcpy(results, ctx->h_results[slot], n);

    int primes = 0;
    for (size_t i = 0; i < n; i++)
        primes += results[i];

    ctx->pending[slot] = 0;
    pthread_cond_broadcast(&ctx->slot_cv[slot]);
    pthread_mutex_unlock(&ctx->slot_mu[slot]);
    return primes;
}

int gpu_fermat_test_batch(gpu_fermat_ctx *ctx,
                          const uint64_t *candidates,
                          uint8_t *results,
                          size_t count)
{
    if (!ctx || !candidates || !results || count == 0) return 0;
    if (count > ctx->max_batch) count = ctx->max_batch;
    if (gpu_fermat_submit(ctx, 0, candidates, count) < 0) return -1;
    return gpu_fermat_collect(ctx, 0, results, count);
}

const char *gpu_fermat_device_name(gpu_fermat_ctx *ctx)
{
    return ctx ? ctx->dev_name : "";
}

void gpu_fermat_set_limbs(gpu_fermat_ctx *ctx, int limbs)
{
    if (!ctx) return;
    if (limbs < 1) limbs = GPU_NLIMBS;
    if (limbs > GPU_NLIMBS) limbs = GPU_NLIMBS;
    __atomic_store_n(&ctx->active_limbs, limbs, __ATOMIC_RELAXED);
}

int gpu_fermat_get_limbs(gpu_fermat_ctx *ctx)
{
    if (!ctx) return GPU_NLIMBS;
    int al = __atomic_load_n(&ctx->active_limbs, __ATOMIC_RELAXED);
    return (al >= 1 && al <= GPU_NLIMBS) ? al : GPU_NLIMBS;
}

void gpu_fermat_destroy(gpu_fermat_ctx *ctx)
{
    if (!ctx) return;
    for (int s = 0; s < 2; s++) {
        if (ctx->queue[s]) clFinish(ctx->queue[s]);
    }
    destroy_partial(ctx);

    free(ctx);
}
