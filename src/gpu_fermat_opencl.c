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
    size_t pending[2];

    char dev_name[256];
    pthread_mutex_t slot_mu[2];
    int slot_mu_inited[2];
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
"static inline ulong mac(__private ulong *acc, ulong a, ulong b, ulong carry)\n"
"{\n"
"    ulong lo = a * b;\n"
"    ulong hi = mul_hi(a, b);\n"
"    lo += carry;\n"
"    hi += (lo < carry);\n"
"    ulong prev = *acc;\n"
"    *acc = prev + lo;\n"
"    hi += (*acc < prev);\n"
"    return hi;\n"
"}\n"
"\n"
"static inline int gte_n(const __private ulong *a, const __private ulong *b, uint al)\n"
"{\n"
"    for (int i = (int)al - 1; i >= 0; i--) {\n"
"        if (a[i] > b[i]) return 1;\n"
"        if (a[i] < b[i]) return 0;\n"
"    }\n"
"    return 1;\n"
"}\n"
"\n"
"static inline void sub_n(__private ulong *r, const __private ulong *a, const __private ulong *b, uint al)\n"
"{\n"
"    ulong borrow = 0;\n"
"    for (uint i = 0; i < al; i++) {\n"
"        ulong ai = a[i], bi = b[i];\n"
"        ulong d = ai - bi;\n"
"        ulong b1 = (ai < bi);\n"
"        ulong d2 = d - borrow;\n"
"        ulong b2 = (d < borrow);\n"
"        r[i] = d2;\n"
"        borrow = b1 + b2;\n"
"    }\n"
"}\n"
"\n"
"static inline void moddbl_n(__private ulong *a, const __private ulong *n, uint al)\n"
"{\n"
"    ulong carry = 0;\n"
"    for (uint i = 0; i < al; i++) {\n"
"        ulong v = a[i];\n"
"        a[i] = (v << 1) | carry;\n"
"        carry = v >> 63;\n"
"    }\n"
"    if (carry || gte_n(a, n, al))\n"
"        sub_n(a, a, n, al);\n"
"}\n"
"\n"
"static inline ulong compute_ninv(ulong n0)\n"
"{\n"
"    ulong x = 1;\n"
"    for (int i = 0; i < 6; i++)\n"
"        x *= (ulong)2 - n0 * x;\n"
"    return ~x + 1;\n"
"}\n"
"\n"
"static inline void compute_rmodn_n(__private ulong *r, const __private ulong *n, uint al)\n"
"{\n"
"    for (uint i = 0; i < al; i++) r[i] = 0;\n"
"    r[0] = 1;\n"
"    for (uint i = 0; i < 64u * al; i++)\n"
"        moddbl_n(r, n, al);\n"
"}\n"
"\n"
"static inline void montmul_n(__private ulong *r,\n"
"                             const __private ulong *a,\n"
"                             const __private ulong *b,\n"
"                             const __private ulong *n,\n"
"                             ulong ninv, uint al)\n"
"{\n"
"    ulong t[NL + 2];\n"
"    for (uint i = 0; i < al + 2; i++) t[i] = 0;\n"
"\n"
"    for (uint i = 0; i < al; i++) {\n"
"        ulong c = 0;\n"
"        for (uint j = 0; j < al; j++)\n"
"            c = mac(&t[j], a[i], b[j], c);\n"
"        ulong old = t[al];\n"
"        t[al] += c;\n"
"        t[al + 1] += (t[al] < old);\n"
"\n"
"        ulong m = t[0] * ninv;\n"
"        c = 0;\n"
"        for (uint j = 0; j < al; j++)\n"
"            c = mac(&t[j], m, n[j], c);\n"
"        old = t[al];\n"
"        t[al] += c;\n"
"        t[al + 1] += (t[al] < old);\n"
"\n"
"        for (uint j = 0; j < al + 1; j++)\n"
"            t[j] = t[j + 1];\n"
"        t[al + 1] = 0;\n"
"    }\n"
"\n"
"    if (t[al] || gte_n(t, n, al))\n"
"        sub_n(r, t, n, al);\n"
"    else\n"
"        for (uint i = 0; i < al; i++) r[i] = t[i];\n"
"}\n"
"\n"
"#define DEFINE_FERMAT_KERNEL(KNAME, AL) \\\n"
"__kernel void KNAME(__global const ulong *cands, __global uchar *results, uint count) { \\\n"
"    uint idx = get_global_id(0); \\\n"
"    if (idx >= count) return; \\\n"
"    const uint al = (AL); \\\n"
"    __private ulong n[NL]; \\\n"
"    __private ulong one_m[NL]; \\\n"
"    __private ulong base_m[NL]; \\\n"
"    __private ulong e[NL]; \\\n"
"    __private ulong res[NL]; \\\n"
"    __private ulong one[NL]; \\\n"
"    uint base = idx * NL; \\\n"
"    if ((base & 3u) == 0u) { \\\n"
"        uint i = 0; \\\n"
"        for (; i + 4u <= al; i += 4u) { \\\n"
"            ulong4 v4 = vload4(0, cands + base + i); \\\n"
"            n[i + 0u] = v4.s0; n[i + 1u] = v4.s1; \\\n"
"            n[i + 2u] = v4.s2; n[i + 3u] = v4.s3; \\\n"
"        } \\\n"
"        if (i + 2u <= al) { \\\n"
"            ulong2 v2 = vload2(0, cands + base + i); \\\n"
"            n[i + 0u] = v2.s0; n[i + 1u] = v2.s1; \\\n"
"            i += 2u; \\\n"
"        } \\\n"
"        for (; i < al; i++) n[i] = cands[base + i]; \\\n"
"    } else { \\\n"
"        for (uint i = 0; i < al; i++) n[i] = cands[base + i]; \\\n"
"    } \\\n"
"    if ((n[0] & 1ul) == 0ul) { results[idx] = (uchar)0; return; } \\\n"
"    ulong ninv = compute_ninv(n[0]); \\\n"
"    compute_rmodn_n(one_m, n, al); \\\n"
"    for (uint i = 0; i < al; i++) base_m[i] = one_m[i]; \\\n"
"    moddbl_n(base_m, n, al); \\\n"
"    for (uint i = 0; i < al; i++) e[i] = n[i]; \\\n"
"    e[0] -= 1; \\\n"
"    int top = (int)al - 1; \\\n"
"    while (top > 0 && e[top] == 0ul) top--; \\\n"
"    int msb = 63 - clz((ulong)e[top]); \\\n"
"    for (uint i = 0; i < al; i++) res[i] = base_m[i]; \\\n"
"    for (int limb = top; limb >= 0; limb--) { \\\n"
"        int start = (limb == top) ? (msb - 1) : 63; \\\n"
"        for (int bit = start; bit >= 0; bit--) { \\\n"
"            montmul_n(res, res, res, n, ninv, al); \\\n"
"            if ((e[limb] >> bit) & 1ul) montmul_n(res, res, base_m, n, ninv, al); \\\n"
"        } \\\n"
"    } \\\n"
"    for (uint i = 0; i < al; i++) one[i] = 0ul; \\\n"
"    one[0] = 1ul; \\\n"
"    montmul_n(res, res, one, n, ninv, al); \\\n"
"    int ok = (res[0] == 1ul); \\\n"
"    for (uint i = 1; i < al; i++) ok &= (res[i] == 0ul); \\\n"
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
"DEFINE_FERMAT_KERNEL(fermat_kernel_nl, NL)\n"
"#undef DEFINE_FERMAT_KERNEL\n";

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

static __inline size_t local_size_for_al(int al)
{
    if (al <= 6) return 256;
    if (al <= 10) return 192;
    return 128;
}

static void destroy_partial(gpu_fermat_ctx *ctx)
{
    if (!ctx) return;
    for (int s = 0; s < 2; s++) {
        if (ctx->d_cands[s]) clReleaseMemObject(ctx->d_cands[s]);
        if (ctx->d_results[s]) clReleaseMemObject(ctx->d_results[s]);
        if (ctx->queue[s]) clReleaseCommandQueue(ctx->queue[s]);
        free(ctx->h_results[s]);
        if (ctx->slot_mu_inited[s]) {
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
    if (ctx->pending[slot] != 0) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    cl_int err;
    size_t cands_bytes = count * GPU_NLIMBS * sizeof(uint64_t);
    err = clEnqueueWriteBuffer(ctx->queue[slot], ctx->d_cands[slot], CL_FALSE,
                               0, cands_bytes, candidates, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    int al = __atomic_load_n(&ctx->active_limbs, __ATOMIC_RELAXED);
    if (al < 1) al = GPU_NLIMBS;
    if (al > GPU_NLIMBS) al = GPU_NLIMBS;
    int kidx = kernel_index_for_al(al);
    cl_kernel k = ctx->kernels[kidx] ? ctx->kernels[kidx] : ctx->kernels[KIDX_ALNL];
    cl_uint ncount = (cl_uint)count;

    err  = clSetKernelArg(k, 0, sizeof(cl_mem), &ctx->d_cands[slot]);
    err |= clSetKernelArg(k, 1, sizeof(cl_mem), &ctx->d_results[slot]);
    err |= clSetKernelArg(k, 2, sizeof(cl_uint), &ncount);
    if (err != CL_SUCCESS) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    size_t local = local_size_for_al(al);
    size_t max_wg = 0;
    if (clGetKernelWorkGroupInfo(k, ctx->device, CL_KERNEL_WORK_GROUP_SIZE,
                                 sizeof(max_wg), &max_wg, NULL) == CL_SUCCESS) {
        if (max_wg > 0 && local > max_wg) local = max_wg;
    }
    if (local < 1) local = 1;
    size_t global = ((count + local - 1) / local) * local;
    err = clEnqueueNDRangeKernel(ctx->queue[slot], k, 1,
                                 NULL, &global, &local, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    err = clEnqueueReadBuffer(ctx->queue[slot], ctx->d_results[slot], CL_FALSE,
                              0, count, ctx->h_results[slot], 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    ctx->pending[slot] = count;
    pthread_mutex_unlock(&ctx->slot_mu[slot]);
    return 0;
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

    cl_int err = clFinish(ctx->queue[slot]);
    if (err != CL_SUCCESS) {
        pthread_mutex_unlock(&ctx->slot_mu[slot]);
        return -1;
    }

    memcpy(results, ctx->h_results[slot], n);

    int primes = 0;
    for (size_t i = 0; i < n; i++)
        primes += results[i];

    ctx->pending[slot] = 0;
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

void gpu_fermat_destroy(gpu_fermat_ctx *ctx)
{
    if (!ctx) return;
    for (int s = 0; s < 2; s++) {
        if (ctx->queue[s]) clFinish(ctx->queue[s]);
    }
    destroy_partial(ctx);

    free(ctx);
}
