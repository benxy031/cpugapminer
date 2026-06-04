/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include <stdatomic.h>

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#define CPU_FEATURES_X86 1
#else
#define CPU_FEATURES_X86 0
#endif

#if CPU_FEATURES_X86 && (defined(__GNUC__) || defined(__clang__))
#define CPU_TARGET_AVX2 __attribute__((target("avx2")))
#else
#define CPU_TARGET_AVX2
#endif

static inline int cpu_features_has_avx2(void)
{
#if CPU_FEATURES_X86 && (defined(__GNUC__) || defined(__clang__))
    static _Atomic int cached = -1;
    int v = atomic_load_explicit(&cached, memory_order_acquire);
    if (v >= 0)
        return v;

    __builtin_cpu_init();
    v = __builtin_cpu_supports("avx2") ? 1 : 0;
    atomic_store_explicit(&cached, v, memory_order_release);
    return v;
#else
    return 0;
#endif
}

static inline int cpu_features_has_sse2(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    return 1;
#elif CPU_FEATURES_X86 && (defined(__GNUC__) || defined(__clang__))
    static _Atomic int cached = -1;
    int v = atomic_load_explicit(&cached, memory_order_acquire);
    if (v >= 0)
        return v;

    __builtin_cpu_init();
    v = __builtin_cpu_supports("sse2") ? 1 : 0;
    atomic_store_explicit(&cached, v, memory_order_release);
    return v;
#else
    return 0;
#endif
}
