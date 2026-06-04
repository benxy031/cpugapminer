/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "crt_heap.h"
#include "stats.h"

#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>

/* Heap priority: normalise Cramér score by sqrt(surv_cnt) so that windows
 * with fewer survivors (cheaper Fermat cost) are preferred when they have
 * comparable gap probability.  Consumer always pops the highest-key item. */
static inline double heap_key(const struct crt_work_item *w) {
    double d = (double)(w->surv_cnt + 1);
    return w->cramer_score / sqrt(d);
}

static struct crt_work_item **crt_heap = NULL;
static size_t crt_heap_size = 0;
size_t crt_heap_cap = CRT_HEAP_CAP;
static pthread_mutex_t crt_heap_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crt_heap_cv = PTHREAD_COND_INITIALIZER;

/* Cached worst (minimum) heap_key() among heap leaves.
 * Updated under crt_heap_mtx; read lock-free via atomic load.
 * Stays -1.0 when the heap has room or is empty. */
static _Atomic double g_crt_heap_worst_score_cache;

volatile uint64_t crt_heap_gen = 0;
volatile int crt_fermat_threads = 0;
int crt_fermat_explicit = 0;
_Atomic int crt_heap_shutdown = 0;

/* Recompute and cache the worst leaf score.  Must be called with
 * crt_heap_mtx held.  Sets the cache to -1.0 when the heap has room
 * or is empty so advisory callers know they should attempt a push. */
static void crt_heap_refresh_worst_cache_locked(void) {
    if (!crt_heap || crt_heap_size < crt_heap_cap || crt_heap_size == 0) {
        atomic_store(&g_crt_heap_worst_score_cache, -1.0);
        return;
    }
    size_t first_leaf = crt_heap_size / 2;
    double min_sc = heap_key(crt_heap[first_leaf]);
    for (size_t i = first_leaf + 1; i < crt_heap_size; i++) {
        double k = heap_key(crt_heap[i]);
        if (k < min_sc) min_sc = k;
    }
    atomic_store(&g_crt_heap_worst_score_cache, min_sc);
}

void crt_heap_init(size_t cap) {
    pthread_mutex_lock(&crt_heap_mtx);
    if (cap == 0) cap = CRT_HEAP_CAP;
    if (crt_heap) {
        /* already allocated — flush and resize */
        for (size_t i = 0; i < crt_heap_size; i++)
            crt_work_free(crt_heap[i]);
        crt_heap_size = 0;
        free(crt_heap);
    }
    crt_heap_cap = cap;
    crt_heap = (struct crt_work_item **)calloc(crt_heap_cap,
                                               sizeof(struct crt_work_item *));
    atomic_store(&g_crt_heap_worst_score_cache, -1.0);
    pthread_mutex_unlock(&crt_heap_mtx);
}

struct crt_work_item *crt_work_alloc(void) {
    struct crt_work_item *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    mpz_init2(w->base, 1024);
    mpz_init2(w->nAdd, 1024);
    return w;
}

void crt_work_free(struct crt_work_item *w) {
    if (!w) return;
    mpz_clear(w->base);
    mpz_clear(w->nAdd);
    free(w->survivors);
    free(w);
}

/* Max-heap on heap_key(): root holds the item with the highest priority
 * (best cramer_score per unit sqrt(surv_cnt) — cheapest+best first). */
static void crt_heap_sift_up(size_t i) {
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (heap_key(crt_heap[parent]) >= heap_key(crt_heap[i])) break;
        struct crt_work_item *tmp = crt_heap[parent];
        crt_heap[parent] = crt_heap[i];
        crt_heap[i] = tmp;
        i = parent;
    }
}

static void crt_heap_sift_down(size_t i, size_t n) {
    while (1) {
        size_t largest = i;
        size_t left = 2 * i + 1, right = 2 * i + 2;
        if (left < n && heap_key(crt_heap[left]) > heap_key(crt_heap[largest]))
            largest = left;
        if (right < n && heap_key(crt_heap[right]) > heap_key(crt_heap[largest]))
            largest = right;
        if (largest == i) break;
        struct crt_work_item *tmp = crt_heap[largest];
        crt_heap[largest] = crt_heap[i];
        crt_heap[i] = tmp;
        i = largest;
    }
}

int crt_heap_push(struct crt_work_item *w) {
    pthread_mutex_lock(&crt_heap_mtx);
    /* lazy init in case crt_heap_init() was never called */
    if (!crt_heap) {
        crt_heap = (struct crt_work_item **)calloc(crt_heap_cap,
                                                   sizeof(struct crt_work_item *));
        if (!crt_heap) { pthread_mutex_unlock(&crt_heap_mtx); crt_work_free(w); return 0; }
    }
    if (crt_heap_size < crt_heap_cap) {
        crt_heap[crt_heap_size] = w;
        crt_heap_sift_up(crt_heap_size);
        crt_heap_size++;
        if (crt_heap_size > stats_crt_heap_hwm)
            stats_crt_heap_hwm = crt_heap_size;
        crt_heap_refresh_worst_cache_locked();
        __sync_fetch_and_add(&stats_crt_heap_push_ok, 1);
        pthread_cond_signal(&crt_heap_cv);
        pthread_mutex_unlock(&crt_heap_mtx);
        return 1;
    }

    /* Max-heap: evict the leaf with the lowest heap_key() (worst window). */
    size_t first_leaf = crt_heap_size / 2;
    size_t min_idx = first_leaf;
    for (size_t i = first_leaf + 1; i < crt_heap_size; i++) {
        if (heap_key(crt_heap[i]) < heap_key(crt_heap[min_idx]))
            min_idx = i;
    }
    if (heap_key(w) > heap_key(crt_heap[min_idx])) {
        crt_work_free(crt_heap[min_idx]);
        crt_heap[min_idx] = w;
        crt_heap_sift_up(min_idx);
        crt_heap_sift_down(min_idx, crt_heap_size);
        crt_heap_refresh_worst_cache_locked();
        __sync_fetch_and_add(&stats_crt_heap_push_replace, 1);
        pthread_cond_signal(&crt_heap_cv);
        pthread_mutex_unlock(&crt_heap_mtx);
        return 1;
    }

    pthread_mutex_unlock(&crt_heap_mtx);
    __sync_fetch_and_add(&stats_crt_heap_push_drop, 1);
    crt_work_free(w);
    return 0;
}

struct crt_work_item *crt_heap_pop(void) {
    pthread_mutex_lock(&crt_heap_mtx);
    while (crt_heap_size == 0 && !crt_heap_shutdown) {
        __sync_fetch_and_add(&stats_crt_heap_waits, 1);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&crt_heap_cv, &crt_heap_mtx, &ts);
    }
    if (crt_heap_size == 0 || crt_heap_shutdown) {
        __sync_fetch_and_add(&stats_crt_heap_pop_empty, 1);
        pthread_mutex_unlock(&crt_heap_mtx);
        return NULL;
    }

    struct crt_work_item *best = crt_heap[0];
    crt_heap_size--;
    if (crt_heap_size > 0) {
        crt_heap[0] = crt_heap[crt_heap_size];
        crt_heap_sift_down(0, crt_heap_size);
    }
    crt_heap_refresh_worst_cache_locked();
    __sync_fetch_and_add(&stats_crt_heap_pop_ok, 1);
    pthread_mutex_unlock(&crt_heap_mtx);
    return best;
}

void crt_heap_flush(void) {
    pthread_mutex_lock(&crt_heap_mtx);
    for (size_t i = 0; i < crt_heap_size; i++)
        crt_work_free(crt_heap[i]);
    crt_heap_size = 0;
    atomic_store(&g_crt_heap_worst_score_cache, -1.0);
    pthread_cond_broadcast(&crt_heap_cv);
    pthread_mutex_unlock(&crt_heap_mtx);
}

size_t crt_heap_count(void) {
    size_t n;
    pthread_mutex_lock(&crt_heap_mtx);
    n = crt_heap_size;
    pthread_mutex_unlock(&crt_heap_mtx);
    return n;
}

void crt_heap_signal_shutdown(void) {
    crt_heap_shutdown = 1;
    pthread_mutex_lock(&crt_heap_mtx);
    pthread_cond_broadcast(&crt_heap_cv);
    pthread_mutex_unlock(&crt_heap_mtx);
}

void crt_heap_clear_shutdown(void) {
    crt_heap_shutdown = 0;
}

void crt_heap_next_generation(void) {
    __sync_fetch_and_add(&crt_heap_gen, 1);
}

/* Advisory: when the heap is full, return the surv_cnt of the worst leaf.
   Returns 0 if the heap has room or is empty. */
size_t crt_heap_worst_surv_advisory(void) {
    pthread_mutex_lock(&crt_heap_mtx);
    if (!crt_heap || crt_heap_size < crt_heap_cap || crt_heap_size == 0) {
        pthread_mutex_unlock(&crt_heap_mtx);
        return 0;
    }
    size_t first_leaf = crt_heap_size / 2;
    size_t max_sc = crt_heap[first_leaf]->surv_cnt;
    for (size_t i = first_leaf + 1; i < crt_heap_size; i++)
        if (crt_heap[i]->surv_cnt > max_sc)
            max_sc = crt_heap[i]->surv_cnt;
    pthread_mutex_unlock(&crt_heap_mtx);
    return max_sc;
}

/* Advisory: return the cached worst (lowest) cramer_score among heap leaves.
   Lock-free O(1) read.  Returns -1.0 when the heap has room or is empty,
   indicating the caller should attempt a push without pre-filtering. */
double crt_heap_worst_score_advisory(void) {
    return atomic_load(&g_crt_heap_worst_score_cache);
}
