#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "crt_heap.h"

#include <pthread.h>
#include <stdlib.h>
#include <time.h>

static struct crt_work_item **crt_heap = NULL;
static size_t crt_heap_size = 0;
size_t crt_heap_cap = CRT_HEAP_CAP;
static pthread_mutex_t crt_heap_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t crt_heap_cv = PTHREAD_COND_INITIALIZER;

volatile uint64_t crt_heap_gen = 0;
volatile int crt_fermat_threads = 0;
int crt_fermat_explicit = 0;
_Atomic int crt_heap_shutdown = 0;

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

static void crt_heap_sift_up(size_t i) {
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (crt_heap[parent]->surv_cnt <= crt_heap[i]->surv_cnt) break;
        struct crt_work_item *tmp = crt_heap[parent];
        crt_heap[parent] = crt_heap[i];
        crt_heap[i] = tmp;
        i = parent;
    }
}

static void crt_heap_sift_down(size_t i, size_t n) {
    while (1) {
        size_t smallest = i;
        size_t left = 2 * i + 1, right = 2 * i + 2;
        if (left < n && crt_heap[left]->surv_cnt < crt_heap[smallest]->surv_cnt)
            smallest = left;
        if (right < n && crt_heap[right]->surv_cnt < crt_heap[smallest]->surv_cnt)
            smallest = right;
        if (smallest == i) break;
        struct crt_work_item *tmp = crt_heap[smallest];
        crt_heap[smallest] = crt_heap[i];
        crt_heap[i] = tmp;
        i = smallest;
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
        pthread_cond_signal(&crt_heap_cv);
        pthread_mutex_unlock(&crt_heap_mtx);
        return 1;
    }

    size_t first_leaf = crt_heap_size / 2;
    size_t max_idx = first_leaf;
    for (size_t i = first_leaf + 1; i < crt_heap_size; i++) {
        if (crt_heap[i]->surv_cnt > crt_heap[max_idx]->surv_cnt)
            max_idx = i;
    }
    if (w->surv_cnt < crt_heap[max_idx]->surv_cnt) {
        crt_work_free(crt_heap[max_idx]);
        crt_heap[max_idx] = w;
        crt_heap_sift_up(max_idx);
        crt_heap_sift_down(max_idx, crt_heap_size);
        pthread_cond_signal(&crt_heap_cv);
        pthread_mutex_unlock(&crt_heap_mtx);
        return 1;
    }

    pthread_mutex_unlock(&crt_heap_mtx);
    crt_work_free(w);
    return 0;
}

struct crt_work_item *crt_heap_pop(void) {
    pthread_mutex_lock(&crt_heap_mtx);
    while (crt_heap_size == 0 && !crt_heap_shutdown) {
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
        pthread_mutex_unlock(&crt_heap_mtx);
        return NULL;
    }

    struct crt_work_item *best = crt_heap[0];
    crt_heap_size--;
    if (crt_heap_size > 0) {
        crt_heap[0] = crt_heap[crt_heap_size];
        crt_heap_sift_down(0, crt_heap_size);
    }
    pthread_mutex_unlock(&crt_heap_mtx);
    return best;
}

void crt_heap_flush(void) {
    pthread_mutex_lock(&crt_heap_mtx);
    for (size_t i = 0; i < crt_heap_size; i++)
        crt_work_free(crt_heap[i]);
    crt_heap_size = 0;
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
