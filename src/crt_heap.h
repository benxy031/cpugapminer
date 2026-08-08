/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef CRT_HEAP_H
#define CRT_HEAP_H

#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <gmp.h>

#define CRT_HEAP_CAP 4096   /* default; override with crt_heap_init() */

extern size_t crt_heap_cap;   /* effective capacity (set by crt_heap_init) */

struct crt_work_item {
    mpz_t    base;
    mpz_t    nAdd;
    uint64_t *survivors;
    size_t   surv_cnt;
    double   cramer_score;  /* Cramér-model prob of qualifying gap (higher = better) */
    uint32_t nonce;
    int      cand_odd;
    double   logbase;
    uint64_t generation;
    uint64_t seq;      /* monotonic push order, used for FIFO eviction when full */
    uint8_t  hdr80[80];
    uint16_t nshift;
};

extern volatile uint64_t crt_heap_gen;
extern volatile int crt_fermat_threads;
extern int crt_fermat_explicit;
extern _Atomic int crt_heap_shutdown;

/* crt_heap_pop() selection policy: 0=score (max-heap on heap_key()),
 * 1=fifo (oldest seq first), 2=random (runtime default, see README.md).
 * Only affects which queued window a consumer takes next; push()/eviction
 * behavior is unchanged. See --crt-heap-pop-order in README.md. */
#define CRT_HEAP_POP_SCORE  0
#define CRT_HEAP_POP_FIFO   1
#define CRT_HEAP_POP_RANDOM 2
extern int crt_heap_pop_order;

void crt_heap_init(size_t cap);   /* call once before mining; 0 = use default */
struct crt_work_item *crt_work_alloc(void);
void crt_work_free(struct crt_work_item *w);
int crt_heap_push(struct crt_work_item *w);
struct crt_work_item *crt_heap_pop(void);
void crt_heap_flush(void);
size_t crt_heap_count(void);

/* Control helpers to avoid touching queue internals from callers. */
void crt_heap_signal_shutdown(void);
void crt_heap_clear_shutdown(void);
void crt_heap_next_generation(void);

/* Advisory: if heap is full, return surv_cnt of worst leaf; else 0.
   Use as a pre-check before crt_work_alloc() to avoid wasted allocation
   when the new window would be immediately dropped. */
size_t crt_heap_worst_surv_advisory(void);

/* Deprecated no-op kept for API compatibility: always returns -1.0.
 * The heap previously used cramer_score as an admission gate (reject a new
 * window outright if it could not beat the worst-scoring leaf once full).
 * Measurement (see cpugapminer-findings.md) showed cramer_score has ~0
 * correlation with actual realized gap outcome, so that gate did nothing
 * but starve an increasing fraction of candidates over a run's lifetime
 * (the admission bar ratchets toward the historical max score as more
 * windows are sampled). The heap now evicts the OLDEST item (FIFO) when
 * full instead, so pushes always succeed and no scoring bias is applied. */
double crt_heap_worst_score_advisory(void);

#endif /* CRT_HEAP_H */
