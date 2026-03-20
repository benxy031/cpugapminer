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
    uint32_t nonce;
    int      cand_odd;
    double   logbase;
    uint64_t generation;
    uint8_t  hdr80[80];
    uint16_t nshift;
};

extern volatile uint64_t crt_heap_gen;
extern volatile int crt_fermat_threads;
extern int crt_fermat_explicit;
extern _Atomic int crt_heap_shutdown;

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

#endif /* CRT_HEAP_H */
