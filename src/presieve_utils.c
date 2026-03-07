#include "presieve_utils.h"

#include <stdlib.h>

int presieve_buf_ensure(struct presieve_buf *b, size_t need) {
    if (b->cap >= need) return 0;
    size_t nc = need + (need >> 1) + 64;
    uint64_t *tmp = realloc(b->pr, nc * sizeof(uint64_t));
    if (!tmp) return -1;
    b->pr = tmp;
    b->cap = nc;
    return 0;
}

int presieve_window(int64_t widx, uint64_t base,
                    uint64_t sieve_size, uint64_t adder_max,
                    uint64_t *out_L, uint64_t *out_R) {
    uint64_t L = base + (uint64_t)widx * sieve_size;
    if ((L & 1) == 0) L++;
    uint64_t R = L + sieve_size;
    uint64_t cap = base + adder_max;
    if (R > cap) R = cap;
    if (R <= L) return 0;
    *out_L = L;
    *out_R = R;
    return 1;
}
