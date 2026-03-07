#ifndef PRESIEVE_UTILS_H
#define PRESIEVE_UTILS_H

#include <stdint.h>
#include <stddef.h>

struct presieve_buf {
    uint64_t *pr;
    size_t    cap;
    size_t    cnt;
    uint64_t  L;
    uint64_t  R;
};

int presieve_buf_ensure(struct presieve_buf *b, size_t need);
int presieve_window(int64_t widx, uint64_t base,
                    uint64_t sieve_size, uint64_t adder_max,
                    uint64_t *out_L, uint64_t *out_R);

#endif /* PRESIEVE_UTILS_H */
