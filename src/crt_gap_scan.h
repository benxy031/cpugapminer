#ifndef CRT_GAP_SCAN_H
#define CRT_GAP_SCAN_H

#include <stdint.h>

#define CRT_GAP_SCAN_FIXED     0
#define CRT_GAP_SCAN_ORIGINAL  1
#define CRT_GAP_SCAN_ORIG_FLOOR 2

#define CRT_GAP_SCAN_FLOOR_DEFAULT 10000ULL

/* Human-readable mode label for logs. */
const char *crt_gap_scan_mode_name(int mode);

/* Parse CLI mode name: fixed|original (aliases: orig,dynamic). */
int crt_gap_scan_mode_parse(const char *mode, int *out_mode);

/* Fixed cpugapminer policy: max(2*gap_target, 10000). */
uint64_t crt_gap_scan_fixed_window(uint64_t gap_target);

/* Startup/template window sizing for selected mode. */
uint64_t crt_gap_scan_template_window(uint64_t gap_target,
                          int mode,
                          uint64_t floor_value);

/* Per-nonce runtime window sizing for selected mode. */
uint64_t crt_gap_scan_for_nonce(double target_merit,
                                double logbase,
                                uint64_t gap_target,
                      int mode,
                      uint64_t floor_value);

#endif /* CRT_GAP_SCAN_H */
