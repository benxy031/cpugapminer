/*
 * Gapcoin stratum protocol client
 *
 * Protocol (JSON-RPC over persistent TCP, newline-delimited):
 *
 *   Client → Server:
 *     Getwork:  {"id":N,"method":"mining.request","params":["user","pass"]}\n
 *     Submit:   {"id":N,"method":"mining.submit","params":["user","pass","hex"]}\n
 *
 *   Server → Client:
 *     Getwork response: {"id":N,"result":{"data":"hex160","difficulty":N},...}\n
 *     Block notify:     {"id":null,"method":"blockchain.block.new",
 *                         "params":{"data":"hex160","difficulty":N}}\n
 *     Share response:   {"id":N,"result":true/false,...}\n
 *
 *   The "data" field is the same 80-byte (160-hex-char) header as getwork RPC.
 *   "difficulty" is nDifficulty (fixed-point, merit = nDifficulty / 2^48).
 */
#ifndef STRATUM_H
#define STRATUM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle */
typedef struct stratum_ctx stratum_ctx;

/* Create a stratum context and connect to pool.
   Returns NULL on failure.  The context runs a background recv thread. */
stratum_ctx *stratum_connect(const char *host, const char *port,
                             const char *user, const char *pass,
                             uint16_t shift);

/* Request work from the pool (blocking until first work arrives).
   Populates data_hex (160 chars + NUL) and *ndiff.
   Returns 1 on success, 0 on failure/disconnect. */
int stratum_get_work(stratum_ctx *ctx, char data_hex[161], uint64_t *ndiff);

/* Poll for new work (non-blocking).
   Returns 1 if new work is available (and fills data_hex/ndiff),
   0 if no new work since last call. */
int stratum_poll_new_work(stratum_ctx *ctx, char data_hex[161], uint64_t *ndiff);

/* Submit a share (assembled block hex).  Non-blocking: queues internally.
   Returns 1 on success (queued), 0 on failure. */
int stratum_submit(stratum_ctx *ctx, const char *block_hex);

/* Get the network nDifficulty extracted from the block header (bytes 72-79).
   This is the difficulty required for a valid block (may differ from the
   pool's share target returned by get_work/poll_new_work). */
uint64_t stratum_get_net_ndiff(stratum_ctx *ctx);

/* Get cumulative accepted/rejected share counts. */
void stratum_get_stats(stratum_ctx *ctx, uint64_t *accepted, uint64_t *rejected);

/* Disconnect and free resources. */
void stratum_disconnect(stratum_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_H */
