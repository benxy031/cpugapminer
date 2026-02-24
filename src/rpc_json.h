#ifndef RPC_JSON_H
#define RPC_JSON_H

#include <stddef.h>

/* Parse JSON-RPC response and detect an error.
 * Returns:  1 if an RPC error object was present (out_code/out_msg set if non-NULL),
 *           0 if no error ("error": null or absent),
 *          -1 on parse error.
 * If out_msg is non-NULL the caller must free(*out_msg) when finished.
 */
int rpc_parse_error(const char *json, int *out_code, char **out_msg);

/* Extract previousblockhash from getblocktemplate JSON.
 * Returns: 1 if found and written to out (NUL-terminated),
 *          0 if not found,
 *         -1 on parse error.
 */
int rpc_extract_prev_hash(const char *json, char *out, size_t outlen);

#endif /* RPC_JSON_H */
