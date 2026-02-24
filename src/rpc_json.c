#include "rpc_json.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>

int rpc_parse_error(const char *json, int *out_code, char **out_msg) {
    if (!json) return -1;
    json_error_t jerr;
    json_t *root = json_loads(json, 0, &jerr);
    if (!root) return -1;
    json_t *err = json_object_get(root, "error");
    if (!err || json_is_null(err)) {
        json_decref(root);
        return 0;
    }
    if (out_code) {
        json_t *jcode = json_object_get(err, "code");
        if (jcode && json_is_integer(jcode)) *out_code = (int)json_integer_value(jcode);
        else *out_code = 0;
    }
    if (out_msg) {
        json_t *jmsg = json_object_get(err, "message");
        if (jmsg && json_is_string(jmsg)) {
            const char *s = json_string_value(jmsg);
            size_t n = s ? strlen(s) : 0;
            *out_msg = (char*)malloc(n+1);
            if (*out_msg) { if (n) memcpy(*out_msg, s, n); (*out_msg)[n] = '\0'; }
        } else {
            *out_msg = (char*)malloc(1);
            if (*out_msg) (*out_msg)[0] = '\0';
        }
    }
    json_decref(root);
    return 1;
}

int rpc_extract_prev_hash(const char *json, char *out, size_t outlen) {
    if (!json || !out || outlen == 0) return -1;
    json_error_t jerr;
    json_t *root = json_loads(json, 0, &jerr);
    if (!root) return -1;
    json_t *prev = json_object_get(root, "previousblockhash");
    if (!prev || !json_is_string(prev)) {
        json_decref(root);
        return 0;
    }
    const char *s = json_string_value(prev);
    if (!s) { json_decref(root); return 0; }
    strncpy(out, s, outlen-1);
    out[outlen-1] = '\0';
    json_decref(root);
    return 1;
}
