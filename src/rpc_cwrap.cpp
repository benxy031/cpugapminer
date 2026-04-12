#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <curl/curl.h>
#include "compat_win32.h"
#include <jansson.h>

extern "C" {
int rpc_submit(const char *url, const char *user, const char *pass, const char *method, const char *hex);
char *rpc_call(const char *url, const char *user, const char *pass, const char *method, const char *params_json);
char *rpc_getblocktemplate(const char *url, const char *user, const char *pass);
int rpc_getwork_data(const char *url, const char *user, const char *pass, char data_out[161], uint64_t *ndiff_out);
}

struct string_s { char *ptr; size_t len; };
static int init_string_s(struct string_s *s) {
    s->len = 0;
    s->ptr = (char*)malloc(1);
    if (!s->ptr) return 0;
    s->ptr[0] = '\0';
    return 1;
}
static size_t writefunc_s(void *ptr, size_t size, size_t nmemb, struct string_s *s) {
    size_t add = size * nmemb;
    if (add > SIZE_MAX - s->len - 1) return 0;
    size_t newlen = s->len + add;
    char *newptr = (char*)realloc(s->ptr, newlen + 1);
    if (!newptr) return 0;
    s->ptr = newptr;
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[newlen] = '\0';
    s->len = newlen;
    return add;
}

int rpc_submit(const char *url, const char *user, const char *pass, const char *method, const char *hex) {
    CURL *c = curl_easy_init();
    if (!c) return -1;
    struct curl_slist *h = NULL;
    h = curl_slist_append(h, "Content-Type: application/json");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_URL, url);
    if (user) curl_easy_setopt(c, CURLOPT_USERNAME, user);
    if (pass) curl_easy_setopt(c, CURLOPT_PASSWORD, pass);

    /* A stuck submitblock cannot be allowed to block the miner indefinitely */
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);

    /* allocate exactly enough room for JSON payload plus some margin */
    size_t needed = strlen(method) + strlen(hex) + 128;
    char *payload = (char*)malloc(needed);
    if (!payload) { curl_slist_free_all(h); curl_easy_cleanup(c); return -1; }
    snprintf(payload, needed, "{\"jsonrpc\":\"1.0\",\"id\":\"Cminer\",\"method\":\"%s\",\"params\":[\"%s\"]}", method, hex);

    /* save exact payload for forensic inspection */
    {
        char fname[256];
        int pid = (int)getpid();
        struct timeval tv; gettimeofday(&tv, NULL);
        snprintf(fname, sizeof(fname), "%sgap_miner_submit_%ld_%d.json", win_temp_dir(), (long)tv.tv_sec, pid);
        FILE *fp = fopen(fname, "wb");
        if (fp) {
            fwrite(payload, 1, strlen(payload), fp);
            fflush(fp); fclose(fp);
        }
    }

    curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload);
    struct string_s s;
    if (!init_string_s(&s)) {
        curl_slist_free_all(h);
        curl_easy_cleanup(c);
        free(payload);
        return -1;
    }
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, writefunc_s);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &s);
    CURLcode rc = curl_easy_perform(c);
    int ret = -1;
    if (rc == CURLE_OK) {
        /* Log raw response for diagnostics */
        fprintf(stderr, "[rpc_submit] raw response: %.*s\n",
                (int)(s.len < 512 ? s.len : 512), s.ptr);

        /* Properly parse JSON-RPC response and surface detailed errors. */
        json_error_t jerr;
        json_t *root = json_loads(s.ptr, 0, &jerr);
        if (!root) {
            fprintf(stderr, "Failed to parse JSON-RPC response: %s\n", jerr.text);
            ret = -1;
        } else {
            json_t *jerrobj = json_object_get(root, "error");
            if (!jerrobj || json_is_null(jerrobj)) {
                /* submitblock RPC convention (Bitcoin-derived coins):
                   result=null  → accepted
                   result=false → rejected (stale / already have it)
                   result="..." → rejected with reason string
                   result=true  → unusual, treat as accepted            */
                json_t *jres = json_object_get(root, "result");
                if (!jres || json_is_null(jres) || json_is_true(jres)) {
                    printf(">>> submitblock: ACCEPTED (result=null)\n");
                    ret = 0;
                } else if (json_is_false(jres)) {
                    fprintf(stderr, ">>> submitblock: REJECTED (result=false) — stale or already known\n");
                    ret = 1;  /* definitive rejection — caller should abort current pass, no retry */
                } else if (json_is_string(jres)) {
                    fprintf(stderr, ">>> submitblock: REJECTED (reason=\"%s\")\n", json_string_value(jres));
                    ret = 1;  /* definitive rejection */
                } else {
                    char *resdump = json_dumps(jres, JSON_COMPACT);
                    fprintf(stderr, ">>> submitblock: REJECTED (result=%s)\n", resdump ? resdump : "?");
                    free(resdump);
                    ret = 1;  /* definitive rejection */
                }
            } else {
                /* extract code/message where available */
                json_t *jcode = json_object_get(jerrobj, "code");
                json_t *jmsg = json_object_get(jerrobj, "message");
                int code = json_is_integer(jcode) ? (int)json_integer_value(jcode) : 0;
                const char *msg = json_is_string(jmsg) ? json_string_value(jmsg) : "(no message)";
                fprintf(stderr, "RPC returned error (code=%d): %s\n", code, msg);
                /* also dump the error object for diagnostics */
                char *errdump = json_dumps(jerrobj, JSON_COMPACT);
                if (errdump) {
                    fprintf(stderr, "RPC error object: %s\n", errdump);
                    free(errdump);
                }
                ret = -1;
            }
            json_decref(root);
        }
    } else {
        fprintf(stderr, "RPC request failed: %s\n", curl_easy_strerror(rc));
        ret = -1;
    }
    free(s.ptr);
    curl_slist_free_all(h);
    curl_easy_cleanup(c);
    free(payload);
    return ret;
}

char *rpc_call(const char *url, const char *user, const char *pass, const char *method, const char *params_json) {
    CURL *c = curl_easy_init();
    if (!c) return NULL;
    struct curl_slist *h = NULL;
    h = curl_slist_append(h, "Content-Type: application/json");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);        /* give up after 10s */
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);  /* connect timeout 5s */
    if (user) curl_easy_setopt(c, CURLOPT_USERNAME, user);
    if (pass) curl_easy_setopt(c, CURLOPT_PASSWORD, pass);
    char payload[8192];
    if (params_json) snprintf(payload, sizeof(payload), "{\"jsonrpc\":\"1.0\",\"id\":\"Cminer\",\"method\":\"%s\",\"params\":%s}", method, params_json);
    else snprintf(payload, sizeof(payload), "{\"jsonrpc\":\"1.0\",\"id\":\"Cminer\",\"method\":\"%s\",\"params\":[]}", method);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload);
    struct string_s s;
    if (!init_string_s(&s)) {
        curl_slist_free_all(h);
        curl_easy_cleanup(c);
        return NULL;
    }
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, writefunc_s);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &s);
    CURLcode rc = curl_easy_perform(c);
    curl_slist_free_all(h);
    curl_easy_cleanup(c);
    if (rc != CURLE_OK) { free(s.ptr); return NULL; }
    return s.ptr; // caller must free
}

char *rpc_getblocktemplate(const char *url, const char *user, const char *pass) {
    char *res = rpc_call(url, user, pass, "getblocktemplate", "{}");
    if (res) {
        /* parse previousblockhash via JSON parser and report header received.
           This is more robust than string searching and avoids false positives. */
        static char last_prev[65] = "";
        json_error_t jerr;
        json_t *root = json_loads(res, 0, &jerr);
        if (!root) {
            fprintf(stderr, "Failed to parse getblocktemplate response: %s\n", jerr.text);
        } else {
            json_t *prev = json_object_get(root, "previousblockhash");
            if (prev && json_is_string(prev)) {
                const char *current = json_string_value(prev);
                if (current && current[0]) {
                    printf("work header %s\n", current);
                    if (strcmp(current, last_prev) != 0) {
                        printf("(different from previous)\n");
                        strncpy(last_prev, current, sizeof(last_prev)-1);
                        last_prev[sizeof(last_prev)-1] = '\0';
                    }
                }
            }
            json_decref(root);
        }
    }
    return res;
}

/* rpc_getwork_data: call getwork (no params), parse the 80-byte header hex
   and nDifficulty integer into the caller's buffers.
   data_out must be at least 161 bytes (160 hex + NUL).
   Returns 1 on success, 0 on any failure. */
int rpc_getwork_data(const char *url, const char *user, const char *pass,
                     char data_out[161], uint64_t *ndiff_out) {
    char *res = rpc_call(url, user, pass, "getwork", NULL);
    if (!res) return 0;
    int ok = 0;
    json_error_t jerr;
    json_t *root = json_loads(res, 0, &jerr);
    if (root) {
        json_t *result = json_object_get(root, "result");
        if (result && json_is_object(result)) {
            json_t *jdata = json_object_get(result, "data");
            json_t *jdiff = json_object_get(result, "difficulty");
            if (jdata && json_is_string(jdata) && jdiff && json_is_number(jdiff)) {
                const char *ds = json_string_value(jdata);
                size_t dlen = strlen(ds);
                fprintf(stderr, "[getwork] data field: %zu hex chars (%zu bytes)\n",
                        dlen, dlen / 2);
                /* Log first 40 and last 40 hex chars for diagnostics */
                if (dlen > 80)
                    fprintf(stderr, "[getwork] data: %.40s...%s\n",
                            ds, ds + dlen - 40);
                else
                    fprintf(stderr, "[getwork] data: %s\n", ds);
                if (dlen >= 160) {
                    strncpy(data_out, ds, 160);
                    data_out[160] = '\0';
                    *ndiff_out = json_is_integer(jdiff)
                        ? (uint64_t)json_integer_value(jdiff)
                        : (uint64_t)json_number_value(jdiff);
                    ok = 1;
                }
            }
        }
        json_decref(root);
    }
    free(res);
    return ok;
}
