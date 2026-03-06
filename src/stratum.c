/*
 * Gapcoin stratum protocol client (pure C, POSIX)
 *
 * See stratum.h for protocol documentation.
 *
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "stratum.h"
#include "compat_win32.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <pthread.h>
#include <jansson.h>

/* ──────────────── constants ──────────────── */
#define RECONNECT_DELAY_S   15
#define RECV_BUF_INIT      4096
#define SEND_BUF_MAX      32768

/* ──────────────── context ──────────────── */
struct stratum_ctx {
    /* connection */
    sock_t           sock;
    char             host[256];
    char             port[16];
    char             user[128];
    char             pass[128];
    uint16_t         shift;
    volatile int     connected;
    volatile int     running;

    /* message counter (for JSON-RPC id) */
    int              msg_id;
    pthread_mutex_t  send_lock;

    /* Ring of pending submit IDs so we can distinguish share responses
       from getwork responses even with multiple in-flight submits. */
#define SUBMIT_ID_RING 32
    int              submit_ids[SUBMIT_ID_RING];
    int              submit_id_count;

    /* latest work (protected by work_lock) */
    pthread_mutex_t  work_lock;
    pthread_cond_t   work_cond;
    char             work_data[161];   /* 160 hex + NUL */
    uint64_t         work_ndiff;
    int              work_ready;       /* 1 = initial work received */
    int              work_new;         /* 1 = new work since last poll */

    /* share stats */
    volatile uint64_t shares_accepted;
    volatile uint64_t shares_rejected;

    /* recv thread */
    pthread_t        recv_thread;

    /* recv line buffer (persistent across recv_line calls) */
    char            *recv_buf;
    size_t           recv_buf_cap;
    size_t           recv_buf_len;     /* bytes currently in buffer */
};

/* ──────────────── TCP helpers ──────────────── */

/* Create socket and connect. Returns fd or SOCK_INVALID. */
static sock_t tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "[stratum] getaddrinfo(%s:%s): %s\n",
                host, port, gai_strerror(ret));
        return SOCK_INVALID;
    }

    sock_t fd = SOCK_INVALID;
    for (rp = result; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == SOCK_INVALID) continue;

        /* TCP keepalive */
        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&optval, sizeof(optval));

        if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0)
            break;  /* success */

        sock_close(fd);
        fd = SOCK_INVALID;
    }
    freeaddrinfo(result);
    return fd;
}

/* Reconnect loop (blocking, retries until success or !running). */
static void stratum_reconnect(stratum_ctx *ctx) {
    if (ctx->sock != SOCK_INVALID) { sock_close(ctx->sock); ctx->sock = SOCK_INVALID; }
    ctx->connected = 0;
    ctx->recv_buf_len = 0;  /* flush partial recv data */

    while (ctx->running) {
        fprintf(stderr, "[stratum] connecting to %s:%s ...\n", ctx->host, ctx->port);
        ctx->sock = tcp_connect(ctx->host, ctx->port);
        if (ctx->sock != SOCK_INVALID) {
            ctx->connected = 1;
            fprintf(stderr, "[stratum] connected to %s:%s\n", ctx->host, ctx->port);
            return;
        }
        fprintf(stderr, "[stratum] connection failed, retrying in %ds...\n",
                RECONNECT_DELAY_S);
        sleep(RECONNECT_DELAY_S);
    }
}

/* ──────────────── send / recv ──────────────── */

/* Send a string over the socket (thread-safe). Returns 0 ok, -1 error. */
static int stratum_send(stratum_ctx *ctx, const char *msg, size_t len) {
    pthread_mutex_lock(&ctx->send_lock);
    size_t sent = 0;
    while (sent < len) {
        int n = send(ctx->sock, msg + sent, (int)(len - sent), MSG_NOSIGNAL);
        if (n <= 0) {
            pthread_mutex_unlock(&ctx->send_lock);
            return -1;
        }
        sent += (size_t)n;
    }
    pthread_mutex_unlock(&ctx->send_lock);
    return 0;
}

/* Receive one newline-terminated line (blocking).
   Returns line length (NUL-terminated in *out), or -1 on error.
   Caller must free *out. */
static int stratum_recv_line(stratum_ctx *ctx, char **out) {
    /* Ensure we have a recv buffer */
    if (!ctx->recv_buf) {
        ctx->recv_buf_cap = RECV_BUF_INIT;
        ctx->recv_buf = (char *)malloc(ctx->recv_buf_cap);
        if (!ctx->recv_buf) return -1;
        ctx->recv_buf_len = 0;
    }

    for (;;) {
        /* Check for newline in existing data */
        for (size_t i = 0; i < ctx->recv_buf_len; i++) {
            if (ctx->recv_buf[i] == '\n') {
                /* Found a complete line */
                *out = (char *)malloc(i + 1);
                if (!*out) return -1;
                memcpy(*out, ctx->recv_buf, i);
                (*out)[i] = '\0';

                /* Remove line from buffer */
                size_t remaining = ctx->recv_buf_len - i - 1;
                if (remaining > 0)
                    memmove(ctx->recv_buf, ctx->recv_buf + i + 1, remaining);
                ctx->recv_buf_len = remaining;
                return (int)i;
            }
        }

        /* Need more data; grow buffer if needed */
        if (ctx->recv_buf_len + 1024 > ctx->recv_buf_cap) {
            ctx->recv_buf_cap *= 2;
            char *tmp = (char *)realloc(ctx->recv_buf, ctx->recv_buf_cap);
            if (!tmp) return -1;
            ctx->recv_buf = tmp;
        }

        int n = recv(ctx->sock, ctx->recv_buf + ctx->recv_buf_len, 1024, 0);
        if (n <= 0) return -1;  /* disconnect or error */
        ctx->recv_buf_len += (size_t)n;
    }
}

/* ──────────────── protocol: send getwork ──────────────── */

/* Register a submit ID in the ring (called under send_lock). */
static void submit_id_push(stratum_ctx *ctx, int id) {
    if (ctx->submit_id_count < SUBMIT_ID_RING)
        ctx->submit_ids[ctx->submit_id_count++] = id;
    /* else ring full — oldest entry lost; acceptable for stats */
}

/* Check if resp_id is a pending submit and remove it (called from recv thread). */
static int submit_id_check(stratum_ctx *ctx, int resp_id) {
    pthread_mutex_lock(&ctx->send_lock);
    for (int i = 0; i < ctx->submit_id_count; i++) {
        if (ctx->submit_ids[i] == resp_id) {
            /* Remove by shifting tail */
            ctx->submit_id_count--;
            for (int j = i; j < ctx->submit_id_count; j++)
                ctx->submit_ids[j] = ctx->submit_ids[j + 1];
            pthread_mutex_unlock(&ctx->send_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&ctx->send_lock);
    return 0;
}

static int stratum_send_getwork(stratum_ctx *ctx) {
    char buf[512];

    pthread_mutex_lock(&ctx->send_lock);
    int id = ctx->msg_id++;
    int len = snprintf(buf, sizeof(buf),
        "{\"id\":%d,\"method\":\"mining.request\","
        "\"params\":[\"%s\",\"%s\"]}\n",
        id, ctx->user, ctx->pass);
    if (len < 0 || (size_t)len >= sizeof(buf)) len = (int)sizeof(buf) - 1;
    pthread_mutex_unlock(&ctx->send_lock);

    fprintf(stderr, "[stratum] requesting work (id=%d)\n", id);
    return stratum_send(ctx, buf, (size_t)len);
}

/* ──────────────── protocol: parse work ──────────────── */

/* Parse {"data":"hex160","difficulty":N} from a JSON object.
   Updates ctx->work_data/work_ndiff and signals work_cond. */
static void parse_work(stratum_ctx *ctx, json_t *obj) {
    json_t *jdata = json_object_get(obj, "data");
    json_t *jdiff = json_object_get(obj, "difficulty");

    if (!json_is_string(jdata)) {
        fprintf(stderr, "[stratum] work: missing/invalid 'data'\n");
        return;
    }
    if (!json_is_number(jdiff)) {
        fprintf(stderr, "[stratum] work: missing/invalid 'difficulty'\n");
        return;
    }

    const char *data = json_string_value(jdata);
    if (strlen(data) < 160) {
        fprintf(stderr, "[stratum] work: data too short (%zu)\n", strlen(data));
        return;
    }

    uint64_t ndiff = json_is_integer(jdiff)
                   ? (uint64_t)json_integer_value(jdiff)
                   : (uint64_t)json_number_value(jdiff);

    pthread_mutex_lock(&ctx->work_lock);
    memcpy(ctx->work_data, data, 160);
    ctx->work_data[160] = '\0';
    ctx->work_ndiff = ndiff;
    ctx->work_ready = 1;
    ctx->work_new   = 1;
    pthread_cond_signal(&ctx->work_cond);
    pthread_mutex_unlock(&ctx->work_lock);

    double merit = (double)ndiff / (double)(1ULL << 48);
    fprintf(stderr, "[stratum] new work: difficulty=%.4f merit (nDifficulty=%llu)\n",
            merit, (unsigned long long)ndiff);
}

/* ──────────────── recv thread ──────────────── */

static void *recv_thread_fn(void *arg) {
    stratum_ctx *ctx = (stratum_ctx *)arg;

    while (ctx->running) {
        if (!ctx->connected) {
            stratum_reconnect(ctx);
            if (!ctx->running) break;
            stratum_send_getwork(ctx);
        }

        char *line = NULL;
        int len = stratum_recv_line(ctx, &line);
        if (len < 0) {
            if (ctx->running) {
                fprintf(stderr, "[stratum] connection lost, reconnecting...\n");
                ctx->connected = 0;
                stratum_reconnect(ctx);
                if (ctx->running)
                    stratum_send_getwork(ctx);
            }
            continue;
        }

        /* Parse JSON */
        json_error_t jerr;
        json_t *root = json_loads(line, 0, &jerr);
        free(line);
        if (!root) {
            fprintf(stderr, "[stratum] JSON parse error: %s\n", jerr.text);
            continue;
        }
        if (!json_is_object(root)) {
            json_decref(root);
            continue;
        }

        json_t *j_id = json_object_get(root, "id");

        /* ── Response to our request (id is integer) ── */
        if (json_is_integer(j_id)) {
            int resp_id = (int)json_integer_value(j_id);
            int is_submit = submit_id_check(ctx, resp_id);
            json_t *result = json_object_get(root, "result");

            /* Share response: result is boolean */
            if (json_is_boolean(result)) {
                int accepted = json_is_true(result);
                if (accepted) {
                    __sync_fetch_and_add(&ctx->shares_accepted, 1);
                    fprintf(stderr, "[stratum] share ACCEPTED\n");
                } else {
                    __sync_fetch_and_add(&ctx->shares_rejected, 1);
                    fprintf(stderr, "[stratum] share REJECTED (stale)\n");
                }
            }
            /* Getwork response: result is object with data+difficulty */
            else if (json_is_object(result)) {
                parse_work(ctx, result);
            }
            /* result is null → error response; extract reason from "error" */
            else if (json_is_null(result)) {
                json_t *j_err = json_object_get(root, "error");
                const char *tag = is_submit ? "share" : "request";
                if (json_is_array(j_err) && json_array_size(j_err) >= 2) {
                    /* Gapcoin-style: [code,"message",...] */
                    json_t *j_msg = json_array_get(j_err, 1);
                    fprintf(stderr, "[stratum] %s REJECTED (id=%d): %s\n",
                            tag, resp_id,
                            json_is_string(j_msg) ? json_string_value(j_msg) : "(unknown)");
                } else if (json_is_object(j_err)) {
                    /* Standard JSON-RPC: {"code":N,"message":"..."} */
                    json_t *j_msg = json_object_get(j_err, "message");
                    fprintf(stderr, "[stratum] %s REJECTED (id=%d): %s\n",
                            tag, resp_id,
                            json_is_string(j_msg) ? json_string_value(j_msg) : "(unknown)");
                } else {
                    /* Dump raw response for diagnostics */
                    char *raw = json_dumps(root, JSON_COMPACT);
                    fprintf(stderr, "[stratum] %s REJECTED (id=%d, result=null): %s\n",
                            tag, resp_id, raw ? raw : "?");
                    free(raw);
                }
                if (is_submit)
                    __sync_fetch_and_add(&ctx->shares_rejected, 1);
            }
        }
        /* ── Server push notification (id is null) ── */
        else {
            json_t *params = json_object_get(root, "params");
            if (json_is_object(params)) {
                /* blockchain.block.new notification */
                parse_work(ctx, params);
            }
        }

        json_decref(root);
    }
    return NULL;
}

/* ──────────────── public API ──────────────── */

stratum_ctx *stratum_connect(const char *host, const char *port,
                             const char *user, const char *pass,
                             uint16_t shift) {
    stratum_ctx *ctx = (stratum_ctx *)calloc(1, sizeof(stratum_ctx));
    if (!ctx) return NULL;

    ctx->sock = SOCK_INVALID;
    strncpy(ctx->host, host, sizeof(ctx->host) - 1);
    strncpy(ctx->port, port, sizeof(ctx->port) - 1);
    strncpy(ctx->user, user, sizeof(ctx->user) - 1);
    strncpy(ctx->pass, pass, sizeof(ctx->pass) - 1);
    ctx->shift = shift;
    ctx->running = 1;
    ctx->msg_id = 1;
    ctx->submit_id_count = 0;

    pthread_mutex_init(&ctx->send_lock, NULL);
    pthread_mutex_init(&ctx->work_lock, NULL);
    pthread_cond_init(&ctx->work_cond, NULL);

    /* Connect */
    stratum_reconnect(ctx);
    if (!ctx->connected) {
        pthread_mutex_destroy(&ctx->send_lock);
        pthread_mutex_destroy(&ctx->work_lock);
        pthread_cond_destroy(&ctx->work_cond);
        free(ctx);
        return NULL;
    }

    /* Send initial getwork and start recv thread */
    stratum_send_getwork(ctx);
    pthread_create(&ctx->recv_thread, NULL, recv_thread_fn, ctx);

    return ctx;
}

int stratum_get_work(stratum_ctx *ctx, char data_hex[161], uint64_t *ndiff) {
    pthread_mutex_lock(&ctx->work_lock);
    while (!ctx->work_ready && ctx->running)
        pthread_cond_wait(&ctx->work_cond, &ctx->work_lock);

    if (!ctx->work_ready) {
        pthread_mutex_unlock(&ctx->work_lock);
        return 0;
    }

    memcpy(data_hex, ctx->work_data, 161);
    *ndiff = ctx->work_ndiff;
    ctx->work_new = 0;
    pthread_mutex_unlock(&ctx->work_lock);
    return 1;
}

int stratum_poll_new_work(stratum_ctx *ctx, char data_hex[161], uint64_t *ndiff) {
    pthread_mutex_lock(&ctx->work_lock);
    if (!ctx->work_new) {
        pthread_mutex_unlock(&ctx->work_lock);
        return 0;
    }
    memcpy(data_hex, ctx->work_data, 161);
    *ndiff = ctx->work_ndiff;
    ctx->work_new = 0;
    pthread_mutex_unlock(&ctx->work_lock);
    return 1;
}

int stratum_submit(stratum_ctx *ctx, const char *block_hex) {
    if (!ctx->connected) {
        fprintf(stderr, "[stratum] submit skipped (not connected)\n");
        return 0;
    }

    /* Compute required buffer size: fixed JSON overhead + variable hex length */
    size_t hex_len = strlen(block_hex);

    /* Allocate id and register as pending submit under one lock */
    pthread_mutex_lock(&ctx->send_lock);
    int id = ctx->msg_id++;
    submit_id_push(ctx, id);
    pthread_mutex_unlock(&ctx->send_lock);

    fprintf(stderr, "[stratum] submitting share id=%d hex_len=%zu bytes=%zu\n",
            id, hex_len, hex_len / 2);
    /* Log first 180 and last 20 hex chars for diagnostics */
    if (hex_len > 200) {
        fprintf(stderr, "[stratum]   hex[0:180]=%.*s...\n", 180, block_hex);
        fprintf(stderr, "[stratum]   hex[end-20:]=%s\n", block_hex + hex_len - 20);
    } else {
        fprintf(stderr, "[stratum]   hex=%s\n", block_hex);
    }

    size_t buf_size = 256 + strlen(ctx->user) + strlen(ctx->pass) + hex_len;
    char *buf = (char *)malloc(buf_size);
    if (!buf) return 0;

    int len = snprintf(buf, buf_size,
        "{\"id\":%d,\"method\":\"mining.submit\","
        "\"params\":[\"%s\",\"%s\",\"%s\"]}\n",
        id, ctx->user, ctx->pass, block_hex);
    if (len < 0 || (size_t)len >= buf_size) len = (int)buf_size - 1;

    int ret = stratum_send(ctx, buf, (size_t)len);
    free(buf);

    if (ret < 0) {
        fprintf(stderr, "[stratum] submit failed (connection error)\n");
        return 0;
    }
    return 1;
}

void stratum_get_stats(stratum_ctx *ctx, uint64_t *accepted, uint64_t *rejected) {
    *accepted = ctx->shares_accepted;
    *rejected = ctx->shares_rejected;
}

void stratum_disconnect(stratum_ctx *ctx) {
    if (!ctx) return;
    ctx->running = 0;

    /* Wake up any thread waiting on work_cond */
    pthread_mutex_lock(&ctx->work_lock);
    pthread_cond_broadcast(&ctx->work_cond);
    pthread_mutex_unlock(&ctx->work_lock);

    /* Close socket to unblock recv */
    if (ctx->sock != SOCK_INVALID) {
        shutdown(ctx->sock, SHUT_RDWR);
        sock_close(ctx->sock);
        ctx->sock = SOCK_INVALID;
    }

    pthread_join(ctx->recv_thread, NULL);

    pthread_mutex_destroy(&ctx->send_lock);
    pthread_mutex_destroy(&ctx->work_lock);
    pthread_cond_destroy(&ctx->work_cond);
    free(ctx->recv_buf);
    free(ctx);
}
