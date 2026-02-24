#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/rpc_json.h"

static void test_parse_error_null(void) {
    const char *s = "{\"result\":null,\"error\":null,\"id\":\"C\"}";
    int code = 0; char *msg = NULL;
    int res = rpc_parse_error(s, &code, &msg);
    if (res != 0) { printf("FAIL: expected 0, got %d\n", res); exit(1); }
    if (msg) free(msg);
}

static void test_parse_error_present(void) {
    const char *s = "{\"result\":null,\"error\":{\"code\":-1,\"message\":\"bad block\"},\"id\":\"C\"}";
    int code = 0; char *msg = NULL;
    int res = rpc_parse_error(s, &code, &msg);
    if (res != 1) { printf("FAIL: expected 1, got %d\n", res); exit(2); }
    if (code != -1) { printf("FAIL: expected code -1, got %d\n", code); exit(3); }
    if (!msg || strcmp(msg, "bad block") != 0) { printf("FAIL: expected message 'bad block', got '%s'\n", msg ? msg : "(null)"); exit(4); }
    free(msg);
}

static void test_extract_prev_hash(void) {
    const char *s = "{\"previousblockhash\":\"abcdef012345\"}";
    char out[128]; memset(out,0,sizeof(out));
    int r = rpc_extract_prev_hash(s, out, sizeof(out));
    if (r != 1) { printf("FAIL: expected 1, got %d\n", r); exit(5); }
    if (strcmp(out, "abcdef012345") != 0) { printf("FAIL: unexpected hash '%s'\n", out); exit(6); }
}

int main(void) {
    test_parse_error_null();
    test_parse_error_present();
    test_extract_prev_hash();
    printf("All rpc_json tests passed.\n");
    return 0;
}
