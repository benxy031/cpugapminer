#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2) return NULL;
    size_t blen = hlen/2;
    unsigned char *b = malloc(blen);
    for (size_t i=0;i<blen;i++) {
        int hi = hexval(hex[2*i]);
        int lo = hexval(hex[2*i+1]);
        if (hi < 0 || lo < 0) { free(b); return NULL; }
        b[i] = (hi<<4) | lo;
    }
    *out_len = blen; return b;
}

static unsigned long long read_compact(const unsigned char *b, size_t blen, size_t p, size_t *size_out) {
    if (p >= blen) { *size_out = 0; return 0; }
    unsigned char x = b[p];
    if (x < 0xFD) { *size_out = 1; return x; }
    if (x == 0xFD) { if (p+3>blen) { *size_out=0; return 0; } *size_out=3; return (unsigned long long)(b[p+1] | (b[p+2]<<8)); }
    if (x == 0xFE) { if (p+5>blen) { *size_out=0; return 0; } *size_out=5; return (unsigned long long)(b[p+1] | (b[p+2]<<8) | (b[p+3]<<16) | (b[p+4]<<24)); }
    if (x == 0xFF) { if (p+9>blen) { *size_out=0; return 0; } *size_out=9; unsigned long long v=0; for (int i=0;i<8;i++) v |= ((unsigned long long)b[p+1+i]) << (8*i); return v; }
    *size_out=0; return 0;
}

int main(int argc, char **argv) {
    char *hex = NULL;
    if (argc >= 2) hex = argv[1];
    else {
        size_t cap=8192; hex = malloc(cap); size_t len=0; int c;
        while ((c=getchar())!=EOF) { if (len+1>=cap) { cap*=2; hex=realloc(hex,cap); } hex[len++]=c; }
        hex[len]='\0';
        while (len>0 && (hex[len-1]=='\n' || hex[len-1]=='\r' || hex[len-1]==' ' || hex[len-1]=='\t')) hex[--len]='\0';
    }
    if (!hex) { fprintf(stderr,"no hex provided\n"); return 2; }
    size_t blen; unsigned char *b = hex_to_bytes(hex, &blen);
    if (!b) { fprintf(stderr,"invalid hex\n"); return 3; }
    if (blen < 80) { fprintf(stderr,"block too short: %zu bytes\n", blen); free(b); return 4; }
    unsigned int version = b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24);
    printf("header version: 0x%x (%u)\n", version, version);
    printf("prevhash (LE): "); for (int i=4;i<36;i++) printf("%02x", b[i]); printf("\n");
    printf("prevhash (BE): "); for (int i=35;i>=4;i--) printf("%02x", b[i]); printf("\n");
    printf("merkle (LE): "); for (int i=36;i<68;i++) printf("%02x", b[i]); printf("\n");
    printf("merkle (BE): "); for (int i=67;i>=36;i--) printf("%02x", b[i]); printf("\n");
    unsigned int curtime = b[68] | (b[69]<<8) | (b[70]<<16) | (b[71]<<24);
    unsigned int bits = b[72] | (b[73]<<8) | (b[74]<<16) | (b[75]<<24);
    unsigned int nonce = b[76] | (b[77]<<8) | (b[78]<<16) | (b[79]<<24);
    printf("curtime: %u bits: 0x%x nonce: 0x%x\n", curtime, bits, nonce);

    size_t p = 80;
    size_t csz; unsigned long long txcount = read_compact(b, blen, p, &csz);
    if (csz==0) { fprintf(stderr,"failed to read txcount\n"); free(b); return 5; }
    printf("txcount: %llu (compact size bytes=%zu)\n", txcount, csz);
    p += csz;
    if (txcount < 1) { fprintf(stderr,"no txs\n"); free(b); return 6; }
    if (p+4 > blen) { fprintf(stderr,"no tx version\n"); free(b); return 7; }
    unsigned int txver = b[p] | (b[p+1]<<8) | (b[p+2]<<16) | (b[p+3]<<24); p+=4;
    printf("first tx version: %u\n", txver);
    if (p >= blen) { fprintf(stderr,"unexpected end\n"); free(b); return 8; }
    unsigned char vin_cnt = b[p++];
    printf("vin count (raw byte): %u\n", vin_cnt);
    if (p+32+4 > blen) { fprintf(stderr,"tx too short for prevout\n"); free(b); return 9; }
    printf("prevout: "); for (int i=0;i<32;i++) printf("%02x", b[p+i]); printf("\n");
    unsigned int prev_index = b[p+32] | (b[p+33]<<8) | (b[p+34]<<16) | (b[p+35]<<24);
    printf("prev_index: 0x%08x\n", prev_index);
    free(b);
    return 0;
}
