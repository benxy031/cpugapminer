#include "block_utils.h"

#include <openssl/sha.h>
#include <string.h>

void u64_to_le(uint64_t v, unsigned char out[8]) {
    for (int i = 0; i < 8; i++) out[i] = (unsigned char)(v & 0xff), v >>= 8;
}

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[bytes[i] & 0xf];
    }
    out[len * 2] = '\0';
}

void write_u32_le(unsigned char **p, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        **p = (unsigned char)(v & 0xff);
        *p += 1;
        v >>= 8;
    }
}

void write_u64_le(unsigned char **p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        **p = (unsigned char)(v & 0xff);
        *p += 1;
        v >>= 8;
    }
}

void write_byte(unsigned char **p, unsigned char b) {
    **p = b;
    *p += 1;
}

size_t push_opcode_size(size_t len) {
    if (len <= 75) return 1 + len;
    if (len <= 0xFF) return 2 + len;
    if (len <= 0xFFFF) return 3 + len;
    return 5 + len;
}

void write_push_data(unsigned char **p, const unsigned char *data, size_t len) {
    if (len <= 75) {
        write_byte(p, (unsigned char)len);
    } else if (len <= 0xFF) {
        write_byte(p, 0x4c);
        write_byte(p, (unsigned char)len);
    } else if (len <= 0xFFFF) {
        write_byte(p, 0x4d);
        unsigned short le = (unsigned short)len;
        memcpy(*p, &le, 2);
        *p += 2;
    } else {
        write_byte(p, 0x4e);
        unsigned int le = (unsigned int)len;
        memcpy(*p, &le, 4);
        *p += 4;
    }
    if (len) {
        memcpy(*p, data, len);
        *p += len;
    }
}

void write_compact_size(unsigned char **p, uint64_t v) {
    if (v < 0xFD) {
        write_byte(p, (unsigned char)v);
    } else if (v <= 0xFFFF) {
        write_byte(p, 0xFD);
        unsigned short le = (unsigned short)v;
        memcpy(*p, &le, 2);
        *p += 2;
    } else if (v <= 0xFFFFFFFF) {
        write_byte(p, 0xFE);
        unsigned int le = (unsigned int)v;
        memcpy(*p, &le, 4);
        *p += 4;
    } else {
        write_byte(p, 0xFF);
        unsigned long long le = (unsigned long long)v;
        memcpy(*p, &le, 8);
        *p += 8;
    }
}

void double_sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    unsigned char tmp[32];
    SHA256(data, len, tmp);
    SHA256(tmp, 32, out);
}
