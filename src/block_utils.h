#ifndef BLOCK_UTILS_H
#define BLOCK_UTILS_H

#include <stddef.h>
#include <stdint.h>

void u64_to_le(uint64_t v, unsigned char out[8]);
void bytes_to_hex(const unsigned char *bytes, size_t len, char *out);
void write_u32_le(unsigned char **p, uint32_t v);
void write_u64_le(unsigned char **p, uint64_t v);
void write_byte(unsigned char **p, unsigned char b);
size_t push_opcode_size(size_t len);
void write_push_data(unsigned char **p, const unsigned char *data, size_t len);
void write_compact_size(unsigned char **p, uint64_t v);
void double_sha256(const unsigned char *data, size_t len, unsigned char out[32]);

#endif
