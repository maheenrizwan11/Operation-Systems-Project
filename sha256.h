#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte

typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);
void sha256_compute_and_print(const BYTE *input);

#endif
