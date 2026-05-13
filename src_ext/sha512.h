#ifndef SHA512_H
#define SHA512_H

#include "sha2_common.h"

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128
#define SHA384_DIGEST_SIZE 48

typedef struct {
    BYTE data[128];
    uint64_t datalen;
    uint64_t bitlen;
    uint64_t state[8];
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const BYTE data[], size_t len);
void sha512_final(SHA512_CTX *ctx, BYTE hash[]);

void sha384_init(SHA512_CTX *ctx);
void sha384_final(SHA512_CTX *ctx, BYTE hash[]);

#endif /* SHA512_H */
