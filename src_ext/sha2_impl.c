/*********************************************************************
* Filename:   sha2_impl.c
* License:    Unlicense (public domain)
* Details:    Parameterized SHA-2 implementation template.
*
*             This file is #included (not compiled directly) by sha256.c
*             and sha512.c after they define algorithm-specific macros.
*
* Required macros before inclusion:
*   WORD_T       - word type (uint32_t or uint64_t)
*   WORD_BITS    - bits per word (32 or 64)
*   BLOCK_BYTES  - block size in bytes (64 or 128)
*   DIGEST_BYTES - output hash size (32 or 64)
*   ROUNDS       - number of rounds (64 or 80)
*   FUNC_PREFIX  - function name prefix (sha256 or sha512)
*   CTX_T        - context type (SHA256_CTX or SHA512_CTX)
*   EP0_R1..R3, EP1_R1..R3       - Sigma rotation amounts
*   SIG0_R1, SIG0_R2, SIG0_S3    - sigma0 rotation/shift amounts
*   SIG1_R1, SIG1_R2, SIG1_S3    - sigma1 rotation/shift amounts
*
* Required data before inclusion:
*   static const WORD_T k[ROUNDS] - round constants
*   static const WORD_T iv[8]     - initial hash values
*********************************************************************/

#define _CONCAT(a, b) a##_##b
#define CONCAT(a, b) _CONCAT(a, b)
#define FN(name) CONCAT(FUNC_PREFIX, name)

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (WORD_BITS - (b))))

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTRIGHT(x, EP0_R1) ^ ROTRIGHT(x, EP0_R2) ^ ROTRIGHT(x, EP0_R3))
#define EP1(x)  (ROTRIGHT(x, EP1_R1) ^ ROTRIGHT(x, EP1_R2) ^ ROTRIGHT(x, EP1_R3))
#define SIG0(x) (ROTRIGHT(x, SIG0_R1) ^ ROTRIGHT(x, SIG0_R2) ^ ((x) >> SIG0_S3))
#define SIG1(x) (ROTRIGHT(x, SIG1_R1) ^ ROTRIGHT(x, SIG1_R2) ^ ((x) >> SIG1_S3))

static void FN(transform)(CTX_T *ctx, const BYTE data[])
{
    WORD_T a, b, c, d, e, f, g, h, t1, t2, m[ROUNDS];
    int i, j;
    int word_bytes = WORD_BITS / 8;

    for (i = 0, j = 0; i < 16; ++i, j += word_bytes) {
        m[i] = 0;
        for (int n = 0; n < word_bytes; n++)
            m[i] |= ((WORD_T)data[j + n]) << (WORD_BITS - 8 - n * 8);
    }
    for (; i < ROUNDS; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < ROUNDS; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void FN(init)(CTX_T *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < 8; i++)
        ctx->state[i] = iv[i];
}

void FN(update)(CTX_T *ctx, const BYTE data[], size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == BLOCK_BYTES) {
            FN(transform)(ctx, ctx->data);
            ctx->bitlen += (uint64_t)BLOCK_BYTES * 8;
            ctx->datalen = 0;
        }
    }
}

void FN(final)(CTX_T *ctx, BYTE hash[])
{
    unsigned int i;
    int word_bytes = WORD_BITS / 8;
    /* Offset where the length field starts: BLOCK_BYTES - 8 for SHA-256,
       BLOCK_BYTES - 16 for SHA-512. Length field is 2 * word_bytes. */
    int len_offset = BLOCK_BYTES - 2 * word_bytes;

    i = ctx->datalen;

    if (ctx->datalen < (unsigned int)len_offset) {
        ctx->data[i++] = 0x80;
        while (i < (unsigned int)len_offset)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < BLOCK_BYTES)
            ctx->data[i++] = 0x00;
        FN(transform)(ctx, ctx->data);
        memset(ctx->data, 0, len_offset);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;

    /*
     * Append total message length in bits as big-endian at the end of the block.
     * SHA-256: 8-byte length at offset 56.
     * SHA-512: 16-byte length at offset 112 (upper 8 bytes zero since we use
     *          uint64_t bitlen which can't exceed 2^64).
     */
#if WORD_BITS == 64
    /* SHA-512: write 16 bytes of length (upper 8 are zero) */
    for (int n = 0; n < 8; n++)
        ctx->data[len_offset + n] = 0;
    for (int n = 0; n < 8; n++)
        ctx->data[len_offset + 8 + n] = (BYTE)(ctx->bitlen >> (56 - n * 8));
#else
    /* SHA-256: write 8 bytes of length */
    for (int n = 0; n < 8; n++)
        ctx->data[len_offset + n] = (BYTE)(ctx->bitlen >> (56 - n * 8));
#endif

    FN(transform)(ctx, ctx->data);

    for (i = 0; i < 8; ++i) {
        for (int n = 0; n < word_bytes && (int)(i * word_bytes + n) < DIGEST_BYTES; n++)
            hash[i * word_bytes + n] = (BYTE)(ctx->state[i] >> (WORD_BITS - 8 - n * 8));
    }
}

#undef _CONCAT
#undef CONCAT
#undef FN
#undef ROTRIGHT
#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1
