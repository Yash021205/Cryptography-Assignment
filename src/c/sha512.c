/*
 * SHA-512 Implementation in C
 * ============================
 * Implements the SHA-512 cryptographic hash function as specified in
 * FIPS PUB 180-4 (Secure Hash Standard).
 *
 * Features:
 *   - SHA-512 (512-bit / 64-byte digest)
 *   - Single-call and streaming (Init/Update/Final) API
 *   - HMAC-SHA-512
 *
 * Reference: NIST FIPS 180-4, RFC 6234
 *
 * Author  : CYG Assignment Group
 * Course  : Cryptography
 * Date    : 2026
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* -----------------------------------------------------------------------
 * SHA-512 Constants
 * ----------------------------------------------------------------------- */

#define SHA512_BLOCK_SIZE   128   /* 1024-bit message schedule block */
#define SHA512_DIGEST_SIZE   64   /* 512-bit output digest            */

/* First 64 bits of the fractional parts of the cube roots of the first 80 primes */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* Initial hash values (first 64 bits of sqrt of first 8 primes) */
static const uint64_t H0[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* -----------------------------------------------------------------------
 * SHA-512 Context
 * ----------------------------------------------------------------------- */

typedef struct {
    uint64_t  state[8];            /* 512-bit intermediate hash       */
    uint64_t  count[2];            /* message length in bits (128-bit) */
    uint8_t   buf[SHA512_BLOCK_SIZE]; /* partial block buffer           */
    size_t    buf_len;             /* bytes in buf                    */
} sha512_ctx_t;

/* -----------------------------------------------------------------------
 * Helper macros
 * ----------------------------------------------------------------------- */

#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define SHR64(x,n)  ((x)>>(n))

#define CH(x,y,z)   (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z)  (((x)&(y))^((x)&(z))^((y)&(z)))

#define SIG0(x)  (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#define SIG1(x)  (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#define sig0(x)  (ROTR64(x, 1)^ROTR64(x, 8)^SHR64(x,  7))
#define sig1(x)  (ROTR64(x,19)^ROTR64(x,61)^SHR64(x,  6))

/* -----------------------------------------------------------------------
 * SHA-512 compression: process one 1024-bit block
 * ----------------------------------------------------------------------- */

static void sha512_compress(sha512_ctx_t *ctx, const uint8_t *block) {
    uint64_t W[80];
    uint64_t a,b,c,d,e,f,g,h;
    uint64_t T1, T2;
    int t;

    /* Message schedule */
    for (t = 0; t < 16; t++) {
        W[t]  = ((uint64_t)block[t*8+0] << 56)
              | ((uint64_t)block[t*8+1] << 48)
              | ((uint64_t)block[t*8+2] << 40)
              | ((uint64_t)block[t*8+3] << 32)
              | ((uint64_t)block[t*8+4] << 24)
              | ((uint64_t)block[t*8+5] << 16)
              | ((uint64_t)block[t*8+6] <<  8)
              | ((uint64_t)block[t*8+7]);
    }
    for (t = 16; t < 80; t++)
        W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];

    /* Initialize working variables */
    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    /* 80 compression rounds */
    for (t = 0; t < 80; t++) {
        T1 = h + SIG1(e) + CH(e,f,g) + K[t] + W[t];
        T2 = SIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    /* Update hash state */
    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

/* -----------------------------------------------------------------------
 * SHA-512 API
 * ----------------------------------------------------------------------- */

void sha512_init(sha512_ctx_t *ctx) {
    int i;
    for (i = 0; i < 8; i++) ctx->state[i] = H0[i];
    ctx->count[0] = ctx->count[1] = 0;
    ctx->buf_len   = 0;
}

void sha512_update(sha512_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t remain = SHA512_BLOCK_SIZE - ctx->buf_len;
    size_t off = 0;

    /* Update bit count (128-bit counter) */
    uint64_t bits_lo = ctx->count[1] + ((uint64_t)len << 3);
    if (bits_lo < ctx->count[1])
        ctx->count[0]++;
    ctx->count[1] = bits_lo;
    ctx->count[0] += (uint64_t)len >> 61;

    /* Fill partial buffer first */
    if (len >= remain) {
        memcpy(ctx->buf + ctx->buf_len, data, remain);
        sha512_compress(ctx, ctx->buf);
        ctx->buf_len = 0;
        off = remain;

        while (off + SHA512_BLOCK_SIZE <= len) {
            sha512_compress(ctx, data + off);
            off += SHA512_BLOCK_SIZE;
        }
    }
    /* Copy remainder */
    memcpy(ctx->buf + ctx->buf_len, data + off, len - off);
    ctx->buf_len += (len - off);
}

void sha512_final(sha512_ctx_t *ctx, uint8_t digest[SHA512_DIGEST_SIZE]) {
    uint8_t pad[SHA512_BLOCK_SIZE * 2];
    size_t pad_len;
    int i;

    /* Padding: 0x80 then zeros then 128-bit length */
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    /* We need buf_len + 1 + zeros + 16 bytes to align to block boundary */
    if (ctx->buf_len < 112)
        pad_len = 112 - ctx->buf_len;
    else
        pad_len = 128 + 112 - ctx->buf_len;

    /* Append length in bits as 128-bit big-endian */
    pad[pad_len + 0]  = (uint8_t)(ctx->count[0] >> 56);
    pad[pad_len + 1]  = (uint8_t)(ctx->count[0] >> 48);
    pad[pad_len + 2]  = (uint8_t)(ctx->count[0] >> 40);
    pad[pad_len + 3]  = (uint8_t)(ctx->count[0] >> 32);
    pad[pad_len + 4]  = (uint8_t)(ctx->count[0] >> 24);
    pad[pad_len + 5]  = (uint8_t)(ctx->count[0] >> 16);
    pad[pad_len + 6]  = (uint8_t)(ctx->count[0] >>  8);
    pad[pad_len + 7]  = (uint8_t)(ctx->count[0]);
    pad[pad_len + 8]  = (uint8_t)(ctx->count[1] >> 56);
    pad[pad_len + 9]  = (uint8_t)(ctx->count[1] >> 48);
    pad[pad_len + 10] = (uint8_t)(ctx->count[1] >> 40);
    pad[pad_len + 11] = (uint8_t)(ctx->count[1] >> 32);
    pad[pad_len + 12] = (uint8_t)(ctx->count[1] >> 24);
    pad[pad_len + 13] = (uint8_t)(ctx->count[1] >> 16);
    pad[pad_len + 14] = (uint8_t)(ctx->count[1] >>  8);
    pad[pad_len + 15] = (uint8_t)(ctx->count[1]);

    sha512_update(ctx, pad, pad_len + 16);

    /* Produce big-endian digest */
    for (i = 0; i < 8; i++) {
        digest[i*8+0] = (uint8_t)(ctx->state[i] >> 56);
        digest[i*8+1] = (uint8_t)(ctx->state[i] >> 48);
        digest[i*8+2] = (uint8_t)(ctx->state[i] >> 40);
        digest[i*8+3] = (uint8_t)(ctx->state[i] >> 32);
        digest[i*8+4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i*8+5] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*8+6] = (uint8_t)(ctx->state[i] >>  8);
        digest[i*8+7] = (uint8_t)(ctx->state[i]);
    }
}

/* Convenience one-shot hash */
void sha512(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_SIZE]) {
    sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, digest);
}

/* -----------------------------------------------------------------------
 * HMAC-SHA-512
 * ----------------------------------------------------------------------- */

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len,
                 uint8_t mac[SHA512_DIGEST_SIZE]) {
    uint8_t K[SHA512_BLOCK_SIZE];
    uint8_t i_pad[SHA512_BLOCK_SIZE], o_pad[SHA512_BLOCK_SIZE];
    uint8_t inner[SHA512_DIGEST_SIZE];
    sha512_ctx_t ctx;
    int i;

    memset(K, 0, sizeof(K));

    /* If key is longer than block, hash it */
    if (key_len > SHA512_BLOCK_SIZE)
        sha512(key, key_len, K);
    else
        memcpy(K, key, key_len);

    /* IPAD = K XOR 0x36... */
    for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
        i_pad[i] = K[i] ^ 0x36;
        o_pad[i] = K[i] ^ 0x5c;
    }

    /* Inner hash: H(ipad || msg) */
    sha512_init(&ctx);
    sha512_update(&ctx, i_pad, SHA512_BLOCK_SIZE);
    sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, inner);

    /* Outer hash: H(opad || inner) */
    sha512_init(&ctx);
    sha512_update(&ctx, o_pad, SHA512_BLOCK_SIZE);
    sha512_update(&ctx, inner, SHA512_DIGEST_SIZE);
    sha512_final(&ctx, mac);
}

/* -----------------------------------------------------------------------
 * Utility helpers
 * ----------------------------------------------------------------------- */

static void print_hash(const char *label, const uint8_t *hash, size_t len) {
    size_t i;
    printf("%-20s :\n  ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", hash[i]);
        if ((i + 1) % 32 == 0) printf("\n  ");
    }
    printf("\n");
}

/* -----------------------------------------------------------------------
 * Demo / main
 * ----------------------------------------------------------------------- */

int main(void) {
    uint8_t digest[SHA512_DIGEST_SIZE];
    clock_t start, end;
    double t;

    printf("==========================================================\n");
    printf("            SHA-512 Implementation – Demo                 \n");
    printf("==========================================================\n\n");

    /* ---- NIST Test Vectors ---- */
    printf("---- NIST FIPS 180-4 Test Vectors ----\n\n");

    /* Vector 1: Empty string */
    {
        const uint8_t expected[] = {
            0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,
            0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
            0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,
            0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
            0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,
            0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
            0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,
            0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
        };
        sha512((const uint8_t *)"", 0, digest);
        printf("Input   : \"\" (empty string)\n");
        print_hash("SHA-512", digest, SHA512_DIGEST_SIZE);
        printf("Test    : %s\n\n",
               memcmp(digest, expected, SHA512_DIGEST_SIZE) == 0 ? "PASSED ✓" : "FAILED ✗");
    }

    /* Vector 2: "abc" */
    {
        const uint8_t expected[] = {
            0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
            0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
            0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
            0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
            0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
            0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
            0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
            0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
        };
        sha512((const uint8_t *)"abc", 3, digest);
        printf("Input   : \"abc\"\n");
        print_hash("SHA-512", digest, SHA512_DIGEST_SIZE);
        printf("Test    : %s\n\n",
               memcmp(digest, expected, SHA512_DIGEST_SIZE) == 0 ? "PASSED ✓" : "FAILED ✗");
    }

    /* Vector 3: Long string */
    {
        const char *msg3 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                           "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        sha512((const uint8_t *)msg3, strlen(msg3), digest);
        printf("Input   : \"abcdefghbcdefghicde...(112 bytes)\"\n");
        print_hash("SHA-512", digest, SHA512_DIGEST_SIZE);
        printf("\n");
    }

    /* ---- Custom message ---- */
    {
        const char *msg = "Cryptography Course – AES256, RSA, ECC, SHA512";
        printf("---- Custom Message Hashing ----\n");
        printf("Message : \"%s\"\n", msg);

        start = clock();
        sha512((const uint8_t *)msg, strlen(msg), digest);
        end   = clock();
        t     = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

        print_hash("SHA-512", digest, SHA512_DIGEST_SIZE);
        printf("Hash time : %.4f ms\n\n", t);
    }

    /* ---- Avalanche Effect ---- */
    printf("---- Avalanche Effect Demonstration ----\n");
    {
        const char *m1 = "Hello World";
        const char *m2 = "Hello World!"; /* one extra char */
        uint8_t d1[SHA512_DIGEST_SIZE], d2[SHA512_DIGEST_SIZE];
        int diff_bits = 0; size_t i;

        sha512((const uint8_t *)m1, strlen(m1), d1);
        sha512((const uint8_t *)m2, strlen(m2), d2);

        printf("Message 1 : \"%s\"\n", m1);
        print_hash("Hash 1", d1, SHA512_DIGEST_SIZE);
        printf("Message 2 : \"%s\"\n", m2);
        print_hash("Hash 2", d2, SHA512_DIGEST_SIZE);

        for (i = 0; i < SHA512_DIGEST_SIZE; i++) {
            uint8_t diff = d1[i] ^ d2[i];
            while (diff) { diff_bits += diff & 1; diff >>= 1; }
        }
        printf("Differing bits : %d / %d (%.1f%%)\n\n",
               diff_bits, SHA512_DIGEST_SIZE * 8,
               (double)diff_bits / (SHA512_DIGEST_SIZE * 8) * 100.0);
    }

    /* ---- HMAC-SHA-512 ---- */
    {
        uint8_t mac[SHA512_DIGEST_SIZE];
        const uint8_t *key = (const uint8_t *)"SuperSecretKey";
        const uint8_t *msg = (const uint8_t *)"Message to authenticate";
        printf("---- HMAC-SHA-512 ----\n");
        printf("Key     : \"%s\"\n", (char *)key);
        printf("Message : \"%s\"\n", (char *)msg);
        hmac_sha512(key, strlen((char *)key), msg, strlen((char *)msg), mac);
        print_hash("HMAC-SHA-512", mac, SHA512_DIGEST_SIZE);
    }

    /* ---- Performance: 1 MB ---- */
    {
        size_t MB = 1024 * 1024;
        uint8_t *buf = (uint8_t *)malloc(MB);
        memset(buf, 0xAB, MB);
        start = clock();
        sha512(buf, MB, digest);
        end = clock();
        t   = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
        printf("---- Throughput Test ----\n");
        printf("Data    : 1 MB (1048576 bytes)\n");
        printf("Time    : %.4f ms\n", t);
        printf("Speed   : %.2f MB/s\n\n", 1.0 / (t / 1000.0));
        free(buf);
    }

    /* ---- Security Summary ---- */
    printf("==========================================================\n");
    printf("                 SHA-512 Security Summary                 \n");
    printf("==========================================================\n");
    printf("Digest Size         : 512 bits (64 bytes)\n");
    printf("Block Size          : 1024 bits\n");
    printf("Rounds              : 80\n");
    printf("Pre-image resist.   : 2^512 (classical)\n");
    printf("Collision resist.   : 2^256 (birthday bound)\n");
    printf("Quantum (Grover)    : 2^256 pre-image, 2^128 collision\n");
    printf("Post-Quantum        : Remains secure with 256-bit truncation\n");

    return 0;
}
