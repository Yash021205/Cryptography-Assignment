/*
 * AES-256 Implementation in C
 * ============================
 * Implements the Advanced Encryption Standard (AES) with a 256-bit key.
 * Supports ECB and CBC modes of operation.
 *
 * Reference: FIPS PUB 197 - Advanced Encryption Standard (AES)
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
 * AES Constants
 * ----------------------------------------------------------------------- */

#define AES_BLOCK_SIZE   16   /* 128-bit block */
#define AES_KEY_SIZE_256 32   /* 256-bit key  */
#define AES_ROUNDS_256   14   /* Nr = 14 for AES-256 */
#define AES_KEY_EXP_SIZE 240  /* (Nr+1) * Nb * 4 = 15 * 16 = 240 bytes */

/* AES S-Box */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* AES Inverse S-Box */
static const uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* Round Constant (Rcon) */
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* -----------------------------------------------------------------------
 * GF(2^8) Multiplication helpers
 * ----------------------------------------------------------------------- */

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

/* -----------------------------------------------------------------------
 * Key Expansion
 * ----------------------------------------------------------------------- */

void aes256_key_expansion(const uint8_t *key, uint8_t *round_key) {
    int i, j;
    uint8_t temp[4], k;

    /* First round key is the key itself */
    for (i = 0; i < AES_KEY_SIZE_256; i++)
        round_key[i] = key[i];

    /* All other round keys are found from the previous round keys */
    for (i = AES_KEY_SIZE_256; i < AES_KEY_EXP_SIZE; i += 4) {
        for (j = 0; j < 4; j++)
            temp[j] = round_key[(i - 4) + j];

        if (i % AES_KEY_SIZE_256 == 0) {
            /* RotWord */
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            /* SubWord */
            for (j = 0; j < 4; j++)
                temp[j] = sbox[temp[j]];
            /* XOR with Rcon */
            temp[0] ^= Rcon[i / AES_KEY_SIZE_256];
        } else if (i % AES_KEY_SIZE_256 == 16) {
            /* SubWord only (AES-256 specific) */
            for (j = 0; j < 4; j++)
                temp[j] = sbox[temp[j]];
        }

        for (j = 0; j < 4; j++)
            round_key[i + j] = round_key[i + j - AES_KEY_SIZE_256] ^ temp[j];
    }
}

/* -----------------------------------------------------------------------
 * AES Round Transformations
 * ----------------------------------------------------------------------- */

/* AddRoundKey: XOR state with round key */
static void add_round_key(uint8_t round, uint8_t state[4][4], const uint8_t *round_key) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] ^= round_key[round * AES_BLOCK_SIZE + i * 4 + j];
}

/* SubBytes: Apply S-Box substitution */
static void sub_bytes(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];
}

/* InvSubBytes: Apply Inverse S-Box */
static void inv_sub_bytes(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = rsbox[state[i][j]];
}

/* ShiftRows: Cyclically shift rows */
static void shift_rows(uint8_t state[4][4]) {
    uint8_t temp;
    /* Row 1: shift left by 1 */
    temp         = state[1][0];
    state[1][0]  = state[1][1];
    state[1][1]  = state[1][2];
    state[1][2]  = state[1][3];
    state[1][3]  = temp;
    /* Row 2: shift left by 2 */
    temp         = state[2][0];
    state[2][0]  = state[2][2];
    state[2][2]  = temp;
    temp         = state[2][1];
    state[2][1]  = state[2][3];
    state[2][3]  = temp;
    /* Row 3: shift left by 3 (= right by 1) */
    temp         = state[3][3];
    state[3][3]  = state[3][2];
    state[3][2]  = state[3][1];
    state[3][1]  = state[3][0];
    state[3][0]  = temp;
}

/* InvShiftRows */
static void inv_shift_rows(uint8_t state[4][4]) {
    uint8_t temp;
    /* Row 1: shift right by 1 */
    temp         = state[1][3];
    state[1][3]  = state[1][2];
    state[1][2]  = state[1][1];
    state[1][1]  = state[1][0];
    state[1][0]  = temp;
    /* Row 2: shift right by 2 */
    temp         = state[2][0];
    state[2][0]  = state[2][2];
    state[2][2]  = temp;
    temp         = state[2][1];
    state[2][1]  = state[2][3];
    state[2][3]  = temp;
    /* Row 3: shift right by 3 (= left by 1) */
    temp         = state[3][0];
    state[3][0]  = state[3][1];
    state[3][1]  = state[3][2];
    state[3][2]  = state[3][3];
    state[3][3]  = temp;
}

/* MixColumns: Mix columns in GF(2^8) */
static void mix_columns(uint8_t state[4][4]) {
    int i;
    uint8_t a, b, c, d, e;
    for (i = 0; i < 4; i++) {
        a = state[0][i]; b = state[1][i];
        c = state[2][i]; d = state[3][i];
        e = a ^ b ^ c ^ d;
        state[0][i] ^= e ^ xtime(a ^ b);
        state[1][i] ^= e ^ xtime(b ^ c);
        state[2][i] ^= e ^ xtime(c ^ d);
        state[3][i] ^= e ^ xtime(d ^ a);
    }
}

/* InvMixColumns */
static void inv_mix_columns(uint8_t state[4][4]) {
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; i++) {
        a = state[0][i]; b = state[1][i];
        c = state[2][i]; d = state[3][i];
        state[0][i] = gmul(a,0x0e) ^ gmul(b,0x0b) ^ gmul(c,0x0d) ^ gmul(d,0x09);
        state[1][i] = gmul(a,0x09) ^ gmul(b,0x0e) ^ gmul(c,0x0b) ^ gmul(d,0x0d);
        state[2][i] = gmul(a,0x0d) ^ gmul(b,0x09) ^ gmul(c,0x0e) ^ gmul(d,0x0b);
        state[3][i] = gmul(a,0x0b) ^ gmul(b,0x0d) ^ gmul(c,0x09) ^ gmul(d,0x0e);
    }
}

/* -----------------------------------------------------------------------
 * AES-256 Block Encrypt / Decrypt
 * ----------------------------------------------------------------------- */

void aes256_encrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_key) {
    int round;
    uint8_t state[4][4];
    int i, j;

    /* Load input into state matrix (column-major) */
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] = in[i * 4 + j];

    add_round_key(0, state, round_key);

    for (round = 1; round < AES_ROUNDS_256; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, round_key);
    }

    /* Final round (no MixColumns) */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(AES_ROUNDS_256, state, round_key);

    /* Store state to output */
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            out[i * 4 + j] = state[j][i];
}

void aes256_decrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_key) {
    int round;
    uint8_t state[4][4];
    int i, j;

    /* Load input into state matrix */
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] = in[i * 4 + j];

    add_round_key(AES_ROUNDS_256, state, round_key);

    for (round = AES_ROUNDS_256 - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(round, state, round_key);
        inv_mix_columns(state);
    }

    /* Final round */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(0, state, round_key);

    /* Store state to output */
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            out[i * 4 + j] = state[j][i];
}

/* -----------------------------------------------------------------------
 * CBC Mode (PKCS#7 Padding)
 * ----------------------------------------------------------------------- */

/* Returns padded length */
static size_t pkcs7_pad(uint8_t *buf, size_t len, size_t block_size) {
    uint8_t pad = (uint8_t)(block_size - (len % block_size));
    size_t i;
    for (i = len; i < len + pad; i++)
        buf[i] = pad;
    return len + pad;
}

/* Returns unpadded length */
static size_t pkcs7_unpad(uint8_t *buf, size_t len) {
    uint8_t pad = buf[len - 1];
    if (pad == 0 || pad > AES_BLOCK_SIZE) return len; /* invalid */
    return len - pad;
}

/* CBC Encrypt: plaintext -> ciphertext (caller must free result) */
uint8_t *aes256_cbc_encrypt(const uint8_t *plaintext, size_t pt_len,
                             const uint8_t *key, const uint8_t *iv,
                             size_t *ct_len) {
    uint8_t round_key[AES_KEY_EXP_SIZE];
    uint8_t *padded, *output;
    size_t padded_len, i, b;
    uint8_t prev[AES_BLOCK_SIZE];

    aes256_key_expansion(key, round_key);

    /* Pad plaintext */
    padded_len = pt_len + AES_BLOCK_SIZE; /* extra space for padding */
    padded = (uint8_t *)malloc(padded_len);
    memcpy(padded, plaintext, pt_len);
    padded_len = pkcs7_pad(padded, pt_len, AES_BLOCK_SIZE);

    output = (uint8_t *)malloc(padded_len);
    memcpy(prev, iv, AES_BLOCK_SIZE);

    for (b = 0; b < padded_len; b += AES_BLOCK_SIZE) {
        /* XOR with IV / previous cipherblock */
        for (i = 0; i < AES_BLOCK_SIZE; i++)
            padded[b + i] ^= prev[i];
        aes256_encrypt_block(padded + b, output + b, round_key);
        memcpy(prev, output + b, AES_BLOCK_SIZE);
    }

    free(padded);
    *ct_len = padded_len;
    return output;
}

/* CBC Decrypt */
uint8_t *aes256_cbc_decrypt(const uint8_t *ciphertext, size_t ct_len,
                             const uint8_t *key, const uint8_t *iv,
                             size_t *pt_len) {
    uint8_t round_key[AES_KEY_EXP_SIZE];
    uint8_t *output;
    size_t b, i;
    uint8_t prev[AES_BLOCK_SIZE], temp[AES_BLOCK_SIZE];

    aes256_key_expansion(key, round_key);
    output = (uint8_t *)malloc(ct_len);
    memcpy(prev, iv, AES_BLOCK_SIZE);

    for (b = 0; b < ct_len; b += AES_BLOCK_SIZE) {
        aes256_decrypt_block(ciphertext + b, output + b, round_key);
        for (i = 0; i < AES_BLOCK_SIZE; i++)
            output[b + i] ^= prev[i];
        memcpy(temp, ciphertext + b, AES_BLOCK_SIZE);
        memcpy(prev, temp, AES_BLOCK_SIZE);
    }

    *pt_len = pkcs7_unpad(output, ct_len);
    return output;
}

/* -----------------------------------------------------------------------
 * Utility helpers
 * ----------------------------------------------------------------------- */

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%-20s : ", label);
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

/* -----------------------------------------------------------------------
 * Demo / main
 * ----------------------------------------------------------------------- */

int main(void) {
    /* 256-bit key (32 bytes) */
    uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    /* 128-bit IV */
    uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    const char *message = "Hello, AES-256-CBC! This message is longer than one block.";
    size_t msg_len = strlen(message);
    size_t ct_len, pt_len;
    uint8_t *ciphertext, *decrypted;
    clock_t start, end;
    double enc_time, dec_time;
    int i;

    printf("==========================================================\n");
    printf("         AES-256 (CBC Mode) - Demonstration               \n");
    printf("==========================================================\n\n");

    printf("Plaintext : \"%s\"\n", message);
    printf("Length    : %zu bytes\n\n", msg_len);

    print_hex("Key (256-bit)", key, 32);
    print_hex("IV  (128-bit)", iv, 16);
    printf("\n");

    /* ---- NIST Test Vector (ECB single block) ---- */
    {
        uint8_t tv_key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        uint8_t tv_pt[16] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };
        /* NIST expected CT: f3eed1bdb5d2a03c064b5a7e3db181f8 */
        uint8_t tv_ct[16];
        uint8_t tv_exp[16] = {
            0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
            0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
        };
        uint8_t tv_rk[AES_KEY_EXP_SIZE];
        aes256_key_expansion(tv_key, tv_rk);
        aes256_encrypt_block(tv_pt, tv_ct, tv_rk);

        printf("---- NIST ECB Test Vector ----\n");
        print_hex("Plaintext ", tv_pt, 16);
        print_hex("Expected  ", tv_exp, 16);
        print_hex("Got       ", tv_ct,  16);
        printf("Test Vector: %s\n\n",
               memcmp(tv_ct, tv_exp, 16) == 0 ? "PASSED ✓" : "FAILED ✗");
    }

    /* ---- CBC Encrypt ---- */
    start = clock();
    ciphertext = aes256_cbc_encrypt((const uint8_t *)message, msg_len, key, iv, &ct_len);
    end = clock();
    enc_time = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    printf("---- CBC Encryption ----\n");
    print_hex("Ciphertext", ciphertext, ct_len);
    printf("Encrypted length  : %zu bytes\n", ct_len);
    printf("Encryption time   : %.4f ms\n\n", enc_time);

    /* ---- CBC Decrypt ---- */
    start = clock();
    decrypted = aes256_cbc_decrypt(ciphertext, ct_len, key, iv, &pt_len);
    end = clock();
    dec_time = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    decrypted[pt_len] = '\0'; /* null-terminate for display */

    printf("---- CBC Decryption ----\n");
    printf("Decrypted text    : \"%s\"\n", (char *)decrypted);
    printf("Decryption time   : %.4f ms\n\n", dec_time);
    printf("Integrity check   : %s\n",
           (pt_len == msg_len && memcmp(decrypted, message, msg_len) == 0)
           ? "PASSED ✓" : "FAILED ✗");

    /* ---- Security summary ---- */
    printf("\n==========================================================\n");
    printf("                 AES-256 Security Summary                 \n");
    printf("==========================================================\n");
    printf("Key Size          : 256 bits\n");
    printf("Block Size        : 128 bits\n");
    printf("Number of Rounds  : 14\n");
    printf("Mode of Operation : CBC (Cipher Block Chaining)\n");
    printf("Key Space         : 2^256 ≈ 1.16 × 10^77 possible keys\n");
    printf("Brute-force       : Computationally infeasible (classical)\n");
    printf("Post-Quantum      : Grover's reduces to 2^128 effective bits\n");

    free(ciphertext);
    free(decrypted);
    return 0;
}
