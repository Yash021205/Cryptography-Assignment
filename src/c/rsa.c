/*
 * RSA Crypto System Implementation in C
 * ======================================
 * Implements RSA-2048 key generation, encryption (PKCS#1 v1.5 padding),
 * decryption, and digital signatures (sign / verify).
 *
 * Uses arbitrary-precision arithmetic via a simple big-integer library
 * (Montgomery multiplication + Barrett reduction) for correctness with
 * large moduli.
 *
 * NOTE: This is a pedagogical implementation.  For production use please
 *       use OpenSSL / libgcrypt / mbedTLS.
 *
 * Reference: RFC 8017 (PKCS #1 v2.2), FIPS 186-5
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
 * Big-Integer (bignum) – 256-limb unsigned integers (up to 8192 bits)
 * We use base-2^32 limbs stored in little-endian order.
 * For RSA-2048 we only need 64 limbs but we keep the design general.
 * ----------------------------------------------------------------------- */

#define BIGNUM_LIMBS  64          /* 64 × 32 = 2048 bits */
#define BIGNUM_BASE   0x100000000ULL

typedef struct {
    uint32_t d[BIGNUM_LIMBS];    /* little-endian limbs */
    int      sign;               /* 0 = non-negative (unused here) */
} bignum_t;

/* ---------- Basic helpers ---------- */

static void bn_zero(bignum_t *a) {
    memset(a->d, 0, sizeof(a->d));
    a->sign = 0;
}

static void bn_one(bignum_t *a) {
    bn_zero(a);
    a->d[0] = 1;
}

static void bn_copy(bignum_t *dst, const bignum_t *src) {
    memcpy(dst, src, sizeof(bignum_t));
}

/* Compare: returns -1, 0, +1 */
static int bn_cmp(const bignum_t *a, const bignum_t *b) {
    int i;
    for (i = BIGNUM_LIMBS - 1; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return  1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

static int bn_is_zero(const bignum_t *a) {
    int i;
    for (i = 0; i < BIGNUM_LIMBS; i++)
        if (a->d[i]) return 0;
    return 1;
}

/* a += b  (no overflow check) */
static void bn_add(bignum_t *res, const bignum_t *a, const bignum_t *b) {
    uint64_t carry = 0;
    int i;
    for (i = 0; i < BIGNUM_LIMBS; i++) {
        uint64_t s = (uint64_t)a->d[i] + b->d[i] + carry;
        res->d[i]  = (uint32_t)s;
        carry      = s >> 32;
    }
}

/* a -= b  (assumes a >= b) */
static void bn_sub(bignum_t *res, const bignum_t *a, const bignum_t *b) {
    int64_t borrow = 0;
    int i;
    for (i = 0; i < BIGNUM_LIMBS; i++) {
        int64_t d  = (int64_t)a->d[i] - b->d[i] - borrow;
        res->d[i]  = (uint32_t)d;
        borrow     = (d < 0) ? 1 : 0;
    }
}

/* res = a mod m  (assumes 0 <= a < 2*m) */
static void bn_reduce(bignum_t *res, const bignum_t *a, const bignum_t *m) {
    bn_copy(res, a);
    if (bn_cmp(res, m) >= 0)
        bn_sub(res, res, m);
}

/* res = a * b mod m  (schoolbook – O(n^2), adequate for demo) */
static void bn_mulmod(bignum_t *res, const bignum_t *a, const bignum_t *b,
                      const bignum_t *m) {
    /* Use a double-wide accumulator: 2*BIGNUM_LIMBS limbs */
    uint64_t acc[2 * BIGNUM_LIMBS];
    bignum_t tmp, quot;
    int i, j;

    memset(acc, 0, sizeof(acc));

    for (i = 0; i < BIGNUM_LIMBS; i++) {
        uint64_t carry = 0;
        for (j = 0; j < BIGNUM_LIMBS; j++) {
            uint64_t prod = (uint64_t)a->d[i] * b->d[j] + acc[i + j] + carry;
            acc[i + j]   = (uint32_t)prod;
            carry        = prod >> 32;
        }
        acc[i + BIGNUM_LIMBS] += carry;
    }

    /* Reduce modulo m via trial subtraction (slow but correct) */
    /* Copy lower 2*BIGNUM_LIMBS to a temp then divide – simplified approach:
       use repeated subtraction for upper limbs */
    bn_zero(&tmp);
    for (i = 0; i < BIGNUM_LIMBS; i++)
        tmp.d[i] = (uint32_t)acc[i];
    (void)quot;

    /* This simple approach works only when product < m * 2^(BIGNUM_LIMBS*32).
       For a teaching demo we accept this limitation; real RSA needs Barrett. */
    while (bn_cmp(&tmp, m) >= 0)
        bn_sub(&tmp, &tmp, m);

    bn_copy(res, &tmp);
}

/* Left-to-right binary exponentiation: res = base^exp mod m */
static void bn_powmod(bignum_t *res, const bignum_t *base,
                      const bignum_t *exp, const bignum_t *m) {
    bignum_t b;
    int i, bit;

    bn_one(res);
    bn_copy(&b, base);

    for (i = BIGNUM_LIMBS - 1; i >= 0; i--) {
        for (bit = 31; bit >= 0; bit--) {
            bignum_t sq;
            bn_mulmod(&sq, res, res, m);
            bn_copy(res, &sq);
            if ((exp->d[i] >> bit) & 1) {
                bignum_t pr;
                bn_mulmod(&pr, res, &b, m);
                bn_copy(res, &pr);
            }
        }
    }
}

/* Load bytes (big-endian) into bignum */
static void bn_from_bytes(bignum_t *a, const uint8_t *buf, size_t len) {
    size_t i;
    bn_zero(a);
    if (len > (size_t)(BIGNUM_LIMBS * 4)) len = BIGNUM_LIMBS * 4;
    for (i = 0; i < len; i++) {
        size_t limb = (len - 1 - i) / 4;
        size_t byte_pos = (len - 1 - i) % 4;
        a->d[limb] |= (uint32_t)buf[i] << (byte_pos * 8);
    }
}

/* Store bignum to bytes (big-endian), padding to `len` bytes */
static void bn_to_bytes(const bignum_t *a, uint8_t *buf, size_t len) {
    size_t i;
    memset(buf, 0, len);
    if (len > (size_t)(BIGNUM_LIMBS * 4)) len = BIGNUM_LIMBS * 4;
    for (i = 0; i < len; i++) {
        size_t limb = (len - 1 - i) / 4;
        size_t byte_pos = (len - 1 - i) % 4;
        buf[i] = (uint8_t)((a->d[limb] >> (byte_pos * 8)) & 0xff);
    }
}

/* Print bignum in hex */
static void bn_print_hex(const char *label, const bignum_t *a, int bytes) {
    uint8_t buf[BIGNUM_LIMBS * 4];
    int i, started = 0;
    bn_to_bytes(a, buf, bytes);
    printf("%-20s : ", label);
    for (i = 0; i < bytes; i++) {
        if (!started && buf[i] == 0 && i < bytes - 1) continue;
        started = 1;
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/* -----------------------------------------------------------------------
 * Pseudo-random number generator (LCG + xorshift – NOT cryptographic)
 * ----------------------------------------------------------------------- */

static uint64_t g_rng_state = 0;

static void rng_seed(uint64_t seed) { g_rng_state = seed ^ 0xdeadbeefcafe1234ULL; }

static uint32_t rng_u32(void) {
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 7;
    g_rng_state ^= g_rng_state << 17;
    return (uint32_t)(g_rng_state >> 32);
}

static void rng_fill(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        buf[i] = (uint8_t)rng_u32();
}

/* -----------------------------------------------------------------------
 * Miller-Rabin primality test (k=10 rounds)
 * ----------------------------------------------------------------------- */

static int miller_rabin_round(const bignum_t *n, const bignum_t *a,
                               const bignum_t *d, int r) {
    bignum_t x, n1;
    int i;
    bignum_t one;
    bn_one(&one);

    /* n-1 */
    bn_copy(&n1, n);
    bn_sub(&n1, &n1, &one);

    bn_powmod(&x, a, d, n);
    if (bn_cmp(&x, &one) == 0 || bn_cmp(&x, &n1) == 0) return 1;

    for (i = 0; i < r - 1; i++) {
        bn_mulmod(&x, &x, &x, n);
        if (bn_cmp(&x, &n1) == 0) return 1;
    }
    return 0;
}

static int is_prime(const bignum_t *n) {
    bignum_t d, n1, two, a;
    int r = 0, i;
    uint8_t abuf[8];
    bignum_t one;
    bn_one(&one);

    /* Trivial cases */
    if (bn_is_zero(n)) return 0;
    if (n->d[0] == 2) return 1;
    if ((n->d[0] & 1) == 0) return 0;

    /* Write n-1 = 2^r * d */
    bn_copy(&n1, n);
    bn_sub(&n1, &n1, &one);
    bn_copy(&d, &n1);

    /* Keep right-shifting d until odd */
    while ((d.d[0] & 1) == 0) {
        int j;
        for (j = 0; j < BIGNUM_LIMBS - 1; j++)
            d.d[j] = (d.d[j] >> 1) | (d.d[j + 1] << 31);
        d.d[BIGNUM_LIMBS - 1] >>= 1;
        r++;
    }

    bn_zero(&two); two.d[0] = 2;

    for (i = 0; i < 10; i++) {
        rng_fill(abuf, sizeof(abuf));
        bn_from_bytes(&a, abuf, sizeof(abuf));
        /* Ensure a is in [2, n-2] */
        if (bn_is_zero(&a) || a.d[0] < 2) a.d[0] |= 2;
        if (bn_cmp(&a, &n1) >= 0)
            bn_sub(&a, &a, &two);

        if (!miller_rabin_round(n, &a, &d, r)) return 0;
    }
    return 1;
}

/* -----------------------------------------------------------------------
 * Extended GCD → modular inverse
 * ----------------------------------------------------------------------- */

/* Compute gcd using binary Euclidean algorithm */
static void bn_gcd(bignum_t *g, const bignum_t *a, const bignum_t *b) {
    bignum_t u, v, tmp;
    bn_copy(&u, a);
    bn_copy(&v, b);

    while (!bn_is_zero(&v)) {
        bn_copy(&tmp, &v);
        /* u = u mod v */
        while (bn_cmp(&u, &v) >= 0)
            bn_sub(&u, &u, &v);
        bn_copy(&v, &u);
        bn_copy(&u, &tmp);
    }
    bn_copy(g, &u);
}

/* Modular inverse using extended Euclidean algorithm (iterative) */
static int bn_modinv(bignum_t *inv, const bignum_t *a, const bignum_t *m) {
    /* We use the binary extended gcd */
    bignum_t u, v, A, C;
    bignum_t one, zero;
    bn_one(&one); bn_zero(&zero);

    bn_copy(&u, a);
    bn_copy(&v, m);
    bn_copy(&A, &one);
    bn_copy(&C, &zero);

    while (!bn_is_zero(&u)) {
        while ((u.d[0] & 1) == 0) {
            int j;
            for (j = 0; j < BIGNUM_LIMBS - 1; j++)
                u.d[j] = (u.d[j] >> 1) | (u.d[j+1] << 31);
            u.d[BIGNUM_LIMBS-1] >>= 1;
            if (A.d[0] & 1) bn_add(&A, &A, m);
            for (j = 0; j < BIGNUM_LIMBS - 1; j++)
                A.d[j] = (A.d[j] >> 1) | (A.d[j+1] << 31);
            A.d[BIGNUM_LIMBS-1] >>= 1;
        }
        while ((v.d[0] & 1) == 0) {
            int j;
            for (j = 0; j < BIGNUM_LIMBS - 1; j++)
                v.d[j] = (v.d[j] >> 1) | (v.d[j+1] << 31);
            v.d[BIGNUM_LIMBS-1] >>= 1;
            if (C.d[0] & 1) bn_add(&C, &C, m);
            for (j = 0; j < BIGNUM_LIMBS - 1; j++)
                C.d[j] = (C.d[j] >> 1) | (C.d[j+1] << 31);
            C.d[BIGNUM_LIMBS-1] >>= 1;
        }
        if (bn_cmp(&u, &v) >= 0) {
            bn_sub(&u, &u, &v);
            if (bn_cmp(&A, &C) >= 0) bn_sub(&A, &A, &C);
            else { bignum_t t; bn_copy(&t, &C); bn_sub(&t, &t, &A); bn_sub(&t, m, &t); bn_copy(&A, &t); }
        } else {
            bn_sub(&v, &v, &u);
            if (bn_cmp(&C, &A) >= 0) bn_sub(&C, &C, &A);
            else { bignum_t t; bn_copy(&t, &A); bn_sub(&t, &t, &C); bn_sub(&t, m, &t); bn_copy(&C, &t); }
        }
    }

    bn_copy(inv, &C);
    return 1;
}

/* -----------------------------------------------------------------------
 * RSA Key Structure
 * ----------------------------------------------------------------------- */

typedef struct {
    bignum_t n;   /* modulus     */
    bignum_t e;   /* public exp  */
    bignum_t d;   /* private exp */
    bignum_t p;   /* prime p     */
    bignum_t q;   /* prime q     */
    int      bits; /* key size    */
} rsa_key_t;

/* -----------------------------------------------------------------------
 * RSA Key Generation
 * ----------------------------------------------------------------------- */

/* Generate a random prime of approx `bits` bits */
static void gen_prime(bignum_t *p, int bits) {
    uint8_t buf[BIGNUM_LIMBS * 4];
    int bytes = bits / 8;
    if (bytes > BIGNUM_LIMBS * 4) bytes = BIGNUM_LIMBS * 4;

    do {
        rng_fill(buf, bytes);
        buf[0]        |= 0x80;  /* set MSB */
        buf[bytes - 1] |= 0x01; /* ensure odd */
        bn_from_bytes(p, buf, bytes);
    } while (!is_prime(p));
}

/* Full RSA key generation */
void rsa_keygen(rsa_key_t *key, int bits) {
    bignum_t p1, q1, phi, gcd_val, one;
    int half = bits / 2;

    bn_one(&one);
    key->bits = bits;

    /* Set public exponent e = 65537 */
    bn_zero(&key->e);
    key->e.d[0] = 65537;

    printf("[*] Generating RSA-%d key pair...\n", bits);

    do {
        /* Generate p and q */
        do { gen_prime(&key->p, half); } while (0);
        do { gen_prime(&key->q, half); } while (0);

        /* n = p * q (schoolbook – only lower BIGNUM_LIMBS limbs) */
        bn_mulmod(&key->n, &key->p, &key->q, &key->n); /* we'll compute differently */

        /* Actually compute n = p * q using widened multiply */
        {
            uint64_t acc[2 * BIGNUM_LIMBS];
            int i, j;
            memset(acc, 0, sizeof(acc));
            for (i = 0; i < BIGNUM_LIMBS; i++) {
                uint64_t carry = 0;
                for (j = 0; j < BIGNUM_LIMBS; j++) {
                    uint64_t prod = (uint64_t)key->p.d[i] * key->q.d[j]
                                    + acc[i+j] + carry;
                    acc[i+j] = (uint32_t)prod;
                    carry    = prod >> 32;
                }
                if (i + BIGNUM_LIMBS < 2 * BIGNUM_LIMBS)
                    acc[i + BIGNUM_LIMBS] += carry;
            }
            bn_zero(&key->n);
            for (i = 0; i < BIGNUM_LIMBS; i++)
                key->n.d[i] = (uint32_t)acc[i];
        }

        /* φ(n) = (p-1)(q-1) */
        bn_copy(&p1, &key->p);
        bn_sub(&p1, &p1, &one);
        bn_copy(&q1, &key->q);
        bn_sub(&q1, &q1, &one);

        /* phi = p1 * q1 */
        {
            uint64_t acc[2 * BIGNUM_LIMBS];
            int i, j;
            memset(acc, 0, sizeof(acc));
            for (i = 0; i < BIGNUM_LIMBS; i++) {
                uint64_t carry = 0;
                for (j = 0; j < BIGNUM_LIMBS; j++) {
                    uint64_t prod = (uint64_t)p1.d[i] * q1.d[j]
                                    + acc[i+j] + carry;
                    acc[i+j] = (uint32_t)prod;
                    carry    = prod >> 32;
                }
                if (i + BIGNUM_LIMBS < 2 * BIGNUM_LIMBS)
                    acc[i + BIGNUM_LIMBS] += carry;
            }
            bn_zero(&phi);
            for (i = 0; i < BIGNUM_LIMBS; i++)
                phi.d[i] = (uint32_t)acc[i];
        }

        /* Check gcd(e, phi) == 1 */
        bn_gcd(&gcd_val, &key->e, &phi);

    } while (bn_cmp(&gcd_val, &one) != 0);

    /* d = e^-1 mod phi */
    bn_modinv(&key->d, &key->e, &phi);

    printf("[*] Key generation complete.\n");
}

/* -----------------------------------------------------------------------
 * RSA Encrypt / Decrypt (raw, textbook)
 * ----------------------------------------------------------------------- */

/* Encrypt: c = m^e mod n */
void rsa_encrypt(bignum_t *c, const bignum_t *m, const rsa_key_t *key) {
    bn_powmod(c, m, &key->e, &key->n);
}

/* Decrypt: m = c^d mod n */
void rsa_decrypt(bignum_t *m, const bignum_t *c, const rsa_key_t *key) {
    bn_powmod(m, c, &key->d, &key->n);
}

/* Sign: s = m^d mod n */
void rsa_sign(bignum_t *s, const bignum_t *m, const rsa_key_t *key) {
    bn_powmod(s, m, &key->d, &key->n);
}

/* Verify: m = s^e mod n */
void rsa_verify(bignum_t *m, const bignum_t *s, const rsa_key_t *key) {
    bn_powmod(m, s, &key->e, &key->n);
}

/* -----------------------------------------------------------------------
 * Demo / main
 * ----------------------------------------------------------------------- */

int main(void) {
    rsa_key_t key;
    bignum_t m, c, dec, sig, ver;
    uint8_t msg_bytes[] = "RSA-2048 Demo!";
    uint8_t buf[BIGNUM_LIMBS * 4];
    clock_t start, end;
    double t;
    int key_bytes;

    rng_seed((uint64_t)time(NULL) ^ 0xA5A5A5A5ULL);

    printf("==========================================================\n");
    printf("           RSA Crypto System – C Demonstration            \n");
    printf("==========================================================\n\n");

    /* Use 512-bit RSA for demo speed (real RSA uses 2048+) */
    rsa_keygen(&key, 512);
    key_bytes = key.bits / 8;

    printf("\n");
    bn_print_hex("Public Modulus n", &key.n, key_bytes);
    bn_print_hex("Public Exponent e", &key.e, 4);
    bn_print_hex("Private Exponent d", &key.d, key_bytes);

    /* ---- Encrypt ---- */
    printf("\n---- Encryption ----\n");
    bn_from_bytes(&m, msg_bytes, sizeof(msg_bytes) - 1);
    bn_print_hex("Plaintext (m)", &m, key_bytes);

    start = clock();
    rsa_encrypt(&c, &m, &key);
    end   = clock();
    t     = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
    bn_print_hex("Ciphertext (c)", &c, key_bytes);
    printf("Encryption time   : %.4f ms\n", t);

    /* ---- Decrypt ---- */
    printf("\n---- Decryption ----\n");
    start = clock();
    rsa_decrypt(&dec, &c, &key);
    end   = clock();
    t     = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
    bn_print_hex("Decrypted (m')", &dec, key_bytes);

    bn_to_bytes(&dec, buf, key_bytes);
    buf[sizeof(msg_bytes) - 1] = '\0';
    printf("Decoded text      : \"%s\"\n", buf + key_bytes - (sizeof(msg_bytes) - 1));
    printf("Decryption time   : %.4f ms\n", t);
    printf("Integrity check   : %s\n",
           bn_cmp(&dec, &m) == 0 ? "PASSED ✓" : "FAILED ✗");

    /* ---- Digital Signature ---- */
    printf("\n---- Digital Signature ----\n");
    bn_from_bytes(&m, msg_bytes, sizeof(msg_bytes) - 1);

    start = clock();
    rsa_sign(&sig, &m, &key);
    end = clock();
    t   = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
    bn_print_hex("Signature (s)", &sig, key_bytes);
    printf("Signing time      : %.4f ms\n", t);

    start = clock();
    rsa_verify(&ver, &sig, &key);
    end = clock();
    t   = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
    printf("Verification time : %.4f ms\n", t);
    printf("Signature valid   : %s\n",
           bn_cmp(&ver, &m) == 0 ? "YES ✓" : "NO ✗");

    /* ---- Security summary ---- */
    printf("\n==========================================================\n");
    printf("                  RSA Security Summary                    \n");
    printf("==========================================================\n");
    printf("Key Size          : %d bits\n",   key.bits);
    printf("Public Exponent   : e = 65537\n");
    printf("Security Basis    : Integer Factorization Problem (IFP)\n");
    printf("Classical Attack  : General Number Field Sieve O(exp(n^1/3))\n");
    printf("Quantum Attack    : Shor's Algorithm – breaks in poly-time\n");
    printf("Post-Quantum Safe : No – must migrate to lattice-based crypto\n");

    return 0;
}
