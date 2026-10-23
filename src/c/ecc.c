/*
 * Elliptic Curve Cryptography (ECC) – secp256k1
 * ===============================================
 * Implements:
 *   - Point addition and doubling on secp256k1 (y² = x³ + 7 over Fp)
 *   - Scalar multiplication (double-and-add) in affine coordinates
 *   - ECDH key exchange
 *   - ECDSA sign and verify
 *
 * Domain parameters: secp256k1 (same as Bitcoin / Ethereum)
 * Reference: SEC 2 v2.0, FIPS 186-4
 *
 * NOTE: Uses 128-bit (two uint64_t) limbs for correct 256-bit arithmetic.
 *       Pure C99, no external library required.
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
 * 256-bit integers stored as 4 × uint64_t, little-endian
 * We use 64-bit limbs for cleaner carries.
 * ----------------------------------------------------------------------- */

#define NLIMBS64 4   /* 4 × 64 = 256 bits */

typedef struct { uint64_t v[NLIMBS64]; } u256;

/* ---------- secp256k1 domain parameters ---------- */

/* p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F */
static const u256 SECP_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};

/* n (order) = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 */
static const u256 SECP_N = {{
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
}};

/* Generator Gx */
static const u256 SECP_GX = {{
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
}};

/* Generator Gy */
static const u256 SECP_GY = {{
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
}};

/* -----------------------------------------------------------------------
 * Basic 256-bit arithmetic
 * ----------------------------------------------------------------------- */

static void u256_zero(u256 *a) { memset(a->v, 0, sizeof(a->v)); }
static void u256_one(u256 *a)  { u256_zero(a); a->v[0] = 1; }
static void u256_copy(u256 *d, const u256 *s) { memcpy(d, s, sizeof(u256)); }

static int u256_iszero(const u256 *a) {
    return !a->v[0] && !a->v[1] && !a->v[2] && !a->v[3];
}

static int u256_cmp(const u256 *a, const u256 *b) {
    int i;
    for (i = NLIMBS64 - 1; i >= 0; i--) {
        if (a->v[i] > b->v[i]) return  1;
        if (a->v[i] < b->v[i]) return -1;
    }
    return 0;
}

/* a += b, return carry */
static uint64_t u256_add(u256 *r, const u256 *a, const u256 *b) {
    __uint128_t carry = 0; int i;
    for (i = 0; i < NLIMBS64; i++) {
        __uint128_t s = (__uint128_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint64_t)s;
        carry   = s >> 64;
    }
    return (uint64_t)carry;
}

/* a -= b, return borrow (a must be >= b) */
static void u256_sub(u256 *r, const u256 *a, const u256 *b) {
    __int128_t borrow = 0; int i;
    for (i = 0; i < NLIMBS64; i++) {
        __int128_t d = (__int128_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint64_t)d;
        borrow  = (d < 0) ? 1 : 0;
    }
}

/* r = (a + b) mod m */
static void u256_addmod(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    uint64_t carry = u256_add(r, a, b);
    if (carry || u256_cmp(r, m) >= 0)
        u256_sub(r, r, m);
}

/* r = (a - b) mod m */
static void u256_submod(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
    if (u256_cmp(a, b) >= 0) {
        u256_sub(r, a, b);
    } else {
        u256 tmp;
        u256_add(&tmp, a, m);
        u256_sub(r, &tmp, b);
    }
}

/*
 * 256-bit modular multiplication for secp256k1 prime p.
 * Uses the special form: p = 2^256 - 2^32 - 977
 * So: 2^256 ≡ 2^32 + 977 (mod p)
 *
 * Algorithm:
 *   1. Compute 512-bit product c = a * b using schoolbook with 128-bit intermediate.
 *   2. Fold upper 256 bits using identity: high * 2^256 ≡ high * (2^32 + 977) mod p
 *   3. Repeat once more for the carry.
 *   4. Final conditional subtraction.
 */
static void u256_mulmod_p(u256 *r, const u256 *a, const u256 *b) {
    /* 512-bit product stored as 8 × uint64_t */
    __uint128_t acc[8];
    u256 lo, hi;
    int i, j;

    memset(acc, 0, sizeof(acc));
    for (i = 0; i < NLIMBS64; i++) {
        __uint128_t carry = 0;
        for (j = 0; j < NLIMBS64; j++) {
            __uint128_t prod = (__uint128_t)a->v[i] * b->v[j] + acc[i+j] + carry;
            acc[i+j] = (uint64_t)prod;
            carry     = prod >> 64;
        }
        acc[i + NLIMBS64] += carry;
    }

    /* lo = lower 256 bits, hi = upper 256 bits */
    for (i = 0; i < NLIMBS64; i++) {
        lo.v[i] = (uint64_t)acc[i];
        hi.v[i] = (uint64_t)acc[i + NLIMBS64];
    }

    /* Fold: result = lo + hi * (2^32 + 977) */
    /* hi * 2^32: shift hi left by 32 bits */
    u256 hi_shifted;
    hi_shifted.v[0] = hi.v[0] << 32;
    hi_shifted.v[1] = (hi.v[1] << 32) | (hi.v[0] >> 32);
    hi_shifted.v[2] = (hi.v[2] << 32) | (hi.v[1] >> 32);
    hi_shifted.v[3] = (hi.v[3] << 32) | (hi.v[2] >> 32);
    /* extra = hi.v[3] >> 32 which would overflow – handle as second fold */

    /* hi * 977 */
    u256 hi_977; __uint128_t carry977 = 0;
    for (i = 0; i < NLIMBS64; i++) {
        __uint128_t s = (__uint128_t)hi.v[i] * 977 + carry977;
        hi_977.v[i] = (uint64_t)s;
        carry977    = s >> 64;
    }
    /* carry977 may be non-zero – fold again below */

    /* result = lo + hi_shifted + hi_977 */
    u256 tmp;
    uint64_t c1 = u256_add(&tmp, &lo, &hi_shifted);
    uint64_t c2; {
        __uint128_t s2 = (__uint128_t)tmp.v[0] + hi_977.v[0];
        tmp.v[0] = (uint64_t)s2; c2 = (uint64_t)(s2 >> 64);
        for (i = 1; i < NLIMBS64; i++) {
            __uint128_t s3 = (__uint128_t)tmp.v[i] + hi_977.v[i] + c2;
            tmp.v[i] = (uint64_t)s3; c2 = (uint64_t)(s3 >> 64);
        }
    }
    c1 += c2;

    /* c1 and carry977 are extra bits above 256 → fold once more */
    /* extra = c1 * (2^32 + 977) + carry977 * 977 ... simplified: add c1*(2^32+977) */
    if (c1 || carry977) {
        __uint128_t extra = (__uint128_t)c1 * (0x100000000ULL + 977) + carry977 * 977;
        __uint128_t carry_e = extra;
        for (i = 0; i < NLIMBS64 && carry_e; i++) {
            __uint128_t s = (__uint128_t)tmp.v[i] + (uint64_t)carry_e;
            tmp.v[i] = (uint64_t)s;
            carry_e  = s >> 64;
        }
    }

    /* Final conditional subtraction */
    if (u256_cmp(&tmp, &SECP_P) >= 0)
        u256_sub(&tmp, &tmp, &SECP_P);

    u256_copy(r, &tmp);
}

/* Modular multiplication mod n (order) – fast schoolbook + trial reduction */
static void u256_mulmod_n(u256 *r, const u256 *a, const u256 *b) {
    /* 512-bit product, then reduce mod n via trial subtraction of n*2^(32k) */
    __uint128_t acc[8];
    u256 tmp;
    int i, j;
    memset(acc, 0, sizeof(acc));
    for (i = 0; i < NLIMBS64; i++) {
        __uint128_t carry = 0;
        for (j = 0; j < NLIMBS64; j++) {
            __uint128_t prod = (__uint128_t)a->v[i] * b->v[j] + acc[i+j] + carry;
            acc[i+j] = (uint64_t)prod;
            carry     = prod >> 64;
        }
        acc[i + NLIMBS64] += carry;
    }
    /* Reduce upper half: upper[i] * 2^(64*(i+4)) mod n */
    /* Since n is close to 2^256, we do trial subtraction */
    /* Reconstruct as 512-bit and do iterative subtraction - simplified */
    u256_zero(&tmp);
    for (i = 0; i < NLIMBS64; i++) tmp.v[i] = (uint64_t)acc[i];
    /* Add upper contribution using: 2^256 mod n = 2^256 - n + n = ... iterate */
    /* 2^256 = n + (2^256 - n), where 2^256 - n = 0x14551231950b75fc4402da1732fc9bebf */
    /* Simpler: use repeated subtraction of n for upper limbs */
    {
        u256 upper;
        for (i = 0; i < NLIMBS64; i++) upper.v[i] = (uint64_t)acc[i + NLIMBS64];
        /* We need to add upper * 2^256 mod n */
        /* 2^256 mod n = 2^256 - n (since n < 2^256) */
        /* = 0x14551231950b75fc4402da1732fc9bebull ... first limb */
        /* Better: for each bit of upper, add 2^256 mod n */
        /* Even simpler: just do it bit by bit like a big-integer modmul */
        if (!u256_iszero(&upper)) {
            /* compute upper * (2^256 mod n) mod n */
            /* 2^256 mod n: subtract n from 2^256 */
            u256 pow256_mod_n;
            /* 2^256 = n + r where r = 2^256 - n */
            /* n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 */
            /* 2^256 - n = 0x14551231950b75fc4402da1732fc9bebf */
            pow256_mod_n.v[0] = 0x402DA1732FC9BEBFULL;
            pow256_mod_n.v[1] = 0x4551231950B75FC4ULL;
            pow256_mod_n.v[2] = 0x0000000000000001ULL;
            pow256_mod_n.v[3] = 0x0000000000000000ULL;
            /* contribution = upper * pow256_mod_n mod n */
            /* use binary method for this smaller multiplication */
            u256 contrib; u256_zero(&contrib);
            u256 base; u256_copy(&base, &pow256_mod_n);
            for (i = NLIMBS64 - 1; i >= 0; i--) {
                int bit;
                for (bit = 63; bit >= 0; bit--) {
                    u256 t2; uint64_t c2 = u256_add(&t2, &contrib, &contrib);
                    if (c2 || u256_cmp(&t2, &SECP_N) >= 0) u256_sub(&t2, &t2, &SECP_N);
                    u256_copy(&contrib, &t2);
                    if ((upper.v[i] >> bit) & 1)
                        u256_addmod(&contrib, &contrib, &base, &SECP_N);
                }
            }
            u256_addmod(&tmp, &tmp, &contrib, &SECP_N);
        }
    }
    /* Final reduction */
    if (u256_cmp(&tmp, &SECP_N) >= 0) u256_sub(&tmp, &tmp, &SECP_N);
    u256_copy(r, &tmp);
}

/* r = a^-1 mod p using Fermat: a^(p-2) mod p */
static void u256_inv_p(u256 *r, const u256 *a) {
    u256 exp, result, base;
    int i, bit;

    /* exp = p - 2 */
    u256_copy(&exp, &SECP_P);
    {
        __int128_t borrow = 2;
        for (i = 0; i < NLIMBS64 && borrow; i++) {
            __int128_t d = (__int128_t)exp.v[i] - borrow;
            exp.v[i] = (uint64_t)d;
            borrow   = (d < 0) ? 1 : 0;
        }
    }
    u256_one(&result);
    u256_copy(&base, a);

    for (i = NLIMBS64 - 1; i >= 0; i--) {
        for (bit = 63; bit >= 0; bit--) {
            u256 sq; u256_mulmod_p(&sq, &result, &result); u256_copy(&result, &sq);
            if ((exp.v[i] >> bit) & 1) {
                u256 pr; u256_mulmod_p(&pr, &result, &base); u256_copy(&result, &pr);
            }
        }
    }
    u256_copy(r, &result);
}

/* r = a^-1 mod n */
static void u256_inv_n(u256 *r, const u256 *a) {
    u256 exp, result, base;
    int i, bit;

    /* exp = n - 2 */
    u256_copy(&exp, &SECP_N);
    {
        __int128_t borrow = 2;
        for (i = 0; i < NLIMBS64 && borrow; i++) {
            __int128_t d = (__int128_t)exp.v[i] - borrow;
            exp.v[i] = (uint64_t)d;
            borrow   = (d < 0) ? 1 : 0;
        }
    }
    u256_one(&result);
    u256_copy(&base, a);

    for (i = NLIMBS64 - 1; i >= 0; i--) {
        for (bit = 63; bit >= 0; bit--) {
            u256 sq; u256_mulmod_n(&sq, &result, &result); u256_copy(&result, &sq);
            if ((exp.v[i] >> bit) & 1) {
                u256 pr; u256_mulmod_n(&pr, &result, &base); u256_copy(&result, &pr);
            }
        }
    }
    u256_copy(r, &result);
}

static void u256_print(const char *label, const u256 *a) {
    printf("%-24s: %016llx%016llx%016llx%016llx\n",
           label,
           (unsigned long long)a->v[3], (unsigned long long)a->v[2],
           (unsigned long long)a->v[1], (unsigned long long)a->v[0]);
}

static void u256_from_bytes_be(u256 *a, const uint8_t *buf) {
    int i; u256_zero(a);
    for (i = 0; i < 32; i++) {
        int limb = (31 - i) / 8;
        int shift = ((31 - i) % 8) * 8;
        a->v[limb] |= (uint64_t)buf[i] << shift;
    }
}

static void u256_to_bytes_be(const u256 *a, uint8_t *buf) {
    int i;
    for (i = 0; i < 32; i++) {
        int limb = (31 - i) / 8;
        int shift = ((31 - i) % 8) * 8;
        buf[i] = (uint8_t)(a->v[limb] >> shift);
    }
}

/* -----------------------------------------------------------------------
 * Elliptic Curve Point (affine coordinates)
 * ----------------------------------------------------------------------- */

typedef struct { u256 x, y; int inf; } ec_pt;

static void ec_inf(ec_pt *P) {
    u256_zero(&P->x); u256_zero(&P->y); P->inf = 1;
}

static int ec_eq(const ec_pt *P, const ec_pt *Q) {
    if (P->inf && Q->inf) return 1;
    if (P->inf || Q->inf) return 0;
    return u256_cmp(&P->x, &Q->x) == 0 && u256_cmp(&P->y, &Q->y) == 0;
}

/* Point doubling: R = 2P (affine, secp256k1 a=0) */
static void ec_dbl(ec_pt *R, const ec_pt *P) {
    u256 lambda, num, den, x3, y3, tmp;

    if (P->inf || u256_iszero(&P->y)) { ec_inf(R); return; }

    /* lambda = 3*x^2 / (2*y) mod p */
    u256_mulmod_p(&num, &P->x, &P->x);         /* x^2 */
    u256_addmod(&tmp, &num, &num, &SECP_P);     /* 2x^2 */
    u256_addmod(&num, &tmp, &num, &SECP_P);     /* 3x^2 */
    u256_addmod(&den, &P->y, &P->y, &SECP_P);  /* 2y */
    u256_inv_p(&tmp, &den);
    u256_mulmod_p(&lambda, &num, &tmp);

    /* x3 = lambda^2 - 2x */
    u256_mulmod_p(&x3, &lambda, &lambda);
    u256_submod(&x3, &x3, &P->x, &SECP_P);
    u256_submod(&x3, &x3, &P->x, &SECP_P);

    /* y3 = lambda*(x - x3) - y */
    u256_submod(&tmp, &P->x, &x3, &SECP_P);
    u256_mulmod_p(&y3, &lambda, &tmp);
    u256_submod(&y3, &y3, &P->y, &SECP_P);

    u256_copy(&R->x, &x3);
    u256_copy(&R->y, &y3);
    R->inf = 0;
}

/* Point addition: R = P + Q (affine) */
static void ec_add(ec_pt *R, const ec_pt *P, const ec_pt *Q) {
    u256 dx, dy, lambda, x3, y3, tmp;

    if (P->inf) { *R = *Q; return; }
    if (Q->inf) { *R = *P; return; }
    if (u256_cmp(&P->x, &Q->x) == 0) {
        if (u256_cmp(&P->y, &Q->y) == 0) { ec_dbl(R, P); return; }
        ec_inf(R); return;
    }

    /* lambda = (yQ - yP) / (xQ - xP) */
    u256_submod(&dy, &Q->y, &P->y, &SECP_P);
    u256_submod(&dx, &Q->x, &P->x, &SECP_P);
    u256_inv_p(&tmp, &dx);
    u256_mulmod_p(&lambda, &dy, &tmp);

    /* x3 = lambda^2 - xP - xQ */
    u256_mulmod_p(&x3, &lambda, &lambda);
    u256_submod(&x3, &x3, &P->x, &SECP_P);
    u256_submod(&x3, &x3, &Q->x, &SECP_P);

    /* y3 = lambda*(xP - x3) - yP */
    u256_submod(&tmp, &P->x, &x3, &SECP_P);
    u256_mulmod_p(&y3, &lambda, &tmp);
    u256_submod(&y3, &y3, &P->y, &SECP_P);

    u256_copy(&R->x, &x3);
    u256_copy(&R->y, &y3);
    R->inf = 0;
}

/* Scalar multiplication: R = k * G (double-and-add, MSB first) */
static void ec_scalar_mul(ec_pt *R, const u256 *k, const ec_pt *G) {
    ec_pt Q; int i, bit;
    ec_inf(&Q);
    for (i = NLIMBS64 - 1; i >= 0; i--) {
        for (bit = 63; bit >= 0; bit--) {
            ec_pt tmp; ec_dbl(&tmp, &Q); Q = tmp;
            if ((k->v[i] >> bit) & 1) {
                ec_add(&tmp, &Q, G); Q = tmp;
            }
        }
    }
    *R = Q;
}

/* -----------------------------------------------------------------------
 * RNG (xorshift64 – NOT cryptographically secure)
 * ----------------------------------------------------------------------- */

static uint64_t g_rng = 0xdeadbeefcafe1234ULL;
static void rng_seed(uint64_t s) { g_rng = s ^ 0x123456789ABCULL; }
static uint64_t rng64(void) {
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}
static void rng_u256_lt(u256 *a, const u256 *max) {
    int i;
    do {
        for (i = 0; i < NLIMBS64; i++) a->v[i] = rng64();
    } while (u256_cmp(a, max) >= 0 || u256_iszero(a));
}

/* -----------------------------------------------------------------------
 * ECDH Key Exchange
 * ----------------------------------------------------------------------- */

typedef struct { u256 priv; ec_pt pub; } ecc_keypair;

static void ecc_gen_key(ecc_keypair *kp) {
    ec_pt G; G.x = SECP_GX; G.y = SECP_GY; G.inf = 0;
    rng_u256_lt(&kp->priv, &SECP_N);
    ec_scalar_mul(&kp->pub, &kp->priv, &G);
}

static void ecdh_secret(u256 *secret, const u256 *myPriv, const ec_pt *theirPub) {
    ec_pt S;
    ec_scalar_mul(&S, myPriv, theirPub);
    u256_copy(secret, &S.x);
}

/* -----------------------------------------------------------------------
 * ECDSA Sign / Verify
 * ----------------------------------------------------------------------- */

typedef struct { u256 r, s; } ecdsa_sig;

static void hash_msg(u256 *h, const uint8_t *msg, size_t len) {
    /* Simple truncating hash: treat first 32 bytes as hash value */
    uint8_t buf[32] = {0};
    size_t i; if (len > 32) len = 32;
    for (i = 0; i < len; i++) buf[i] = msg[i] ^ (uint8_t)(i * 0x53 + 0x17);
    u256_from_bytes_be(h, buf);
    while (u256_cmp(h, &SECP_N) >= 0) u256_sub(h, h, &SECP_N);
}

static void ecdsa_sign(ecdsa_sig *sig, const uint8_t *msg, size_t len, const u256 *priv) {
    u256 k, h, kinv, tmp;
    ec_pt G, R_pt;
    G.x = SECP_GX; G.y = SECP_GY; G.inf = 0;

    hash_msg(&h, msg, len);

    do {
        rng_u256_lt(&k, &SECP_N);
        ec_scalar_mul(&R_pt, &k, &G);
        u256_copy(&sig->r, &R_pt.x);
        while (u256_cmp(&sig->r, &SECP_N) >= 0) u256_sub(&sig->r, &sig->r, &SECP_N);
    } while (u256_iszero(&sig->r));

    /* s = k^-1 * (h + r*priv) mod n */
    u256_inv_n(&kinv, &k);
    u256_mulmod_n(&tmp, &sig->r, priv);
    u256_addmod(&tmp, &h, &tmp, &SECP_N);
    u256_mulmod_n(&sig->s, &kinv, &tmp);
}

static int ecdsa_verify(const ecdsa_sig *sig, const uint8_t *msg, size_t len,
                         const ec_pt *pub) {
    u256 h, sinv, u1, u2;
    ec_pt G, P1, P2, P;
    G.x = SECP_GX; G.y = SECP_GY; G.inf = 0;

    if (u256_iszero(&sig->r) || u256_iszero(&sig->s)) return 0;
    if (u256_cmp(&sig->r, &SECP_N) >= 0) return 0;
    if (u256_cmp(&sig->s, &SECP_N) >= 0) return 0;

    hash_msg(&h, msg, len);

    u256_inv_n(&sinv, &sig->s);
    u256_mulmod_n(&u1, &h, &sinv);
    u256_mulmod_n(&u2, &sig->r, &sinv);

    ec_scalar_mul(&P1, &u1, &G);
    ec_scalar_mul(&P2, &u2, pub);
    ec_add(&P, &P1, &P2);
    if (P.inf) return 0;

    u256 rx; u256_copy(&rx, &P.x);
    while (u256_cmp(&rx, &SECP_N) >= 0) u256_sub(&rx, &rx, &SECP_N);
    return u256_cmp(&rx, &sig->r) == 0;
}

/* -----------------------------------------------------------------------
 * Demo / main
 * ----------------------------------------------------------------------- */

int main(void) {
    ecc_keypair alice, bob;
    u256 alice_secret, bob_secret;
    const uint8_t *message = (const uint8_t *)"ECC secp256k1 ECDSA Demo!";
    size_t msg_len = 25;
    ecdsa_sig sig;
    clock_t start, end;
    double t;
    int verify_ok;

    rng_seed((uint64_t)time(NULL) ^ 0xCAFEBABEULL);

    printf("==========================================================\n");
    printf("         Elliptic Curve Cryptography (ECC) – Demo        \n");
    printf("         Curve: secp256k1 (y\xc2\xb2 = x\xc2\xb3 + 7 over Fp)          \n");
    printf("==========================================================\n\n");

    printf("---- Generator Point G ----\n");
    u256_print("Gx", &SECP_GX);
    u256_print("Gy", &SECP_GY);
    printf("\n");

    /* ---- ECDH ---- */
    printf("---- ECDH Key Exchange ----\n");
    start = clock();
    ecc_gen_key(&alice);
    ecc_gen_key(&bob);
    end = clock();
    t   = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    u256_print("Alice Private Key", &alice.priv);
    u256_print("Alice Public Key X", &alice.pub.x);
    u256_print("Alice Public Key Y", &alice.pub.y);
    printf("\n");
    u256_print("Bob   Private Key", &bob.priv);
    u256_print("Bob   Public Key X", &bob.pub.x);
    u256_print("Bob   Public Key Y", &bob.pub.y);
    printf("\nKey generation time  : %.2f ms\n\n", t);

    start = clock();
    ecdh_secret(&alice_secret, &alice.priv, &bob.pub);
    ecdh_secret(&bob_secret, &bob.priv, &alice.pub);
    end = clock();
    t   = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    u256_print("Alice Shared Secret", &alice_secret);
    u256_print("Bob   Shared Secret", &bob_secret);
    printf("ECDH time            : %.2f ms\n", t);
    printf("Shared secrets match : %s\n\n",
           u256_cmp(&alice_secret, &bob_secret) == 0 ? "YES \xe2\x9c\x93" : "NO \xe2\x9c\x97");

    /* ---- ECDSA ---- */
    printf("---- ECDSA Sign / Verify ----\n");
    printf("Message : \"%s\"\n\n", (const char *)message);

    start = clock();
    ecdsa_sign(&sig, message, msg_len, &alice.priv);
    end = clock();
    t   = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    u256_print("Signature r", &sig.r);
    u256_print("Signature s", &sig.s);
    printf("ECDSA Sign time      : %.2f ms\n\n", t);

    start = clock();
    verify_ok = ecdsa_verify(&sig, message, msg_len, &alice.pub);
    end = clock();
    t   = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;

    printf("ECDSA Verify         : %s\n", verify_ok ? "VALID \xe2\x9c\x93" : "INVALID \xe2\x9c\x97");
    printf("Verification time    : %.2f ms\n\n", t);

    /* Test tampered message */
    {
        const uint8_t *tampered = (const uint8_t *)"Tampered!";
        int tamp = ecdsa_verify(&sig, tampered, 9, &alice.pub);
        printf("Tampered message     : %s\n",
               tamp ? "Wrongly accepted \xe2\x9c\x97" : "Correctly rejected \xe2\x9c\x93");
    }

    /* ---- Security Summary ---- */
    printf("\n==========================================================\n");
    printf("                  ECC Security Summary                   \n");
    printf("==========================================================\n");
    printf("Curve             : secp256k1\n");
    printf("Field Size        : 256 bits\n");
    printf("Security Level    : ~128 bits (classical)\n");
    printf("Security Basis    : Elliptic Curve Discrete Log (ECDLP)\n");
    printf("Classical Attack  : Pollard's rho O(sqrt(n)) approx 2^128 ops\n");
    printf("Quantum Attack    : Shor's Algorithm - poly-time ECDLP\n");
    printf("Post-Quantum Safe : No - must migrate to CRYSTALS-Kyber\n");

    return 0;
}
