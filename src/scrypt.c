#include "scrypt.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BLK 64
#define DIG 32
#define RL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define RR(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (RR(x, 2) ^ RR(x, 13) ^ RR(x, 22))
#define EP1(x) (RR(x, 6) ^ RR(x, 11) ^ RR(x, 25))
#define S0(x) (RR(x, 7) ^ RR(x, 18) ^ ((x) >> 3))
#define S1(x) (RR(x, 17) ^ RR(x, 19) ^ ((x) >> 10))

typedef struct
{
    uint32_t s[8];
    uint64_t b;
    uint8_t buf[BLK];
} CTX;

static const uint32_t K[64] = {
    0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul,
    0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
    0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul,
    0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
    0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul,
    0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
    0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul,
    0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
    0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul,
    0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
    0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul,
    0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
    0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul,
    0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
    0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul,
    0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul
};

static void sha256_tr(CTX *c, const uint8_t d[])
{
    uint32_t m[64], a, b, e, f, g, h, t1, t2;
    for (uint32_t i = 0; i < 16; ++i)
        m[i] = (d[i * 4] << 24) | (d[i * 4 + 1] << 16) | (d[i * 4 + 2] << 8) | d[i * 4 + 3];
    for (uint32_t i = 16; i < 64; ++i)
        m[i] = S1(m[i - 2]) + m[i - 7] + S0(m[i - 15]) + m[i - 16];
    a = c->s[0];
    b = c->s[1];
    uint32_t c0 = c->s[2], d0 = c->s[3];
    e = c->s[4];
    f = c->s[5];
    g = c->s[6];
    h = c->s[7];
    for (uint32_t i = 0; i < 64; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c0);
        h = g;
        g = f;
        f = e;
        e = d0 + t1;
        d0 = c0;
        c0 = b;
        b = a;
        a = t1 + t2;
    }
    c->s[0] += a;
    c->s[1] += b;
    c->s[2] += c0;
    c->s[3] += d0;
    c->s[4] += e;
    c->s[5] += f;
    c->s[6] += g;
    c->s[7] += h;
}

static void sha256_init(CTX *c)
{
    c->b = 0;
    c->s[0] = 0x6a09e667ul;
    c->s[1] = 0xbb67ae85ul;
    c->s[2] = 0x3c6ef372ul;
    c->s[3] = 0xa54ff53aul;
    c->s[4] = 0x510e527ful;
    c->s[5] = 0x9b05688cul;
    c->s[6] = 0x1f83d9abul;
    c->s[7] = 0x5be0cd19ul;
}

static void sha256_up(CTX *c, const uint8_t d[], size_t l)
{
    size_t i = (c->b >> 3) % BLK;
    c->b += ((uint64_t)l) << 3;
    size_t p = BLK - i, o = 0;
    if (l >= p)
    {
        memcpy(&c->buf[i], &d[0], p);
        sha256_tr(c, c->buf);
        for (o = p; o + BLK - 1 < l; o += BLK)
            sha256_tr(c, &d[o]);
        i = 0;
    }
    memcpy(&c->buf[i], &d[o], l - o);
}

static void sha256_fin(CTX *c, uint8_t h[])
{
    uint8_t i = (c->b >> 3) % BLK;
    c->buf[i++] = 0x80;
    if (i > 56)
    {
        memset(&c->buf[i], 0, BLK - i);
        sha256_tr(c, c->buf);
        i = 0;
    }
    memset(&c->buf[i], 0, 56 - i);
    uint64_t b = __builtin_bswap64(c->b);
    memcpy(&c->buf[56], &b, 8);
    sha256_tr(c, c->buf);
    for (i = 0; i < 8; ++i)
    {
        uint32_t be = __builtin_bswap32(c->s[i]);
        memcpy(&h[i * 4], &be, 4);
    }
}

static void hmac_sha256(const uint8_t *k, size_t kl, const uint8_t *d, size_t dl, uint8_t *dg)
{
    uint8_t kipad[BLK], kopad[BLK], tk[DIG];
    if (kl > BLK)
    {
        CTX t;
        sha256_init(&t);
        sha256_up(&t, k, kl);
        sha256_fin(&t, tk);
        k = tk;
        kl = DIG;
    }
    memset(kipad, 0x36, BLK);
    memset(kopad, 0x5c, BLK);
    for (size_t i = 0; i < kl; i++)
    {
        kipad[i] ^= k[i];
        kopad[i] ^= k[i];
    }
    CTX ctx;
    sha256_init(&ctx);
    sha256_up(&ctx, kipad, BLK);
    sha256_up(&ctx, d, dl);
    sha256_fin(&ctx, dg);
    sha256_init(&ctx);
    sha256_up(&ctx, kopad, BLK);
    sha256_up(&ctx, dg, DIG);
    sha256_fin(&ctx, dg);
}

static void pbkdf2_hmac_sha256(const uint8_t *pw, size_t pl, const uint8_t *s, size_t sl, uint64_t c, uint8_t *dk, size_t dklen)
{
    uint8_t U[DIG], T[DIG], b1[sl + 4];
    memcpy(b1, s, sl);
    uint32_t blks = (dklen + DIG - 1) / DIG;
    for (uint32_t i = 1; i <= blks; i++)
    {
        b1[sl] = (i >> 24) & 0xff;
        b1[sl + 1] = (i >> 16) & 0xff;
        b1[sl + 2] = (i >> 8) & 0xff;
        b1[sl + 3] = i & 0xff;
        hmac_sha256(pw, pl, b1, sl + 4, U);
        memcpy(T, U, DIG);
        for (uint64_t j = 1; j < c; j++)
        {
            hmac_sha256(pw, pl, U, DIG, U);
            for (uint32_t k = 0; k < DIG; k++)
                T[k] ^= U[k];
        }
        size_t o = (i - 1) * DIG, l = (dklen - o) > DIG ? DIG : (dklen - o);
        memcpy(dk + o, T, l);
    }
}

static void salsa20_8(uint32_t B[16])
{
    uint32_t x[16];
    memcpy(x, B, sizeof(x));
    for (int i = 0; i < 8; i += 2)
    {
        x[4] ^= RL(x[0] + x[12], 7);
        x[8] ^= RL(x[4] + x[0], 9);
        x[12] ^= RL(x[8] + x[4], 13);
        x[0] ^= RL(x[12] + x[8], 18);
        x[9] ^= RL(x[5] + x[1], 7);
        x[13] ^= RL(x[9] + x[5], 9);
        x[1] ^= RL(x[13] + x[9], 13);
        x[5] ^= RL(x[1] + x[13], 18);
        x[14] ^= RL(x[10] + x[6], 7);
        x[2] ^= RL(x[14] + x[10], 9);
        x[6] ^= RL(x[2] + x[14], 13);
        x[10] ^= RL(x[6] + x[2], 18);
        x[3] ^= RL(x[15] + x[11], 7);
        x[7] ^= RL(x[3] + x[15], 9);
        x[11] ^= RL(x[7] + x[3], 13);
        x[15] ^= RL(x[11] + x[7], 18);
        x[1] ^= RL(x[0] + x[3], 7);
        x[2] ^= RL(x[1] + x[0], 9);
        x[3] ^= RL(x[2] + x[1], 13);
        x[0] ^= RL(x[3] + x[2], 18);
        x[6] ^= RL(x[5] + x[4], 7);
        x[7] ^= RL(x[6] + x[5], 9);
        x[4] ^= RL(x[7] + x[6], 13);
        x[5] ^= RL(x[4] + x[7], 18);
        x[11] ^= RL(x[10] + x[9], 7);
        x[8] ^= RL(x[11] + x[10], 9);
        x[9] ^= RL(x[8] + x[11], 13);
        x[10] ^= RL(x[9] + x[8], 18);
        x[12] ^= RL(x[15] + x[14], 7);
        x[13] ^= RL(x[12] + x[15], 9);
        x[14] ^= RL(x[13] + x[12], 13);
        x[15] ^= RL(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; ++i)
        B[i] += x[i];
}

static void blockmix_salsa8(uint8_t *B, uint32_t r)
{
    uint32_t X[16];
    uint8_t *Y = malloc(128 * r);
    memcpy(X, &B[(2 * r - 1) * 64], 64);
    for (uint32_t i = 0; i < 2 * r; i++)
    {
        for (uint32_t j = 0; j < 16; j++)
            X[j] ^= ((uint32_t *)B)[i * 16 + j];
        salsa20_8(X);
        memcpy(&Y[i * 64], X, 64);
    }
    for (uint32_t i = 0; i < r; i++)
        memcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
    for (uint32_t i = 0; i < r; i++)
        memcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
    free(Y);
}

static void scrypt_romix(uint8_t *B, uint32_t r, uint64_t N)
{
    size_t bs = 128 * r;
    uint8_t *X = malloc(bs), *V = malloc(N * bs);
    memcpy(X, B, bs);
    for (uint64_t i = 0; i < N; i++)
    {
        memcpy(&V[i * bs], X, bs);
        blockmix_salsa8(X, r);
    }
    for (uint64_t i = 0; i < N; i++)
    {
        uint64_t j = ((uint32_t *)X)[(2 * r - 1) * 16] % N;
        for (size_t k = 0; k < bs; k++)
            X[k] ^= V[j * bs + k];
        blockmix_salsa8(X, r);
    }
    memcpy(B, X, bs);
    free(X);
    free(V);
}

int scrypt(const uint8_t *pw, size_t pwl, const uint8_t *s, size_t sl,
           uint64_t N, uint32_t r, uint32_t p, uint8_t *buf, size_t buflen)
{
    if (N == 0 || (N & (N - 1)) != 0)
        return -1;
    size_t bs = 128 * r * p;
    uint8_t *B = malloc(bs);
    if (!B)
        return -1;
    pbkdf2_hmac_sha256(pw, pwl, s, sl, 1, B, bs);
    for (uint32_t i = 0; i < p; i++)
        scrypt_romix(B + i * 128 * r, r, N);
    pbkdf2_hmac_sha256(pw, pwl, B, bs, 1, buf, buflen);
    free(B);
    return 0;
}