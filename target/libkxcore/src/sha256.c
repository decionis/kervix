/* SHA-256 / HMAC-SHA256 for libkxcore. See kervix/sha256.h. */
#include <string.h>

#include "kervix/sha256.h"

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void compress(uint32_t h[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)blk[4 * i] << 24 | (uint32_t)blk[4 * i + 1] << 16 |
               (uint32_t)blk[4 * i + 2] << 8 | (uint32_t)blk[4 * i + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void kx_sha256_init(kx_sha256_t *s) {
    static const uint32_t iv[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    memcpy(s->h, iv, sizeof iv);
    s->total = 0;
    s->buf_len = 0;
}

void kx_sha256_update(kx_sha256_t *s, const void *data, size_t len) {
    const uint8_t *p = data;
    s->total += len;
    if (s->buf_len > 0) {
        size_t take = 64u - s->buf_len;
        if (take > len) take = len;
        memcpy(s->buf + s->buf_len, p, take);
        s->buf_len += (uint32_t)take;
        p += take;
        len -= take;
        if (s->buf_len == 64u) {
            compress(s->h, s->buf);
            s->buf_len = 0;
        }
    }
    while (len >= 64u) {
        compress(s->h, p);
        p += 64;
        len -= 64;
    }
    if (len > 0) {
        memcpy(s->buf, p, len);
        s->buf_len = (uint32_t)len;
    }
}

void kx_sha256_final(kx_sha256_t *s, uint8_t out[KX_SHA256_LEN]) {
    uint64_t bits = s->total * 8u;
    uint8_t pad = 0x80;
    kx_sha256_update(s, &pad, 1);
    uint8_t zero = 0;
    while (s->buf_len != 56u) kx_sha256_update(s, &zero, 1);
    uint8_t lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (uint8_t)(bits >> (56 - 8 * i));
    kx_sha256_update(s, lenbe, 8);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)s->h[i];
    }
    memset(s, 0, sizeof *s);
}

void kx_sha256(const void *data, size_t len, uint8_t out[KX_SHA256_LEN]) {
    kx_sha256_t s;
    kx_sha256_init(&s);
    kx_sha256_update(&s, data, len);
    kx_sha256_final(&s, out);
}

void kx_hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len,
                    uint8_t out[KX_SHA256_LEN]) {
    uint8_t k[64];
    memset(k, 0, sizeof k);
    if (key_len > 64u) kx_sha256(key, key_len, k);
    else if (key_len > 0) memcpy(k, key, key_len);

    uint8_t ipad[64], opad[64], inner[KX_SHA256_LEN];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36u);
        opad[i] = (uint8_t)(k[i] ^ 0x5cu);
    }
    kx_sha256_t s;
    kx_sha256_init(&s);
    kx_sha256_update(&s, ipad, 64);
    kx_sha256_update(&s, msg, msg_len);
    kx_sha256_final(&s, inner);
    kx_sha256_init(&s);
    kx_sha256_update(&s, opad, 64);
    kx_sha256_update(&s, inner, sizeof inner);
    kx_sha256_final(&s, out);
    memset(k, 0, sizeof k);
    memset(ipad, 0, sizeof ipad);
    memset(opad, 0, sizeof opad);
}

int kx_ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

void kx_hex(const uint8_t *in, size_t len, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hx[in[i] >> 4];
        out[2 * i + 1] = hx[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
}
