/*
 * SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), portable and
 * allocation-free. Lives in libkxcore so that intent hashes and capsule ids
 * are bit-identical on QNX, on the host and in the offline replay verifier.
 */
#ifndef KERVIX_SHA256_H
#define KERVIX_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define KX_SHA256_LEN 32u

typedef struct {
    uint32_t h[8];
    uint64_t total;     /* bytes processed */
    uint8_t  buf[64];
    uint32_t buf_len;
} kx_sha256_t;

void kx_sha256_init(kx_sha256_t *s);
void kx_sha256_update(kx_sha256_t *s, const void *data, size_t len);
void kx_sha256_final(kx_sha256_t *s, uint8_t out[KX_SHA256_LEN]);
void kx_sha256(const void *data, size_t len, uint8_t out[KX_SHA256_LEN]);

void kx_hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len,
                    uint8_t out[KX_SHA256_LEN]);

/* Constant-time comparison: 1 if equal. */
int kx_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Lowercase hex; out must hold 2*len+1 bytes (NUL-terminated). */
void kx_hex(const uint8_t *in, size_t len, char *out);

#endif /* KERVIX_SHA256_H */
