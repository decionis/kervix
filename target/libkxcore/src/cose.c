/* Draft-04 Producer Envelope byte templates. See kervix/cose.h. */
#include <string.h>

#include "kervix/cose.h"

static const char CT[] = "application/agent-action-capsule-id"; /* 35 bytes */
#define PROT_LEN 76u /* a3 01 27 03 78 23 <35> 04 58 20 <32> */

static void protected_header(const uint8_t pk[32], uint8_t out[PROT_LEN]) {
    size_t p = 0;
    out[p++] = 0xa3; out[p++] = 0x01; out[p++] = 0x27; out[p++] = 0x03;
    out[p++] = 0x78; out[p++] = (uint8_t)(sizeof CT - 1);
    memcpy(out + p, CT, sizeof CT - 1); p += sizeof CT - 1;
    out[p++] = 0x04; out[p++] = 0x58; out[p++] = 0x20;
    memcpy(out + p, pk, 32);
}

void kx_cose_sig_structure(const uint8_t pk[32], const uint8_t capsule_id[32], uint8_t out[KX_COSE_SIG_STRUCTURE_LEN]) {
    size_t o = 0;
    out[o++] = 0x84;                               /* array(4) */
    out[o++] = 0x6a; memcpy(out + o, "Signature1", 10); o += 10;
    out[o++] = 0x58; out[o++] = PROT_LEN; protected_header(pk, out + o); o += PROT_LEN;
    out[o++] = 0x40;                               /* external_aad: h'' */
    out[o++] = 0x58; out[o++] = 0x20; memcpy(out + o, capsule_id, 32);
}

void kx_cose_envelope(const uint8_t pk[32], const uint8_t capsule_id[32], const uint8_t sig[64],
                      uint8_t out[KX_COSE_ENVELOPE_LEN]) {
    size_t o = 0;
    out[o++] = 0xd2;                               /* tag 18 = COSE_Sign1 */
    out[o++] = 0x84;
    out[o++] = 0x58; out[o++] = PROT_LEN; protected_header(pk, out + o); o += PROT_LEN;
    out[o++] = 0xa0;                               /* unprotected: {} */
    out[o++] = 0x58; out[o++] = 0x20; memcpy(out + o, capsule_id, 32); o += 32;
    out[o++] = 0x58; out[o++] = 0x40; memcpy(out + o, sig, 64);
}

_Static_assert(1 + 1 + 10 + 2 + PROT_LEN + 1 + 2 + 32 == KX_COSE_SIG_STRUCTURE_LEN, "sig structure length");
_Static_assert(1 + 1 + 2 + PROT_LEN + 1 + 2 + 32 + 2 + 64 == KX_COSE_ENVELOPE_LEN, "envelope length");

size_t kx_base64url(const uint8_t *in, size_t n, char *out) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0, i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out[o++] = A[v >> 18]; out[o++] = A[(v >> 12) & 63]; out[o++] = A[(v >> 6) & 63]; out[o++] = A[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = A[v >> 18]; out[o++] = A[(v >> 12) & 63];
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        out[o++] = A[v >> 18]; out[o++] = A[(v >> 12) & 63]; out[o++] = A[(v >> 6) & 63];
    }
    out[o] = '\0';
    return o;
}
