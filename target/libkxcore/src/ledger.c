/* Ledger framing + CRC-32C. See kervix/ledger.h. */
#include <string.h>

#include "kervix/ledger.h"

/* CRC-32C (Castagnoli, reflected poly 0x82F63B78), bitwise: small, portable, bounded. */
uint32_t kx_crc32c(uint32_t crc, const void *data, size_t n) {
    const uint8_t *p = data;
    crc = ~crc;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t get64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = v << 8 | p[i]; return v; }

static uint32_t record_crc(const uint8_t hdr[KX_LEDGER_HDR_LEN], const char *capsule, uint32_t len,
                           const uint8_t env[KX_COSE_ENVELOPE_LEN]) {
    uint32_t c = kx_crc32c(0, hdr, 48);
    c = kx_crc32c(c, capsule, len);
    return kx_crc32c(c, env, KX_COSE_ENVELOPE_LEN);
}

void kx_ledger_frame(uint8_t hdr[KX_LEDGER_HDR_LEN], uint64_t seq, const uint8_t capsule_id[32],
                     const char *capsule, uint32_t capsule_len, const uint8_t envelope[KX_COSE_ENVELOPE_LEN]) {
    put32(hdr, KX_LEDGER_MAGIC);
    put32(hdr + 4, capsule_len);
    put64(hdr + 8, seq);
    memcpy(hdr + 16, capsule_id, 32);
    put32(hdr + 48, record_crc(hdr, capsule, capsule_len, envelope));
}

int kx_ledger_hdr_decode(const uint8_t hdr[KX_LEDGER_HDR_LEN], kx_ledger_hdr_t *out) {
    if (get32(hdr) != KX_LEDGER_MAGIC) return -1;
    out->capsule_len = get32(hdr + 4);
    if (out->capsule_len == 0 || out->capsule_len > KX_CAPSULE_JCS_MAX) return -1;
    out->seq = get64(hdr + 8);
    memcpy(out->capsule_id, hdr + 16, 32);
    out->crc = get32(hdr + 48);
    return 0;
}

int kx_ledger_crc_ok(const uint8_t hdr[KX_LEDGER_HDR_LEN], const kx_ledger_hdr_t *h, const char *capsule,
                     const uint8_t envelope[KX_COSE_ENVELOPE_LEN]) {
    return record_crc(hdr, capsule, h->capsule_len, envelope) == h->crc;
}

size_t kx_ledger_scan(const uint8_t *buf, size_t n, uint64_t *records, uint64_t *last_seq, uint8_t last_id[32]) {
    size_t off = 0;
    *records = 0;
    *last_seq = 0;
    memset(last_id, 0, 32);
    while (n - off >= KX_LEDGER_HDR_LEN) {
        kx_ledger_hdr_t h;
        if (kx_ledger_hdr_decode(buf + off, &h) != 0) break;
        size_t total = KX_LEDGER_HDR_LEN + h.capsule_len + KX_COSE_ENVELOPE_LEN;
        if (n - off < total) break;                                   /* torn tail */
        const char *cap = (const char *)(buf + off + KX_LEDGER_HDR_LEN);
        const uint8_t *env = buf + off + KX_LEDGER_HDR_LEN + h.capsule_len;
        if (!kx_ledger_crc_ok(buf + off, &h, cap, env)) break;        /* corrupt */
        if (*records > 0 && h.seq != *last_seq + 1) break;            /* sequence must be contiguous */
        (*records)++;
        *last_seq = h.seq;
        memcpy(last_id, h.capsule_id, 32);
        off += total;
    }
    return off;
}
