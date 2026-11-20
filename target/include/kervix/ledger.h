/*
 * Ledger record framing (append-only file /data/kervix/ledger/ledger.kxl).
 *
 *   header (52 B, little-endian):
 *     magic "KXL1" | u32 capsule_len | u64 ledger_seq | 32 B capsule_id | u32 crc32c
 *   capsule_len bytes of capsule JSON (JCS)
 *   181 bytes COSE_Sign1 producer envelope
 *
 * crc32c covers the header's first 48 bytes, the capsule and the envelope, so
 * a torn or partial write is detected at recovery without parsing JSON.
 * Integrity against TAMPERING comes from the capsule identity + Ed25519
 * signature + chain (checked offline by kervix-verify), not from the CRC.
 */
#ifndef KERVIX_LEDGER_H
#define KERVIX_LEDGER_H

#include <stddef.h>
#include <stdint.h>

#include "kervix/capsule.h"
#include "kervix/cose.h"

#define KX_LEDGER_MAGIC   0x314C584Bu  /* "KXL1" as little-endian bytes */
#define KX_LEDGER_HDR_LEN 52u
#define KX_LEDGER_REC_MAX (KX_LEDGER_HDR_LEN + KX_CAPSULE_JCS_MAX + KX_COSE_ENVELOPE_LEN)

typedef struct {
    uint32_t capsule_len;
    uint64_t seq;
    uint8_t  capsule_id[32];
    uint32_t crc;
} kx_ledger_hdr_t;

uint32_t kx_crc32c(uint32_t crc, const void *data, size_t n); /* start with 0 */

/* Fill the 52-byte header for a record. */
void kx_ledger_frame(uint8_t hdr[KX_LEDGER_HDR_LEN], uint64_t seq, const uint8_t capsule_id[32],
                     const char *capsule, uint32_t capsule_len, const uint8_t envelope[KX_COSE_ENVELOPE_LEN]);

/* Decode a header: 0 ok, -1 bad magic or length out of bounds. */
int kx_ledger_hdr_decode(const uint8_t hdr[KX_LEDGER_HDR_LEN], kx_ledger_hdr_t *out);

/* 1 if the CRC over (header, capsule, envelope) matches. */
int kx_ledger_crc_ok(const uint8_t hdr[KX_LEDGER_HDR_LEN], const kx_ledger_hdr_t *h, const char *capsule,
                     const uint8_t envelope[KX_COSE_ENVELOPE_LEN]);

/* Scan a whole in-memory ledger: returns the byte length of the valid prefix,
 * and the count / last seq / last id of the valid records in it. Used by the
 * recovery path (kervixd) and by tests. */
size_t kx_ledger_scan(const uint8_t *buf, size_t n, uint64_t *records, uint64_t *last_seq, uint8_t last_id[32]);

#endif /* KERVIX_LEDGER_H */
