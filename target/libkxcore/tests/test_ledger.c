/* Ledger framing: CRC-32C vectors, round trip, torn tails, corruption. */
#include <string.h>

#include "kervix/ledger.h"
#include "kx_test.h"

static uint8_t BUF[8 * KX_LEDGER_REC_MAX];

static size_t append(size_t off, uint64_t seq, const char *capsule, uint8_t idbyte) {
    uint8_t id[32], env[KX_COSE_ENVELOPE_LEN];
    memset(id, idbyte, 32);
    memset(env, (int)seq, sizeof env);
    uint32_t len = (uint32_t)strlen(capsule);
    kx_ledger_frame(BUF + off, seq, id, capsule, len, env);
    memcpy(BUF + off + KX_LEDGER_HDR_LEN, capsule, len);
    memcpy(BUF + off + KX_LEDGER_HDR_LEN + len, env, sizeof env);
    return off + KX_LEDGER_HDR_LEN + len + sizeof env;
}

int main(void) {
    /* CRC-32C check value (RFC 3720 / iSCSI): "123456789" -> 0xE3069283 */
    KX_CHECK(kx_crc32c(0, "123456789", 9) == 0xE3069283u);
    KX_CHECK(kx_crc32c(0, "", 0) == 0);
    uint8_t zeros[32] = { 0 };
    KX_CHECK(kx_crc32c(0, zeros, 32) == 0x8A9136AAu);   /* RFC 3720 B.4: 32 bytes of zeros */
    /* incremental == one-shot */
    KX_CHECK(kx_crc32c(kx_crc32c(0, "12345", 5), "6789", 4) == 0xE3069283u);

    size_t off = 0;
    off = append(off, 1, "{\"a\":1}", 0x11);
    off = append(off, 2, "{\"b\":2}", 0x22);
    size_t two = off;
    off = append(off, 3, "{\"c\":3}", 0x33);
    uint64_t n, seq;
    uint8_t last[32];
    KX_CHECK(kx_ledger_scan(BUF, off, &n, &seq, last) == off);
    KX_CHECK(n == 3 && seq == 3 && last[0] == 0x33);

    /* torn tail: every truncation inside the last record keeps exactly the first two */
    int ok = 1;
    for (size_t cut = two + 1; cut < off; cut++) {
        if (kx_ledger_scan(BUF, cut, &n, &seq, last) != two || n != 2 || seq != 2 || last[0] != 0x22) ok = 0;
    }
    KX_CHECK(ok);

    /* any flipped bit in the last record invalidates it (and only it) */
    ok = 1;
    for (size_t b = two; b < off; b++) {
        BUF[b] ^= 0x01;
        if (kx_ledger_scan(BUF, off, &n, &seq, last) != two || n != 2) ok = 0;
        BUF[b] ^= 0x01;
    }
    KX_CHECK(ok);

    /* sequence gap: records after a gap are not part of the valid prefix */
    off = 0;
    off = append(off, 1, "{\"a\":1}", 1);
    size_t one = off;
    off = append(off, 3, "{\"c\":3}", 3);
    KX_CHECK(kx_ledger_scan(BUF, off, &n, &seq, last) == one && n == 1);

    /* header bounds */
    kx_ledger_hdr_t h;
    uint8_t hdr[KX_LEDGER_HDR_LEN];
    memcpy(hdr, BUF, sizeof hdr);
    KX_CHECK(kx_ledger_hdr_decode(hdr, &h) == 0 && h.seq == 1 && h.capsule_len == 7);
    hdr[4] = 0; hdr[5] = 0; hdr[6] = 0; hdr[7] = 0;                    /* length 0 */
    KX_CHECK(kx_ledger_hdr_decode(hdr, &h) == -1);
    hdr[4] = 0xff; hdr[5] = 0xff; hdr[6] = 0xff; hdr[7] = 0x7f;        /* absurd length */
    KX_CHECK(kx_ledger_hdr_decode(hdr, &h) == -1);
    hdr[0] = 'X';
    KX_CHECK(kx_ledger_hdr_decode(hdr, &h) == -1);
    KX_CHECK(kx_ledger_scan(BUF, 0, &n, &seq, last) == 0 && n == 0);    /* empty ledger */
    KX_TEST_DONE();
}
