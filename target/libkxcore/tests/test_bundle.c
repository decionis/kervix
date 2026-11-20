/* Signed policy bundles: structure, trust file and the acceptance rule. The
 * Ed25519 check is a stub here ("valid" iff sig[0..31] == the message digest
 * XOR the key): real signatures are verified with qcrypto on QNX and Node on the host. */
#include <stdio.h>
#include <string.h>

#include "kervix/bundle.h"
#include "kervix/sha256.h"
#include "kx_test.h"

static uint8_t BODY[64] = "pretend body";
static uint8_t KA[32], KB[32], KC[32];

static void fake_sign(const uint8_t pub[32], uint8_t role, uint8_t sig[64]) {
    uint8_t msg[KX_BUNDLE_MSG_LEN], d[32];
    kx_bundle_message(role, BODY, sizeof BODY, msg);
    kx_sha256(msg, sizeof msg, d);
    for (int i = 0; i < 32; i++) sig[i] = (uint8_t)(d[i] ^ pub[i]);
    memset(sig + 32, 0, 32);
}
static int fake_verify(const uint8_t pub[32], const uint8_t *msg, uint32_t n, const uint8_t sig[64], void *ctx) {
    (void)ctx;
    uint8_t d[32];
    kx_sha256(msg, n, d);
    for (int i = 0; i < 32; i++) if (sig[i] != (uint8_t)(d[i] ^ pub[i])) return 0;
    return 1;
}
static uint32_t make(uint8_t *buf, int n_sigs, const uint8_t roles[2], const uint8_t *keys[2]) {
    memcpy(buf, "KXP1", 4);
    uint32_t L = sizeof BODY;
    buf[4] = (uint8_t)L; buf[5] = buf[6] = buf[7] = 0;
    memcpy(buf + 8, BODY, L);
    buf[8 + L] = (uint8_t)n_sigs;
    for (int i = 0; i < n_sigs; i++) {
        uint8_t *s = buf + 9 + L + i * 97;
        s[0] = roles[i];
        memcpy(s + 1, keys[i], 32);
        fake_sign(keys[i], roles[i], s + 33);
    }
    return 9 + L + (uint32_t)n_sigs * 97u;
}

int main(void) {
    memset(KA, 0xa1, 32); memset(KB, 0xb2, 32); memset(KC, 0xc3, 32);
    char trust_text[512];
    snprintf(trust_text, sizeof trust_text,
             "# vehicle policy trust\nauthor ed25519:%s policy-team\n\n  approver ed25519:%s safety-board  \n",
             "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
             "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2");
    kx_trust_t T[KX_TRUST_MAX];
    int nt = kx_trust_parse(trust_text, (uint32_t)strlen(trust_text), T, KX_TRUST_MAX);
    KX_CHECK(nt == 2 && T[0].role == KX_ROLE_AUTHOR && T[1].role == KX_ROLE_APPROVER);
    KX_CHECK(!strcmp(T[0].label, "policy-team") && !strcmp(T[1].label, "safety-board") && T[1].pub[0] == 0xb2);
    KX_CHECK(kx_trust_parse("owner ed25519:00\n", 17, T, KX_TRUST_MAX) == -1);
    KX_CHECK(kx_trust_parse("author ed25519:zz\n", 18, T, KX_TRUST_MAX) == -1);
    nt = kx_trust_parse(trust_text, (uint32_t)strlen(trust_text), T, KX_TRUST_MAX);

    static uint8_t buf[KX_BUNDLE_MAX];
    kx_bundle_t b;
    int ia = -1, ip = -1;
    const uint8_t ok_roles[2] = { KX_ROLE_AUTHOR, KX_ROLE_APPROVER };
    const uint8_t *ok_keys[2] = { KA, KB };
    uint32_t n = make(buf, 2, ok_roles, ok_keys);
    KX_CHECK(kx_bundle_parse(buf, n, &b) == 0 && b.body_len == sizeof BODY && b.n_sigs == 2);
    KX_CHECK(kx_bundle_accept(&b, T, nt, fake_verify, NULL, &ia, &ip) == KX_BUNDLE_OK && ia == 0 && ip == 1);

    /* structure */
    KX_CHECK(kx_bundle_parse(buf, n - 1, &b) != 0);
    KX_CHECK(kx_bundle_parse(buf, n + 1, &b) != 0);
    int all = 1;
    for (uint32_t k = 0; k < n; k++) if (kx_bundle_parse(buf, k, &b) == 0) all = 0;
    KX_CHECK(all);
    buf[0] = 'X'; KX_CHECK(kx_bundle_parse(buf, n, &b) != 0); buf[0] = 'K';

    /* the acceptance rule, one failure at a time */
    const uint8_t one[2] = { KX_ROLE_AUTHOR, 0 };
    n = make(buf, 1, one, ok_keys);
    KX_CHECK(kx_bundle_parse(buf, n, &b) == 0 && kx_bundle_accept(&b, T, nt, fake_verify, NULL, &ia, &ip) == KX_BUNDLE_MISSING_ROLE);
    const uint8_t *same[2] = { KA, KA };
    n = make(buf, 2, ok_roles, same);
    KX_CHECK(kx_bundle_parse(buf, n, &b) == 0 && kx_bundle_accept(&b, T, nt, fake_verify, NULL, &ia, &ip) == KX_BUNDLE_SAME_KEY);
    const uint8_t *stranger[2] = { KA, KC };
    n = make(buf, 2, ok_roles, stranger);
    KX_CHECK(kx_bundle_parse(buf, n, &b) == 0 && kx_bundle_accept(&b, T, nt, fake_verify, NULL, &ia, &ip) == KX_BUNDLE_UNTRUSTED);
    const uint8_t *swapped[2] = { KB, KA };                       /* the approver's key may not author */
    n = make(buf, 2, ok_roles, swapped);
    KX_CHECK(kx_bundle_parse(buf, n, &b) == 0 && kx_bundle_accept(&b, T, nt, fake_verify, NULL, &ia, &ip) == KX_BUNDLE_UNTRUSTED);
    const uint8_t two_authors[2] = { KX_ROLE_AUTHOR, KX_ROLE_AUTHOR };
    n = make(buf, 2, two_authors, ok_keys);
    KX_CHECK(kx_bundle_parse(buf, n, &b) == 0 && kx_bundle_accept(&b, T, nt, fake_verify, NULL, &ia, &ip) == KX_BUNDLE_MALFORMED);
    n = make(buf, 2, ok_roles, ok_keys);
    buf[8 + 3] ^= 1;                                             /* body changed after signing */
    KX_CHECK(kx_bundle_parse(buf, n, &b) == 0 && kx_bundle_accept(&b, T, nt, fake_verify, NULL, &ia, &ip) == KX_BUNDLE_BAD_SIGNATURE);
    KX_CHECK(!strcmp(kx_bundle_verdict_name(KX_BUNDLE_SAME_KEY), "SAME_KEY"));
    KX_TEST_DONE();
}
