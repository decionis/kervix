/* Signed policy bundles: structure, signed message, trust file, acceptance rule (bundle.h). */
#include "kervix/bundle.h"

#include <string.h>

#include "kervix/sha256.h"

static const char DOMAIN[] = "kervix.policy-signature/1";   /* + NUL + role + sha256 = 59 bytes */

int kx_bundle_parse(const uint8_t *buf, uint32_t n, kx_bundle_t *out) {
    if (buf == NULL || out == NULL || n < 9 || n > KX_BUNDLE_MAX || memcmp(buf, "KXP1", 4) != 0) return -1;
    uint32_t len = (uint32_t)buf[4] | (uint32_t)buf[5] << 8 | (uint32_t)buf[6] << 16 | (uint32_t)buf[7] << 24;
    if (len > n - 9 || len > KX_POLICY_BODY_MAX) return -1;
    uint8_t count = buf[8 + len];
    if (count > 2 || n != 9 + len + (uint32_t)count * 97u) return -1;
    memset(out, 0, sizeof *out);
    out->body = buf + 8;
    out->body_len = len;
    out->n_sigs = count;
    for (uint8_t i = 0; i < count; i++) {
        const uint8_t *s = buf + 9 + len + (uint32_t)i * 97u;
        if (s[0] != KX_ROLE_AUTHOR && s[0] != KX_ROLE_APPROVER) return -1;
        out->sig[i].role = s[0];
        memcpy(out->sig[i].pub, s + 1, 32);
        memcpy(out->sig[i].sig, s + 33, 64);
    }
    return 0;
}

void kx_bundle_message(uint8_t role, const uint8_t *body, uint32_t body_len, uint8_t out[KX_BUNDLE_MSG_LEN]) {
    memcpy(out, DOMAIN, sizeof DOMAIN);           /* includes the NUL */
    out[sizeof DOMAIN] = role;
    kx_sha256(body, body_len, out + sizeof DOMAIN + 1);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int kx_trust_parse(const char *text, uint32_t n, kx_trust_t *out, int max) {
    int count = 0;
    uint32_t i = 0;
    while (i < n) {
        uint32_t s = i;
        while (i < n && text[i] != '\n') i++;
        uint32_t e = i;
        if (i < n) i++;
        while (s < e && (text[s] == ' ' || text[s] == '\t')) s++;
        while (e > s && (text[e - 1] == ' ' || text[e - 1] == '\t' || text[e - 1] == '\r')) e--;
        if (s == e || text[s] == '#') continue;
        kx_trust_t t;
        memset(&t, 0, sizeof t);
        uint32_t p = s;
        if (e - p >= 7 && memcmp(text + p, "author ", 7) == 0) { t.role = KX_ROLE_AUTHOR; p += 7; }
        else if (e - p >= 9 && memcmp(text + p, "approver ", 9) == 0) { t.role = KX_ROLE_APPROVER; p += 9; }
        else return -1;
        while (p < e && text[p] == ' ') p++;
        if (e - p < 8 + 64 || memcmp(text + p, "ed25519:", 8) != 0) return -1;
        p += 8;
        for (int b = 0; b < 32; b++) {
            int hi = hexval(text[p + 2 * b]), lo = hexval(text[p + 2 * b + 1]);
            if (hi < 0 || lo < 0) return -1;
            t.pub[b] = (uint8_t)(hi << 4 | lo);
        }
        p += 64;
        if (p < e && text[p] != ' ') return -1;
        while (p < e && text[p] == ' ') p++;
        uint32_t L = 0;
        for (; p < e && L < KX_TRUST_LABEL - 1; p++) {
            char c = text[p];
            t.label[L++] = (c >= 0x21 && c <= 0x7e) ? c : '_';   /* printable ASCII: it is recorded in capsules */
        }
        if (count >= max) return -1;
        out[count++] = t;
    }
    return count;
}

kx_bundle_verdict_t kx_bundle_accept(const kx_bundle_t *b, const kx_trust_t *trust, int n_trust,
                                     kx_sig_verify_fn verify, void *ctx, int *author, int *approver) {
    if (b == NULL || verify == NULL) return KX_BUNDLE_MALFORMED;
    const kx_bundle_sig_t *s[3] = { NULL, NULL, NULL };
    for (uint8_t i = 0; i < b->n_sigs && i < 2; i++) {
        if (s[b->sig[i].role] != NULL) return KX_BUNDLE_MALFORMED;      /* one signature per role */
        s[b->sig[i].role] = &b->sig[i];
    }
    if (s[KX_ROLE_AUTHOR] == NULL || s[KX_ROLE_APPROVER] == NULL) return KX_BUNDLE_MISSING_ROLE;
    if (memcmp(s[KX_ROLE_AUTHOR]->pub, s[KX_ROLE_APPROVER]->pub, 32) == 0) return KX_BUNDLE_SAME_KEY;
    int idx[3] = { -1, -1, -1 };
    for (uint8_t role = KX_ROLE_AUTHOR; role <= KX_ROLE_APPROVER; role++) {
        for (int t = 0; t < n_trust; t++)
            if (trust[t].role == role && memcmp(trust[t].pub, s[role]->pub, 32) == 0) idx[role] = t;
        if (idx[role] < 0) return KX_BUNDLE_UNTRUSTED;
    }
    for (uint8_t role = KX_ROLE_AUTHOR; role <= KX_ROLE_APPROVER; role++) {
        uint8_t msg[KX_BUNDLE_MSG_LEN];
        kx_bundle_message(role, b->body, b->body_len, msg);
        if (verify(s[role]->pub, msg, sizeof msg, s[role]->sig, ctx) != 1) return KX_BUNDLE_BAD_SIGNATURE;
    }
    if (author) *author = idx[KX_ROLE_AUTHOR];
    if (approver) *approver = idx[KX_ROLE_APPROVER];
    return KX_BUNDLE_OK;
}

const char *kx_bundle_verdict_name(kx_bundle_verdict_t v) {
    static const char *const N[] = { "OK", "MALFORMED", "MISSING_ROLE", "SAME_KEY", "UNTRUSTED", "BAD_SIGNATURE" };
    return (unsigned)v < sizeof N / sizeof N[0] ? N[v] : "?";
}
