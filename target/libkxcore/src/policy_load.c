/*
 * kx_policy_load: canonical policy body -> finalized, hashed kx_policy_t.
 * Bounded reader over untrusted bytes (they are signed, but parsing comes
 * first): every read is length-checked, every count is bounded by the
 * engine's limits, trailing bytes are an error. Format: kervix/policy.h.
 */
#include <string.h>

#include "kervix/policy.h"

typedef struct { const uint8_t *p; uint32_t n, i; int err; } rd_t;

static const uint8_t *take(rd_t *r, uint32_t k) {
    if (r->err || r->n - r->i < k) { r->err = 1; return NULL; }
    const uint8_t *q = r->p + r->i;
    r->i += k;
    return q;
}
static uint8_t u8(rd_t *r) { const uint8_t *q = take(r, 1); return q ? q[0] : 0; }
static uint16_t u16(rd_t *r) { const uint8_t *q = take(r, 2); return q ? (uint16_t)(q[0] | q[1] << 8) : 0; }
static uint32_t u32(rd_t *r) {
    const uint8_t *q = take(r, 4);
    return q ? (uint32_t)q[0] | (uint32_t)q[1] << 8 | (uint32_t)q[2] << 16 | (uint32_t)q[3] << 24 : 0;
}
static int64_t i64(rd_t *r) {
    const uint8_t *q = take(r, 8);
    uint64_t v = 0;
    for (int b = 7; q && b >= 0; b--) v = v << 8 | q[b];
    return (int64_t)v;
}
/* NUL-terminated, non-empty, and zero after the terminator: one canonical encoding per name */
static int name_ok(const uint8_t *p, uint32_t cap) {
    const uint8_t *z = memchr(p, '\0', cap);
    if (p[0] == '\0' || z == NULL) return 0;
    for (const uint8_t *q = z; q < p + cap; q++) if (*q) return 0;
    return 1;
}
static kx_pred_span_t span(rd_t *r) { kx_pred_span_t s; s.off = u16(r); s.n = u8(r); s._pad = 0; return s; }

int kx_policy_load(kx_policy_t *pol, const uint8_t *body, uint32_t n) {
    if (pol == NULL || body == NULL || n > KX_POLICY_BODY_MAX) return -1;
    rd_t r = { body, n, 0, 0 };
    const uint8_t *magic = take(&r, 20);
    if (magic == NULL || memcmp(magic, KX_POLICY_BODY_MAGIC, 20) != 0) return -1;
    const uint8_t *id = take(&r, KX_POLICY_ID_LEN);
    if (id == NULL || !name_ok(id, KX_POLICY_ID_LEN)) return -1;
    uint32_t version = u32(&r);
    kx_policy_init(pol, (const char *)id, version);
    pol->default_verdict = u8(&r);
    pol->default_reason = u16(&r);
    if (r.err || kx_catalog_reason(pol->default_reason) == NULL) return -1;

    uint16_t n_preds = u16(&r);
    if (r.err || n_preds > KX_MAX_PREDS) return -1;
    for (uint16_t i = 0; i < n_preds; i++) {
        kx_pred_t p;
        memset(&p, 0, sizeof p);
        p.a.src = u8(&r); p.a.id = u16(&r);
        p.b.src = u8(&r); p.b.id = u16(&r);
        p.fn = u8(&r); p.op = u8(&r); p.group = u8(&r);
        p.k = i64(&r);
        if (r.err || kx_policy_add_pred(pol, p) < 0) return -1;
    }
    uint16_t n_rules = u16(&r);
    if (r.err || n_rules > KX_MAX_RULES) return -1;
    for (uint16_t i = 0; i < n_rules; i++) {
        kx_rule_t ru;
        memset(&ru, 0, sizeof ru);
        const uint8_t *rid = take(&r, KX_RULE_ID_LEN);
        if (rid == NULL || !name_ok(rid, KX_RULE_ID_LEN)) return -1;
        memcpy(ru.id, rid, KX_RULE_ID_LEN);
        ru.action = u16(&r); ru.verdict = u8(&r); ru.reason = u16(&r); ru.require_reason = u16(&r);
        ru.when = span(&r); ru.interlock = span(&r); ru.require = span(&r);
        ru.grant_ttl_ms = u32(&r); ru.esc_timeout_ms = u32(&r);
        if (r.err || kx_policy_add_rule(pol, &ru) != 0) return -1;
    }
    if (r.err || r.i != r.n) return -1;              /* nothing may follow the rules */
    if (kx_policy_finalize(pol) != 0) return -1;      /* actions, reasons, spans, operands, defaults */
    kx_policy_hash(pol, pol->hash);
    return 0;
}
