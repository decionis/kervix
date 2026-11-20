/*
 * kxgw wire format: closed, bounded JSON-lines parser and emitters (see wire.h).
 * No recursion, no allocation; every loop advances the cursor or exits.
 */
#include "wire.h"

#include <string.h>

#include "kervix/catalog_gen.h"
#include "kervix/policy.h"
#include "kervix/sha256.h"

typedef struct {
    const char *s;
    size_t      n, i;
    const char *err;
} cur_t;

static int fail(cur_t *c, const char *why) {
    if (c->err == NULL) c->err = why;
    return -1;
}
static void ws(cur_t *c) {
    while (c->i < c->n && (c->s[c->i] == ' ' || c->s[c->i] == '\t')) c->i++;
}
static int peek(cur_t *c) { return c->i < c->n ? (unsigned char)c->s[c->i] : -1; }
static int expect(cur_t *c, char ch, const char *why) {
    ws(c);
    if (peek(c) != (unsigned char)ch) return fail(c, why);
    c->i++;
    return 0;
}

/* JSON string into out[cap] (NUL-terminated). Printable ASCII only. */
static int str(cur_t *c, char *out, size_t cap) {
    ws(c);
    if (peek(c) != '"') return fail(c, "expected a string");
    c->i++;
    size_t o = 0;
    while (c->i < c->n) {
        unsigned char ch = (unsigned char)c->s[c->i++];
        if (ch == '"') { if (cap) out[o] = '\0'; return 0; }
        if (ch == '\\') {
            if (c->i >= c->n) break;
            ch = (unsigned char)c->s[c->i++];
            if (ch != '"' && ch != '\\' && ch != '/') return fail(c, "unsupported string escape (printable ASCII only)");
        } else if (ch < 0x20 || ch > 0x7e) {
            return fail(c, "non-printable or non-ASCII byte in string");
        }
        if (o + 1 >= cap) return fail(c, "string too long");
        out[o++] = (char)ch;
    }
    return fail(c, "unterminated string");
}

/* Integer in the JavaScript safe range. */
static int integer(cur_t *c, int64_t *v) {
    ws(c);
    int neg = 0;
    if (peek(c) == '-') { neg = 1; c->i++; }
    int ch = peek(c);
    if (ch < '0' || ch > '9') return fail(c, "expected an integer");
    if (ch == '0' && c->i + 1 < c->n && c->s[c->i + 1] >= '0' && c->s[c->i + 1] <= '9')
        return fail(c, "leading zero");
    uint64_t u = 0;
    int digits = 0;
    while ((ch = peek(c)) >= '0' && ch <= '9') {
        if (++digits > 16) return fail(c, "integer out of range");
        u = u * 10u + (uint64_t)(ch - '0');
        c->i++;
    }
    if (ch == '.' || ch == 'e' || ch == 'E') return fail(c, "integers only (no fraction or exponent)");
    if (u > (uint64_t)KX_JW_MAX_SAFE_INT) return fail(c, "integer out of range");
    *v = neg ? -(int64_t)u : (int64_t)u;
    return 0;
}

static int boolean(cur_t *c, uint8_t *v) {
    ws(c);
    if (c->n - c->i >= 4 && memcmp(c->s + c->i, "true", 4) == 0) { c->i += 4; *v = 1; return 0; }
    if (c->n - c->i >= 5 && memcmp(c->s + c->i, "false", 5) == 0) { c->i += 5; *v = 0; return 0; }
    return fail(c, "expected true or false");
}

static int u32(cur_t *c, uint32_t *v, int64_t max) {
    int64_t x;
    if (integer(c, &x) != 0) return -1;
    if (x < 0 || x > max) return fail(c, "integer out of range");
    *v = (uint32_t)x;
    return 0;
}

static int hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
static int hexbytes(const char *s, uint8_t *out, size_t n) {
    for (size_t b = 0; b < n; b++) {
        int hi = hexval((unsigned char)s[2 * b]), lo = hexval((unsigned char)s[2 * b + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[b] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}
/* 8-4-4-4-12 hex */
static int uuid(const char *s, uint8_t out[16]) {
    if (strlen(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-') return -1;
    char h[33];
    size_t o = 0;
    for (size_t i = 0; i < 36; i++) if (s[i] != '-') h[o++] = s[i];
    h[32] = '\0';
    return o == 32 ? hexbytes(h, out, 16) : -1;
}

static int id_ok(const char *s) {
    for (; *s; s++) {
        char ch = *s;
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' ||
              ch == '_' || ch == ':' || ch == '-'))
            return 0;
    }
    return 1;
}

static int params(cur_t *c, kxw_req_t *rq) {
    if (expect(c, '{', "params must be an object") != 0) return -1;
    ws(c);
    if (peek(c) == '}') { c->i++; return 0; }
    for (;;) {
        if (rq->n_params >= KXW_MAX_PARAMS) return fail(c, "too many params");
        kxw_param_t *p = &rq->p[rq->n_params];
        if (str(c, p->name, sizeof p->name) != 0) return -1;
        for (uint8_t k = 0; k < rq->n_params; k++)
            if (strcmp(rq->p[k].name, p->name) == 0) return fail(c, "duplicate param");
        if (expect(c, ':', "expected ':'") != 0) return -1;
        ws(c);
        int ch = peek(c);
        if (ch == '"') {
            p->is_str = 1;
            if (str(c, p->str, sizeof p->str) != 0) return -1;
        } else if (ch == 't' || ch == 'f') {
            uint8_t b;
            if (boolean(c, &b) != 0) return -1;
            p->num = b;
        } else if (integer(c, &p->num) != 0) {
            return -1;
        }
        rq->n_params++;
        ws(c);
        if (peek(c) == ',') { c->i++; continue; }
        if (peek(c) == '}') { c->i++; return 0; }
        return fail(c, "expected ',' or '}' in params");
    }
}

static const char *const OPS[KXW_OP__COUNT] = {
    [KXW_OP_NONE] = "", [KXW_OP_HELLO] = "hello", [KXW_OP_PROPOSE] = "propose", [KXW_OP_EXECUTE] = "execute",
    [KXW_OP_STATE] = "state", [KXW_OP_STATS] = "stats", [KXW_OP_ESCALATIONS] = "escalations",
    [KXW_OP_RESOLVE] = "resolve", [KXW_OP_SUBSCRIBE] = "subscribe", [KXW_OP_SIM] = "sim",
    [KXW_OP_LEDGER_INFO] = "ledger_info", [KXW_OP_LEDGER] = "ledger", [KXW_OP_POLICY] = "policy",
};

enum {
    K_OP, K_ID, K_ACTION, K_ACTOR, K_INTENT_ID, K_EXPIRES, K_PARAMS, K_EXEC, K_AWAIT, K_GRANT_ID,
    K_ESC_ID, K_APPROVE, K_APPROVER, K_CMD, K_HZ, K_FROM_SEQ, K_MAX, K_NAME, K__COUNT
};
static const char *const KEYS[K__COUNT] = {
    "op", "id", "action", "actor", "intent_id", "expires_at_ms", "params", "exec", "await", "grant_id",
    "escalation_id", "approve", "approver", "cmd", "hz", "from_seq", "max", "name",
};

int kxw_parse(const char *line, size_t n, kxw_req_t *rq, const char **err) {
    memset(rq, 0, sizeof *rq);
    cur_t c = { line, n, 0, NULL };
    *err = NULL;
    if (n > KXW_LINE_MAX) { *err = "line too long"; return -1; }
    while (c.n > 0 && (line[c.n - 1] == '\n' || line[c.n - 1] == '\r')) c.n--;
    uint32_t seen = 0;
    if (expect(&c, '{', "expected a JSON object") != 0) goto bad;
    ws(&c);
    if (peek(&c) == '}') { c.i++; goto end; }
    for (;;) {
        char key[24];
        if (str(&c, key, sizeof key) != 0) goto bad;
        int k = -1;
        for (int i = 0; i < K__COUNT; i++) if (strcmp(key, KEYS[i]) == 0) k = i;
        if (k < 0) { fail(&c, "unknown key"); goto bad; }
        if (seen & (1u << k)) { fail(&c, "duplicate key"); goto bad; }
        seen |= 1u << k;
        if (expect(&c, ':', "expected ':'") != 0) goto bad;
        int rc = 0;
        char tmp[48];
        switch (k) {
        case K_OP:
            rc = str(&c, tmp, sizeof tmp);
            if (rc == 0) {
                for (int o = 1; o < KXW_OP__COUNT; o++) if (strcmp(tmp, OPS[o]) == 0) rq->op = (uint8_t)o;
                if (rq->op == KXW_OP_NONE) rc = fail(&c, "unknown op");
            }
            break;
        case K_ID:
            rc = str(&c, rq->id, sizeof rq->id);
            if (rc == 0 && !id_ok(rq->id)) rc = fail(&c, "id may only contain [A-Za-z0-9._:-]");
            break;
        case K_ACTION: rc = str(&c, rq->action, sizeof rq->action); break;
        case K_ACTOR: rc = str(&c, rq->actor, sizeof rq->actor); break;
        case K_INTENT_ID:
            rc = str(&c, tmp, sizeof tmp);
            if (rc == 0 && uuid(tmp, rq->intent_id) != 0) rc = fail(&c, "intent_id must be a UUID");
            rq->has_intent_id = 1;
            break;
        case K_EXPIRES:
            rc = integer(&c, &rq->expires_at_ms);
            if (rc == 0 && rq->expires_at_ms < 0) rc = fail(&c, "expires_at_ms must be >= 0");
            break;
        case K_PARAMS: rc = params(&c, rq); break;
        case K_EXEC: rc = boolean(&c, &rq->exec); break;
        case K_AWAIT: rc = boolean(&c, &rq->await_esc); break;
        case K_GRANT_ID:
            rc = str(&c, tmp, sizeof tmp);
            if (rc == 0 && (strlen(tmp) != 32 || hexbytes(tmp, rq->grant_id, 16) != 0)) rc = fail(&c, "grant_id must be 32 hex digits");
            rq->has_grant_id = 1;
            break;
        case K_ESC_ID: rc = u32(&c, &rq->escalation_id, 0x7fffffff); break;
        case K_APPROVE: rc = boolean(&c, &rq->approve); rq->has_approve = 1; break;
        case K_APPROVER: rc = str(&c, rq->approver, sizeof rq->approver); break;
        case K_CMD: rc = str(&c, rq->cmd, sizeof rq->cmd); break;
        case K_HZ: rc = u32(&c, &rq->hz, 1000); break;
        case K_FROM_SEQ:
            rc = integer(&c, &rq->from_seq);
            if (rc == 0 && rq->from_seq < 1) rc = fail(&c, "from_seq must be >= 1");
            break;
        case K_MAX: rc = u32(&c, &rq->max, 1000); break;
        case K_NAME: rc = str(&c, rq->name, sizeof rq->name); break;
        default: rc = fail(&c, "unknown key"); break;
        }
        if (rc != 0) goto bad;
        ws(&c);
        if (peek(&c) == ',') { c.i++; continue; }
        if (peek(&c) == '}') { c.i++; break; }
        fail(&c, "expected ',' or '}'");
        goto bad;
    }
end:
    ws(&c);
    if (c.i != c.n) { fail(&c, "trailing bytes after the object"); goto bad; }
    if (rq->op == KXW_OP_NONE) { fail(&c, "missing op"); goto bad; }
    if (rq->op == KXW_OP_PROPOSE && rq->action[0] == '\0') { fail(&c, "propose needs an action"); goto bad; }
    if (rq->op == KXW_OP_EXECUTE && !rq->has_grant_id) { fail(&c, "execute needs a grant_id"); goto bad; }
    if (rq->op == KXW_OP_RESOLVE && (!(seen & (1u << K_ESC_ID)) || !rq->has_approve)) {
        fail(&c, "resolve needs escalation_id and approve");
        goto bad;
    }
    if (rq->op == KXW_OP_SIM && rq->cmd[0] == '\0') { fail(&c, "sim needs a cmd"); goto bad; }
    if (rq->op == KXW_OP_POLICY && (strlen(rq->name) != 16 || strspn(rq->name, "0123456789abcdef") != 16)) {
        fail(&c, "policy needs a name of 16 hex digits");
        goto bad;
    }
    return 0;
bad:
    *err = c.err ? c.err : "malformed request";
    return -1;
}

int kxw_to_intent(const kxw_req_t *rq, kx_intent_t *in, const char **err) {
    memset(in, 0, sizeof *in);
    in->abi = KX_ABI_VERSION;
    const kx_action_spec_t *a = NULL;
    for (int i = 0; i < KX_ACTION_COUNT; i++)
        if (strcmp(kx_catalog_actions[i].name, rq->action) == 0) a = &kx_catalog_actions[i];
    if (a == NULL) { *err = "unknown action"; return -1; }
    in->action = a->id;
    memcpy(in->actor_id, rq->actor, sizeof in->actor_id);
    if (rq->has_intent_id) memcpy(in->intent_id, rq->intent_id, 16);
    in->expires_rt_ms = rq->expires_at_ms;
    for (uint8_t k = 0; k < rq->n_params; k++) {
        const kxw_param_t *p = &rq->p[k];
        const kx_param_spec_t *ps = NULL;
        for (int j = 0; j < a->n_params; j++) if (strcmp(a->params[j].name, p->name) == 0) ps = &a->params[j];
        if (ps == NULL) { *err = "unknown parameter for this action"; return -1; }
        if (ps->type == KX_PT_DIGEST) {
            const char *v = p->str;
            if (!p->is_str || strncmp(v, "sha256:", 7) != 0 || strlen(v) != 71 || hexbytes(v + 7, in->digest, 32) != 0) {
                *err = "digest parameters must be \"sha256:<64 hex>\"";
                return -1;
            }
            if (in->has_digest) { *err = "duplicate digest parameter"; return -1; }
            in->has_digest = 1;
            continue;
        }
        int64_t val = p->num;
        if (p->is_str) {
            if (ps->type != KX_PT_ENUM) { *err = "this parameter takes an integer"; return -1; }
            val = -1;
            for (int64_t e = ps->min; e <= ps->max; e++) if (strcmp(ps->enum_values[e], p->str) == 0) val = e;
            if (val < 0) { *err = "unknown enum value"; return -1; }
        }
        if (in->n_params >= KX_MAX_PARAMS) { *err = "too many parameters"; return -1; }
        in->p[in->n_params].key = ps->key;
        in->p[in->n_params].val = val;
        in->n_params++;
    }
    return 0;
}

const char *kxw_op_name(uint8_t op) { return op < KXW_OP__COUNT ? OPS[op] : ""; }

const char *kxw_verdict_name(uint8_t v) {
    return v == KX_VERDICT_ALLOW ? "ALLOW" : v == KX_VERDICT_ESCALATE ? "ESCALATE" : v == KX_VERDICT_BLOCK ? "BLOCK" : "NONE";
}

const char *kxw_gate_name(uint8_t g) {
    static const char *const G[] = { "RULE", "K4_VALIDATION", "EXPIRY", "K1_STALE", "K2_IMPLAUSIBLE", "K3_LEDGER", "REQUIRE" };
    return g < sizeof G / sizeof G[0] ? G[g] : "?";
}

void kxw_emit_hex(kx_jw_t *w, const char *key, const char *prefix, const uint8_t *b, size_t n) {
    char h[2 * 32 + 8 + 1];
    size_t pl = strlen(prefix);
    if (n > 32 || pl > 8) { w->err = 1; return; }
    memcpy(h, prefix, pl);
    kx_hex(b, n, h + pl);
    kx_jw_key(w, key);
    kx_jw_strn(w, h, pl + 2 * n);
}

static int nonzero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 1;
    return 0;
}

void kxw_emit_decision(kx_jw_t *w, const kx_decision_t *d) {
    const kx_reason_spec_t *r = kx_catalog_reason(d->reason);
    char rule[sizeof d->rule_id + 1];
    memcpy(rule, d->rule_id, sizeof d->rule_id);
    rule[sizeof d->rule_id] = '\0';
    kx_jw_key(w, "verdict"); kx_jw_str(w, kxw_verdict_name(d->verdict));
    kx_jw_key(w, "reason"); kx_jw_str(w, r ? r->name : "?");
    kx_jw_key(w, "reason_text"); kx_jw_str(w, r ? r->text : "");
    kx_jw_key(w, "gate"); kx_jw_str(w, kxw_gate_name(d->gate));
    kx_jw_key(w, "rule"); kx_jw_str(w, rule);
    kxw_emit_hex(w, "intent_hash", "sha256:", d->intent_hash, 32);
    kxw_emit_hex(w, "policy_hash", "sha256:", d->policy_hash, 32);
    kx_jw_key(w, "telemetry_seq"); kx_jw_int(w, (int64_t)(d->telemetry_seq & 0x1fffffffffffffull));
    kx_jw_key(w, "eval_ns"); kx_jw_int(w, d->eval_ns);
    if (d->verdict == KX_VERDICT_ESCALATE || d->escalation_id) { kx_jw_key(w, "escalation_id"); kx_jw_int(w, d->escalation_id); }
    if (d->verdict == KX_VERDICT_ALLOW && nonzero(d->grant.grant_id, 16)) {
        kxw_emit_hex(w, "grant_id", "", d->grant.grant_id, 16);
        kx_jw_key(w, "grant_ttl_ms");
        kx_jw_int(w, (int64_t)((d->grant.not_after_mono_ns - d->grant.issued_mono_ns) / 1000000u));
    }
}

void kxw_emit_intent(kx_jw_t *w, const char *key, const kx_intent_t *in) {
    const kx_action_spec_t *a = kx_catalog_action(in->action);
    char actor[KX_ACTOR_LEN + 1], id[37];
    memcpy(actor, in->actor_id, KX_ACTOR_LEN);
    actor[KX_ACTOR_LEN] = '\0';
    kx_fmt_uuid(in->intent_id, id);
    kx_jw_key(w, key);
    kx_jw_obj_begin(w);
    kx_jw_key(w, "action"); kx_jw_str(w, a ? a->name : "?");
    kx_jw_key(w, "actor"); kx_jw_str(w, actor);
    kx_jw_key(w, "intent_id"); kx_jw_str(w, id);
    kx_jw_key(w, "params");
    kx_jw_obj_begin(w);
    for (uint8_t k = 0; k < in->n_params && k < KX_MAX_PARAMS; k++) {
        const kx_param_spec_t *ps = a ? kx_catalog_param(a, in->p[k].key) : NULL;
        if (ps == NULL) continue;
        kx_jw_key(w, ps->name);
        if (ps->type == KX_PT_ENUM && in->p[k].val >= ps->min && in->p[k].val <= ps->max) kx_jw_str(w, ps->enum_values[in->p[k].val]);
        else if (ps->type == KX_PT_BOOL) kx_jw_bool(w, in->p[k].val != 0);
        else kx_jw_int(w, in->p[k].val);
    }
    if (in->has_digest && a) {
        for (int j = 0; j < a->n_params; j++)
            if (a->params[j].type == KX_PT_DIGEST) kxw_emit_hex(w, a->params[j].name, "sha256:", in->digest, 32);
    }
    kx_jw_obj_end(w);
    kx_jw_obj_end(w);
}

void kxw_emit_telemetry(kx_jw_t *w, const char *key, const kx_telemetry_t *t) {
    kx_jw_key(w, key);
    kx_jw_obj_begin(w);
    kx_jw_key(w, "seq"); kx_jw_int(w, (int64_t)(t->seq & 0x1fffffffffffffull));
    kx_jw_key(w, "mono_ns"); kx_jw_int(w, (int64_t)(t->mono_ns & 0x1fffffffffffffull));
    for (int f = 0; f < KX_TF__COUNT; f++) {
        kx_jw_key(w, kx_catalog_tfields[f].name);
        kx_jw_int(w, t->v[f]);
    }
    kx_jw_obj_end(w);
}

void kxw_emit_text(kx_jw_t *w, const char *key, const char *text, size_t n) {
    kx_jw_key(w, key);
    kx_jw_arr_begin(w);
    size_t i = 0;
    for (int lines = 0; i < n && lines < 64; lines++) {
        char line[256];
        size_t o = 0;
        while (i < n && text[i] != '\n') {
            unsigned char ch = (unsigned char)text[i];
            if (ch == 0xe2 && i + 2 < n && (unsigned char)text[i + 1] == 0x80 && (unsigned char)text[i + 2] == 0xa6) {
                for (int d = 0; d < 3 && o < sizeof line; d++) line[o++] = '.';
                i += 3;
                continue;
            }
            if (ch >= 0x80) {                         /* skip a whole UTF-8 sequence */
                i++;
                while (i < n && ((unsigned char)text[i] & 0xc0) == 0x80) i++;
                if (o < sizeof line) line[o++] = '?';
                continue;
            }
            if (o < sizeof line) line[o++] = (ch < 0x20 || ch == 0x7f) ? (ch == '\t' ? ' ' : '?') : (char)ch;
            i++;
        }
        if (i < n) i++;                                /* the newline */
        kx_jw_strn(w, line, o);
    }
    kx_jw_arr_end(w);
}
