/* AAC draft-04 capsules for Kervix events. See kervix/capsule.h and
 * docs/03-architecture.md §8.2. Every object's keys are emitted in sorted
 * (byte = UTF-16 for ASCII) order, as JCS requires; tests verify the output
 * equals @decionis/verify's jcsCanonicalize() of it. */
#include <string.h>

#include "kervix/capsule.h"
#include "kervix/jcs.h"
#include "kervix/sha256.h"

static const char *const GATE_NAMES[] = { "none", "k4_validation", "expiry", "k1_stale", "k2_implausible", "k3_ledger", "require", "rate_limit" };
static const char *const EVENT_NAMES[] = { "", "epoch", "decision", "effect", "escalation_resolved", "grant_refused", "grant_expired", "policy_activated" };
static const char *const VERDICTS[] = { "NONE", "ALLOW", "ESCALATE", "BLOCK" };

static void hex(const uint8_t *b, size_t n, char *out) { kx_hex(b, n, out); }
static size_t bnlen(const char *s, size_t max) { size_t n = 0; while (n < max && s[n]) n++; return n; }
static void sha_hex_prefixed(const uint8_t d[32], char out[72]) { memcpy(out, "sha256:", 7); hex(d, 32, out + 7); }
static const char *reason_name(uint16_t r) { const kx_reason_spec_t *s = kx_catalog_reason(r); return s ? s->name : "UNKNOWN"; }

/* ------------------------------------------------------------ evidence */

typedef struct { const char *k; int64_t v; } kv_t;

static void write_telemetry(kx_jw_t *w, const kx_telemetry_t *t) {
    kv_t kv[KX_TF__COUNT + 2];
    size_t n = 0;
    for (int f = 0; f < KX_TF__COUNT; f++) kv[n++] = (kv_t){ kx_catalog_tfields[f].name, t->v[f] };
    kv[n++] = (kv_t){ "mono_ns", (int64_t)t->mono_ns };
    kv[n++] = (kv_t){ "seq", (int64_t)t->seq };
    for (size_t i = 1; i < n; i++) {           /* sort keys (n <= 21) */
        kv_t x = kv[i];
        size_t j = i;
        while (j > 0 && strcmp(kv[j - 1].k, x.k) > 0) { kv[j] = kv[j - 1]; j--; }
        kv[j] = x;
    }
    kx_jw_obj_begin(w);
    for (size_t i = 0; i < n; i++) { kx_jw_key(w, kv[i].k); kx_jw_int(w, kv[i].v); }
    kx_jw_obj_end(w);
}

/* intent as the replay verifier needs it; parameters rendered like the binding */
static void write_intent(kx_jw_t *w, const kx_capsule_rec_t *r, const char *tenant_id) {
    const kx_intent_t *in = &r->intent;
    const kx_action_spec_t *a = kx_catalog_action(in->action);
    char uuid[37], dig[72];
    kx_fmt_uuid(in->intent_id, uuid);
    kx_jw_obj_begin(w);
    kx_jw_key(w, "action");          kx_jw_str(w, a ? a->name : "unknown");
    kx_jw_key(w, "actor");           kx_jw_str(w, in->actor_id);
    kx_jw_key(w, "captured_at_ms");  kx_jw_int(w, r->captured_at_ms);
    kx_jw_key(w, "expires_at_ms");   kx_jw_int(w, in->expires_rt_ms);
    kx_jw_key(w, "intent_id");       kx_jw_str(w, uuid);
    kx_jw_key(w, "parameters");
    kx_jw_obj_begin(w);
    if (a != NULL) {
        /* catalog order -> sorted by name */
        const kx_param_spec_t *ps[KX_CATALOG_MAX_PARAMS];
        uint8_t n = 0;
        for (uint8_t i = 0; i < a->n_params && i < KX_CATALOG_MAX_PARAMS; i++) {
            const kx_param_spec_t *s = &a->params[i];
            uint8_t k = n++;
            while (k > 0 && strcmp(ps[k - 1]->name, s->name) > 0) { ps[k] = ps[k - 1]; k--; }
            ps[k] = s;
        }
        for (uint8_t i = 0; i < n; i++) {
            const kx_param_spec_t *s = ps[i];
            if (s->type == KX_PT_DIGEST) {
                if (!in->has_digest) continue;
                memcpy(dig, "sha256:", 7);
                hex(in->digest, 32, dig + 7);
                kx_jw_key(w, s->name); kx_jw_str(w, dig);
                continue;
            }
            const kx_param_t *v = NULL;
            for (uint8_t j = 0; j < in->n_params && j < KX_MAX_PARAMS; j++) if (in->p[j].key == s->key) v = &in->p[j];
            if (v == NULL) continue;           /* invalid intents are recorded as received */
            kx_jw_key(w, s->name);
            if (s->type == KX_PT_ENUM && v->val >= s->min && v->val <= s->max) kx_jw_str(w, s->enum_values[v->val]);
            else if (s->type == KX_PT_BOOL) kx_jw_bool(w, v->val != 0);
            else kx_jw_int(w, v->val);
        }
    }
    kx_jw_obj_end(w);
    if (tenant_id) { kx_jw_key(w, "tenant_id"); kx_jw_str(w, tenant_id); }
    kx_jw_obj_end(w);
}

static int write_evidence(const kx_capsule_rec_t *r, const char *tenant_id, char *buf, size_t cap) {
    char h[72], gid[33];
    kx_jw_t w;
    kx_jw_init(&w, buf, cap);
    kx_jw_obj_begin(&w);
    if (r->approver[0]) { kx_jw_key(&w, "approver"); kx_jw_strn(&w, r->approver, bnlen(r->approver, sizeof r->approver)); }
    kx_jw_key(&w, "client_pid");  kx_jw_int(&w, r->client_pid);
    kx_jw_key(&w, "client_type"); kx_jw_int(&w, r->client_type);
    if (r->event == KX_EV_DECISION) {
        kx_jw_key(&w, "env");
        kx_jw_obj_begin(&w);
        kx_jw_key(&w, "ledger_ok");   kx_jw_int(&w, r->env.ledger_ok);
        kx_jw_key(&w, "max_age_ns");  kx_jw_int(&w, (int64_t)r->env.telemetry_max_age_ns);
        kx_jw_key(&w, "now_mono_ns"); kx_jw_int(&w, (int64_t)r->env.now_mono_ns);
        kx_jw_key(&w, "now_rt_ms");   kx_jw_int(&w, r->env.now_rt_ms);
        kx_jw_obj_end(&w);
    }
    if (r->escalation_id) { kx_jw_key(&w, "escalation_id"); kx_jw_int(&w, r->escalation_id); }
    if (r->event == KX_EV_DECISION) { kx_jw_key(&w, "eval_ns"); kx_jw_int(&w, r->eval_ns); }
    kx_jw_key(&w, "event"); kx_jw_str(&w, EVENT_NAMES[r->event]);
    if (r->event == KX_EV_DECISION) { kx_jw_key(&w, "gate"); kx_jw_str(&w, GATE_NAMES[r->gate <= KX_GATE__MAX ? r->gate : 0]); }
    if (r->has_grant) { hex(r->grant_id, 16, gid); kx_jw_key(&w, "grant_id"); kx_jw_str(&w, gid); }
    if (r->has_intent) {
        kx_jw_key(&w, "intent");
        write_intent(&w, r, tenant_id);
        sha_hex_prefixed(r->intent_hash, h);
        kx_jw_key(&w, "intent_hash"); kx_jw_str(&w, h);
    }
    kx_jw_key(&w, "ledger_seq"); kx_jw_int(&w, (int64_t)r->ledger_seq);
    sha_hex_prefixed(r->policy_hash, h);
    kx_jw_key(&w, "policy_hash"); kx_jw_str(&w, h);
    if (r->event == KX_EV_POLICY) { sha_hex_prefixed(r->prev_policy_hash, h); kx_jw_key(&w, "previous_policy_hash"); kx_jw_str(&w, h); }
    if (r->event == KX_EV_EPOCH) { kx_jw_key(&w, "quarantined_bytes"); kx_jw_int(&w, (int64_t)r->quarantined_bytes); }
    if (r->event == KX_EV_EPOCH && r->has_rate_config) {   /* F12: the principals this epoch rate-limits */
        kx_jw_key(&w, "rate"); kx_jw_obj_begin(&w);
        kx_jw_key(&w, "all_types"); kx_jw_int(&w, r->rate_all_types);
        kx_jw_key(&w, "types"); kx_jw_arr_begin(&w);
        for (uint8_t i = 0; i < r->n_rate_types && i < KX_RL_MAX_TYPES; i++) kx_jw_int(&w, r->rate_types[i]);
        kx_jw_arr_end(&w);
        kx_jw_obj_end(&w);
    }
    if (r->event == KX_EV_DECISION && r->has_rate) {        /* F12: the bucket this decision was made on */
        kx_jw_key(&w, "rate"); kx_jw_obj_begin(&w);
        kx_jw_key(&w, "burst"); kx_jw_int(&w, r->rate_burst);
        if (r->rate_overflow) { kx_jw_key(&w, "overflow"); kx_jw_int(&w, 1); }
        kx_jw_key(&w, "per_min"); kx_jw_int(&w, r->rate_per_min);
        kx_jw_key(&w, "tat_ns"); kx_jw_int(&w, (int64_t)r->rate_tat_ns);
        kx_jw_obj_end(&w);
    }
    kx_jw_key(&w, "reason"); kx_jw_str(&w, reason_name(r->reason));
    if (r->event == KX_EV_EPOCH && r->restart) {       /* why this epoch began: supervisor restart */
        kx_jw_key(&w, "recovery"); kx_jw_obj_begin(&w);
        kx_jw_key(&w, "cause"); kx_jw_strn(&w, r->restart_cause, bnlen(r->restart_cause, sizeof r->restart_cause));
        kx_jw_key(&w, "restart"); kx_jw_int(&w, r->restart);
        kx_jw_obj_end(&w);
    }
    if (r->rule_id[0]) { kx_jw_key(&w, "rule_id"); kx_jw_strn(&w, r->rule_id, bnlen(r->rule_id, sizeof r->rule_id)); }
    if (r->has_telemetry) { kx_jw_key(&w, "telemetry"); write_telemetry(&w, &r->telemetry); }
    if (r->event == KX_EV_DECISION || r->event == KX_EV_ESC_RESOLVED) {
        kx_jw_key(&w, "verdict"); kx_jw_str(&w, VERDICTS[r->verdict & 3]);
    }
    kx_jw_obj_end(&w);
    return kx_jw_ok(&w) ? (int)w.len : -1;
}

/* ------------------------------------------------------------ disposition */

typedef struct { const char *decision, *approver, *verdict_class; int human; } disp_t;

static disp_t disposition_of(const kx_capsule_rec_t *r) {
    switch (r->event) {
    case KX_EV_EPOCH:         return (disp_t){ "accept", "policy", "epoch_boundary", 0 };
    case KX_EV_POLICY:        return (disp_t){ "accept", "human", "resolved", 1 };   /* author + approver signed it */
    case KX_EV_EFFECT:        return (disp_t){ "accept", "policy", r->effect_ok ? "executed" : "errored", 0 };
    case KX_EV_GRANT_REFUSED: return (disp_t){ "reject", "policy", "denied", 0 };
    case KX_EV_GRANT_EXPIRED: return (disp_t){ "reject", "policy", "expired", 0 };
    case KX_EV_DECISION:
        if (r->verdict == KX_VERDICT_ALLOW)    return (disp_t){ "accept", "policy", NULL, 0 }; /* authorized, not yet executed */
        if (r->verdict == KX_VERDICT_ESCALATE) return (disp_t){ "needs_input", "policy", "escalated", 0 };
        return (disp_t){ "reject", "policy", "blocked", 0 };
    case KX_EV_ESC_RESOLVED:
        if (r->reason == KX_R_HUMAN_APPROVED)    return (disp_t){ "accept", "human", "resolved", 1 };
        if (r->reason == KX_R_HUMAN_DENIED)      return (disp_t){ "reject", "human", "denied", 1 };
        if (r->reason == KX_R_ESCALATION_TIMEOUT) return (disp_t){ "reject", "policy", "expired", 0 };
        return (disp_t){ "reject", "policy", "blocked", 0 };  /* approved, but re-evaluation blocked it */
    default:
        return (disp_t){ NULL, NULL, NULL, 0 };
    }
}

/* ------------------------------------------------------------ capsule */

static int write_capsule(kx_jw_t *w, const kx_capsule_rec_t *r, const kx_capsule_ctx_t *ctx, const uint8_t parent[32],
                         kx_relation_t rel, const uint8_t ref[32], const char *evidence, size_t ev_len,
                         const uint8_t ev_digest[32], const char *capsule_id_hex) {
    char uuid[37], h[72], ts[25], tmp[72];
    disp_t d = disposition_of(r);
    if (d.decision == NULL || kx_fmt_rfc3339_ms(r->timestamp_ms, ts) != 0) return -1;
    int fyi = r->event == KX_EV_EPOCH || r->event == KX_EV_POLICY;
    if (!fyi && !r->has_intent) return -1;
    const kx_action_spec_t *a = r->has_intent ? kx_catalog_action(r->intent.action) : NULL;
    int planned = r->event == KX_EV_DECISION && r->verdict == KX_VERDICT_ALLOW;
    int dispatched = r->event == KX_EV_EFFECT;
    if ((planned || dispatched) && a == NULL) return -1;
    if (r->has_intent) kx_fmt_uuid(r->intent.intent_id, uuid);
    char epoch_hex[65];
    hex(ctx->epoch_id, 32, epoch_hex);

    kx_jw_obj_begin(w);
    kx_jw_key(w, "action_id");
    if (r->event == KX_EV_EPOCH) { memcpy(tmp, "epoch:", 6); memcpy(tmp + 6, epoch_hex, 16); tmp[22] = '\0'; kx_jw_str(w, tmp); }
    else if (r->event == KX_EV_POLICY) { memcpy(tmp, "policy:", 7); hex(r->policy_hash, 8, tmp + 7); kx_jw_str(w, tmp); }
    else kx_jw_str(w, uuid);
    kx_jw_key(w, "action_type"); kx_jw_str(w, fyi ? "fyi" : "decide");
    kx_jw_key(w, "assurance");
    kx_jw_obj_begin(w);
    kx_jw_key(w, "attestation_mode"); kx_jw_str(w, "self_attested");
    kx_jw_key(w, "effect_mode"); kx_jw_str(w, dispatched ? (r->effect_ok ? "confirmed" : "dispatched_unconfirmed") : "not_applicable");
    kx_jw_key(w, "ledger_mode"); kx_jw_str(w, parent ? "chained" : "standalone");
    kx_jw_obj_end(w);
    kx_jw_key(w, "canonicalization_id"); kx_jw_str(w, "jcs");
    if (capsule_id_hex) { kx_jw_key(w, "capsule_id"); kx_jw_str(w, capsule_id_hex); }
    if (parent) {
        static const char *const REL[] = { "", "follows", "confirms", "epoch_opens" };
        hex(parent, 32, tmp);
        kx_jw_key(w, "chain");
        kx_jw_obj_begin(w);
        kx_jw_key(w, "parent_capsule_id"); kx_jw_str(w, tmp);
        kx_jw_key(w, "relation"); kx_jw_str(w, REL[rel <= KX_REL_EPOCH_OPENS ? rel : KX_REL_FOLLOWS]);
        kx_jw_obj_end(w);
    }
    if (r->event == KX_EV_DECISION) {
        char cid[96];
        size_t L;
        if (r->gate != KX_GATE_NONE) {
            memcpy(cid, "com.kervix.constitution.", 24);
            L = strlen(GATE_NAMES[r->gate <= KX_GATE__MAX ? r->gate : 0]);
            memcpy(cid + 24, GATE_NAMES[r->gate <= KX_GATE__MAX ? r->gate : 0], L + 1);
        } else {
            memcpy(cid, "com.kervix.policy.", 18);
            const char *rid = r->rule_id[0] ? r->rule_id : "default";
            L = bnlen(rid, sizeof r->rule_id);
            memcpy(cid + 18, rid, L);
            cid[18 + L] = '\0';
        }
        int blocking = r->verdict == KX_VERDICT_BLOCK;
        hex(ev_digest, 32, tmp);
        kx_jw_key(w, "constraints");
        kx_jw_arr_begin(w);
        kx_jw_obj_begin(w);
        kx_jw_key(w, "blocking"); kx_jw_bool(w, blocking);
        kx_jw_key(w, "check_type"); kx_jw_str(w, r->gate != KX_GATE_NONE ? "com.kervix.constitution" : "com.kervix.deterministic_policy");
        kx_jw_key(w, "evidence_digest"); kx_jw_str(w, tmp);
        kx_jw_key(w, "id"); kx_jw_str(w, cid);
        kx_jw_key(w, "method"); kx_jw_str(w, "com.kervix.kx_eval.v1");
        kx_jw_key(w, "result"); kx_jw_str(w, blocking ? "fail" : "pass");
        kx_jw_key(w, "severity"); kx_jw_str(w, blocking ? "critical" : "info");
        kx_jw_obj_end(w);
        kx_jw_arr_end(w);
    }
    if (r->has_intent) { memcpy(tmp, "intent:", 7); memcpy(tmp + 7, uuid, 37); kx_jw_key(w, "decision_id"); kx_jw_str(w, tmp); }
    kx_jw_key(w, "developer"); kx_jw_str(w, KX_CAPSULE_DEVELOPER);
    kx_jw_key(w, "disposition");
    kx_jw_obj_begin(w);
    kx_jw_key(w, "approver"); kx_jw_str(w, d.approver);
    sha_hex_prefixed(r->policy_hash, h);
    kx_jw_key(w, "authority"); kx_jw_str(w, h);
    kx_jw_key(w, "decision"); kx_jw_str(w, d.decision);
    kx_jw_key(w, "human_disposed"); kx_jw_bool(w, d.human);
    {
        uint8_t rd[32];
        const char *rn = reason_name(r->reason);
        kx_sha256(rn, strlen(rn), rd);
        hex(rd, 32, tmp);
        kx_jw_key(w, "reason_digest"); kx_jw_str(w, tmp);
    }
    if (d.verdict_class) { kx_jw_key(w, "verdict_class"); kx_jw_str(w, d.verdict_class); }
    kx_jw_obj_end(w);
    if (planned || dispatched) {
        char type[96];
        memcpy(type, "vehicle.", 8);
        memcpy(type + 8, a->name, strlen(a->name) + 1);
        kx_jw_key(w, "effect");
        kx_jw_obj_begin(w);
        if (dispatched) { kx_jw_key(w, "effect_attestation"); kx_jw_str(w, "gate_executed"); }
        kx_jw_key(w, "irreversibility_class"); kx_jw_str(w, kx_irreversibility_names[a->irreversibility]);
        if (dispatched) {
            hex(r->request_digest, 32, tmp);  kx_jw_key(w, "request_digest");  kx_jw_str(w, tmp);
            if (r->effect_ok) { hex(r->response_digest, 32, tmp); kx_jw_key(w, "response_digest"); kx_jw_str(w, tmp); }
        }
        kx_jw_key(w, "status"); kx_jw_str(w, planned ? "planned" : r->effect_ok ? "confirmed" : "failed");
        kx_jw_key(w, "type"); kx_jw_str(w, type);
        kx_jw_obj_end(w);
    }
    memcpy(h, "sha256:", 7); memcpy(h + 7, epoch_hex, 65);
    kx_jw_key(w, "epoch_id"); kx_jw_str(w, h);
    kx_jw_key(w, "evidence");
    kx_jw_obj_begin(w);
    kx_jw_key(w, "kervix"); kx_jw_raw(w, evidence, ev_len);
    kx_jw_obj_end(w);
    kx_jw_key(w, "format_version"); kx_jw_str(w, "4");
    kx_jw_key(w, "operator"); kx_jw_str(w, ctx->vehicle_id);
    if (dispatched && ref != NULL && !(parent != NULL && memcmp(parent, ref, 32) == 0)) {
        hex(ref, 32, tmp);
        kx_jw_key(w, "references");
        kx_jw_arr_begin(w);
        kx_jw_obj_begin(w);
        kx_jw_key(w, "citation_purpose"); kx_jw_str(w, "responds_to");
        kx_jw_key(w, "digest"); kx_jw_str(w, tmp);
        kx_jw_key(w, "digest_alg"); kx_jw_str(w, "sha-256");
        kx_jw_key(w, "type"); kx_jw_str(w, "aac-capsule");
        kx_jw_obj_end(w);
        kx_jw_arr_end(w);
    }
    kx_jw_key(w, "spec_version"); kx_jw_str(w, KX_AAC_SPEC_VERSION);
    kx_jw_key(w, "timestamp"); kx_jw_str(w, ts);
    kx_jw_obj_end(w);
    return 0;
}

int kx_capsule_build(const kx_capsule_rec_t *rec, const kx_capsule_ctx_t *ctx, const uint8_t parent[32],
                     kx_relation_t relation, const uint8_t ref_decision[32], char *out, size_t cap,
                     uint8_t capsule_id[32]) {
    if (rec == NULL || ctx == NULL || ctx->vehicle_id == NULL || out == NULL) return -1;
    if (rec->event < KX_EV_EPOCH || rec->event > KX_EV_POLICY) return -1;
    static char evidence[3072];  /* single writer thread: static scratch, not reentrant */
    int ev = write_evidence(rec, ctx->tenant_id, evidence, sizeof evidence);
    if (ev < 0) return -1;
    uint8_t ev_digest[32];
    kx_sha256(evidence, (size_t)ev, ev_digest);

    /* pass 1: preimage without capsule_id -> identity */
    kx_jw_t w;
    kx_jw_init(&w, out, cap);
    if (write_capsule(&w, rec, ctx, parent, relation, ref_decision, evidence, (size_t)ev, ev_digest, NULL) != 0 || !kx_jw_ok(&w)) return -1;
    kx_sha256(out, w.len, capsule_id);
    /* pass 2: final capsule with capsule_id */
    char idhex[65];
    hex(capsule_id, 32, idhex);
    kx_jw_init(&w, out, cap);
    if (write_capsule(&w, rec, ctx, parent, relation, ref_decision, evidence, (size_t)ev, ev_digest, idhex) != 0 || !kx_jw_ok(&w)) return -1;
    return (int)w.len;
}

kx_verdict_t kx_capsule_replay(const kx_policy_t *pol, const kx_capsule_rec_t *rec, kx_eval_result_t *out) {
    return kx_eval(pol, &rec->intent, &rec->telemetry, &rec->env, out);
}
