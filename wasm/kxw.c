/*
 * WebAssembly export layer over the UNMODIFIED libkxcore sources, for the
 * offline replay check in kervix-verify (and, later, in-browser verification).
 * JS fills the evaluation inputs through setters, so it never depends on C
 * struct layout; everything decisive runs in the same C code as on QNX.
 */
#include <stdint.h>
#include <string.h>

#include "kervix/intent.h"
#include "kervix/policy.h"

#define EXPORT(name) __attribute__((export_name(name)))

static kx_policy_t    POL;
static kx_intent_t    IN;
static kx_telemetry_t TEL;
static kx_eval_env_t  ENV;
static kx_eval_result_t RES;
static char           STR[256];   /* scratch for strings passed in from JS */
static uint8_t        HASH[32];

EXPORT("kxw_init") int kxw_init(void) { return kx_policy_build_default(&POL); }
EXPORT("kxw_policy_hash") const uint8_t *kxw_policy_hash(void) { return POL.hash; }
/* Load a policy body (written by JS into the kxw_body() buffer) in place of the
 * current policy: the same loader and finalize that run in kervixd. 0 = ok;
 * on failure the built-in policy is restored and -1 returned. */
static uint8_t BODY[KX_POLICY_BODY_MAX];
EXPORT("kxw_body") uint8_t *kxw_body(void) { return BODY; }
EXPORT("kxw_body_max") uint32_t kxw_body_max(void) { return KX_POLICY_BODY_MAX; }
EXPORT("kxw_load") int kxw_load(uint32_t n) {
    if (n <= KX_POLICY_BODY_MAX && kx_policy_load(&POL, BODY, n) == 0) return 0;
    kx_policy_build_default(&POL);
    return -1;
}
EXPORT("kxw_rule_count") uint32_t kxw_rule_count(void) { return POL.n_rules; }
EXPORT("kxw_str") char *kxw_str(void) { return STR; }
EXPORT("kxw_hash") const uint8_t *kxw_hash(void) { return HASH; }
EXPORT("kxw_catalog_sha") const char *kxw_catalog_sha(void) { return KX_CATALOG_SHA256; }

EXPORT("kxw_intent_reset") void kxw_intent_reset(uint32_t action, int64_t expires_rt_ms) {
    memset(&IN, 0, sizeof IN);
    IN.abi = KX_ABI_VERSION;
    IN.action = (uint16_t)action;
    IN.expires_rt_ms = expires_rt_ms;
}
EXPORT("kxw_intent_param") int kxw_intent_param(uint32_t key, int64_t val) {
    if (IN.n_params >= KX_MAX_PARAMS) return -1;
    IN.p[IN.n_params].key = (uint16_t)key;
    IN.p[IN.n_params].val = val;
    IN.n_params++;
    return 0;
}
EXPORT("kxw_intent_digest") void kxw_intent_digest(uint32_t i, uint32_t byte) { if (i < 32) { IN.digest[i] = (uint8_t)byte; IN.has_digest = 1; } }
EXPORT("kxw_intent_id") void kxw_intent_id(uint32_t i, uint32_t byte) { if (i < 16) IN.intent_id[i] = (uint8_t)byte; }
/* actor id from STR */
EXPORT("kxw_intent_actor") int kxw_intent_actor(void) {
    size_t n = strlen(STR);
    if (n >= KX_ACTOR_LEN) return -1;
    memcpy(IN.actor_id, STR, n + 1);
    return 0;
}
EXPORT("kxw_tel_reset") void kxw_tel_reset(int64_t seq, int64_t mono_ns) { memset(&TEL, 0, sizeof TEL); TEL.seq = (uint64_t)seq; TEL.mono_ns = (uint64_t)mono_ns; }
EXPORT("kxw_tel_set") int kxw_tel_set(uint32_t field, int32_t v) { if (field >= KX_TF__COUNT) return -1; TEL.v[field] = v; return 0; }
EXPORT("kxw_env") void kxw_env(int64_t now_mono_ns, int64_t now_rt_ms, int64_t max_age_ns, uint32_t ledger_ok) {
    ENV.now_mono_ns = (uint64_t)now_mono_ns;
    ENV.now_rt_ms = now_rt_ms;
    ENV.telemetry_max_age_ns = (uint64_t)max_age_ns;
    ENV.ledger_ok = (uint8_t)ledger_ok;
}
/* returns verdict | gate << 8 | reason << 16 */
EXPORT("kxw_eval") uint32_t kxw_eval(void) {
    kx_eval(&POL, &IN, &TEL, &ENV, &RES);
    return (uint32_t)RES.verdict | (uint32_t)RES.gate << 8 | (uint32_t)RES.reason << 16;
}
EXPORT("kxw_rule_index") int32_t kxw_rule_index(void) { return RES.rule_index; }
EXPORT("kxw_rule_id") const char *kxw_rule_id(void) { return RES.rule_index >= 0 ? POL.rules[RES.rule_index].id : ""; }
/* intent hash with context from STR: "tenant\nvehicle\nactor_type" and captured_at_ms */
EXPORT("kxw_intent_hash") int kxw_intent_hash(int64_t captured_at_ms) {
    char *t = STR, *v = 0, *a = 0;
    for (char *p = STR; *p; p++) if (*p == '\n') { *p = 0; if (!v) v = p + 1; else if (!a) a = p + 1; }
    if (!v || !a) return -1;
    kx_intent_ctx_t ctx = { t, v, a, captured_at_ms };
    return kx_intent_hash(&IN, &ctx, HASH);
}
