/*
 * libkxcore: deterministic policy evaluation. See kervix/policy.h.
 * Rules for this file: no OS headers, no clocks, no malloc, no recursion,
 * every loop bounded by a compile-time constant.
 */
#include <stddef.h>
#include <string.h>

#include "kervix/jcs.h"
#include "kervix/policy.h"

#define KX_DEFAULT_GRANT_TTL_MS  250u
#define KX_DEFAULT_ESC_TIMEOUT_MS 30000u

/* ------------------------------------------------------------------ helpers */

static const kx_param_t *find_param(const kx_intent_t *in, uint16_t key) {
    uint8_t n = in->n_params <= KX_MAX_PARAMS ? in->n_params : KX_MAX_PARAMS;
    for (uint8_t i = 0; i < n; i++) {
        if (in->p[i].key == key) return &in->p[i];
    }
    return NULL;
}

/* Returns 0 and sets *v on success; -1 if the operand cannot be resolved. */
static int operand_value(const kx_operand_t *o, const kx_intent_t *in, const kx_telemetry_t *tel,
                         int64_t *v) {
    switch (o->src) {
    case KX_SRC_TELEMETRY:
        if (o->id >= KX_TF__COUNT) return -1;
        *v = tel->v[o->id];
        return 0;
    case KX_SRC_PARAM: {
        const kx_param_t *p = find_param(in, o->id);
        if (p == NULL) return -1;
        *v = p->val;
        return 0;
    }
    default:
        return -1;
    }
}

/* An unresolvable predicate is FALSE: a rule can never match on missing data. */
static int pred_true(const kx_pred_t *pr, const kx_intent_t *in, const kx_telemetry_t *tel) {
    int64_t a, b, v;
    if (operand_value(&pr->a, in, tel, &a) != 0) return 0;
    if (pr->fn == KX_FN_ABSDIFF) {
        if (operand_value(&pr->b, in, tel, &b) != 0) return 0;
        v = a - b; /* operands are range-checked catalog values: no overflow */
        if (v < 0) v = -v;
    } else if (pr->fn == KX_FN_VALUE) {
        v = a;
    } else {
        return 0;
    }
    switch (pr->op) {
    case KX_OP_EQ: return v == pr->k;
    case KX_OP_NE: return v != pr->k;
    case KX_OP_LT: return v <  pr->k;
    case KX_OP_LE: return v <= pr->k;
    case KX_OP_GT: return v >  pr->k;
    case KX_OP_GE: return v >= pr->k;
    default:       return 0;
    }
}

/* AND of ungrouped predicates, AND over groups of (OR within group).
 * An empty span is TRUE. */
static int span_true(const kx_policy_t *pol, kx_pred_span_t s, const kx_intent_t *in,
                     const kx_telemetry_t *tel) {
    uint8_t groups[KX_MAX_RULE_PREDS];
    uint8_t group_sat[KX_MAX_RULE_PREDS];
    uint8_t n_groups = 0;
    uint8_t n = s.n <= KX_MAX_RULE_PREDS ? s.n : KX_MAX_RULE_PREDS;

    for (uint8_t i = 0; i < n; i++) {
        const kx_pred_t *pr = &pol->preds[s.off + i];
        int t = pred_true(pr, in, tel);
        if (pr->group == 0) {
            if (!t) return 0;
            continue;
        }
        uint8_t g = 0;
        while (g < n_groups && groups[g] != pr->group) g++;
        if (g == n_groups) {
            groups[n_groups] = pr->group;
            group_sat[n_groups] = 0;
            n_groups++;
        }
        if (t) group_sat[g] = 1;
    }
    for (uint8_t g = 0; g < n_groups; g++) {
        if (!group_sat[g]) return 0;
    }
    return 1;
}

static void result_set(kx_eval_result_t *out, kx_verdict_t v, kx_gate_t gate, uint16_t reason,
                       int16_t rule_index) {
    out->verdict = (uint8_t)v;
    out->gate = (uint8_t)gate;
    out->reason = reason;
    out->rule_index = rule_index;
    out->_pad = 0;
    out->grant_ttl_ms = 0;
    out->esc_timeout_ms = 0;
}

/* --------------------------------------------------------------- validation */

uint16_t kx_validate_intent(const kx_intent_t *in) {
    if (in == NULL || in->abi != KX_ABI_VERSION) return KX_R_PARAM_INVALID;

    const kx_action_spec_t *spec = kx_catalog_action(in->action);
    if (spec == NULL) return KX_R_UNKNOWN_ACTION;

    /* actor id: non-empty, NUL-terminated within the buffer, printable ASCII
     * (it is bound into the canonical intent; no Unicode ambiguity allowed) */
    if (in->actor_id[0] == '\0' || memchr(in->actor_id, '\0', KX_ACTOR_LEN) == NULL) {
        return KX_R_PARAM_INVALID;
    }
    for (size_t i = 0; i < KX_ACTOR_LEN && in->actor_id[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in->actor_id[i];
        if (c < 0x20u || c > 0x7Eu) return KX_R_PARAM_INVALID;
    }
    /* Agent-Safe Intent requires an RFC 4122 UUID (version 1..8) */
    if (!kx_uuid_valid(in->intent_id)) return KX_R_PARAM_INVALID;

    uint8_t want_scalar = 0, want_digest = 0;
    for (uint8_t i = 0; i < spec->n_params && i < KX_CATALOG_MAX_PARAMS; i++) {
        if (spec->params[i].type == KX_PT_DIGEST) want_digest = 1;
        else want_scalar++;
    }
    if (in->n_params != want_scalar || in->n_params > KX_MAX_PARAMS) return KX_R_PARAM_INVALID;
    if (in->has_digest > 1 || in->has_digest != want_digest) return KX_R_PARAM_INVALID;

    for (uint8_t i = 0; i < in->n_params; i++) {
        const kx_param_spec_t *ps = kx_catalog_param(spec, in->p[i].key);
        if (ps == NULL || ps->type == KX_PT_DIGEST) return KX_R_PARAM_INVALID;
        if (in->p[i].val < ps->min || in->p[i].val > ps->max) return KX_R_PARAM_INVALID;
        for (uint8_t j = 0; j < i; j++) {
            if (in->p[j].key == in->p[i].key) return KX_R_PARAM_INVALID; /* duplicate */
        }
    }
    return KX_R_OK;
}

int kx_telemetry_plausible(const kx_telemetry_t *tel) {
    for (uint16_t f = 0; f < KX_TF__COUNT; f++) {
        if (tel->v[f] < kx_catalog_tfields[f].min || tel->v[f] > kx_catalog_tfields[f].max) return 0;
    }
    if (tel->v[KX_TF_GEAR] == KX_GEAR_P && tel->v[KX_TF_SPEED_DKPH] > KX_PLAUSIBLE_MAX_SPEED_IN_P_DKPH) {
        return 0;
    }
    return 1;
}

/* --------------------------------------------------------------- evaluation */

kx_verdict_t kx_eval(const kx_policy_t *pol, const kx_intent_t *in, const kx_telemetry_t *tel,
                     const kx_eval_env_t *env, kx_eval_result_t *out) {
    /* K4: structural validation */
    uint16_t vr = kx_validate_intent(in);
    if (vr != KX_R_OK) {
        result_set(out, KX_VERDICT_BLOCK, KX_GATE_K4_VALIDATION, vr, -1);
        return KX_VERDICT_BLOCK;
    }
    if (pol == NULL || !pol->finalized) {
        result_set(out, KX_VERDICT_BLOCK, KX_GATE_K4_VALIDATION, KX_R_DEFAULT_DENY, -1);
        return KX_VERDICT_BLOCK;
    }
    const kx_action_spec_t *spec = kx_catalog_action(in->action);
    const int low_risk = spec->irreversibility == KX_IRR_TWO_WAY && spec->safety == KX_SAFETY_QM;

    /* caller-supplied expiry */
    if (in->expires_rt_ms != 0 && env->now_rt_ms > in->expires_rt_ms) {
        result_set(out, KX_VERDICT_BLOCK, KX_GATE_EXPIRY, KX_R_INTENT_EXPIRED, -1);
        return KX_VERDICT_BLOCK;
    }

    /* K1: freshness. A sample from the "future" is treated as stale. */
    int stale = tel->mono_ns > env->now_mono_ns ||
                (env->now_mono_ns - tel->mono_ns) > env->telemetry_max_age_ns;
    if (stale && !low_risk) {
        result_set(out, KX_VERDICT_BLOCK, KX_GATE_K1_STALE, KX_R_TELEMETRY_STALE, -1);
        return KX_VERDICT_BLOCK;
    }

    /* K2: plausibility applies to every action: policy must not reason on lies */
    if (!kx_telemetry_plausible(tel)) {
        result_set(out, KX_VERDICT_BLOCK, KX_GATE_K2_IMPLAUSIBLE, KX_R_TELEMETRY_IMPLAUSIBLE, -1);
        return KX_VERDICT_BLOCK;
    }

    /* K3: no audit, no (non-QM) action */
    if (!env->ledger_ok && spec->safety != KX_SAFETY_QM) {
        result_set(out, KX_VERDICT_BLOCK, KX_GATE_K3_LEDGER, KX_R_LEDGER_PRESSURE, -1);
        return KX_VERDICT_BLOCK;
    }

    /* rules: first match wins */
    uint16_t first = pol->first[in->action], count = pol->count[in->action];
    for (uint16_t i = 0; i < count && i < KX_MAX_RULES; i++) {
        uint16_t ri = (uint16_t)(first + i);
        const kx_rule_t *r = &pol->rules[ri];
        if (!span_true(pol, r->when, in, tel)) continue;

        if (r->verdict == KX_VERDICT_ESCALATE && !span_true(pol, r->require, in, tel)) {
            result_set(out, KX_VERDICT_BLOCK, KX_GATE_REQUIRE, r->require_reason, (int16_t)ri);
            return KX_VERDICT_BLOCK;
        }
        result_set(out, (kx_verdict_t)r->verdict, KX_GATE_NONE, r->reason, (int16_t)ri);
        if (r->verdict == KX_VERDICT_ALLOW || r->verdict == KX_VERDICT_ESCALATE) {
            out->grant_ttl_ms = r->grant_ttl_ms;
        }
        if (r->verdict == KX_VERDICT_ESCALATE) out->esc_timeout_ms = r->esc_timeout_ms;
        return (kx_verdict_t)r->verdict;
    }

    result_set(out, (kx_verdict_t)pol->default_verdict, KX_GATE_NONE, pol->default_reason, -1);
    return (kx_verdict_t)pol->default_verdict;
}

int kx_interlock_ok(const kx_policy_t *pol, int16_t rule_index, const kx_intent_t *in,
                    const kx_telemetry_t *tel) {
    if (pol == NULL || !pol->finalized || rule_index < 0 || rule_index >= (int16_t)pol->n_rules) return 0;
    if (!kx_telemetry_plausible(tel)) return 0;
    return span_true(pol, pol->rules[rule_index].interlock, in, tel);
}

/* ------------------------------------------------------------- construction */

void kx_policy_init(kx_policy_t *pol, const char *policy_id, uint32_t version) {
    memset(pol, 0, sizeof(*pol));
    if (policy_id != NULL) {
        size_t n = strlen(policy_id);
        if (n >= KX_POLICY_ID_LEN) n = KX_POLICY_ID_LEN - 1;
        memcpy(pol->policy_id, policy_id, n);
    }
    pol->version = version;
    pol->default_verdict = KX_VERDICT_BLOCK;
    pol->default_reason = KX_R_DEFAULT_DENY;
}

int kx_policy_add_pred(kx_policy_t *pol, kx_pred_t pred) {
    if (pol->finalized || pol->n_preds >= KX_MAX_PREDS) return -1;
    pol->preds[pol->n_preds] = pred;
    return (int)pol->n_preds++;
}

int kx_policy_add_rule(kx_policy_t *pol, const kx_rule_t *rule) {
    if (pol->finalized || pol->n_rules >= KX_MAX_RULES) return -1;
    pol->rules[pol->n_rules++] = *rule;
    return 0;
}

static int operand_valid(const kx_operand_t *o, const kx_action_spec_t *spec) {
    if (o->src == KX_SRC_TELEMETRY) return o->id < KX_TF__COUNT;
    if (o->src == KX_SRC_PARAM) {
        const kx_param_spec_t *ps = kx_catalog_param(spec, o->id);
        return ps != NULL && ps->type != KX_PT_DIGEST;
    }
    return 0;
}

static int span_valid(const kx_policy_t *pol, kx_pred_span_t s, const kx_action_spec_t *spec) {
    if (s.n > KX_MAX_RULE_PREDS) return 0;
    if ((uint32_t)s.off + s.n > pol->n_preds) return 0;
    for (uint8_t i = 0; i < s.n; i++) {
        const kx_pred_t *pr = &pol->preds[s.off + i];
        if (pr->op > KX_OP_GE || pr->fn > KX_FN_ABSDIFF) return 0;
        if (!operand_valid(&pr->a, spec)) return 0;
        if (pr->fn == KX_FN_ABSDIFF && !operand_valid(&pr->b, spec)) return 0;
    }
    return 1;
}

int kx_policy_finalize(kx_policy_t *pol) {
    if (pol->finalized) return -1;
    if (pol->default_verdict != KX_VERDICT_BLOCK && pol->default_verdict != KX_VERDICT_ESCALATE &&
        pol->default_verdict != KX_VERDICT_ALLOW) {
        return -1;
    }

    for (uint16_t i = 0; i < pol->n_rules; i++) {
        kx_rule_t *r = &pol->rules[i];
        const kx_action_spec_t *spec = kx_catalog_action(r->action);
        if (spec == NULL) return -1;
        if (r->verdict < KX_VERDICT_ALLOW || r->verdict > KX_VERDICT_BLOCK) return -1;
        if (kx_catalog_reason(r->reason) == NULL) return -1;
        if (memchr(r->id, '\0', KX_RULE_ID_LEN) == NULL || r->id[0] == '\0') return -1;
        if (!span_valid(pol, r->when, spec) || !span_valid(pol, r->interlock, spec) ||
            !span_valid(pol, r->require, spec)) {
            return -1;
        }
        if (r->verdict == KX_VERDICT_ESCALATE) {
            if (r->esc_timeout_ms == 0) r->esc_timeout_ms = KX_DEFAULT_ESC_TIMEOUT_MS;
            if (r->require.n > 0 && kx_catalog_reason(r->require_reason) == NULL) return -1;
        } else if (r->require.n != 0) {
            return -1; /* `require` only makes sense for ESCALATE */
        }
        if (r->verdict != KX_VERDICT_BLOCK && r->grant_ttl_ms == 0) r->grant_ttl_ms = KX_DEFAULT_GRANT_TTL_MS;
    }

    /* Stable insertion sort by action (load-time only, n <= 256), then index. */
    for (uint16_t i = 1; i < pol->n_rules; i++) {
        kx_rule_t tmp = pol->rules[i];
        uint16_t j = i;
        while (j > 0 && pol->rules[j - 1].action > tmp.action) {
            pol->rules[j] = pol->rules[j - 1];
            j--;
        }
        pol->rules[j] = tmp;
    }
    memset(pol->first, 0, sizeof(pol->first));
    memset(pol->count, 0, sizeof(pol->count));
    for (uint16_t i = 0; i < pol->n_rules; i++) {
        uint16_t a = pol->rules[i].action;
        if (pol->count[a] == 0) pol->first[a] = i;
        pol->count[a]++;
    }
    pol->finalized = 1;
    return 0;
}
