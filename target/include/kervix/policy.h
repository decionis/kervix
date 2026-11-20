/*
 * libkxcore policy engine: deterministic, bounded-time, allocation-free.
 *
 *   kx_eval() is a PURE function of (policy, intent, telemetry, env).
 *   It reads no clock, does no I/O and allocates nothing, so the offline
 *   verifier can replay any recorded decision bit-for-bit.
 *
 * Evaluation order (first failure wins):
 *   K4  intent validation (known action, exact params, ranges, digest)
 *   --  caller expiry (env.now_rt_ms > intent.expires_rt_ms)
 *   K1  telemetry freshness (stale -> BLOCK unless action is two_way + QM)
 *   K2  telemetry plausibility (ranges, gear P while moving)
 *   K3  ledger health (no audit -> BLOCK non-QM)
 *   --  rules for the action, in policy order, first match wins
 *   --  policy default verdict (BLOCK by default)
 */
#ifndef KERVIX_POLICY_H
#define KERVIX_POLICY_H

#include <stdint.h>
#include "kervix/abi.h"

#define KX_MAX_RULES       256u
#define KX_MAX_PREDS       2048u
#define KX_MAX_RULE_PREDS  8u     /* per section (when / interlock / require) */
#define KX_RULE_ID_LEN     32u
#define KX_POLICY_ID_LEN   32u

/* Plausibility: gear P while faster than this is physically inconsistent. */
#define KX_PLAUSIBLE_MAX_SPEED_IN_P_DKPH 20

/* ---- predicates ---------------------------------------------------------
 * value = fn(a [, b]);  result = value <op> k
 * Predicates with the same non-zero `group` are OR-ed; groups and
 * ungrouped predicates are AND-ed. */
typedef enum { KX_SRC_NONE = 0, KX_SRC_TELEMETRY = 1, KX_SRC_PARAM = 2 } kx_src_t;
typedef enum { KX_FN_VALUE = 0, KX_FN_ABSDIFF = 1 } kx_fn_t;
typedef enum { KX_OP_EQ = 0, KX_OP_NE, KX_OP_LT, KX_OP_LE, KX_OP_GT, KX_OP_GE } kx_op_t;

typedef struct {
    uint8_t  src;   /* kx_src_t */
    uint8_t  _pad;
    uint16_t id;    /* kx_tfield_t or kx_param_key_t */
} kx_operand_t;

typedef struct {
    kx_operand_t a, b;  /* b used only by KX_FN_ABSDIFF */
    uint8_t      fn;    /* kx_fn_t */
    uint8_t      op;    /* kx_op_t */
    uint8_t      group; /* 0 = AND; n>0 = OR within group n */
    uint8_t      _pad[5];
    int64_t      k;
} kx_pred_t;

typedef struct {
    uint16_t off;  /* index into kx_policy_t.preds */
    uint8_t  n;    /* <= KX_MAX_RULE_PREDS */
    uint8_t  _pad;
} kx_pred_span_t;

typedef struct {
    char           id[KX_RULE_ID_LEN]; /* stable rule id, recorded in capsules */
    uint16_t       action;             /* kx_action_id_t */
    uint8_t        verdict;            /* kx_verdict_t */
    uint8_t        _pad;
    uint16_t       reason;             /* kx_reason_t reported when the rule matches */
    uint16_t       require_reason;     /* ESCALATE: reason when `require` fails (-> BLOCK) */
    kx_pred_span_t when;               /* match condition */
    kx_pred_span_t interlock;          /* must still hold at grant redemption */
    kx_pred_span_t require;            /* ESCALATE only: preconditions for asking a human */
    uint32_t       grant_ttl_ms;       /* ALLOW: grant lifetime */
    uint32_t       esc_timeout_ms;     /* ESCALATE: human response window */
} kx_rule_t;

typedef struct {
    char      policy_id[KX_POLICY_ID_LEN];
    uint32_t  version;                 /* semver packed: major<<16 | minor<<8 | patch */
    uint8_t   hash[32];                /* sha256 of the signed bundle body */
    uint8_t   default_verdict;         /* KX_VERDICT_BLOCK */
    uint8_t   finalized;
    uint16_t  default_reason;          /* KX_R_DEFAULT_DENY */
    uint16_t  n_rules;
    uint16_t  n_preds;
    kx_rule_t rules[KX_MAX_RULES];
    kx_pred_t preds[KX_MAX_PREDS];
    /* index: rules for action a are rules[first[a] .. first[a]+count[a]) */
    uint16_t  first[KX_ACTION_MAX_ID + 1];
    uint16_t  count[KX_ACTION_MAX_ID + 1];
} kx_policy_t;

/* ---- evaluation ---------------------------------------------------------- */
typedef struct {
    uint64_t now_mono_ns;            /* CLOCK_MONOTONIC "now" as seen by the caller */
    int64_t  now_rt_ms;              /* realtime epoch ms (intent expiry only) */
    uint64_t telemetry_max_age_ns;   /* K1 threshold, e.g. 50 ms */
    uint8_t  ledger_ok;              /* K3: 0 = audit path unhealthy */
} kx_eval_env_t;

typedef enum {
    KX_GATE_NONE = 0,       /* decided by a rule or the default */
    KX_GATE_K4_VALIDATION,
    KX_GATE_EXPIRY,
    KX_GATE_K1_STALE,
    KX_GATE_K2_IMPLAUSIBLE,
    KX_GATE_K3_LEDGER,
    KX_GATE_REQUIRE         /* ESCALATE rule whose `require` failed */
} kx_gate_t;

typedef struct {
    uint8_t  verdict;        /* kx_verdict_t */
    uint8_t  gate;           /* kx_gate_t */
    uint16_t reason;         /* kx_reason_t */
    int16_t  rule_index;     /* matched rule, or -1 */
    uint16_t _pad;
    uint32_t grant_ttl_ms;
    uint32_t esc_timeout_ms;
} kx_eval_result_t;

/* Pure evaluation. Never fails: invalid inputs yield BLOCK with a reason.
 * Returns the verdict for convenience. */
kx_verdict_t kx_eval(const kx_policy_t *pol, const kx_intent_t *in, const kx_telemetry_t *tel,
                     const kx_eval_env_t *env, kx_eval_result_t *out);

/* Interlock re-check at grant redemption (TOCTOU closure).
 * 1 = still safe, 0 = interlock failed (or rule index invalid). */
int kx_interlock_ok(const kx_policy_t *pol, int16_t rule_index, const kx_intent_t *in,
                    const kx_telemetry_t *tel);

/* Building blocks, exposed for kervixd and tests. */
uint16_t kx_validate_intent(const kx_intent_t *in);        /* KX_R_OK or a reason */
int      kx_telemetry_plausible(const kx_telemetry_t *tel); /* 1 / 0 */

/* ---- construction (used by the .kxp loader and by tests) ----------------
 * All return 0 on success, -1 on a bound/validation error. */
void kx_policy_init(kx_policy_t *pol, const char *policy_id, uint32_t version);
int  kx_policy_add_pred(kx_policy_t *pol, kx_pred_t pred);   /* appends; returns index or -1 */
int  kx_policy_add_rule(kx_policy_t *pol, const kx_rule_t *rule);
int  kx_policy_finalize(kx_policy_t *pol);                    /* validates + builds the action index */

#endif /* KERVIX_POLICY_H */
