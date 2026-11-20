/*
 * Agent Action Capsule (draft-04) builder for Kervix lifecycle events.
 * Portable, allocation-free, bounded. Mapping: docs/03-architecture.md §8.2
 * (frozen by spike S5).
 *
 * kervixd's hot path fills a fixed-size kx_capsule_rec_t and enqueues it; the
 * low-priority ledger writer turns it into canonical JSON (RFC 8785 / JCS),
 * derives capsule_id = sha256(JCS(capsule without capsule_id)), signs that id
 * (COSE_Sign1, kervix/cose.h) and appends both to the ledger.
 *
 * Evidence carries the INPUTS of every decision (intent, telemetry snapshot,
 * evaluation environment), not just its outputs, so an offline verifier can
 * re-run kx_eval() and reproduce the verdict bit-for-bit (replay).
 */
#ifndef KERVIX_CAPSULE_H
#define KERVIX_CAPSULE_H

#include <stddef.h>
#include <stdint.h>

#include "kervix/abi.h"
#include "kervix/policy.h"

#define KX_AAC_SPEC_VERSION   "draft-mih-scitt-agent-action-capsule-04"
#define KX_CAPSULE_DEVELOPER  "kervix:authority:0.2.0"
#define KX_CAPSULE_JCS_MAX    6144u

typedef enum {
    KX_EV_EPOCH = 1,        /* kervixd (re)start: new epoch, chained to the previous head */
    KX_EV_DECISION,         /* PROPOSE outcome: ALLOW (planned effect) / ESCALATE / BLOCK */
    KX_EV_EFFECT,           /* actuation outcome reported by sdv_actuatord */
    KX_EV_ESC_RESOLVED,     /* driver approved / denied, or the escalation timed out */
    KX_EV_GRANT_REFUSED,    /* redemption refused: MAC/UNKNOWN/SPENT/EXPIRED/PARAMS/BINDING/INTERLOCK */
    KX_EV_GRANT_EXPIRED,    /* grant reaped unused */
} kx_event_t;

typedef enum { KX_REL_NONE = 0, KX_REL_FOLLOWS, KX_REL_CONFIRMS, KX_REL_EPOCH_OPENS } kx_relation_t;

/* Everything one capsule needs, by value (no pointers): queue-friendly. */
typedef struct {
    uint8_t        event;              /* kx_event_t */
    uint8_t        verdict;            /* kx_verdict_t (DECISION, ESC_RESOLVED) */
    uint8_t        gate;               /* kx_gate_t (DECISION) */
    uint8_t        human;              /* 1 if a human disposed (ESC_RESOLVED approve/deny) */
    uint16_t       reason;             /* kx_reason_t */
    int16_t        rule_index;
    char           rule_id[32];
    uint8_t        effect_ok;          /* EFFECT */
    uint8_t        has_intent, has_telemetry, has_grant;
    uint32_t       escalation_id;
    uint32_t       eval_ns;
    uint64_t       ledger_seq;         /* assigned by the writer */
    int64_t        timestamp_ms;       /* realtime, for the capsule timestamp */
    kx_intent_t    intent;             /* has_intent */
    int64_t        captured_at_ms;     /* binding context (intent hash recomputation) */
    uint8_t        intent_hash[32];
    uint8_t        policy_hash[32];
    kx_telemetry_t telemetry;          /* has_telemetry */
    kx_eval_env_t  env;                /* evaluation environment (replay) */
    uint8_t        grant_id[16];       /* has_grant */
    uint8_t        request_digest[32], response_digest[32]; /* EFFECT */
    char           approver[48];       /* ESC_RESOLVED */
    uint32_t       client_type;
    int32_t        client_pid;
    uint64_t       quarantined_bytes;  /* EPOCH: torn ledger tail moved aside at recovery */
} kx_capsule_rec_t;

typedef struct {
    const char *vehicle_id;            /* operator */
    const char *tenant_id;             /* binding context */
    uint8_t     epoch_id[32];
} kx_capsule_ctx_t;

/* Canonical capsule JSON. parent == NULL means no chain member.
 * ref_decision (EFFECT only, may be NULL): the decision capsule this effect
 * responds to, cited in references[] when it is not the chain parent.
 * Writes NUL-terminated JSON (with capsule_id) to out and the id to capsule_id.
 * Returns the JSON length, or -1 (invalid record / buffer too small). */
int kx_capsule_build(const kx_capsule_rec_t *rec, const kx_capsule_ctx_t *ctx, const uint8_t parent[32],
                     kx_relation_t relation, const uint8_t ref_decision[32], char *out, size_t cap,
                     uint8_t capsule_id[32]);

/* Reconstruct the evaluation inputs recorded in a DECISION record (replay):
 * returns kx_eval() on (policy, rec->intent, rec->telemetry, rec->env). */
kx_verdict_t kx_capsule_replay(const kx_policy_t *pol, const kx_capsule_rec_t *rec, kx_eval_result_t *out);

#endif /* KERVIX_CAPSULE_H */
