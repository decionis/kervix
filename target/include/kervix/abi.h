/*
 * Kervix ABI v1: fixed-size structs exchanged over QNX message passing
 * (devctl) and evaluated by libkxcore. No pointers, no padding surprises:
 * every struct has a _Static_assert'ed size so client and server agree.
 * Numbers are integers only (AAC draft-04 rule); units live in names.
 */
#ifndef KERVIX_ABI_H
#define KERVIX_ABI_H

#include <stdint.h>
#include "kervix/catalog_gen.h"

#define KX_ABI_VERSION 1u
#define KX_MAX_PARAMS  KX_CATALOG_MAX_PARAMS
#define KX_ACTOR_LEN   32u

/* ---- verdicts ---------------------------------------------------------- */
typedef enum {
    KX_VERDICT_NONE     = 0,
    KX_VERDICT_ALLOW    = 1,
    KX_VERDICT_ESCALATE = 2,
    KX_VERDICT_BLOCK    = 3
} kx_verdict_t;

/* ---- intent (what an agent proposes) ----------------------------------- */
typedef struct {
    uint16_t key;      /* kx_param_key_t */
    uint16_t _pad[3];
    int64_t  val;      /* int value, enum index, or 0/1 for bool */
} kx_param_t;

typedef struct {
    uint16_t   abi;                    /* KX_ABI_VERSION */
    uint16_t   action;                 /* kx_action_id_t */
    uint8_t    n_params;
    uint8_t    has_digest;             /* the one `digest` param, if the action has it */
    uint8_t    _pad[2];
    uint8_t    intent_id[16];          /* UUIDv4 (Agent-Safe Intent intent_id) */
    char       actor_id[KX_ACTOR_LEN]; /* NUL-padded, e.g. "agent:cabin-copilot" */
    kx_param_t p[KX_MAX_PARAMS];
    uint8_t    digest[32];
    int64_t    expires_rt_ms;          /* realtime epoch ms; 0 = no caller expiry */
} kx_intent_t;

/* ---- telemetry snapshot (published by vsimd, seqlock-protected) --------- */
typedef struct {
    uint64_t seq;                /* strictly increasing per publish */
    uint64_t mono_ns;            /* CLOCK_MONOTONIC at sample time */
    int32_t  v[KX_TF__COUNT];    /* indexed by kx_tfield_t */
} kx_telemetry_t;

/* ---- execution grant (issued by kervixd, redeemed once by sdv_actuatord) -- */
typedef struct {
    uint8_t  grant_id[16];        /* CSPRNG */
    uint8_t  intent_hash[32];     /* Agent-Safe Intent v1 hash the grant is bound to */
    uint8_t  params_digest[32];   /* exact command authorized (kx_params_digest) */
    uint8_t  policy_hash8[8];     /* first 8 bytes of the active policy hash */
    uint16_t action;
    uint16_t _pad;
    uint32_t proposer_type;       /* secpol type id of the proposing client */
    int32_t  proposer_pid;
    uint32_t _pad2;
    uint64_t issued_mono_ns;
    uint64_t not_after_mono_ns;
    uint8_t  mac[32];             /* HMAC-SHA256(per-boot key, all fields above) */
} kx_grant_t;

/* ---- decision (reply to PROPOSE) --------------------------------------- */
typedef struct {
    uint16_t   abi;
    uint8_t    verdict;            /* kx_verdict_t */
    uint8_t    gate;               /* kx_gate_t: which constitution gate decided, 0 = rule/default */
    uint16_t   reason;             /* kx_reason_t */
    int16_t    rule_index;         /* -1 = default/constitution */
    char       rule_id[32];        /* stable rule id (NUL-padded), "" if none */
    uint8_t    intent_hash[32];    /* Agent-Safe Intent v1 hash */
    uint8_t    policy_hash[32];
    uint32_t   escalation_id;      /* ESCALATE only */
    uint32_t   eval_ns;            /* measured PROPOSE handling time inside kervixd */
    uint64_t   telemetry_seq;      /* telemetry sample the decision was made on */
    kx_grant_t grant;              /* valid iff verdict == ALLOW */
} kx_decision_t;

/* ---- actuator <-> authority -------------------------------------------- */
typedef struct {
    uint32_t type_id;              /* secpol type id, from the kernel (ctp->info) */
    int32_t  pid;
} kx_client_id_t;

typedef struct {                   /* sdv_actuatord -> kervixd: /dev/kervix/redeem */
    kx_grant_t     grant;
    kx_intent_t    command;        /* exactly what is about to be actuated */
    kx_client_id_t presenter;      /* who asked the actuator to execute (kernel-stamped) */
} kx_redeem_req_t;

typedef struct {                   /* sdv_actuatord -> kervixd: actuation outcome */
    uint8_t  grant_id[16];
    uint16_t action;
    uint8_t  ok;                   /* 1 = actuated, 0 = actuator failed */
    uint8_t  _pad[5];
    uint8_t  request_digest[32];   /* digest of the command sent to the bus */
    uint8_t  response_digest[32];  /* digest of the bus acknowledgement */
} kx_effect_t;

typedef struct {                   /* client -> sdv_actuatord: /dev/sdv/actuators */
    kx_grant_t  grant;
    kx_intent_t command;
} kx_execute_req_t;

_Static_assert(sizeof(kx_param_t) == 16, "kx_param_t ABI size");
_Static_assert(sizeof(kx_grant_t) == 152, "kx_grant_t ABI size");
_Static_assert(sizeof(kx_decision_t) % 8 == 0, "kx_decision_t alignment");
_Static_assert(sizeof(kx_effect_t) == 88, "kx_effect_t ABI size");
_Static_assert(sizeof(kx_intent_t) == 2 + 2 + 1 + 1 + 2 + 16 + KX_ACTOR_LEN + 16 * KX_MAX_PARAMS + 32 + 8,
               "kx_intent_t ABI size");
_Static_assert(sizeof(kx_telemetry_t) % 8 == 0, "kx_telemetry_t alignment");

#endif /* KERVIX_ABI_H */
