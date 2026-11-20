/*
 * kervixd / sdv_actuatord interface: paths and devctls.
 *
 * Each trust level is its own dispatch channel, so the security policy can
 * type it (spike S1). The kernel refuses connects from types without a rule:
 *   agent channel     /dev/kervix/intent   PROPOSE        (agent gateways, kxctl)
 *   observer channel  /dev/kervix/stats    read (text)    (observers, agents, HMI, operator)
 *   actuator channel  /dev/kervix/redeem   REDEEM, EFFECT (sdv_actuatord only)
 *   actuator bus      /dev/sdv/actuators   EXECUTE        (agent gateway with a grant)
 *   hmi channel       /dev/kervix/escalations  read (text) | LIST | SUBSCRIBE | RESOLVE
 *                     (the driver's HMI; outranks agent traffic by priority)
 *   admin channel     /dev/kervix/policy   write(bundle) + POLICY_ACTIVATE, POLICY_STATUS (operator only)
 *
 * ESCALATE lifecycle: PROPOSE -> ESCALATE(id) -> the proposer may AWAIT(id),
 * a deferred reply: it stays REPLY-blocked in the kernel, no polling. The HMI
 * RESOLVEs approve/deny, or the rule's timeout fires. On approval the policy is
 * re-evaluated on live telemetry before any grant is issued.
 */
#ifndef KERVIX_KERVIX_ABI_H
#define KERVIX_KERVIX_ABI_H

#include <devctl.h>
#include <sys/neutrino.h>

#include "kervix/abi.h"

#define KX_PATH_INTENT    "/dev/kervix/intent"
#define KX_PATH_STATS     "/dev/kervix/stats"
#define KX_PATH_REDEEM    "/dev/kervix/redeem"
#define KX_PATH_ACTUATORS "/dev/sdv/actuators"
#define KX_PATH_ESCALATIONS "/dev/kervix/escalations"
#define KX_PATH_POLICY    "/dev/kervix/policy"
/* Raw actuator access WITHOUT a grant: the maintenance path real ECUs have.
 * Its channel type has no connect rule for ANY process type (secpol): it
 * exists to show that bypassing Kervix is impossible, not merely forbidden. */
#define KX_PATH_ACTUATORS_RAW "/dev/sdv/actuators/raw"

#define KX_MAX_ESCALATIONS 32
#define KX_ESC_LIST_MAX    16

typedef struct { uint32_t escalation_id; uint32_t _pad; } kx_await_req_t;

typedef struct {
    uint32_t escalation_id;
    uint8_t  approve;              /* 1 approve, 0 deny */
    uint8_t  _pad[3];
    char     approver[32];         /* e.g. "hmi:driver-seat" (identity is also taken from the kernel) */
} kx_resolve_req_t;

typedef struct {
    uint32_t    escalation_id;
    uint16_t    reason;            /* why a human is needed (e.g. DRIVER_CONSENT) */
    uint16_t    _pad;
    int32_t     remaining_ms;      /* until the timeout BLOCKs it */
    int32_t     proposer_pid;
    char        rule_id[32];
    kx_intent_t intent;            /* what the agent wants to do */
} kx_esc_info_t;

typedef struct {
    uint32_t      n;
    uint32_t      _pad;
    kx_esc_info_t e[KX_ESC_LIST_MAX];
} kx_esc_list_t;

/* PROPOSE: in kx_intent_t, out kx_decision_t (same buffer, larger of the two) */
#define KX_DCMD_PROPOSE   __DIOTF(_DCMD_MISC, 0x201, kx_decision_t)
/* REDEEM: in kx_redeem_req_t; devctl return value (ret_val) = kx_reason_t */
#define KX_DCMD_REDEEM    __DIOT(_DCMD_MISC, 0x210, kx_redeem_req_t)
/* EFFECT: in kx_effect_t */
#define KX_DCMD_EFFECT    __DIOT(_DCMD_MISC, 0x211, kx_effect_t)
/* EXECUTE on the actuator bus: in kx_execute_req_t; ret_val = kx_reason_t */
#define KX_DCMD_EXECUTE   __DIOT(_DCMD_MISC, 0x220, kx_execute_req_t)
/* RAW_APPLY on the raw maintenance path: in kx_intent_t (no grant) */
#define KX_DCMD_RAW_APPLY __DIOT(_DCMD_MISC, 0x221, kx_intent_t)
/* AWAIT (agent channel): in kx_await_req_t, out kx_decision_t; deferred reply */
#define KX_DCMD_AWAIT     __DIOTF(_DCMD_MISC, 0x202, kx_decision_t)
/* HMI channel */
#define KX_DCMD_ESC_LIST      __DIOF(_DCMD_MISC, 0x230, kx_esc_list_t)
#define KX_DCMD_ESC_RESOLVE   __DIOT(_DCMD_MISC, 0x231, kx_resolve_req_t)
#define KX_DCMD_ESC_SUBSCRIBE __DIOT(_DCMD_MISC, 0x232, struct sigevent)

/* Signed policy bundles (kervix/bundle.h): write() the .kxp to /dev/kervix/policy
 * (offset 0 starts a new upload), then POLICY_ACTIVATE. The reply always
 * carries the status; `result` is 0 or an errno (EACCES signature/trust,
 * EBADMSG malformed, EINVAL rejected by the loader, EBUSY grants or escalations
 * in flight, EALREADY already active, EAGAIN ledger full, EIO persist failed). */
typedef struct {
    char     policy_id[32];
    uint32_t version;
    int32_t  result;
    uint8_t  hash[32];
    char     source[64];            /* "built-in" or "bundle author:<label> approver:<label>" */
    char     detail[64];            /* why an activation was refused */
} kx_policy_status_t;
#define KX_DCMD_POLICY_ACTIVATE __DIOF(_DCMD_MISC, 0x240, kx_policy_status_t)
#define KX_DCMD_POLICY_STATUS   __DIOF(_DCMD_MISC, 0x241, kx_policy_status_t)

_Static_assert(sizeof(kx_decision_t) >= sizeof(kx_intent_t), "PROPOSE reuses one buffer");
_Static_assert(sizeof(kx_decision_t) >= sizeof(kx_await_req_t), "AWAIT reuses one buffer");

#endif /* KERVIX_KERVIX_ABI_H */
