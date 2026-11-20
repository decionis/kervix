/*
 * kervixd / sdv_actuatord interface: paths and devctls.
 *
 * Each trust level is its own dispatch channel, so the security policy can
 * type it (spike S1). The kernel refuses connects from types without a rule:
 *   agent channel     /dev/kervix/intent   PROPOSE        (agent gateways, kxctl)
 *                     /dev/kervix/stats    read (text)
 *   actuator channel  /dev/kervix/redeem   REDEEM, EFFECT (sdv_actuatord only)
 *   actuator bus      /dev/sdv/actuators   EXECUTE        (agent gateway with a grant)
 * HMI (/dev/kervix/escalations) and admin (/dev/kervix/policy) channels land
 * with the escalation and signed-policy milestones.
 */
#ifndef KERVIX_KERVIX_ABI_H
#define KERVIX_KERVIX_ABI_H

#include <devctl.h>

#include "kervix/abi.h"

#define KX_PATH_INTENT    "/dev/kervix/intent"
#define KX_PATH_STATS     "/dev/kervix/stats"
#define KX_PATH_REDEEM    "/dev/kervix/redeem"
#define KX_PATH_ACTUATORS "/dev/sdv/actuators"

/* PROPOSE: in kx_intent_t, out kx_decision_t (same buffer, larger of the two) */
#define KX_DCMD_PROPOSE   __DIOTF(_DCMD_MISC, 0x201, kx_decision_t)
/* REDEEM: in kx_redeem_req_t; devctl return value (ret_val) = kx_reason_t */
#define KX_DCMD_REDEEM    __DIOT(_DCMD_MISC, 0x210, kx_redeem_req_t)
/* EFFECT: in kx_effect_t */
#define KX_DCMD_EFFECT    __DIOT(_DCMD_MISC, 0x211, kx_effect_t)
/* EXECUTE on the actuator bus: in kx_execute_req_t; ret_val = kx_reason_t */
#define KX_DCMD_EXECUTE   __DIOT(_DCMD_MISC, 0x220, kx_execute_req_t)

_Static_assert(sizeof(kx_decision_t) >= sizeof(kx_intent_t), "PROPOSE reuses one buffer");

#endif /* KERVIX_KERVIX_ABI_H */
