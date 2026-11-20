/* The demo vehicle's built-in default policy. Mirrors policies/default.yaml
 * rule-for-rule until host/kxpolicy compiles signed .kxp bundles (M2); then a
 * test asserts both produce the same kx_policy_hash(). */
#include <string.h>

#include "kervix/policy.h"

#define P  KX_VERDICT_ALLOW
#define E  KX_VERDICT_ESCALATE
#define B  KX_VERDICT_BLOCK

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wmissing-field-initializers" /* positional rule table */
#endif

static kx_pred_t tel(kx_tfield_t f, kx_op_t op, int64_t k) {
    kx_pred_t p;
    memset(&p, 0, sizeof p);
    p.a.src = KX_SRC_TELEMETRY; p.a.id = (uint16_t)f; p.fn = KX_FN_VALUE; p.op = (uint8_t)op; p.k = k;
    return p;
}
static kx_pred_t par(kx_param_key_t key, kx_op_t op, int64_t k) {
    kx_pred_t p = tel(0, op, k);
    p.a.src = KX_SRC_PARAM; p.a.id = (uint16_t)key;
    return p;
}
static kx_pred_t absdiff(kx_param_key_t key, kx_tfield_t f, kx_op_t op, int64_t k) {
    kx_pred_t p = par(key, op, k);
    p.fn = KX_FN_ABSDIFF; p.b.src = KX_SRC_TELEMETRY; p.b.id = (uint16_t)f;
    return p;
}
static kx_pred_t any(kx_pred_t p, uint8_t group) { p.group = group; return p; }

static kx_pred_span_t span(kx_policy_t *pol, const kx_pred_t *ps, uint8_t n) {
    kx_pred_span_t s = { (uint16_t)pol->n_preds, n, 0 };
    for (uint8_t i = 0; i < n; i++) (void)kx_policy_add_pred(pol, ps[i]);
    return s;
}

typedef struct {
    const char *id;
    uint16_t action;
    uint8_t verdict;
    uint16_t reason;
    const kx_pred_t *when;      uint8_t n_when;
    const kx_pred_t *interlock; uint8_t n_interlock;
    const kx_pred_t *require;   uint8_t n_require; uint16_t require_reason;
    uint32_t grant_ttl_ms, esc_timeout_ms;
} rule_src_t;

static int add_rule(kx_policy_t *pol, const rule_src_t *s) {
    kx_rule_t r;
    memset(&r, 0, sizeof r);
    strncpy(r.id, s->id, KX_RULE_ID_LEN - 1);
    r.action = s->action; r.verdict = s->verdict; r.reason = s->reason;
    r.when = span(pol, s->when, s->n_when);
    r.interlock = span(pol, s->interlock, s->n_interlock);
    r.require = span(pol, s->require, s->n_require);
    r.require_reason = s->require_reason;
    r.grant_ttl_ms = s->grant_ttl_ms; r.esc_timeout_ms = s->esc_timeout_ms;
    return kx_policy_add_rule(pol, &r);
}

#define N(arr) (uint8_t)(sizeof(arr) / sizeof((arr)[0]))
#define RULE(...) do { rule_src_t _s = { __VA_ARGS__ }; if (add_rule(pol, &_s) != 0) return -1; } while (0)

int kx_policy_build_default(kx_policy_t *pol) {
    kx_policy_init(pol, "kervix-default", (1u << 16));

    const kx_pred_t driver[] = { tel(KX_TF_DRIVER_PRESENT, KX_OP_EQ, 1) };

    RULE("climate-any", KX_ACT_CABIN_CLIMATE_SET, P, KX_R_OK);

    const kx_pred_t win_fast[] = { tel(KX_TF_SPEED_DKPH, KX_OP_GT, 800), par(KX_P_POS_PCT, KX_OP_GT, 50) };
    RULE("window-high-speed", KX_ACT_CABIN_WINDOW_SET, E, KX_R_WINDOW_HIGH_SPEED, win_fast, N(win_fast),
         NULL, 0, driver, N(driver), KX_R_DRIVER_ABSENT, 0, 15000);
    RULE("window-ok", KX_ACT_CABIN_WINDOW_SET, P, KX_R_OK);

    RULE("hazard-any", KX_ACT_LIGHT_HAZARD_SET, P, KX_R_OK);
    RULE("charge-limit-any", KX_ACT_BATTERY_CHARGE_LIMIT_SET, P, KX_R_OK);

    const kx_pred_t parked[] = { tel(KX_TF_SPEED_DKPH, KX_OP_EQ, 0), tel(KX_TF_GEAR, KX_OP_EQ, KX_GEAR_P) };
    const kx_pred_t moving[] = { tel(KX_TF_SPEED_DKPH, KX_OP_GT, 0) };
    RULE("door-unlock-parked", KX_ACT_BODY_DOOR_UNLOCK, P, KX_R_OK, parked, N(parked), parked, N(parked));
    RULE("door-unlock-moving", KX_ACT_BODY_DOOR_UNLOCK, B, KX_R_VEHICLE_MOVING, moving, N(moving));
    RULE("door-unlock-not-parked", KX_ACT_BODY_DOOR_UNLOCK, B, KX_R_NOT_PARKED);

    const kx_pred_t acc_lim[] = { par(KX_P_TARGET_KPH, KX_OP_GT, 130) };
    const kx_pred_t acc_delta[] = { absdiff(KX_P_TARGET_KPH, KX_TF_ACC_TARGET_KPH, KX_OP_GT, 20) };
    RULE("acc-above-limit", KX_ACT_ADAS_ACC_SET_SPEED, B, KX_R_SPEED_ABOVE_LIMIT, acc_lim, N(acc_lim));
    RULE("acc-large-delta", KX_ACT_ADAS_ACC_SET_SPEED, E, KX_R_SPEED_DELTA_LARGE, acc_delta, N(acc_delta),
         NULL, 0, driver, N(driver), KX_R_DRIVER_ABSENT, 0, 10000);
    RULE("acc-ok", KX_ACT_ADAS_ACC_SET_SPEED, P, KX_R_OK);

    RULE("location-consent", KX_ACT_TELEMATICS_LOCATION_SHARE, E, KX_R_DRIVER_CONSENT, NULL, 0,
         NULL, 0, driver, N(driver), KX_R_DRIVER_ABSENT, 0, 30000);

    const kx_pred_t service[] = { tel(KX_TF_SERVICE_MODE, KX_OP_EQ, 1) };
    RULE("dtc-service", KX_ACT_DIAG_DTC_CLEAR, P, KX_R_OK, service, N(service));
    RULE("dtc-consent", KX_ACT_DIAG_DTC_CLEAR, E, KX_R_DRIVER_CONSENT);

    const kx_pred_t still[] = { tel(KX_TF_SPEED_DKPH, KX_OP_EQ, 0) };
    RULE("immobilizer-moving", KX_ACT_VEHICLE_IMMOBILIZER_ENGAGE, B, KX_R_VEHICLE_MOVING, moving, N(moving));
    RULE("immobilizer-parked", KX_ACT_VEHICLE_IMMOBILIZER_ENGAGE, E, KX_R_DRIVER_CONSENT, NULL, 0, still, N(still));

    const kx_pred_t workshop[] = { tel(KX_TF_SERVICE_MODE, KX_OP_EQ, 1), tel(KX_TF_SPEED_DKPH, KX_OP_EQ, 0),
                                   tel(KX_TF_GEAR, KX_OP_EQ, KX_GEAR_P), tel(KX_TF_PARK_BRAKE, KX_OP_EQ, 1) };
    RULE("brake-cal-service", KX_ACT_CHASSIS_BRAKE_CALIBRATION_WRITE, P, KX_R_OK, workshop, N(workshop),
         workshop, N(workshop));
    RULE("brake-cal-deny", KX_ACT_CHASSIS_BRAKE_CALIBRATION_WRITE, B, KX_R_SERVICE_MODE_REQUIRED);

    const kx_pred_t not_parked[] = { any(tel(KX_TF_GEAR, KX_OP_NE, KX_GEAR_P), 1),
                                     any(tel(KX_TF_PARK_BRAKE, KX_OP_EQ, 0), 1) };
    const kx_pred_t energy[] = { any(tel(KX_TF_SOC_DPCT, KX_OP_GE, 400), 1),
                                 any(tel(KX_TF_CHARGING, KX_OP_EQ, 1), 1) };
    const kx_pred_t ota_ilock[] = { tel(KX_TF_SPEED_DKPH, KX_OP_EQ, 0), tel(KX_TF_GEAR, KX_OP_EQ, KX_GEAR_P),
                                    tel(KX_TF_PARK_BRAKE, KX_OP_EQ, 1) };
    RULE("ota-block-moving", KX_ACT_OTA_ECU_FLASH, B, KX_R_R156_NOT_SAFE_STATE, moving, N(moving));
    RULE("ota-block-not-parked", KX_ACT_OTA_ECU_FLASH, B, KX_R_R156_NOT_SAFE_STATE, not_parked, N(not_parked));
    RULE("ota-escalate", KX_ACT_OTA_ECU_FLASH, E, KX_R_DRIVER_CONSENT, energy, N(energy), ota_ilock,
         N(ota_ilock), driver, N(driver), KX_R_DRIVER_ABSENT, 500, 30000);
    RULE("ota-low-power", KX_ACT_OTA_ECU_FLASH, B, KX_R_R156_INSUFFICIENT_POWER);

    if (kx_policy_finalize(pol) != 0) return -1;
    kx_policy_hash(pol, pol->hash);
    return 0;
}
