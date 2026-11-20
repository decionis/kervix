/* Policy engine tests: constitution K1-K4, every default rule family,
 * interlocks, finalize validation, determinism and a property sweep. */
#include <stdint.h>
#include <string.h>

#include "default_policy.h"
#include "kx_test.h"

#define NOW_NS   1000000000000ull  /* arbitrary monotonic "now" */
#define NOW_MS   1795000000000ll   /* arbitrary realtime "now" */
#define MS       1000000ull

static kx_policy_t POL; /* static: ~70 KB, keep it off the stack */

static kx_eval_env_t env_ok(void) {
    kx_eval_env_t e = { NOW_NS, NOW_MS, 50 * MS, 1 };
    return e;
}

/* Parked, healthy, driver in seat, sample 5 ms old. */
static kx_telemetry_t tel_parked(void) {
    kx_telemetry_t t;
    memset(&t, 0, sizeof t);
    t.seq = 42;
    t.mono_ns = NOW_NS - 5 * MS;
    t.v[KX_TF_SPEED_DKPH] = 0;
    t.v[KX_TF_GEAR] = KX_GEAR_P;
    t.v[KX_TF_PARK_BRAKE] = 1;
    t.v[KX_TF_SOC_DPCT] = 620;
    t.v[KX_TF_DRIVER_PRESENT] = 1;
    t.v[KX_TF_DOORS_LOCKED_MASK] = 15;
    t.v[KX_TF_HVAC_SETPOINT_DC] = 210;
    t.v[KX_TF_ACC_TARGET_KPH] = 100;
    t.v[KX_TF_CHARGE_LIMIT_PCT] = 80;
    return t;
}

static kx_telemetry_t tel_driving(int32_t speed_dkph) {
    kx_telemetry_t t = tel_parked();
    t.v[KX_TF_SPEED_DKPH] = speed_dkph;
    t.v[KX_TF_GEAR] = KX_GEAR_D;
    t.v[KX_TF_PARK_BRAKE] = 0;
    return t;
}

static kx_intent_t intent(uint16_t action) {
    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.abi = KX_ABI_VERSION;
    in.action = action;
    strcpy(in.actor_id, "agent:cabin-copilot");
    return in;
}
static void add(kx_intent_t *in, uint16_t key, int64_t v) {
    in->p[in->n_params].key = key;
    in->p[in->n_params].val = v;
    in->n_params++;
}
static kx_intent_t ota(void) {
    kx_intent_t in = intent(KX_ACT_OTA_ECU_FLASH);
    add(&in, KX_P_ECU, KX_ECU_BRAKE);
    in.has_digest = 1;
    memset(in.digest, 0xAB, sizeof in.digest);
    return in;
}

static kx_eval_result_t R;
static kx_verdict_t ev(const kx_intent_t *in, const kx_telemetry_t *t) {
    kx_eval_env_t e = env_ok();
    return kx_eval(&POL, in, t, &e, &R);
}
static const char *rule_id(void) { return R.rule_index >= 0 ? POL.rules[R.rule_index].id : "(none)"; }

#define EXPECT(verdict_, reason_, gate_)                                                   \
    do {                                                                                   \
        KX_CHECK(R.verdict == (verdict_));                                                 \
        KX_CHECK(R.reason == (reason_));                                                   \
        KX_CHECK(R.gate == (gate_));                                                       \
        if (R.verdict != (verdict_) || R.reason != (reason_) || R.gate != (gate_))         \
            fprintf(stderr, "  got verdict=%u reason=%u gate=%u rule=%s\n", R.verdict,     \
                    R.reason, R.gate, rule_id());                                          \
    } while (0)

static void test_comfort(void) {
    kx_intent_t in = intent(KX_ACT_CABIN_CLIMATE_SET);
    add(&in, KX_P_TEMP_DC, 225);
    kx_telemetry_t t = tel_driving(600);
    ev(&in, &t);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);
    KX_CHECK_STR(rule_id(), "climate-any");
    KX_CHECK(R.grant_ttl_ms == 250);

    in.p[0].val = 300; /* 30.0 °C: outside catalog range */
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);

    /* windows: wide open at highway speed needs the driver */
    kx_intent_t w = intent(KX_ACT_CABIN_WINDOW_SET);
    add(&w, KX_P_WINDOW, KX_WINDOW_FRONT_LEFT);
    add(&w, KX_P_POS_PCT, 80);
    t = tel_driving(1000);
    ev(&w, &t);
    EXPECT(KX_VERDICT_ESCALATE, KX_R_WINDOW_HIGH_SPEED, KX_GATE_NONE);
    KX_CHECK(R.esc_timeout_ms == 15000);
    t.v[KX_TF_DRIVER_PRESENT] = 0;
    ev(&w, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_DRIVER_ABSENT, KX_GATE_REQUIRE);
    t = tel_driving(300);
    ev(&w, &t);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);
}

static void test_door(void) {
    kx_intent_t in = intent(KX_ACT_BODY_DOOR_UNLOCK);
    add(&in, KX_P_DOOR, KX_DOOR_FRONT_LEFT);
    kx_telemetry_t t = tel_parked();
    ev(&in, &t);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);
    KX_CHECK_STR(rule_id(), "door-unlock-parked");

    /* TOCTOU: the car starts moving between grant and redemption */
    int16_t granted = R.rule_index;
    KX_CHECK(kx_interlock_ok(&POL, granted, &in, &t) == 1);
    kx_telemetry_t later = tel_driving(50);
    KX_CHECK(kx_interlock_ok(&POL, granted, &in, &later) == 0);
    KX_CHECK(kx_interlock_ok(&POL, -1, &in, &t) == 0);
    KX_CHECK(kx_interlock_ok(&POL, (int16_t)POL.n_rules, &in, &t) == 0);

    t = tel_driving(600);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_VEHICLE_MOVING, KX_GATE_NONE);

    t = tel_parked();
    t.v[KX_TF_GEAR] = KX_GEAR_N;
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_NOT_PARKED, KX_GATE_NONE);
}

static void test_ota_r156(void) {
    kx_intent_t in = ota();
    kx_telemetry_t t = tel_driving(1100); /* the prompt-injection scene */
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_R156_NOT_SAFE_STATE, KX_GATE_NONE);
    KX_CHECK_STR(rule_id(), "ota-block-moving");

    t = tel_parked();
    ev(&in, &t);
    EXPECT(KX_VERDICT_ESCALATE, KX_R_DRIVER_CONSENT, KX_GATE_NONE);
    KX_CHECK_STR(rule_id(), "ota-escalate");
    KX_CHECK(R.grant_ttl_ms == 500 && R.esc_timeout_ms == 30000);

    t.v[KX_TF_PARK_BRAKE] = 0;
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_R156_NOT_SAFE_STATE, KX_GATE_NONE);
    KX_CHECK_STR(rule_id(), "ota-block-not-parked");

    t = tel_parked();
    t.v[KX_TF_SOC_DPCT] = 300;
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_R156_INSUFFICIENT_POWER, KX_GATE_NONE);
    t.v[KX_TF_CHARGING] = 1; /* low SoC but plugged in: OR group satisfied */
    ev(&in, &t);
    EXPECT(KX_VERDICT_ESCALATE, KX_R_DRIVER_CONSENT, KX_GATE_NONE);

    t = tel_parked();
    t.v[KX_TF_DRIVER_PRESENT] = 0;
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_DRIVER_ABSENT, KX_GATE_REQUIRE);

    in.has_digest = 0; /* image digest is mandatory */
    t = tel_parked();
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);
}

static void test_acc_and_misc(void) {
    kx_intent_t in = intent(KX_ACT_ADAS_ACC_SET_SPEED);
    add(&in, KX_P_TARGET_KPH, 140);
    kx_telemetry_t t = tel_driving(1000);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_SPEED_ABOVE_LIMIT, KX_GATE_NONE);
    in.p[0].val = 110; /* +10 from 100 */
    ev(&in, &t);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);
    in.p[0].val = 125; /* +25: absdiff > 20 */
    ev(&in, &t);
    EXPECT(KX_VERDICT_ESCALATE, KX_R_SPEED_DELTA_LARGE, KX_GATE_NONE);
    in.p[0].val = 75;  /* -25 also counts */
    ev(&in, &t);
    EXPECT(KX_VERDICT_ESCALATE, KX_R_SPEED_DELTA_LARGE, KX_GATE_NONE);

    kx_intent_t loc = intent(KX_ACT_TELEMATICS_LOCATION_SHARE);
    add(&loc, KX_P_RECIPIENT, KX_RECIPIENT_FLEET_OPERATOR);
    add(&loc, KX_P_DURATION_S, 3600);
    t = tel_parked();
    ev(&loc, &t);
    EXPECT(KX_VERDICT_ESCALATE, KX_R_DRIVER_CONSENT, KX_GATE_NONE);

    kx_intent_t cal = intent(KX_ACT_CHASSIS_BRAKE_CALIBRATION_WRITE);
    add(&cal, KX_P_ECU, KX_ECU_BRAKE);
    cal.has_digest = 1;
    ev(&cal, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_SERVICE_MODE_REQUIRED, KX_GATE_NONE);
    t.v[KX_TF_SERVICE_MODE] = 1;
    ev(&cal, &t);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);

    kx_intent_t imm = intent(KX_ACT_VEHICLE_IMMOBILIZER_ENGAGE);
    t = tel_driving(300);
    ev(&imm, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_VEHICLE_MOVING, KX_GATE_NONE);
}

static void test_constitution(void) {
    kx_intent_t door = intent(KX_ACT_BODY_DOOR_UNLOCK);
    add(&door, KX_P_DOOR, KX_DOOR_REAR_RIGHT);
    kx_intent_t climate = intent(KX_ACT_CABIN_CLIMATE_SET);
    add(&climate, KX_P_TEMP_DC, 200);

    /* K1: stale telemetry blocks safety actions, not two-way comfort ones */
    kx_telemetry_t t = tel_parked();
    t.mono_ns = NOW_NS - 100 * MS;
    ev(&door, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_TELEMETRY_STALE, KX_GATE_K1_STALE);
    ev(&climate, &t);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);
    t.mono_ns = NOW_NS + 1; /* sample from the future */
    ev(&door, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_TELEMETRY_STALE, KX_GATE_K1_STALE);
    t.mono_ns = NOW_NS - 50 * MS; /* exactly at the threshold is still fresh */
    ev(&door, &t);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);

    /* K2: "parked" at 60 km/h is a lie -> block everything */
    t = tel_parked();
    t.v[KX_TF_SPEED_DKPH] = 600;
    ev(&climate, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_TELEMETRY_IMPLAUSIBLE, KX_GATE_K2_IMPLAUSIBLE);
    t = tel_parked();
    t.v[KX_TF_SOC_DPCT] = 1200; /* out of catalog range */
    ev(&climate, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_TELEMETRY_IMPLAUSIBLE, KX_GATE_K2_IMPLAUSIBLE);

    /* K3: no audit, no safety action */
    t = tel_parked();
    kx_eval_env_t e = env_ok();
    e.ledger_ok = 0;
    kx_eval(&POL, &door, &t, &e, &R);
    EXPECT(KX_VERDICT_BLOCK, KX_R_LEDGER_PRESSURE, KX_GATE_K3_LEDGER);
    kx_eval(&POL, &climate, &t, &e, &R);
    EXPECT(KX_VERDICT_ALLOW, KX_R_OK, KX_GATE_NONE);

    /* caller expiry */
    climate.expires_rt_ms = NOW_MS - 1;
    ev(&climate, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_INTENT_EXPIRED, KX_GATE_EXPIRY);
}

static void test_validation(void) {
    kx_telemetry_t t = tel_parked();
    kx_intent_t in = intent(0);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_UNKNOWN_ACTION, KX_GATE_K4_VALIDATION);
    in = intent(KX_ACTION_MAX_ID + 1);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_UNKNOWN_ACTION, KX_GATE_K4_VALIDATION);

    in = intent(KX_ACT_CABIN_CLIMATE_SET); /* missing param */
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);

    in = intent(KX_ACT_CABIN_WINDOW_SET); /* duplicate key */
    add(&in, KX_P_POS_PCT, 10);
    add(&in, KX_P_POS_PCT, 20);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);

    in = intent(KX_ACT_CABIN_CLIMATE_SET); /* key from another action */
    add(&in, KX_P_TARGET_KPH, 100);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);

    in = intent(KX_ACT_CABIN_CLIMATE_SET); /* wrong ABI */
    add(&in, KX_P_TEMP_DC, 200);
    in.abi = 99;
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);

    in.abi = KX_ABI_VERSION; /* actor id must be NUL-terminated and non-empty */
    memset(in.actor_id, 'x', KX_ACTOR_LEN);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);
    memset(in.actor_id, 0, KX_ACTOR_LEN);
    ev(&in, &t);
    EXPECT(KX_VERDICT_BLOCK, KX_R_PARAM_INVALID, KX_GATE_K4_VALIDATION);
}

static void test_policy_construction(void) {
    static kx_policy_t p; /* empty policy -> default deny */
    kx_policy_init(&p, "empty", 1);
    KX_CHECK(kx_policy_finalize(&p) == 0);
    kx_intent_t in = intent(KX_ACT_LIGHT_HAZARD_SET);
    add(&in, KX_P_ON, 1);
    kx_telemetry_t t = tel_parked();
    kx_eval_env_t e = env_ok();
    kx_eval(&p, &in, &t, &e, &R);
    EXPECT(KX_VERDICT_BLOCK, KX_R_DEFAULT_DENY, KX_GATE_NONE);
    KX_CHECK(R.rule_index == -1);
    KX_CHECK(kx_policy_finalize(&p) == -1); /* only once */

    /* unfinalized policy never allows */
    kx_policy_init(&p, "unfinalized", 1);
    kx_eval(&p, &in, &t, &e, &R);
    KX_CHECK(R.verdict == KX_VERDICT_BLOCK);

    /* invalid: param operand that the action doesn't have */
    kx_policy_init(&p, "bad", 1);
    kx_pred_t pr;
    memset(&pr, 0, sizeof pr);
    pr.a.src = KX_SRC_PARAM;
    pr.a.id = KX_P_TARGET_KPH;
    pr.op = KX_OP_GT;
    kx_rule_t r;
    memset(&r, 0, sizeof r);
    strcpy(r.id, "bad-operand");
    r.action = KX_ACT_LIGHT_HAZARD_SET;
    r.verdict = KX_VERDICT_ALLOW;
    r.when.off = (uint16_t)kx_policy_add_pred(&p, pr);
    r.when.n = 1;
    KX_CHECK(kx_policy_add_rule(&p, &r) == 0);
    KX_CHECK(kx_policy_finalize(&p) == -1);

    /* invalid: `require` on an ALLOW rule; unknown reason; empty id */
    kx_rule_t ok;
    memset(&ok, 0, sizeof ok);
    strcpy(ok.id, "x");
    ok.action = KX_ACT_LIGHT_HAZARD_SET;
    ok.verdict = KX_VERDICT_ALLOW;
    kx_rule_t bad = ok;
    kx_policy_init(&p, "bad2", 1);
    pr.a.src = KX_SRC_TELEMETRY;
    pr.a.id = KX_TF_DRIVER_PRESENT;
    bad.require.off = (uint16_t)kx_policy_add_pred(&p, pr);
    bad.require.n = 1;
    kx_policy_add_rule(&p, &bad);
    KX_CHECK(kx_policy_finalize(&p) == -1);
    kx_policy_init(&p, "bad3", 1);
    bad = ok;
    bad.reason = 9; /* not a reason id */
    kx_policy_add_rule(&p, &bad);
    KX_CHECK(kx_policy_finalize(&p) == -1);
    kx_policy_init(&p, "bad4", 1);
    bad = ok;
    bad.id[0] = '\0';
    kx_policy_add_rule(&p, &bad);
    KX_CHECK(kx_policy_finalize(&p) == -1);

    /* rules added out of order are indexed by action, order kept per action */
    KX_CHECK(POL.count[KX_ACT_OTA_ECU_FLASH] == 4);
    KX_CHECK_STR(POL.rules[POL.first[KX_ACT_OTA_ECU_FLASH]].id, "ota-block-moving");
    KX_CHECK(POL.count[0] == 0);
}

/* Deterministic LCG so the sweep is reproducible everywhere. */
static uint64_t rng = 0x9E3779B97F4A7C15ull;
static int64_t rnd(int64_t lo, int64_t hi) {
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    return lo + (int64_t)((rng >> 33) % (uint64_t)(hi - lo + 1));
}

static void test_property_sweep(void) {
    int bad = 0;
    for (int i = 0; i < 200000; i++) {
        kx_intent_t in = intent((uint16_t)rnd(0, KX_ACTION_MAX_ID + 1));
        const kx_action_spec_t *spec = kx_catalog_action(in.action);
        if (spec) {
            for (uint8_t p = 0; p < spec->n_params; p++) {
                if (spec->params[p].type == KX_PT_DIGEST) { in.has_digest = (uint8_t)rnd(0, 1); continue; }
                add(&in, spec->params[p].key, rnd(spec->params[p].min - 2, spec->params[p].max + 2));
            }
        }
        kx_telemetry_t t = tel_parked();
        t.v[KX_TF_SPEED_DKPH] = (int32_t)rnd(0, 1500);
        t.v[KX_TF_GEAR] = (int32_t)rnd(0, 3);
        t.v[KX_TF_PARK_BRAKE] = (int32_t)rnd(0, 1);
        t.v[KX_TF_SOC_DPCT] = (int32_t)rnd(0, 1000);
        t.v[KX_TF_CHARGING] = (int32_t)rnd(0, 1);
        t.v[KX_TF_DRIVER_PRESENT] = (int32_t)rnd(0, 1);
        t.v[KX_TF_SERVICE_MODE] = (int32_t)rnd(0, 1);
        t.mono_ns = NOW_NS - (uint64_t)rnd(0, 80) * MS;
        kx_eval_env_t e = env_ok();
        e.ledger_ok = (uint8_t)rnd(0, 1);

        kx_eval_result_t a, b;
        kx_eval(&POL, &in, &t, &e, &a);
        kx_eval(&POL, &in, &t, &e, &b);
        int speed = t.v[KX_TF_SPEED_DKPH];
        int stale = (NOW_NS - t.mono_ns) > e.telemetry_max_age_ns;
        /* invariants */
        if (memcmp(&a, &b, sizeof a) != 0) bad++;                                       /* determinism */
        if (a.verdict < KX_VERDICT_ALLOW || a.verdict > KX_VERDICT_BLOCK) bad++;        /* closed set */
        if (a.rule_index < -1 || a.rule_index >= (int16_t)POL.n_rules) bad++;
        if (kx_validate_intent(&in) != KX_R_OK && a.verdict != KX_VERDICT_BLOCK) bad++; /* K4 */
        if (in.action == KX_ACT_OTA_ECU_FLASH && speed > 0 && a.verdict != KX_VERDICT_BLOCK) bad++;
        if (spec && spec->safety == KX_SAFETY_SAFETY && stale && a.verdict != KX_VERDICT_BLOCK) bad++;
        if (spec && spec->safety == KX_SAFETY_SAFETY && !e.ledger_ok && a.verdict != KX_VERDICT_BLOCK) bad++;
        if (a.verdict == KX_VERDICT_ALLOW && a.grant_ttl_ms == 0) bad++;
    }
    KX_CHECK(bad == 0);
    if (bad) fprintf(stderr, "  property sweep: %d invariant violations\n", bad);
}

int main(void) {
    KX_CHECK(kx_test_build_default_policy(&POL) == 0);
    KX_CHECK(POL.finalized && POL.n_rules == 22);
    test_comfort();
    test_door();
    test_ota_r156();
    test_acc_and_misc();
    test_constitution();
    test_validation();
    test_policy_construction();
    test_property_sweep();
    KX_TEST_DONE();
}
