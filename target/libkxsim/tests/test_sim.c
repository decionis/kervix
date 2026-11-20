/* libkxsim: physics invariants, scenarios, commands, actuation effects. */
#include <string.h>

#include "kervix/policy.h"   /* kx_telemetry_plausible (constitution K2) */
#include "kervix/sim.h"
#include "../../libkxcore/tests/kx_test.h"

static kx_sim_t S;
static char R[256];

static void run(uint32_t ms) { for (uint32_t t = 0; t < ms; t += 10) kx_sim_step(&S, 10); }
static int plausible(void) { kx_telemetry_t t; kx_sim_snapshot(&S, 1, 1, &t); return kx_telemetry_plausible(&t); }
static int cmd(const char *c) { return kx_sim_command(&S, c, R, sizeof R); }

static void test_initial_and_park(void) {
    kx_sim_init(&S);
    KX_CHECK(S.v[KX_TF_GEAR] == KX_GEAR_P && S.v[KX_TF_PARK_BRAKE] == 1 && S.v[KX_TF_SPEED_DKPH] == 0);
    KX_CHECK(plausible());
    run(5000);
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] == 0 && S.v[KX_TF_GEAR] == KX_GEAR_P);
}

static void test_highway_and_back(void) {
    kx_sim_init(&S);
    KX_CHECK(cmd("scenario highway") == 0);
    run(10);
    KX_CHECK(S.v[KX_TF_GEAR] == KX_GEAR_D && S.v[KX_TF_PARK_BRAKE] == 0);
    run(10000);  /* 2.5 m/s^2: 0 -> 90 km/h in 10 s */
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] >= 895 && S.v[KX_TF_SPEED_DKPH] <= 905);
    run(10000);
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] == KX_SIM_HIGHWAY_DKPH);
    KX_CHECK(S.v[KX_TF_DOORS_LOCKED_MASK] == 15);              /* auto-locked */
    KX_CHECK(cmd("scenario park") == 0);
    run(5000);
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] > 0 && S.v[KX_TF_GEAR] == KX_GEAR_D); /* still braking */
    run(10000);
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] == 0 && S.v[KX_TF_GEAR] == KX_GEAR_P && S.v[KX_TF_PARK_BRAKE] == 1);
}

static void test_invariants_long_run(void) {
    /* 2 simulated hours across every scenario: never implausible, bounded jerk */
    kx_sim_init(&S);
    int bad = 0;
    int32_t prev = 0;
    const char *scn[] = { "scenario drivecycle", "scenario city", "scenario highway", "scenario charging", "scenario park" };
    for (int phase = 0; phase < 10; phase++) {
        cmd(scn[phase % 5]);
        for (int t = 0; t < 72000 / 10 * 10 / 10; t++) {   /* 720 s per phase */
            kx_sim_step(&S, 100);
            int32_t sp = S.v[KX_TF_SPEED_DKPH];
            if (!plausible()) bad++;
            if (S.v[KX_TF_GEAR] == KX_GEAR_P && sp != 0) bad++;
            if (sp < 0 || sp > 3000) bad++;
            if (sp - prev > 10 || prev - sp > 11) bad++;           /* <= 9 / 10.8 dkph per 100 ms */
            prev = sp;
        }
    }
    KX_CHECK(bad == 0);
    if (bad) fprintf(stderr, "  %d invariant violations\n", bad);
}

static void test_drivecycle_shape(void) {
    kx_sim_init(&S);
    cmd("scenario drivecycle");
    int32_t vmax = 0;
    int stops = 0, moving = 0;
    for (int t = 0; t < 136000; t += 100) {      /* one full loop */
        kx_sim_step(&S, 100);
        int32_t sp = S.v[KX_TF_SPEED_DKPH];
        if (sp > vmax) vmax = sp;
        if (sp == 0 && moving) { stops++; moving = 0; }
        if (sp > 50) moving = 1;
    }
    KX_CHECK(vmax >= 1250 && vmax <= 1310);        /* reaches the extra-high phase */
    KX_CHECK(stops >= 2);                          /* stop-and-go */
}

static void test_charging_and_acc(void) {
    kx_sim_init(&S);
    S.v[KX_TF_SOC_DPCT] = 300;
    cmd("scenario charging");
    run(3000);
    KX_CHECK(S.v[KX_TF_CHARGING] == 1 && S.v[KX_TF_SOC_DPCT] == 310);
    run(300000);
    KX_CHECK(S.v[KX_TF_SOC_DPCT] == 800);          /* stops at charge limit 80% */

    cmd("scenario highway");                        /* driving away unplugs */
    run(100);
    KX_CHECK(S.v[KX_TF_CHARGING] == 0 && S.v[KX_TF_GEAR] == KX_GEAR_D);
    run(60000);
    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.action = KX_ACT_ADAS_ACC_SET_SPEED;
    in.n_params = 1;
    in.p[0].key = KX_P_TARGET_KPH;
    in.p[0].val = 90;
    KX_CHECK(kx_sim_apply(&S, &in) == 0);
    KX_CHECK(kx_sim_target_dkph(&S) == 900);
    run(30000);
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] == 900);
    KX_CHECK(S.v[KX_TF_SOC_DPCT] < 800);           /* driving drains */
}

static kx_intent_t act(uint16_t action, uint16_t key, int64_t val) {
    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.action = action;
    if (key) { in.n_params = 1; in.p[0].key = key; in.p[0].val = val; }
    return in;
}

static void test_effects(void) {
    kx_sim_init(&S);
    kx_intent_t in;
    in = act(KX_ACT_CABIN_CLIMATE_SET, KX_P_TEMP_DC, 225);  KX_CHECK(kx_sim_apply(&S, &in) == 0 && S.v[KX_TF_HVAC_SETPOINT_DC] == 225);
    in = act(KX_ACT_BODY_DOOR_UNLOCK, KX_P_DOOR, 2);       KX_CHECK(kx_sim_apply(&S, &in) == 0 && S.v[KX_TF_DOORS_LOCKED_MASK] == 11);
    in = act(KX_ACT_LIGHT_HAZARD_SET, KX_P_ON, 1);         KX_CHECK(kx_sim_apply(&S, &in) == 0 && S.v[KX_TF_HAZARD_ON] == 1);
    in = act(KX_ACT_BATTERY_CHARGE_LIMIT_SET, KX_P_PCT, 90); KX_CHECK(kx_sim_apply(&S, &in) == 0 && S.v[KX_TF_CHARGE_LIMIT_PCT] == 90);
    in = act(KX_ACT_TELEMATICS_LOCATION_SHARE, 0, 0);      KX_CHECK(kx_sim_apply(&S, &in) == 0 && S.v[KX_TF_LOCATION_SHARED] == 1);
    in = act(KX_ACT_CABIN_WINDOW_SET, KX_P_WINDOW, KX_WINDOW_REAR_RIGHT);
    in.n_params = 2; in.p[1].key = KX_P_POS_PCT; in.p[1].val = 60;
    KX_CHECK(kx_sim_apply(&S, &in) == 0 && S.v[KX_TF_WINDOW_RR_PCT] == 60);
    in = act(KX_ACT_DIAG_DTC_CLEAR, KX_P_ECU, 0);           KX_CHECK(kx_sim_apply(&S, &in) == 0);
    in = act(0, 0, 0);                                     KX_CHECK(kx_sim_apply(&S, &in) == -1);

    /* OTA: vehicle immobile while flashing, then idle */
    cmd("scenario highway");
    in = act(KX_ACT_OTA_ECU_FLASH, KX_P_ECU, 0);
    KX_CHECK(kx_sim_apply(&S, &in) == 0 && S.v[KX_TF_OTA_STATE] == KX_OTA_STATE_FLASHING);
    run(3000);
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] == 0 && S.v[KX_TF_GEAR] == KX_GEAR_P);
    run(5100);
    KX_CHECK(S.v[KX_TF_OTA_STATE] == KX_OTA_STATE_IDLE);

    /* immobilizer: stops and stays stopped */
    in = act(KX_ACT_VEHICLE_IMMOBILIZER_ENGAGE, 0, 0);
    KX_CHECK(kx_sim_apply(&S, &in) == 0);
    run(30000);
    KX_CHECK(S.v[KX_TF_SPEED_DKPH] == 0 && S.v[KX_TF_GEAR] == KX_GEAR_P);
}

static void test_commands(void) {
    kx_sim_init(&S);
    KX_CHECK(cmd("help") == 0);
    KX_CHECK(cmd("status") == 0 && strstr(R, "scenario=park") != NULL);
    KX_CHECK(cmd("scenario mars") == -1);
    KX_CHECK(cmd("set soc_dpct 1200") == -1);       /* out of catalog range */
    KX_CHECK(cmd("set nope 1") == -1);
    KX_CHECK(cmd("set soc_dpct 4x") == -1);
    KX_CHECK(cmd("driver 0") == 0 && S.v[KX_TF_DRIVER_PRESENT] == 0);
    KX_CHECK(cmd("service 1\n") == 0 && S.v[KX_TF_SERVICE_MODE] == 1);
    KX_CHECK(cmd("   ") == -1);
    char longcmd[300];
    memset(longcmd, 'a', sizeof longcmd - 1); longcmd[sizeof longcmd - 1] = '\0';
    KX_CHECK(cmd(longcmd) == -1);
    KX_CHECK(cmd("stall 1") == 0 && S.stalled == 1);
    KX_CHECK(cmd("stall 2") == -1);

    /* spoof: published state lies (gear P at 60 km/h) and K2 catches it */
    cmd("scenario highway");
    run(10000);
    KX_CHECK(plausible());
    KX_CHECK(cmd("spoof gear 0") == 0);
    KX_CHECK(!plausible());
    KX_CHECK(S.v[KX_TF_GEAR] == KX_GEAR_D);         /* the model itself is unchanged */
    KX_CHECK(cmd("spoof off") == 0 && plausible());
    KX_CHECK(cmd("spoof gear") == -1);
}

int main(void) {
    test_initial_and_park();
    test_highway_and_back();
    test_invariants_long_run();
    test_drivecycle_shape();
    test_charging_and_acc();
    test_effects();
    test_commands();
    KX_TEST_DONE();
}
