/* libkxsim vehicle model. See kervix/sim.h. */
#include <stdio.h>
#include <string.h>

#include "kervix/sim.h"

const char *const kx_scenario_names[KX_SCN__COUNT] = { "park", "charging", "city", "highway", "drivecycle" };

typedef struct { int32_t target_dkph; uint32_t ms; } seg_t;

/* Stop-and-go urban loop. */
static const seg_t CITY[] = { { 0, 3000 }, { 500, 9000 }, { 0, 4000 }, { 300, 7000 }, { 0, 3000 }, { 450, 8000 } };
/* Synthetic WLTP-like loop (low / medium / high / extra-high phases).
 * Generated for Kervix, NOT the regulatory WLTC trace. */
static const seg_t CYCLE[] = {
    { 0, 5000 },   { 400, 10000 }, { 0, 4000 },   { 560, 15000 }, { 200, 6000 },  { 0, 5000 },
    { 760, 20000 }, { 500, 8000 }, { 970, 25000 }, { 1310, 20000 }, { 900, 10000 }, { 0, 8000 },
};
#define NSEG(a) (uint32_t)(sizeof(a) / sizeof((a)[0]))

void kx_sim_init(kx_sim_t *s) {
    memset(s, 0, sizeof *s);
    s->v[KX_TF_GEAR] = KX_GEAR_P;
    s->v[KX_TF_PARK_BRAKE] = 1;
    s->v[KX_TF_SOC_DPCT] = 620;
    s->v[KX_TF_DRIVER_PRESENT] = 1;
    s->v[KX_TF_DOORS_LOCKED_MASK] = 15;
    s->v[KX_TF_HVAC_SETPOINT_DC] = 210;
    s->v[KX_TF_CHARGE_LIMIT_PCT] = 80;
    s->v[KX_TF_OTA_STATE] = KX_OTA_STATE_IDLE;
    s->scenario = KX_SCN_PARK;
}

static const seg_t *segments(uint8_t scn, uint32_t *n) {
    if (scn == KX_SCN_CITY) { *n = NSEG(CITY); return CITY; }
    if (scn == KX_SCN_DRIVECYCLE) { *n = NSEG(CYCLE); return CYCLE; }
    *n = 0;
    return NULL;
}

int32_t kx_sim_target_dkph(const kx_sim_t *s) {
    if (s->v[KX_TF_IMMOBILIZER_ON] || s->v[KX_TF_OTA_STATE] == KX_OTA_STATE_FLASHING) return 0;
    switch (s->scenario) {
    case KX_SCN_HIGHWAY:
        return s->v[KX_TF_ACC_TARGET_KPH] > 0 ? s->v[KX_TF_ACC_TARGET_KPH] * 10 : KX_SIM_HIGHWAY_DKPH;
    case KX_SCN_CITY:
    case KX_SCN_DRIVECYCLE: {
        uint32_t n;
        const seg_t *seg = segments(s->scenario, &n);
        int32_t t = seg[s->seg_index % n].target_dkph;
        /* ACC caps the set speed when engaged */
        if (s->v[KX_TF_ACC_TARGET_KPH] > 0 && t > s->v[KX_TF_ACC_TARGET_KPH] * 10) t = s->v[KX_TF_ACC_TARGET_KPH] * 10;
        return t;
    }
    default:
        return 0;
    }
}

void kx_sim_step(kx_sim_t *s, uint32_t dt_ms) {
    if (dt_ms == 0) return;
    if (dt_ms > 1000) dt_ms = 1000;

    /* scenario timeline */
    uint32_t n;
    const seg_t *seg = segments(s->scenario, &n);
    if (seg != NULL) {
        s->seg_elapsed_ms += dt_ms;
        while (s->seg_elapsed_ms >= seg[s->seg_index % n].ms) {
            s->seg_elapsed_ms -= seg[s->seg_index % n].ms;
            s->seg_index = (s->seg_index + 1) % n;
        }
    }

    int32_t target = kx_sim_target_dkph(s);
    int32_t speed = s->speed_mdkph / 1000;

    /* drivetrain: shift out of P only at standstill, into P only at standstill */
    if (target > 0 && s->v[KX_TF_GEAR] == KX_GEAR_P && s->speed_mdkph == 0) {
        s->v[KX_TF_PARK_BRAKE] = 0;
        s->v[KX_TF_GEAR] = KX_GEAR_D;
        s->v[KX_TF_CHARGING] = 0; /* unplug to drive */
    }
    if (s->v[KX_TF_GEAR] == KX_GEAR_D) {
        int32_t want = target * 1000;
        if (s->speed_mdkph < want) {
            s->speed_mdkph += KX_SIM_ACCEL_MDKPH_PER_MS * (int32_t)dt_ms;
            if (s->speed_mdkph > want) s->speed_mdkph = want;
        } else if (s->speed_mdkph > want) {
            s->speed_mdkph -= KX_SIM_DECEL_MDKPH_PER_MS * (int32_t)dt_ms;
            if (s->speed_mdkph < want) s->speed_mdkph = want;
        }
    }
    speed = s->speed_mdkph / 1000;
    int parked_scenario = s->scenario == KX_SCN_PARK || s->scenario == KX_SCN_CHARGING;
    if (s->speed_mdkph == 0 && s->v[KX_TF_GEAR] == KX_GEAR_D && (parked_scenario || target == 0) &&
        (parked_scenario || s->v[KX_TF_IMMOBILIZER_ON] || s->v[KX_TF_OTA_STATE] == KX_OTA_STATE_FLASHING)) {
        s->v[KX_TF_GEAR] = KX_GEAR_P;
        s->v[KX_TF_PARK_BRAKE] = 1;
    }
    s->v[KX_TF_SPEED_DKPH] = speed;

    /* body: doors auto-lock above 15 km/h */
    if (speed > KX_SIM_AUTOLOCK_DKPH) s->v[KX_TF_DOORS_LOCKED_MASK] = 15;

    /* energy */
    s->soc_timer_ms += dt_ms;
    if (s->scenario == KX_SCN_CHARGING && s->v[KX_TF_GEAR] == KX_GEAR_P) s->v[KX_TF_CHARGING] = 1;
    int32_t cap = s->v[KX_TF_CHARGE_LIMIT_PCT] * 10;
    if (s->v[KX_TF_CHARGING]) {
        if (s->soc_timer_ms >= 300) {
            s->soc_timer_ms = 0;
            if (s->v[KX_TF_SOC_DPCT] < cap) s->v[KX_TF_SOC_DPCT]++;
        }
    } else if (speed > 0) {
        if (s->soc_timer_ms >= 3000) {
            s->soc_timer_ms = 0;
            if (s->v[KX_TF_SOC_DPCT] > 0) s->v[KX_TF_SOC_DPCT]--;
        }
    } else {
        s->soc_timer_ms = 0;
    }

    /* OTA flashing completes after a fixed time */
    if (s->v[KX_TF_OTA_STATE] == KX_OTA_STATE_FLASHING) {
        if (s->ota_remaining_ms <= dt_ms) {
            s->ota_remaining_ms = 0;
            s->v[KX_TF_OTA_STATE] = KX_OTA_STATE_IDLE;
        } else {
            s->ota_remaining_ms -= dt_ms;
        }
    }
}

void kx_sim_snapshot(const kx_sim_t *s, uint64_t seq, uint64_t mono_ns, kx_telemetry_t *out) {
    memset(out, 0, sizeof *out);
    out->seq = seq;
    out->mono_ns = mono_ns;
    memcpy(out->v, s->v, sizeof out->v);
    if (s->spoof_active && s->spoof_field >= 0 && s->spoof_field < KX_TF__COUNT) {
        out->v[s->spoof_field] = s->spoof_value;
    }
}

/* ------------------------------------------------------------ commands */

static int field_index(const char *name) {
    for (int i = 0; i < KX_TF__COUNT; i++) {
        if (strcmp(kx_catalog_tfields[i].name, name) == 0) return i;
    }
    return -1;
}

static int parse_int(const char *t, int32_t *out) {
    if (t == NULL || *t == '\0') return -1;
    int neg = 0;
    if (*t == '-') { neg = 1; t++; }
    if (*t == '\0') return -1;
    int64_t v = 0;
    for (; *t; t++) {
        if (*t < '0' || *t > '9') return -1;
        v = v * 10 + (*t - '0');
        if (v > 1000000) return -1;
    }
    *out = (int32_t)(neg ? -v : v);
    return 0;
}

#define REPLY(...) do { if (cap) snprintf(reply, cap, __VA_ARGS__); } while (0)

int kx_sim_command(kx_sim_t *s, const char *line, char *reply, size_t cap) {
    char buf[128];
    size_t L = strlen(line);
    if (L >= sizeof buf) { REPLY("error: command too long"); return -1; }
    memcpy(buf, line, L + 1);
    /* tokenize (<= 4 tokens), trimming whitespace/newlines */
    char *tok[4] = { 0 };
    int nt = 0;
    for (char *p = buf; *p && nt < 4;) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') *p++ = '\0';
        if (!*p) break;
        tok[nt++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    }
    if (nt == 0) { REPLY("error: empty command"); return -1; }

    if (!strcmp(tok[0], "help")) {
        REPLY("commands: scenario <park|charging|city|highway|drivecycle> | set <field> <int> | driver <0|1> | "
              "service <0|1> | stall <0|1> | spoof <field> <int> | spoof off | status");
        return 0;
    }
    if (!strcmp(tok[0], "status")) {
        REPLY("scenario=%s speed_dkph=%d gear=%s target_dkph=%d soc_dpct=%d charging=%d stalled=%d spoof=%s",
              kx_scenario_names[s->scenario], s->v[KX_TF_SPEED_DKPH], kx_enum_gear[s->v[KX_TF_GEAR]],
              kx_sim_target_dkph(s), s->v[KX_TF_SOC_DPCT], s->v[KX_TF_CHARGING], s->stalled,
              s->spoof_active ? kx_catalog_tfields[s->spoof_field].name : "off");
        return 0;
    }
    if (!strcmp(tok[0], "scenario") && nt == 2) {
        for (int i = 0; i < KX_SCN__COUNT; i++) {
            if (!strcmp(tok[1], kx_scenario_names[i])) {
                s->scenario = (uint8_t)i;
                s->seg_index = 0;
                s->seg_elapsed_ms = 0;
                if (i != KX_SCN_CHARGING) s->v[KX_TF_CHARGING] = 0;
                REPLY("ok scenario=%s", kx_scenario_names[i]);
                return 0;
            }
        }
        REPLY("error: unknown scenario '%s'", tok[1]);
        return -1;
    }
    if (!strcmp(tok[0], "stall") && nt == 2 && (tok[1][0] == '0' || tok[1][0] == '1') && !tok[1][1]) {
        s->stalled = (uint8_t)(tok[1][0] - '0');
        REPLY("ok stalled=%d", s->stalled);
        return 0;
    }
    if (!strcmp(tok[0], "spoof")) {
        if (nt == 2 && !strcmp(tok[1], "off")) {
            s->spoof_active = 0;
            REPLY("ok spoof=off");
            return 0;
        }
        int f = nt == 3 ? field_index(tok[1]) : -1;
        int32_t v;
        if (f < 0 || parse_int(tok[2], &v) != 0) { REPLY("error: usage: spoof <field> <int> | spoof off"); return -1; }
        s->spoof_active = 1;
        s->spoof_field = f;
        s->spoof_value = v;
        REPLY("ok spoof %s=%d (published only)", kx_catalog_tfields[f].name, v);
        return 0;
    }
    const char *field = NULL, *val = NULL;
    if (!strcmp(tok[0], "set") && nt == 3) { field = tok[1]; val = tok[2]; }
    if (!strcmp(tok[0], "driver") && nt == 2) { field = "driver_present"; val = tok[1]; }
    if (!strcmp(tok[0], "service") && nt == 2) { field = "service_mode"; val = tok[1]; }
    if (field != NULL) {
        int f = field_index(field);
        int32_t v;
        if (f < 0) { REPLY("error: unknown field '%s'", field); return -1; }
        if (parse_int(val, &v) != 0 || v < kx_catalog_tfields[f].min || v > kx_catalog_tfields[f].max) {
            REPLY("error: %s must be an integer in %d..%d", field, kx_catalog_tfields[f].min, kx_catalog_tfields[f].max);
            return -1;
        }
        if (f == KX_TF_SPEED_DKPH) s->speed_mdkph = v * 1000;
        s->v[f] = v;
        REPLY("ok %s=%d", field, v);
        return 0;
    }
    REPLY("error: unknown command (try: help)");
    return -1;
}

/* ------------------------------------------------------------ actuation */

static int64_t param(const kx_intent_t *in, uint16_t key, int64_t dflt) {
    for (uint8_t i = 0; i < in->n_params && i < KX_MAX_PARAMS; i++) {
        if (in->p[i].key == key) return in->p[i].val;
    }
    return dflt;
}

int kx_sim_apply(kx_sim_t *s, const kx_intent_t *in) {
    static const kx_tfield_t windows[4] = { KX_TF_WINDOW_FL_PCT, KX_TF_WINDOW_FR_PCT, KX_TF_WINDOW_RL_PCT, KX_TF_WINDOW_RR_PCT };
    switch (in->action) {
    case KX_ACT_CABIN_CLIMATE_SET:
        s->v[KX_TF_HVAC_SETPOINT_DC] = (int32_t)param(in, KX_P_TEMP_DC, s->v[KX_TF_HVAC_SETPOINT_DC]);
        return 0;
    case KX_ACT_CABIN_WINDOW_SET: {
        int64_t w = param(in, KX_P_WINDOW, -1);
        if (w < 0 || w > 3) return -1;
        s->v[windows[w]] = (int32_t)param(in, KX_P_POS_PCT, s->v[windows[w]]);
        return 0;
    }
    case KX_ACT_BODY_DOOR_UNLOCK: {
        int64_t d = param(in, KX_P_DOOR, -1);
        if (d < 0 || d > 3) return -1;
        s->v[KX_TF_DOORS_LOCKED_MASK] &= ~(1 << d);
        return 0;
    }
    case KX_ACT_LIGHT_HAZARD_SET:
        s->v[KX_TF_HAZARD_ON] = param(in, KX_P_ON, 0) ? 1 : 0;
        return 0;
    case KX_ACT_ADAS_ACC_SET_SPEED:
        s->v[KX_TF_ACC_TARGET_KPH] = (int32_t)param(in, KX_P_TARGET_KPH, s->v[KX_TF_ACC_TARGET_KPH]);
        return 0;
    case KX_ACT_BATTERY_CHARGE_LIMIT_SET:
        s->v[KX_TF_CHARGE_LIMIT_PCT] = (int32_t)param(in, KX_P_PCT, s->v[KX_TF_CHARGE_LIMIT_PCT]);
        return 0;
    case KX_ACT_TELEMATICS_LOCATION_SHARE:
        s->v[KX_TF_LOCATION_SHARED] = 1;
        return 0;
    case KX_ACT_VEHICLE_IMMOBILIZER_ENGAGE:
        s->v[KX_TF_IMMOBILIZER_ON] = 1;
        return 0;
    case KX_ACT_OTA_ECU_FLASH:
        s->v[KX_TF_OTA_STATE] = KX_OTA_STATE_FLASHING;
        s->ota_remaining_ms = KX_SIM_OTA_MS;
        return 0;
    case KX_ACT_DIAG_DTC_CLEAR:
    case KX_ACT_CHASSIS_BRAKE_CALIBRATION_WRITE:
        return 0; /* no telemetry-visible effect */
    default:
        return -1;
    }
}
