/*
 * libkxsim: deterministic vehicle model behind vsimd (portable C11, no OS
 * dependencies, integer math only, no allocation).
 *
 * The model is PHYSICALLY CONSISTENT by construction: it never reports gear P
 * while moving, accelerates at <= 2.5 m/s^2 and brakes at <= 3 m/s^2, and only
 * shifts out of P at standstill. The only way to publish an inconsistent
 * state is the explicit `spoof` command, which exists to demonstrate Kervix's
 * plausibility check (constitution K2).
 *
 * Actuation (kx_sim_apply) models the actuator bus: it performs what it is
 * told. Deciding WHETHER an action may happen is Kervix's job, not the car's.
 */
#ifndef KERVIX_SIM_H
#define KERVIX_SIM_H

#include <stddef.h>
#include <stdint.h>

#include "kervix/abi.h"

typedef enum {
    KX_SCN_PARK = 0,
    KX_SCN_CHARGING,
    KX_SCN_CITY,
    KX_SCN_HIGHWAY,
    KX_SCN_DRIVECYCLE,
    KX_SCN__COUNT
} kx_scenario_t;

extern const char *const kx_scenario_names[KX_SCN__COUNT];

#define KX_SIM_ACCEL_MDKPH_PER_MS   90   /* 2.5 m/s^2 = 9 km/h/s = 90 dkph/s */
#define KX_SIM_DECEL_MDKPH_PER_MS   108  /* 3.0 m/s^2 */
#define KX_SIM_HIGHWAY_DKPH         1100
#define KX_SIM_AUTOLOCK_DKPH        150  /* doors auto-lock above 15 km/h */
#define KX_SIM_OTA_MS               8000

typedef struct {
    int32_t  v[KX_TF__COUNT];   /* current state, indexed like telemetry */
    int32_t  speed_mdkph;       /* speed in 0.001 dkph for smooth integer kinematics */
    uint8_t  scenario;          /* kx_scenario_t */
    uint8_t  stalled;           /* 1 = publisher should stop (K1 demo) */
    uint8_t  spoof_active;
    uint8_t  _pad;
    int32_t  spoof_field, spoof_value;
    uint32_t seg_index, seg_elapsed_ms;
    uint32_t ota_remaining_ms;
    uint32_t soc_timer_ms;
} kx_sim_t;

void kx_sim_init(kx_sim_t *s);
void kx_sim_step(kx_sim_t *s, uint32_t dt_ms);
/* Snapshot for publishing (applies an active spoof override). */
void kx_sim_snapshot(const kx_sim_t *s, uint64_t seq, uint64_t mono_ns, kx_telemetry_t *out);
/* Current target speed the model is steering toward (dkph). */
int32_t kx_sim_target_dkph(const kx_sim_t *s);

/* One text command (see vsimd /dev/sdv/sim/ctl):
 *   scenario <park|charging|city|highway|drivecycle>
 *   set <telemetry_field> <int>     direct override (range-checked; debugging)
 *   driver <0|1> | service <0|1>   aliases of set
 *   stall <0|1>                     stop/resume publishing (telemetry freshness demo)
 *   spoof <field> <int> | spoof off publish an inconsistent value (plausibility demo)
 *   status | help
 * Returns 0 and writes a one-line reply, or -1 with an error message. */
int kx_sim_command(kx_sim_t *s, const char *line, char *reply, size_t cap);

/* Apply an actuation for a (validated) intent. 0 = applied, -1 = unknown action. */
int kx_sim_apply(kx_sim_t *s, const kx_intent_t *in);

#endif /* KERVIX_SIM_H */
