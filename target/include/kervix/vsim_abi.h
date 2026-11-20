/*
 * vsimd interface (QNX resource-manager devctls + paths).
 *
 *   /dev/sdv/telemetry   read: one JSON line (latest snapshot)
 *                        devctl SUBSCRIBE / UNSUBSCRIBE / GET
 *                        Readers normally map KX_TELEMETRY_SHM_NAME read-only
 *                        and use the pulse only as a "new sample" doorbell.
 *   /dev/sdv/sim/ctl     write: one text command (kx_sim_command), read: last reply
 *   /dev/sdv/sim/actuate devctl APPLY: actuation effect (sdv_actuatord only)
 *
 * Each path is attached on its own dispatch channel so the security policy can
 * type it separately (spike S1): only actuator_t may reach /dev/sdv/sim/actuate.
 */
#ifndef KERVIX_VSIM_ABI_H
#define KERVIX_VSIM_ABI_H

#include <devctl.h>
#include <sys/neutrino.h>

#include "kervix/abi.h"

#define KX_VSIM_PATH_TELEMETRY "/dev/sdv/telemetry"
#define KX_VSIM_PATH_CTL       "/dev/sdv/sim/ctl"
#define KX_VSIM_PATH_ACTUATE   "/dev/sdv/sim/actuate"

#define KX_VSIM_MAX_SUBSCRIBERS 8

/* the subscriber's event, registered with MsgRegisterEvent(&ev, fd) first */
#define KX_DCMD_TEL_SUBSCRIBE   __DIOT(_DCMD_MISC, 0x101, struct sigevent)
#define KX_DCMD_TEL_UNSUBSCRIBE __DION(_DCMD_MISC, 0x102)
#define KX_DCMD_TEL_GET         __DIOF(_DCMD_MISC, 0x103, kx_telemetry_t)
#define KX_DCMD_SIM_APPLY       __DIOT(_DCMD_MISC, 0x110, kx_intent_t)

#endif /* KERVIX_VSIM_ABI_H */
