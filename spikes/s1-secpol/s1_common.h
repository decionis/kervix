/* Spike S1/S2 shared definitions. */
#ifndef KX_S1_COMMON_H
#define KX_S1_COMMON_H

#include <devctl.h>
#include <stdint.h>
#include <sys/neutrino.h>

#define S1_PATH_OPEN "/dev/kxs1/open"  /* channel type kxs1_open_ch_t: agents + actuators */
#define S1_PATH_PRIV "/dev/kxs1/priv"  /* channel type kxs1_priv_ch_t: actuators only    */

typedef struct {
    int32_t  pid;
    uint32_t uid;
    uint32_t type_id;        /* S2: client's secpol type id as seen by the server */
    char     type_name[48];  /* resolved via secpol_get_type_name */
    char     node[16];       /* which node answered: "open" | "priv" */
} s1_whoami_t;

typedef struct {
    struct sigevent ev;      /* registered with MsgRegisterEvent by the client */
    uint32_t delay_ms;
} s1_subscribe_t;

#define S1_DCMD_WHOAMI    __DIOF(_DCMD_MISC, 0x51, s1_whoami_t)
#define S1_DCMD_SUBSCRIBE __DIOT(_DCMD_MISC, 0x52, s1_subscribe_t)

#define S1_PULSE_CODE (_PULSE_CODE_MINAVAIL + 7)

#endif
