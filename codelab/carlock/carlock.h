/* Codelab: the car-lock resource manager's interface (shared by daemon and client). */
#ifndef CARLOCK_H
#define CARLOCK_H

#include <devctl.h>
#include <stdint.h>

#define CARLOCK_STATUS  "/dev/carlock/status"   /* any app may ask: locked or not?        */
#define CARLOCK_COMMAND "/dev/carlock/command"  /* only the key fob may lock or unlock     */

typedef struct {
    uint32_t locked;          /* in (SET): 1 lock, 0 unlock; out: current state */
    uint32_t caller_type;     /* out: the caller's secpol type id, as the kernel stamped it */
    char     caller_name[48]; /* out: that type's name */
} carlock_msg_t;

#define CARLOCK_GET __DIOF(_DCMD_MISC, 0x701, carlock_msg_t)
#define CARLOCK_SET __DIOTF(_DCMD_MISC, 0x702, carlock_msg_t)

#endif
