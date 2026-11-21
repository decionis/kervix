/*
 * carlock: the client. Run it under different secpol types:
 *   on -T app_t carlock status       an infotainment app reads the lock state
 *   on -T app_t carlock unlock       ... and tries to unlock the car
 *   on -T keyfob_t carlock unlock    the key-fob receiver unlocks it
 *   on -T app_t carlock squat        try to impersonate carlockd (attach its path)
 */
#include <errno.h>
#include <fcntl.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <unistd.h>

#include "carlock.h"

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: carlock status|lock|unlock|squat\n"); return 2; }
    const char *me = secpol_get_type_name(NULL, secpol_type_id());
    printf("carlock: I am uid %d, type %s\n", (int)getuid(), me ? me : "(no policy)");

    if (!strcmp(argv[1], "squat")) {          /* pretend to be carlockd */
        dispatch_t *d = dispatch_create();
        resmgr_connect_funcs_t cf; resmgr_io_funcs_t io; iofunc_attr_t a;
        iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cf, _RESMGR_IO_NFUNCS, &io);
        iofunc_attr_init(&a, S_IFCHR | 0666, NULL, NULL);
        int id = secpol_resmgr_attach(NULL, d, NULL, CARLOCK_COMMAND, _FTYPE_ANY, 0, &cf, &io, &a, NULL);
        printf(id == -1 ? "squat: REFUSED: %s\n" : "squat: attached %s (anyone could impersonate carlockd!)\n",
               id == -1 ? strerror(errno) : CARLOCK_COMMAND);
        return id == -1 ? 1 : 0;
    }
    int set = strcmp(argv[1], "status") != 0;
    const char *path = set ? CARLOCK_COMMAND : CARLOCK_STATUS;
    int fd = open(path, O_RDWR);              /* the kernel checks the channel type HERE */
    if (fd == -1) { printf("%s: REFUSED: open %s: %s\n", argv[1], path, strerror(errno)); return 1; }
    carlock_msg_t m;
    memset(&m, 0, sizeof m);
    m.locked = !strcmp(argv[1], "lock");
    int rc = devctl(fd, set ? CARLOCK_SET : CARLOCK_GET, &m, sizeof m, NULL);
    close(fd);
    if (rc != EOK) { printf("%s: failed: %s\n", argv[1], strerror(rc)); return 1; }
    printf("%s: OK, the car is %s (carlockd saw caller type %s)\n", argv[1], m.locked ? "LOCKED" : "UNLOCKED", m.caller_name);
    return 0;
}
