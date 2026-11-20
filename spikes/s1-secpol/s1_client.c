/*
 * Spike S1/S2 client. Run under different secpol types (on -T <type> s1_client)
 * and report what the kernel lets it do:
 *   OPEN   open()+WHOAMI on /dev/kxs1/open
 *   PRIV   open()+WHOAMI on /dev/kxs1/priv
 *   SQUAT  try to attach /dev/kxs1/priv itself (path squatting)
 *   PULSE  MsgRegisterEvent + server-delivered pulse over the open node
 * Output: one "RESULT <test> <ok|denied|error> <detail>" line per test.
 */
#include <errno.h>
#include <fcntl.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/neutrino.h>
#include <unistd.h>

#include "s1_common.h"

static const char *classify(int err) {
    return (err == EACCES || err == EPERM) ? "denied" : "error";
}

static void test_node(const char *label, const char *path) {
    int fd = open(path, O_RDWR);
    if (fd == -1) {
        printf("RESULT %s %s open: %s (errno %d)\n", label, classify(errno), strerror(errno), errno);
        return;
    }
    s1_whoami_t w;
    int rc = devctl(fd, S1_DCMD_WHOAMI, &w, sizeof w, NULL);
    if (rc != EOK) {
        printf("RESULT %s %s devctl: %s\n", label, classify(rc), strerror(rc));
    } else {
        printf("RESULT %s ok node=%s server_sees pid=%d uid=%u type_id=%u type=%s\n", label, w.node,
               w.pid, w.uid, w.type_id, w.type_name);
    }
    close(fd);
}

static void test_squat(void) {
    dispatch_t *d = dispatch_create();
    resmgr_connect_funcs_t cf; resmgr_io_funcs_t io; iofunc_attr_t a;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cf, _RESMGR_IO_NFUNCS, &io);
    iofunc_attr_init(&a, S_IFCHR | 0666, NULL, NULL);
    int id = secpol_resmgr_attach(NULL, d, NULL, S1_PATH_PRIV, _FTYPE_ANY, 0, &cf, &io, &a, NULL);
    if (id == -1) {
        printf("RESULT SQUAT %s attach %s: %s (errno %d)\n", classify(errno), S1_PATH_PRIV, strerror(errno), errno);
    } else {
        printf("RESULT SQUAT ok attached %s (VULNERABLE)\n", S1_PATH_PRIV);
        resmgr_detach(d, id, 0);
    }
}

static void test_pulse(void) {
    int chid = ChannelCreate(_NTO_CHF_PRIVATE);
    int self = ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0);
    int fd = open(S1_PATH_OPEN, O_RDWR);
    if (chid == -1 || self == -1 || fd == -1) {
        printf("RESULT PULSE error setup: %s\n", strerror(errno));
        return;
    }
    s1_subscribe_t s;
    memset(&s, 0, sizeof s);
    SIGEV_PULSE_INIT(&s.ev, self, SIGEV_PULSE_PRIO_INHERIT, S1_PULSE_CODE, 0x5151);
    if (MsgRegisterEvent(&s.ev, fd) == -1) { /* QNX 8: server may only deliver registered events */
        printf("RESULT PULSE error MsgRegisterEvent: %s\n", strerror(errno));
        return;
    }
    s.delay_ms = 100;
    int rc = devctl(fd, S1_DCMD_SUBSCRIBE, &s, sizeof s, NULL);
    if (rc != EOK) { printf("RESULT PULSE %s subscribe: %s\n", classify(rc), strerror(rc)); return; }

    struct _pulse p;
    uint64_t timeout = 3000000000ull;
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &timeout, NULL);
    int r = MsgReceivePulse(chid, &p, sizeof p, NULL);
    if (r == -1) printf("RESULT PULSE error receive: %s\n", strerror(errno));
    else printf("RESULT PULSE ok code=%d value=0x%x\n", p.code, (unsigned)p.value.sival_int);
    close(fd);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    uint32_t t = secpol_type_id();
    printf("s1_client: pid=%d uid=%d my type=%u (%s)\n", getpid(), getuid(), t,
           secpol_get_type_name(NULL, t) ?: "?");
    const char *only = argc > 1 ? argv[1] : "all";
    if (!strcmp(only, "all") || !strcmp(only, "open")) test_node("OPEN", S1_PATH_OPEN);
    if (!strcmp(only, "all") || !strcmp(only, "priv")) test_node("PRIV", S1_PATH_PRIV);
    if (!strcmp(only, "all") || !strcmp(only, "squat")) test_squat();
    if (!strcmp(only, "all") || !strcmp(only, "pulse")) test_pulse();
    return 0;
}
