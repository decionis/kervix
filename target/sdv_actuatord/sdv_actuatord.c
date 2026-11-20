/*
 * sdv_actuatord: the actuator bus gateway (QNX 8.0 resource manager).
 *
 *   /dev/sdv/actuators  EXECUTE(grant, command) -> devctl ret_val = kx_reason_t
 *
 * The ONLY process allowed to move the vehicle (/dev/sdv/sim/actuate; secpol
 * enforces it in M2). For every EXECUTE it:
 *   1. takes the presenter's identity from the kernel-stamped message info
 *   2. asks kervixd to REDEEM the grant (MAC, single use, deadline, exact
 *      command, proposer binding, live interlock); nothing else is trusted
 *   3. only on OK applies the command to the bus, then reports the EFFECT
 * If kervixd is unreachable, nothing moves: AUTHORITY_UNAVAILABLE (fail closed).
 *
 * usage: sdv_actuatord [-v]
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/neutrino.h>
#include <unistd.h>

#include "kervix/grant.h"
#include "kervix/kervix_abi.h"
#include "kervix/sha256.h"
#include "kervix/vsim_abi.h"

static int g_verbose;
static int g_redeem_fd = -1, g_bus_fd = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static resmgr_connect_funcs_t g_cf;
static resmgr_io_funcs_t g_io;
static iofunc_attr_t g_attr;

static const char *rname(uint16_t r) {
    const kx_reason_spec_t *s = kx_catalog_reason(r);
    return s ? s->name : "?";
}

/* (Re)connect lazily: kervixd/vsimd restarts must not need an actuatord restart. */
static int ensure(int *fd, const char *path) {
    if (*fd == -1) *fd = open(path, O_RDWR);
    return *fd;
}
static int call(int *fd, const char *path, int dcmd, void *data, size_t n, int *ret) {
    for (int attempt = 0; attempt < 2; attempt++) {
        if (ensure(fd, path) == -1) return errno;
        int rc = devctl(*fd, dcmd, data, n, ret);
        if (rc == EOK) return EOK;
        if (rc != EBADF && rc != ESRCH && rc != ENOTCONN) return rc;
        close(*fd); /* server restarted: reconnect once */
        *fd = -1;
    }
    return ENOTCONN;
}

static uint16_t execute(resmgr_context_t *ctp, const kx_execute_req_t *rq) {
    kx_redeem_req_t rr;
    memset(&rr, 0, sizeof rr);
    rr.grant = rq->grant;
    rr.command = rq->command;
    rr.presenter.pid = ctp->info.pid;          /* the kernel says who is asking */
    rr.presenter.type_id = ctp->info.type_id;

    pthread_mutex_lock(&g_lock);
    int ret = -1;
    int rc = call(&g_redeem_fd, KX_PATH_REDEEM, KX_DCMD_REDEEM, &rr, sizeof rr, &ret);
    uint16_t reason = rc == EOK ? (uint16_t)ret : KX_R_AUTHORITY_UNAVAILABLE;
    if (reason == KX_R_OK) {
        kx_intent_t cmd = rq->command;
        int bus_ret = 0;
        int brc = call(&g_bus_fd, KX_VSIM_PATH_ACTUATE, KX_DCMD_SIM_APPLY, &cmd, sizeof cmd, &bus_ret);
        kx_effect_t e;
        memset(&e, 0, sizeof e);
        memcpy(e.grant_id, rq->grant.grant_id, 16);
        e.action = cmd.action;
        e.ok = brc == EOK;
        kx_params_digest(&cmd, e.request_digest);
        uint8_t ack[16 + 32 + 1];
        memcpy(ack, "kervix.ack/1\0\0\0\0", 16);
        memcpy(ack + 16, e.request_digest, 32);
        ack[48] = e.ok;
        kx_sha256(ack, sizeof ack, e.response_digest);
        int eret;
        call(&g_redeem_fd, KX_PATH_REDEEM, KX_DCMD_EFFECT, &e, sizeof e, &eret);
        if (!e.ok) reason = KX_R_ACTUATOR_FAILED;
    }
    pthread_mutex_unlock(&g_lock);
    if (g_verbose) printf("sdv_actuatord: EXECUTE from pid=%d action=%u -> %s\n", ctp->info.pid, rq->command.action, rname(reason));
    return reason;
}

static int io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, void *ocb_v) {
    int st = iofunc_devctl_default(ctp, msg, ocb_v);
    if (st != _RESMGR_DEFAULT) return st;
    if (msg->i.dcmd != KX_DCMD_EXECUTE) return ENOSYS;
    kx_execute_req_t rq;
    memcpy(&rq, _DEVCTL_DATA(msg->i), sizeof rq);
    uint16_t reason = execute(ctp, &rq);
    memset(&msg->o, 0, sizeof msg->o);
    msg->o.ret_val = reason;
    return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        if (opt == 'v') g_verbose = 1;
        else { fprintf(stderr, "usage: sdv_actuatord [-v]\n"); return 2; }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    dispatch_t *dpp = dispatch_create();
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &g_cf, _RESMGR_IO_NFUNCS, &g_io);
    g_io.devctl = io_devctl;
    iofunc_attr_init(&g_attr, S_IFCHR | 0666, NULL, NULL);
    resmgr_attr_t ra;
    memset(&ra, 0, sizeof ra);
    ra.nparts_max = 1;
    ra.msg_max_size = 4096;
    if (dpp == NULL ||
        secpol_resmgr_attach(NULL, dpp, &ra, KX_PATH_ACTUATORS, _FTYPE_ANY, 0, &g_cf, &g_io, &g_attr, NULL) == -1) {
        fprintf(stderr, "sdv_actuatord: attach %s: %s\n", KX_PATH_ACTUATORS, strerror(errno));
        return 1;
    }
    secpol_transition_type(NULL, NULL, 0);
    printf("sdv_actuatord: ready on %s pid=%d\n", KX_PATH_ACTUATORS, getpid());
    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    for (;;) {
        if (dispatch_block(ctp) == NULL) continue;
        dispatch_handler(ctp);
    }
}
