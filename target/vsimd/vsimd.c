/*
 * vsimd: vehicle simulator daemon (QNX 8.0).
 *
 *  - a CLOCK_MONOTONIC timer pulse drives libkxsim at <rate> Hz (default 100)
 *    on a SCHED_FIFO thread (priority 50, above every Kervix client)
 *  - each tick publishes a snapshot into the shared-memory seqlock
 *    KX_TELEMETRY_SHM_NAME (readers map it read-only) and rings every
 *    subscriber's registered pulse
 *  - three resource-manager paths on three dispatch channels (one channel
 *    type each under secpol): see kervix/vsim_abi.h
 *
 * usage: vsimd [-r rate_hz] [-s scenario] [-g ctl_gid] [-v]
 *   -g: group that may write /dev/sdv/sim/ctl (the demo's world gateway, kxgw --role world)
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <secpol/secpol.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <time.h>
#include <unistd.h>

#include "kervix/seqlock.h"
#include "kervix/sim.h"
#include "kervix/vsim_abi.h"

#define TICK_PRIO     50
#define PULSE_TICK    (_PULSE_CODE_MINAVAIL + 1)

static kx_sim_t            g_sim;
static pthread_mutex_t     g_lock = PTHREAD_MUTEX_INITIALIZER; /* QNX mutexes: priority inheritance */
static kx_telemetry_shm_t *g_shm;
static int                 g_verbose;
static char                g_ctl_reply[256] = "ready (try: help)";

typedef struct { int active; int rcvid; void *ocb; struct sigevent ev; } sub_t;
static sub_t g_subs[KX_VSIM_MAX_SUBSCRIBERS];
static pthread_mutex_t g_sub_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    const char            *path;
    dispatch_t            *dpp;
    resmgr_connect_funcs_t cf;
    resmgr_io_funcs_t      io;
    iofunc_attr_t          attr;
} node_t;
enum { N_TEL = 0, N_CTL, N_ACT, N__COUNT };
static node_t g_nodes[N__COUNT] = {
    { .path = KX_VSIM_PATH_TELEMETRY }, { .path = KX_VSIM_PATH_CTL }, { .path = KX_VSIM_PATH_ACTUATE },
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------ tick */

static void ring_subscribers(void) {
    pthread_mutex_lock(&g_sub_lock);
    for (int i = 0; i < KX_VSIM_MAX_SUBSCRIBERS; i++) {
        if (!g_subs[i].active) continue;
        if (MsgDeliverEvent(g_subs[i].rcvid, &g_subs[i].ev) == -1) {
            if (g_verbose) printf("vsimd: subscriber %d gone (%s)\n", i, strerror(errno));
            g_subs[i].active = 0;
        }
    }
    pthread_mutex_unlock(&g_sub_lock);
}

static void *tick_thread(void *arg) {
    unsigned rate = *(unsigned *)arg;
    struct sched_param sp = { .sched_priority = TICK_PRIO };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    int chid = ChannelCreate(_NTO_CHF_PRIVATE);
    int coid = ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, TICK_PRIO, PULSE_TICK, 0);
    timer_t tid;
    if (chid == -1 || coid == -1 || timer_create(CLOCK_MONOTONIC, &ev, &tid) == -1) {
        perror("vsimd: timer setup");
        exit(1);
    }
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    its.it_value.tv_nsec = (long)(1000000000u / rate);
    its.it_interval.tv_nsec = (long)(1000000000u / rate);
    timer_settime(tid, 0, &its, NULL);

    uint64_t seq = __atomic_load_n(&g_shm->snap.seq, __ATOMIC_RELAXED); /* continue across restarts */
    uint64_t last = now_ns(), carry_ns = 0;
    for (;;) {
        struct _pulse p;
        if (MsgReceivePulse(chid, &p, sizeof p, NULL) == -1 || p.code != PULSE_TICK) continue;
        uint64_t t = now_ns();
        carry_ns += t - last;
        last = t;
        uint32_t dt_ms = (uint32_t)(carry_ns / 1000000u);
        carry_ns %= 1000000u;

        kx_telemetry_t snap;
        pthread_mutex_lock(&g_lock);
        kx_sim_step(&g_sim, dt_ms);
        int stalled = g_sim.stalled;
        kx_sim_snapshot(&g_sim, seq + 1, t, &snap);
        pthread_mutex_unlock(&g_lock);

        if (stalled) continue; /* demo: telemetry goes stale, Kervix must fail closed */
        seq++;
        kx_seqlock_write(g_shm, &snap);
        ring_subscribers();
    }
    return NULL;
}

/* ------------------------------------------------------------ resmgr */

static node_t *node_of(void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    for (int i = 0; i < N__COUNT; i++) if (ocb->attr == &g_nodes[i].attr) return &g_nodes[i];
    return NULL;
}

static int reply_text(resmgr_context_t *ctp, io_read_t *msg, iofunc_ocb_t *ocb, const char *text) {
    size_t len = strlen(text);
    if (ocb->offset > 0 || msg->i.nbytes == 0) { _IO_SET_READ_NBYTES(ctp, 0); return _RESMGR_NPARTS(0); }
    size_t n = len < msg->i.nbytes ? len : msg->i.nbytes;
    ocb->offset += (off_t)n;
    _IO_SET_READ_NBYTES(ctp, (long)n);
    MsgReply(ctp->rcvid, (long)n, text, n);
    return _RESMGR_NOREPLY;
}

static int io_read(resmgr_context_t *ctp, io_read_t *msg, void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    int st = iofunc_read_verify(ctp, msg, ocb, NULL);
    if (st != EOK) return st;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    node_t *n = node_of(ocb);
    char buf[640];
    if (n == &g_nodes[N_CTL]) {
        pthread_mutex_lock(&g_lock);
        snprintf(buf, sizeof buf, "%s\n", g_ctl_reply);
        pthread_mutex_unlock(&g_lock);
    } else if (n == &g_nodes[N_TEL]) {
        kx_telemetry_t t;
        memset(&t, 0, sizeof t);
        if (kx_seqlock_read(g_shm, &t, 16) != 0) return EAGAIN;
        size_t o = (size_t)snprintf(buf, sizeof buf, "{\"seq\":%llu,\"mono_ns\":%llu",
                                    (unsigned long long)t.seq, (unsigned long long)t.mono_ns);
        for (int f = 0; f < KX_TF__COUNT && o < sizeof buf - 40; f++) {
            o += (size_t)snprintf(buf + o, sizeof buf - o, ",\"%s\":%d", kx_catalog_tfields[f].name, t.v[f]);
        }
        snprintf(buf + o, sizeof buf - o, "}\n");
    } else {
        return EBADF;
    }
    return reply_text(ctp, msg, ocb, buf);
}

static int io_write(resmgr_context_t *ctp, io_write_t *msg, void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    int st = iofunc_write_verify(ctp, msg, ocb, NULL);
    if (st != EOK) return st;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    if (node_of(ocb) != &g_nodes[N_CTL]) return EBADF;
    size_t n = _IO_WRITE_GET_NBYTES(msg);
    char line[128];
    if (n >= sizeof line) return E2BIG;
    if (resmgr_msgget(ctp, line, n, sizeof msg->i) != (ssize_t)n) return EIO;
    line[n] = '\0';
    pthread_mutex_lock(&g_lock);
    int rc = kx_sim_command(&g_sim, line, g_ctl_reply, sizeof g_ctl_reply);
    pthread_mutex_unlock(&g_lock);
    if (g_verbose) printf("vsimd: ctl '%.*s' -> %s\n", (int)strcspn(line, "\n"), line, g_ctl_reply);
    if (rc != 0) return EINVAL;
    _IO_SET_WRITE_NBYTES(ctp, (long)n);
    return EOK;
}

static int io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    int st = iofunc_devctl_default(ctp, msg, ocb);
    if (st != _RESMGR_DEFAULT) return st;
    node_t *n = node_of(ocb);
    void *data = _DEVCTL_DATA(msg->i);
    switch (msg->i.dcmd) {
    case KX_DCMD_TEL_SUBSCRIBE: {
        if (n != &g_nodes[N_TEL]) return ENOTTY;
        int slot = -1;
        pthread_mutex_lock(&g_sub_lock);
        for (int i = 0; i < KX_VSIM_MAX_SUBSCRIBERS; i++) {
            if (g_subs[i].active && g_subs[i].ocb == ocb) { slot = i; break; }   /* re-subscribe */
            if (!g_subs[i].active && slot < 0) slot = i;
        }
        if (slot >= 0) {
            g_subs[slot].active = 1;
            g_subs[slot].rcvid = ctp->rcvid;
            g_subs[slot].ocb = ocb;
            memcpy(&g_subs[slot].ev, data, sizeof(struct sigevent));
        }
        pthread_mutex_unlock(&g_sub_lock);
        if (slot < 0) return EBUSY;
        memset(&msg->o, 0, sizeof msg->o);
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    case KX_DCMD_TEL_UNSUBSCRIBE: {
        pthread_mutex_lock(&g_sub_lock);
        for (int i = 0; i < KX_VSIM_MAX_SUBSCRIBERS; i++) if (g_subs[i].ocb == ocb) g_subs[i].active = 0;
        pthread_mutex_unlock(&g_sub_lock);
        memset(&msg->o, 0, sizeof msg->o);
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    case KX_DCMD_TEL_GET: {
        if (n != &g_nodes[N_TEL]) return ENOTTY;
        kx_telemetry_t t;
        memset(&t, 0, sizeof t);
        if (kx_seqlock_read(g_shm, &t, 16) != 0) return EAGAIN;
        memcpy(data, &t, sizeof t);
        memset(&msg->o, 0, sizeof msg->o);
        msg->o.nbytes = sizeof t;
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o + sizeof t);
    }
    case KX_DCMD_SIM_APPLY: {
        if (n != &g_nodes[N_ACT]) return ENOTTY;
        kx_intent_t in;
        memcpy(&in, data, sizeof in);
        pthread_mutex_lock(&g_lock);
        int rc = kx_sim_apply(&g_sim, &in);
        pthread_mutex_unlock(&g_lock);
        if (g_verbose) printf("vsimd: apply action=%u -> %d\n", in.action, rc);
        if (rc != 0) return EINVAL;
        memset(&msg->o, 0, sizeof msg->o);
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    default:
        return ENOSYS;
    }
}

static int io_close_ocb(resmgr_context_t *ctp, void *reserved, void *ocb_v) {
    pthread_mutex_lock(&g_sub_lock);
    for (int i = 0; i < KX_VSIM_MAX_SUBSCRIBERS; i++) if (g_subs[i].ocb == ocb_v) g_subs[i].active = 0;
    pthread_mutex_unlock(&g_sub_lock);
    return iofunc_close_ocb_default(ctp, reserved, ocb_v);
}

static void *serve(void *arg) {
    node_t *n = arg;
    dispatch_context_t *ctp = dispatch_context_alloc(n->dpp);
    for (;;) {
        if (dispatch_block(ctp) == NULL) continue;
        dispatch_handler(ctp);
    }
    return NULL;
}

/* ------------------------------------------------------------ main */

int main(int argc, char **argv) {
    unsigned rate = 100;
    const char *scenario = "park";
    int ctl_gid = -1;
    int opt;
    while ((opt = getopt(argc, argv, "r:s:g:v")) != -1) {
        if (opt == 'r') rate = (unsigned)atoi(optarg);
        else if (opt == 's') scenario = optarg;
        else if (opt == 'g') ctl_gid = atoi(optarg);
        else if (opt == 'v') g_verbose = 1;
        else { fprintf(stderr, "usage: vsimd [-r rate_hz] [-s scenario] [-g ctl_gid] [-v]\n"); return 2; }
    }
    if (rate < 1 || rate > 1000) { fprintf(stderr, "vsimd: rate must be 1..1000 Hz\n"); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);

    kx_sim_init(&g_sim);
    char cmd[64];
    snprintf(cmd, sizeof cmd, "scenario %s", scenario);
    if (kx_sim_command(&g_sim, cmd, g_ctl_reply, sizeof g_ctl_reply) != 0) {
        fprintf(stderr, "vsimd: %s\n", g_ctl_reply);
        return 2;
    }

    /* shared memory: create or reuse (readers keep their mapping across vsimd restarts) */
    int fd = shm_open(KX_TELEMETRY_SHM_NAME, O_RDWR | O_CREAT, 0644);
    if (fd == -1 || ftruncate(fd, sizeof(kx_telemetry_shm_t)) == -1) { perror("vsimd: shm"); return 1; }
    fchmod(fd, 0644);
    g_shm = mmap(NULL, sizeof(kx_telemetry_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (g_shm == MAP_FAILED) { perror("vsimd: mmap"); return 1; }
    g_shm->abi = KX_ABI_VERSION;
    g_shm->n_fields = KX_TF__COUNT;
    g_shm->period_us = 1000000u / rate;
    g_shm->writer_pid = (uint32_t)getpid();
    {   /* publish an initial snapshot before announcing the segment as valid */
        kx_telemetry_t t;
        kx_sim_snapshot(&g_sim, __atomic_load_n(&g_shm->snap.seq, __ATOMIC_RELAXED), now_ns(), &t);
        kx_seqlock_write(g_shm, &t);
        __atomic_store_n(&g_shm->magic, KX_TELEMETRY_SHM_MAGIC, __ATOMIC_RELEASE);
    }

    for (int i = 0; i < N__COUNT; i++) {
        node_t *n = &g_nodes[i];
        n->dpp = dispatch_create();
        if (n->dpp == NULL) { perror("vsimd: dispatch_create"); return 1; }
        iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &n->cf, _RESMGR_IO_NFUNCS, &n->io);
        n->io.read = io_read;
        n->io.write = io_write;
        n->io.devctl = io_devctl;
        n->io.close_ocb = io_close_ocb;
        iofunc_attr_init(&n->attr, S_IFCHR | (i == N_TEL ? 0644 : 0660), NULL, NULL);
        if (i == N_CTL && ctl_gid >= 0) n->attr.gid = (gid_t)ctl_gid;   /* uid separation for the world gateway */
        resmgr_attr_t ra;
        memset(&ra, 0, sizeof ra);
        ra.nparts_max = 1;
        ra.msg_max_size = 2048;
        if (secpol_resmgr_attach(NULL, n->dpp, &ra, n->path, _FTYPE_ANY, 0, &n->cf, &n->io, &n->attr, NULL) == -1) {
            fprintf(stderr, "vsimd: attach %s: %s\n", n->path, strerror(errno));
            return 1;
        }
    }
    secpol_transition_type(NULL, NULL, 0); /* drop to vsim_run_t when a policy is in force */

    pthread_t th[N__COUNT + 1];
    for (int i = 0; i < N__COUNT; i++) pthread_create(&th[i], NULL, serve, &g_nodes[i]);
    pthread_create(&th[N__COUNT], NULL, tick_thread, &rate);
    printf("vsimd: ready rate=%uHz scenario=%s shm=%s pid=%d\n", rate, scenario, KX_TELEMETRY_SHM_NAME, getpid());
    pthread_join(th[N__COUNT], NULL);
    return 0;
}
