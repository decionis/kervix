/*
 * Spike S1/S2 server: two resource-manager paths on TWO dispatch channels,
 * attached with secpol_resmgr_attach() so the policy can type each channel
 * independently. Answers WHOAMI (S2: client type id via
 * ConnectClientInfoExtraArgs) and delivers a registered pulse (MsgRegisterEvent).
 */
#include <errno.h>
#include <pthread.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/neutrino.h>
#include <time.h>
#include <unistd.h>

#include "s1_common.h"

typedef struct {
    const char           *name;
    const char           *path;
    dispatch_t           *dpp;
    resmgr_connect_funcs_t cfuncs;
    resmgr_io_funcs_t     iofuncs;
    iofunc_attr_t         attr;
} node_t;

static node_t g_nodes[2] = {
    { .name = "open", .path = S1_PATH_OPEN },
    { .name = "priv", .path = S1_PATH_PRIV },
};

/* single pending subscription (spike only) */
static struct { int rcvid; struct sigevent ev; uint32_t delay_ms; int armed; } g_sub;
static pthread_mutex_t g_sub_lock = PTHREAD_MUTEX_INITIALIZER;

static void *deliver_thread(void *arg) {
    (void)arg;
    for (;;) {
        usleep(20000);
        pthread_mutex_lock(&g_sub_lock);
        if (g_sub.armed) {
            usleep(g_sub.delay_ms * 1000u);
            int rc = MsgDeliverEvent(g_sub.rcvid, &g_sub.ev);
            printf("s1_server: MsgDeliverEvent(rcvid=%d) -> %d%s%s\n", g_sub.rcvid, rc,
                   rc == -1 ? " errno=" : "", rc == -1 ? strerror(errno) : "");
            g_sub.armed = 0;
        }
        pthread_mutex_unlock(&g_sub_lock);
    }
    return NULL;
}

static int io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    int status = iofunc_devctl_default(ctp, msg, ocb);
    if (status != _RESMGR_DEFAULT) return status;

    node_t *node = NULL;
    for (int i = 0; i < 2; i++) {
        if (ocb->attr == &g_nodes[i].attr) node = &g_nodes[i];
    }
    void *data = _DEVCTL_DATA(msg->i);

    switch (msg->i.dcmd) {
    case S1_DCMD_WHOAMI: {
        s1_whoami_t w;
        memset(&w, 0, sizeof w);
        struct _client_info info;
        unsigned type_id = SECPOL_INVALID_TYPE;
        if (ConnectClientInfoExtraArgs(ctp->info.scoid, &info, 0, NULL, 0, &type_id) == -1) {
            return errno;
        }
        w.pid = info.pid;
        w.uid = info.cred.euid;
        /* S2: the kernel stamps the sender's type into every message's info */
        w.type_id = ctp->info.type_id;
        if (type_id != w.type_id) {
            printf("s1_server: note: ConnectClientInfoExtraArgs type_id=%u vs msg info type_id=%u\n",
                   type_id, w.type_id);
        }
        const char *tn = secpol_get_type_name(NULL, w.type_id);
        snprintf(w.type_name, sizeof w.type_name, "%s", tn ? tn : "(no policy/unknown)");
        snprintf(w.node, sizeof w.node, "%s", node ? node->name : "?");
        memcpy(data, &w, sizeof w);
        memset(&msg->o, 0, sizeof msg->o);
        msg->o.nbytes = sizeof w;
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o + sizeof w);
    }
    case S1_DCMD_SUBSCRIBE: {
        s1_subscribe_t s;
        memcpy(&s, data, sizeof s);
        pthread_mutex_lock(&g_sub_lock);
        g_sub.rcvid = ctp->rcvid;
        g_sub.ev = s.ev;
        g_sub.delay_ms = s.delay_ms > 2000 ? 2000 : s.delay_ms;
        g_sub.armed = 1;
        pthread_mutex_unlock(&g_sub_lock);
        memset(&msg->o, 0, sizeof msg->o);
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    default:
        return ENOSYS;
    }
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

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("s1_server: pid=%d my type=%u (%s)\n", getpid(), secpol_type_id(),
           secpol_get_type_name(NULL, secpol_type_id()) ?: "?");

    for (int i = 0; i < 2; i++) {
        node_t *n = &g_nodes[i];
        n->dpp = dispatch_create(); /* one channel per node => one channel type per node */
        if (n->dpp == NULL) { perror("dispatch_create"); return 1; }
        iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &n->cfuncs, _RESMGR_IO_NFUNCS, &n->iofuncs);
        n->iofuncs.devctl = io_devctl;
        iofunc_attr_init(&n->attr, S_IFCHR | 0666, NULL, NULL);
        resmgr_attr_t rattr;
        memset(&rattr, 0, sizeof rattr);
        rattr.nparts_max = 1;
        rattr.msg_max_size = 2048;
        bool perms_set = false;
        int id = secpol_resmgr_attach(NULL, n->dpp, &rattr, n->path, _FTYPE_ANY, 0, &n->cfuncs,
                                      &n->iofuncs, &n->attr, &perms_set);
        printf("s1_server: secpol_resmgr_attach(%s) -> %d%s%s perms_set=%d\n", n->path, id,
               id == -1 ? " errno=" : "", id == -1 ? strerror(errno) : "", perms_set);
        if (id == -1) return 1;
    }

    /* a path this type is NOT allowed to attach: proves allow_attach is enforced */
    {
        dispatch_t *d = dispatch_create();
        static resmgr_connect_funcs_t cf; static resmgr_io_funcs_t io; static iofunc_attr_t a;
        iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cf, _RESMGR_IO_NFUNCS, &io);
        iofunc_attr_init(&a, S_IFCHR | 0666, NULL, NULL);
        int id = secpol_resmgr_attach(NULL, d, NULL, "/dev/kxs1/forbidden", _FTYPE_ANY, 0, &cf, &io, &a, NULL);
        printf("s1_server: attach /dev/kxs1/forbidden (not in policy) -> %d%s%s\n", id,
               id == -1 ? " errno=" : "", id == -1 ? strerror(errno) : "");
    }

    int t = secpol_transition_type(NULL, NULL, 0);
    printf("s1_server: secpol_transition_type(run) -> %d%s%s; now type=%u (%s)\n", t,
           t == -1 ? " errno=" : "", t == -1 ? strerror(errno) : "", secpol_type_id(),
           secpol_get_type_name(NULL, secpol_type_id()) ?: "?");

    pthread_t th[3];
    pthread_create(&th[0], NULL, serve, &g_nodes[0]);
    pthread_create(&th[1], NULL, serve, &g_nodes[1]);
    pthread_create(&th[2], NULL, deliver_thread, NULL);
    printf("s1_server: ready\n");
    pthread_join(th[0], NULL);
    return 0;
}
