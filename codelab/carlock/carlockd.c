/*
 * carlockd: a tiny QNX 8.0 resource manager with two paths, each on its OWN
 * dispatch channel, so a security policy (secpol) can give each channel its
 * own type and the kernel can decide who may connect to which.
 *
 *   /dev/carlock/status   CARLOCK_GET   read the lock state
 *   /dev/carlock/command  CARLOCK_SET   lock / unlock
 *
 * The daemon itself never checks who may unlock: the kernel already did,
 * when the client tried to connect. It only reports who called (the type the
 * kernel stamped on the message) so you can see it.
 */
#include <errno.h>
#include <pthread.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <unistd.h>

#include "carlock.h"

typedef struct {
    const char            *path;
    dispatch_t            *dpp;     /* one dispatch structure = one channel = one channel type */
    resmgr_connect_funcs_t cf;
    resmgr_io_funcs_t      io;
    iofunc_attr_t          attr;
} node_t;

static node_t nodes[2] = { { .path = CARLOCK_STATUS }, { .path = CARLOCK_COMMAND } };
static uint32_t locked = 1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    int st = iofunc_devctl_default(ctp, msg, ocb);
    if (st != _RESMGR_DEFAULT) return st;
    int on_command = ocb->attr == &nodes[1].attr;
    carlock_msg_t *m = _DEVCTL_DATA(msg->i);

    if (msg->i.dcmd == CARLOCK_SET && !on_command) return EPERM;   /* commands only on the command path */
    if (msg->i.dcmd != CARLOCK_GET && msg->i.dcmd != CARLOCK_SET) return ENOSYS;
    pthread_mutex_lock(&lock);
    if (msg->i.dcmd == CARLOCK_SET) {
        locked = m->locked ? 1 : 0;
        const char *who = secpol_get_type_name(NULL, ctp->info.type_id);
        printf("carlockd: %s by type %s\n", locked ? "LOCKED" : "UNLOCKED", who ? who : "(no policy)");
    }
    m->locked = locked;
    pthread_mutex_unlock(&lock);
    /* The kernel stamps the sender's secpol type into every message: no extra call needed. */
    m->caller_type = ctp->info.type_id;
    const char *name = secpol_get_type_name(NULL, m->caller_type);
    snprintf(m->caller_name, sizeof m->caller_name, "%s", name ? name : "(no policy)");
    memset(&msg->o, 0, sizeof msg->o);
    msg->o.nbytes = sizeof *m;
    return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o + sizeof *m);
}

static void *serve(void *arg) {
    node_t *n = arg;
    dispatch_context_t *ctp = dispatch_context_alloc(n->dpp);
    for (;;) if (dispatch_block(ctp) != NULL) dispatch_handler(ctp);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int i = 0; i < 2; i++) {
        node_t *n = &nodes[i];
        if ((n->dpp = dispatch_create()) == NULL) { perror("dispatch_create"); return 1; }
        iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &n->cf, _RESMGR_IO_NFUNCS, &n->io);
        n->io.devctl = io_devctl;
        iofunc_attr_init(&n->attr, S_IFCHR | 0666, NULL, NULL);
        /* secpol_resmgr_attach(): like resmgr_attach(), but the policy's
         * allow_attach rule decides whether we may attach this path AND which
         * type the channel gets. Without a policy it behaves like resmgr_attach(). */
        if (secpol_resmgr_attach(NULL, n->dpp, NULL, n->path, _FTYPE_ANY, 0, &n->cf, &n->io, &n->attr, NULL) == -1) {
            printf("carlockd: attach %s: %s\n", n->path, strerror(errno));
            return 1;
        }
    }
    /* Paths attached: we will never need that right again. Drop to the
     * "run" type the policy derives from ours (no-op without a policy). */
    secpol_transition_type(NULL, NULL, 0);
    const char *t = secpol_get_type_name(NULL, secpol_type_id());
    printf("carlockd: ready, pid %d, running as type %s\n", getpid(), t ? t : "(no policy)");

    pthread_t th;
    pthread_create(&th, NULL, serve, &nodes[0]);
    serve(&nodes[1]);
    return 0;
}
