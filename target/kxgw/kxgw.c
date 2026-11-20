/*
 * kxgw: the network gateway between the host domain (AI agent, HMI, dashboard)
 * and the QNX safety domain. One process per role, each under its own secpol
 * type, uid and priority (started at boot from post_start.custom):
 *
 *   role      port  type        uid  prio  may reach (secpol)
 *   agent     7301  agentgw_t   400  10    /dev/kervix/intent (propose, await), /dev/sdv/actuators (execute with a grant)
 *   hmi       7302  hmigw_t     401  30    /dev/kervix/escalations (list, subscribe, resolve)
 *   observer  7303  obsgw_t     402   5    /dev/kervix/stats only (read-only: it cannot propose)
 *   world     7304  worldgw_t     0   5    /dev/sdv/sim/ctl only (the demo's physical world; not a vehicle interface)
 *
 * The gateway holds NO authority. It converts bounded JSON lines (wire.h) to
 * the fixed ABI structs and back; kervixd decides, sdv_actuatord actuates.
 * Grants never leave the vehicle: the host sees a grant_id, the gateway keeps
 * the MAC'd grant and presents it on "execute". It forwards every execute to
 * the actuator, so a replayed or expired grant is refused AND recorded by the
 * authority, not filtered here.
 *
 * Every request is answered by one or more lines with the request's "id"; the
 * last one has "done":true. HMI connections also receive "escalations" pushes
 * (kervixd's doorbell pulse, no polling); observer connections receive a
 * telemetry stream (default 10 Hz) and stats (1 Hz).
 *
 * usage: kxgw --role agent|hmi|observer|world [-p port] [-c max_clients] [-v]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <secpol/secpol.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "kervix/cose.h"
#include "kervix/kervix_abi.h"
#include "kervix/policy.h"
#include "kervix/seqlock.h"
#include "kervix/vsim_abi.h"
#include "wire.h"

enum { ROLE_AGENT = 0, ROLE_HMI, ROLE_OBSERVER, ROLE_WORLD, ROLE__COUNT };
static const char *const ROLE_NAMES[ROLE__COUNT] = { "agent", "hmi", "observer", "world" };
static const int ROLE_PORTS[ROLE__COUNT] = { 7301, 7302, 7303, 7304 };
static const int ROLE_MAX_CLIENTS[ROLE__COUNT] = { 8, 3, 4, 2 };   /* kervixd serves 4 HMI subscribers */
/* which ops each role may use (bit per kxw_op_t) */
#define OPB(o) (1u << (o))
static const uint32_t ROLE_OPS[ROLE__COUNT] = {
    OPB(KXW_OP_HELLO) | OPB(KXW_OP_PROPOSE) | OPB(KXW_OP_EXECUTE) | OPB(KXW_OP_STATE) | OPB(KXW_OP_STATS),
    OPB(KXW_OP_HELLO) | OPB(KXW_OP_ESCALATIONS) | OPB(KXW_OP_RESOLVE) | OPB(KXW_OP_STATE) | OPB(KXW_OP_STATS),
    OPB(KXW_OP_HELLO) | OPB(KXW_OP_SUBSCRIBE) | OPB(KXW_OP_STATE) | OPB(KXW_OP_STATS) |
        OPB(KXW_OP_LEDGER_INFO) | OPB(KXW_OP_LEDGER) | OPB(KXW_OP_POLICY),
    OPB(KXW_OP_HELLO) | OPB(KXW_OP_SIM) | OPB(KXW_OP_STATE),
};

#define OUT_MAX   16384u   /* one response line (an escalation list of 16 intents fits) */
#define N_GRANTS  64u
#define PULSE_ESC  (_PULSE_CODE_MINAVAIL + 1)
#define PULSE_QUIT (_PULSE_CODE_MINAVAIL + 2)

static struct {
    int         role;
    int         port, max_clients, verbose;
    atomic_int  clients;
    char        type_name[48];
    int         prio;
    const kx_telemetry_shm_t *shm;
    pthread_mutex_t shm_lock;
    /* agent: grants issued to THIS process (proposer binding is per process) */
    pthread_mutex_t g_lock;
    struct { uint8_t used; kx_grant_t g; kx_intent_t cmd; } grants[N_GRANTS];
    unsigned    g_next;
} G = { .shm_lock = PTHREAD_MUTEX_INITIALIZER, .g_lock = PTHREAD_MUTEX_INITIALIZER };

typedef struct {
    int             fd;
    pthread_mutex_t wlock;
    int             dead;
} conn_t;

static uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static int64_t realtime_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---------------------------------------------------------------- output */

static void send_raw(conn_t *c, const char *buf, size_t n) {
    pthread_mutex_lock(&c->wlock);
    while (!c->dead && n > 0) {
        ssize_t w = send(c->fd, buf, n, 0);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { c->dead = 1; break; }
        buf += w;
        n -= (size_t)w;
    }
    pthread_mutex_unlock(&c->wlock);
}

typedef struct { kx_jw_t w; char buf[OUT_MAX]; } out_t;

static void begin(out_t *o, const char *kind, const kxw_req_t *rq) {
    kx_jw_init(&o->w, o->buf, sizeof o->buf - 1);
    kx_jw_obj_begin(&o->w);
    kx_jw_key(&o->w, "kind"); kx_jw_str(&o->w, kind);
    if (rq && rq->id[0]) { kx_jw_key(&o->w, "id"); kx_jw_str(&o->w, rq->id); }
}
static void finish(conn_t *c, out_t *o, int done) {
    kx_jw_key(&o->w, "done"); kx_jw_bool(&o->w, done);
    kx_jw_obj_end(&o->w);
    if (!kx_jw_ok(&o->w)) {
        static const char e[] = "{\"kind\":\"error\",\"error\":\"internal: response did not fit\",\"done\":true}\n";
        send_raw(c, e, sizeof e - 1);
        return;
    }
    o->buf[o->w.len] = '\n';
    send_raw(c, o->buf, o->w.len + 1);
}
static void reply_error(conn_t *c, const kxw_req_t *rq, const char *msg) {
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "error", rq);
    kx_jw_key(&o->w, "error"); kx_jw_str(&o->w, msg);
    finish(c, o, 1);
    free(o);
}

/* ------------------------------------------------------------ telemetry */

static int read_telemetry(kx_telemetry_t *t) {
    pthread_mutex_lock(&G.shm_lock);
    if (G.shm == NULL) {
        int fd = shm_open(KX_TELEMETRY_SHM_NAME, O_RDONLY, 0);
        if (fd != -1) {
            void *p = mmap(NULL, sizeof(kx_telemetry_shm_t), PROT_READ, MAP_SHARED, fd, 0); /* read-only */
            close(fd);
            if (p != MAP_FAILED) G.shm = p;
        }
    }
    const kx_telemetry_shm_t *shm = G.shm;
    pthread_mutex_unlock(&G.shm_lock);
    memset(t, 0, sizeof *t);
    return shm ? kx_seqlock_read(shm, t, 64) : -1;
}

static void emit_state(out_t *o) {
    kx_telemetry_t t;
    if (read_telemetry(&t) != 0) {
        kx_jw_key(&o->w, "available"); kx_jw_bool(&o->w, 0);
        return;
    }
    uint64_t now = mono_ns();
    kx_jw_key(&o->w, "available"); kx_jw_bool(&o->w, 1);
    kx_jw_key(&o->w, "age_us"); kx_jw_int(&o->w, now > t.mono_ns ? (int64_t)((now - t.mono_ns) / 1000u) : 0);
    kx_jw_key(&o->w, "plausible"); kx_jw_bool(&o->w, kx_telemetry_plausible(&t));
    kxw_emit_telemetry(&o->w, "telemetry", &t);
}

static ssize_t read_node(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return -1;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n >= 0) buf[n] = '\0';
    return n;
}

static void op_state(conn_t *c, const kxw_req_t *rq) {
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "state", rq);
    emit_state(o);
    finish(c, o, 1);
    free(o);
}

static void op_stats(conn_t *c, const kxw_req_t *rq) {
    char text[4096];
    ssize_t n = read_node(KX_PATH_STATS, text, sizeof text);
    if (n < 0) { reply_error(c, rq, "authority unavailable (is kervixd running?)"); return; }
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "stats", rq);
    kxw_emit_text(&o->w, "text", text, (size_t)n);
    finish(c, o, 1);
    free(o);
}

/* ---------------------------------------------------------------- agent */

static int random_uuid(uint8_t u[16]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) return -1;
    ssize_t r = read(fd, u, 16);
    close(fd);
    if (r != 16) return -1;
    u[6] = (uint8_t)((u[6] & 0x0f) | 0x40);
    u[8] = (uint8_t)((u[8] & 0x3f) | 0x80);
    return 0;
}

static void grant_put(const kx_grant_t *g, const kx_intent_t *cmd) {
    pthread_mutex_lock(&G.g_lock);
    unsigned i = G.g_next++ % N_GRANTS;               /* oldest is evicted: it expired long ago (TTL ~ 500 ms) */
    G.grants[i].used = 1;
    G.grants[i].g = *g;
    G.grants[i].cmd = *cmd;
    pthread_mutex_unlock(&G.g_lock);
}
static int grant_get(const uint8_t id[16], kx_grant_t *g, kx_intent_t *cmd) {
    int found = 0;
    pthread_mutex_lock(&G.g_lock);
    for (unsigned i = 0; i < N_GRANTS && !found; i++)
        if (G.grants[i].used && memcmp(G.grants[i].g.grant_id, id, 16) == 0) {
            *g = G.grants[i].g;
            *cmd = G.grants[i].cmd;
            found = 1;
        }
    pthread_mutex_unlock(&G.g_lock);
    return found;
}

static uint16_t execute_grant(const kx_grant_t *g, const kx_intent_t *cmd) {
    int fd = open(KX_PATH_ACTUATORS, O_RDWR);
    if (fd == -1) return KX_R_AUTHORITY_UNAVAILABLE;
    kx_execute_req_t rq;
    memset(&rq, 0, sizeof rq);
    rq.grant = *g;
    rq.command = *cmd;
    int ret = -1;
    int rc = devctl(fd, KX_DCMD_EXECUTE, &rq, sizeof rq, &ret);
    close(fd);
    return rc == EOK ? (uint16_t)ret : KX_R_AUTHORITY_UNAVAILABLE;
}

static void send_execution(conn_t *c, const kxw_req_t *rq, const uint8_t grant_id[16], uint16_t r) {
    const kx_reason_spec_t *rs = kx_catalog_reason(r);
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "execution", rq);
    kx_jw_key(&o->w, "result"); kx_jw_str(&o->w, r == KX_R_OK ? "EXECUTED" : "REFUSED");
    kx_jw_key(&o->w, "reason"); kx_jw_str(&o->w, rs ? rs->name : "?");
    kx_jw_key(&o->w, "reason_text"); kx_jw_str(&o->w, rs ? rs->text : "");
    kxw_emit_hex(&o->w, "grant_id", "", grant_id, 16);
    finish(c, o, 1);
    free(o);
}

static void send_decision(conn_t *c, const kxw_req_t *rq, const char *kind, const kx_decision_t *d,
                          const kx_intent_t *in, uint64_t rtt_ns, int done) {
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, kind, rq);
    kxw_emit_decision(&o->w, d);
    kxw_emit_intent(&o->w, "intent", in);
    kx_jw_key(&o->w, "rtt_us"); kx_jw_int(&o->w, (int64_t)(rtt_ns / 1000u));
    finish(c, o, done);
    free(o);
}

static void op_propose(conn_t *c, const kxw_req_t *rq) {
    kx_intent_t in;
    const char *err = NULL;
    if (kxw_to_intent(rq, &in, &err) != 0) { reply_error(c, rq, err); return; }
    if (in.actor_id[0] == '\0') snprintf(in.actor_id, sizeof in.actor_id, "agent:remote");
    if (!rq->has_intent_id && random_uuid(in.intent_id) != 0) { reply_error(c, rq, "no entropy for an intent id"); return; }

    int fd = open(KX_PATH_INTENT, O_RDWR);
    if (fd == -1) { reply_error(c, rq, "authority unavailable (AUTHORITY_UNAVAILABLE): actuation is locked"); return; }
    union { kx_intent_t in; kx_decision_t d; } u;
    memset(&u, 0, sizeof u);
    u.in = in;
    uint64_t t0 = mono_ns();
    int rc = devctl(fd, KX_DCMD_PROPOSE, &u, sizeof u.d, NULL);
    uint64_t rtt = mono_ns() - t0;
    if (rc != EOK) { close(fd); reply_error(c, rq, strerror(rc)); return; }
    kx_decision_t d = u.d;
    int awaiting = d.verdict == KX_VERDICT_ESCALATE && rq->await_esc;
    int executing = d.verdict == KX_VERDICT_ALLOW && rq->exec;
    if (d.verdict == KX_VERDICT_ALLOW) grant_put(&d.grant, &in);
    send_decision(c, rq, "decision", &d, &in, rtt, !(awaiting || executing));
    if (G.verbose) printf("kxgw[agent] %s %s -> %s\n", rq->action, in.actor_id, kxw_verdict_name(d.verdict));

    if (awaiting) {
        union { kx_await_req_t aw; kx_decision_t d; } w;
        memset(&w, 0, sizeof w);
        w.aw.escalation_id = d.escalation_id;
        t0 = mono_ns();
        rc = devctl(fd, KX_DCMD_AWAIT, &w, sizeof w.d, NULL);   /* REPLY-blocked in the kernel until the driver decides */
        if (rc != EOK) { close(fd); reply_error(c, rq, rc == EINTR ? "await interrupted" : strerror(rc)); return; }
        d = w.d;
        executing = d.verdict == KX_VERDICT_ALLOW && rq->exec;
        if (d.verdict == KX_VERDICT_ALLOW) grant_put(&d.grant, &in);
        send_decision(c, rq, "resolution", &d, &in, mono_ns() - t0, !executing);
    }
    close(fd);
    if (executing) send_execution(c, rq, d.grant.grant_id, execute_grant(&d.grant, &in));
}

static void op_execute(conn_t *c, const kxw_req_t *rq) {
    kx_grant_t g;
    kx_intent_t cmd;
    if (!grant_get(rq->grant_id, &g, &cmd)) {
        reply_error(c, rq, "unknown grant_id: grants never leave the vehicle; present one this gateway was issued");
        return;
    }
    send_execution(c, rq, rq->grant_id, execute_grant(&g, &cmd));   /* replays are refused by the authority */
}

/* ------------------------------------------------------------------ hmi */

static void emit_escalations(out_t *o, int *ok) {
    kx_esc_list_t l;
    memset(&l, 0, sizeof l);
    int fd = open(KX_PATH_ESCALATIONS, O_RDWR);
    int rc = fd == -1 ? errno : devctl(fd, KX_DCMD_ESC_LIST, &l, sizeof l, NULL);
    if (fd != -1) close(fd);
    *ok = rc == EOK;
    kx_jw_key(&o->w, "available"); kx_jw_bool(&o->w, rc == EOK);
    kx_jw_key(&o->w, "items");
    kx_jw_arr_begin(&o->w);
    for (uint32_t i = 0; rc == EOK && i < l.n && i < KX_ESC_LIST_MAX; i++) {
        const kx_esc_info_t *e = &l.e[i];
        const kx_reason_spec_t *rs = kx_catalog_reason(e->reason);
        char rule[sizeof e->rule_id + 1];
        memcpy(rule, e->rule_id, sizeof e->rule_id);
        rule[sizeof e->rule_id] = '\0';
        kx_jw_obj_begin(&o->w);
        kx_jw_key(&o->w, "escalation_id"); kx_jw_int(&o->w, e->escalation_id);
        kx_jw_key(&o->w, "reason"); kx_jw_str(&o->w, rs ? rs->name : "?");
        kx_jw_key(&o->w, "reason_text"); kx_jw_str(&o->w, rs ? rs->text : "");
        kx_jw_key(&o->w, "rule"); kx_jw_str(&o->w, rule);
        kx_jw_key(&o->w, "remaining_ms"); kx_jw_int(&o->w, e->remaining_ms);
        kx_jw_key(&o->w, "proposer_pid"); kx_jw_int(&o->w, e->proposer_pid);
        kxw_emit_intent(&o->w, "intent", &e->intent);
        kx_jw_obj_end(&o->w);
    }
    kx_jw_arr_end(&o->w);
}

static int push_escalations(conn_t *c, const kxw_req_t *rq) {
    out_t *o = malloc(sizeof *o);
    if (!o) return 0;
    int ok = 0;
    begin(o, "escalations", rq);
    emit_escalations(o, &ok);
    finish(c, o, 1);
    free(o);
    return ok;
}

static void op_resolve(conn_t *c, const kxw_req_t *rq) {
    kx_resolve_req_t rr;
    memset(&rr, 0, sizeof rr);
    rr.escalation_id = rq->escalation_id;
    rr.approve = rq->approve;
    snprintf(rr.approver, sizeof rr.approver, "%s", rq->approver[0] ? rq->approver : "hmi:driver");
    int fd = open(KX_PATH_ESCALATIONS, O_RDWR);
    int rc = fd == -1 ? errno : devctl(fd, KX_DCMD_ESC_RESOLVE, &rr, sizeof rr, NULL);
    if (fd != -1) close(fd);
    if (rc != EOK) {
        reply_error(c, rq, rc == ENOENT ? "no such escalation" : rc == EALREADY ? "already resolved"
                         : fd == -1 ? "authority unavailable" : strerror(rc));
        return;
    }
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "resolved", rq);
    kx_jw_key(&o->w, "escalation_id"); kx_jw_int(&o->w, rr.escalation_id);
    kx_jw_key(&o->w, "approve"); kx_jw_bool(&o->w, rr.approve);
    kx_jw_key(&o->w, "approver"); kx_jw_str(&o->w, rr.approver);
    finish(c, o, 1);
    free(o);
}

/* One per HMI connection: kervixd rings a registered pulse whenever the
 * escalation queue changes; push the new list. Resubscribes if the authority
 * restarted (checked every 2 s while idle). */
typedef struct { conn_t *c; int chid, coid; } notifier_t;

static int esc_subscribe(notifier_t *n) {
    int fd = open(KX_PATH_ESCALATIONS, O_RDWR);
    if (fd == -1) return -1;
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, n->coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_ESC, 0);
    if (MsgRegisterEvent(&ev, fd) == -1 || devctl(fd, KX_DCMD_ESC_SUBSCRIBE, &ev, sizeof ev, NULL) != EOK) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *notifier(void *arg) {
    notifier_t *n = arg;
    int fd = esc_subscribe(n);
    push_escalations(n->c, NULL);
    while (!n->c->dead) {
        struct _pulse p;
        uint64_t to = 2000000000ull;
        TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &to, NULL);
        int r = MsgReceivePulse(n->chid, &p, sizeof p, NULL);
        if (r == 0 && p.code == PULSE_QUIT) break;
        if (r == 0 && p.code == PULSE_ESC) { push_escalations(n->c, NULL); continue; }
        /* idle: is the subscription still alive (authority restarted)? */
        kx_esc_list_t probe;
        if (fd == -1 || devctl(fd, KX_DCMD_ESC_LIST, &probe, sizeof probe, NULL) != EOK) {
            if (fd != -1) close(fd);
            fd = esc_subscribe(n);
            if (fd != -1) push_escalations(n->c, NULL);
        }
    }
    if (fd != -1) close(fd);
    return NULL;
}

/* ------------------------------------------------------------- world */

static void op_sim(conn_t *c, const kxw_req_t *rq) {
    int fd = open(KX_VSIM_PATH_CTL, O_RDWR);
    if (fd == -1) { reply_error(c, rq, "simulator unavailable"); return; }
    ssize_t w = write(fd, rq->cmd, strlen(rq->cmd));
    close(fd);
    char reply[512];
    ssize_t r = read_node(KX_VSIM_PATH_CTL, reply, sizeof reply);  /* fresh open: reply from offset 0 */
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "sim", rq);
    kx_jw_key(&o->w, "ok"); kx_jw_bool(&o->w, w >= 0);
    kxw_emit_text(&o->w, "reply", reply, r > 0 ? (size_t)r : 0);
    finish(c, o, 1);
    free(o);
}

/* ------------------------------------------------------------- ledger (observer) */

static void op_ledger_info(conn_t *c, const kxw_req_t *rq) {
    static kx_dossier_info_t di;
    int fd = open(KX_PATH_DOSSIER, O_RDONLY);
    int rc = fd == -1 ? errno : devctl(fd, KX_DCMD_DOSSIER_INFO, &di, sizeof di, NULL);
    if (fd != -1) close(fd);
    if (rc != EOK) { reply_error(c, rq, "authority unavailable (is kervixd running?)"); return; }
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "ledger_info", rq);
    kx_jw_key(&o->w, "records"); kx_jw_int(&o->w, (int64_t)di.records);
    kx_jw_key(&o->w, "first_seq"); kx_jw_int(&o->w, (int64_t)di.first_seq);
    kx_jw_key(&o->w, "last_seq"); kx_jw_int(&o->w, (int64_t)di.last_seq);
    di.jwk[sizeof di.jwk - 1] = '\0';
    kx_jw_key(&o->w, "jwk"); kx_jw_strn(&o->w, di.jwk, strcspn(di.jwk, "\n"));
    kx_jw_key(&o->w, "policies");
    kx_jw_arr_begin(&o->w);
    for (uint32_t i = 0; i < di.n_policies && i < KX_DOSSIER_POLICIES; i++) kx_jw_str(&o->w, di.policies[i]);
    kx_jw_arr_end(&o->w);
    finish(c, o, 1);
    free(o);
}

/* stream records [from_seq, from_seq + max) as one line each, then ledger_end */
static void op_ledger(conn_t *c, const kxw_req_t *rq) {
    int fd = open(KX_PATH_DOSSIER, O_RDONLY);
    if (fd == -1) { reply_error(c, rq, "authority unavailable (is kervixd running?)"); return; }
    kx_dossier_rec_t *rec = malloc(sizeof *rec);
    out_t *o = malloc(sizeof *o);
    uint64_t seq = rq->from_seq > 0 ? (uint64_t)rq->from_seq : 1, end = seq + (rq->max ? rq->max : 100);
    uint64_t sent = 0;
    while (rec && o && seq < end && !c->dead) {
        memset(rec, 0, offsetof(kx_dossier_rec_t, capsule));
        memcpy(rec, &seq, sizeof seq);
        if (devctl(fd, KX_DCMD_DOSSIER_GET, rec, sizeof *rec, NULL) != EOK) break;   /* past the end */
        char env[256];
        size_t en = kx_base64url(rec->envelope, sizeof rec->envelope, env);
        begin(o, "record", rq);
        kx_jw_key(&o->w, "seq"); kx_jw_int(&o->w, (int64_t)rec->seq);
        kxw_emit_hex(&o->w, "capsule_id", "", rec->capsule_id, 32);
        kx_jw_key(&o->w, "capsule"); kx_jw_strn(&o->w, rec->capsule, rec->capsule_len);
        kx_jw_key(&o->w, "envelope"); kx_jw_strn(&o->w, env, en);
        finish(c, o, 0);
        seq++;
        sent++;
    }
    close(fd);
    if (o) {
        begin(o, "ledger_end", rq);
        kx_jw_key(&o->w, "sent"); kx_jw_int(&o->w, (int64_t)sent);
        kx_jw_key(&o->w, "next_seq"); kx_jw_int(&o->w, (int64_t)seq);
        finish(c, o, 1);
    }
    free(rec);
    free(o);
}

/* stream an archived signed policy bundle in base64url chunks */
static void op_policy(conn_t *c, const kxw_req_t *rq) {
    int fd = open(KX_PATH_DOSSIER, O_RDONLY);
    if (fd == -1) { reply_error(c, rq, "authority unavailable (is kervixd running?)"); return; }
    kx_policy_chunk_t *ch = malloc(sizeof *ch);
    out_t *o = malloc(sizeof *o);
    char *b64 = malloc(4 * sizeof ch->data / 3 + 8);
    uint32_t off = 0, total = 0;
    int ok = ch && o && b64;
    while (ok && !c->dead) {
        memset(ch, 0, offsetof(kx_policy_chunk_t, data));
        memcpy(ch->name, rq->name, 16);
        ch->offset = off;
        if (devctl(fd, KX_DCMD_POLICY_CHUNK, ch, sizeof *ch, NULL) != EOK) { ok = 0; break; }
        total = ch->total;
        if (ch->n == 0) break;
        size_t bn = kx_base64url(ch->data, ch->n, b64);
        begin(o, "policy_chunk", rq);
        kx_jw_key(&o->w, "offset"); kx_jw_int(&o->w, off);
        kx_jw_key(&o->w, "data"); kx_jw_strn(&o->w, b64, bn);
        finish(c, o, 0);
        off += ch->n;
        if (off >= total) break;
    }
    close(fd);
    if (!ok) reply_error(c, rq, "no such policy bundle");
    else {
        begin(o, "policy_end", rq);
        kx_jw_key(&o->w, "name"); kx_jw_str(&o->w, rq->name);
        kx_jw_key(&o->w, "total"); kx_jw_int(&o->w, total);
        finish(c, o, 1);
    }
    free(ch);
    free(o);
    free(b64);
}

/* ------------------------------------------------------------- dispatch */

static void op_hello(conn_t *c, const kxw_req_t *rq) {
    out_t *o = malloc(sizeof *o);
    if (!o) return;
    begin(o, "hello", rq);
    kx_jw_key(&o->w, "role"); kx_jw_str(&o->w, ROLE_NAMES[G.role]);
    kx_jw_key(&o->w, "pid"); kx_jw_int(&o->w, getpid());
    kx_jw_key(&o->w, "uid"); kx_jw_int(&o->w, (int64_t)getuid());
    kx_jw_key(&o->w, "type"); kx_jw_str(&o->w, G.type_name);
    kx_jw_key(&o->w, "prio"); kx_jw_int(&o->w, G.prio);
    kx_jw_key(&o->w, "abi"); kx_jw_int(&o->w, KX_ABI_VERSION);
    kx_jw_key(&o->w, "catalog_sha256"); kx_jw_str(&o->w, KX_CATALOG_SHA256);
    kx_jw_key(&o->w, "ops");
    kx_jw_arr_begin(&o->w);
    for (int op = 1; op < KXW_OP__COUNT; op++) if (ROLE_OPS[G.role] & OPB(op)) kx_jw_str(&o->w, kxw_op_name((uint8_t)op));
    kx_jw_arr_end(&o->w);
    finish(c, o, 1);
    free(o);
}

static void handle(conn_t *c, const char *line, size_t n, uint32_t *obs_hz) {
    kxw_req_t rq;
    const char *err = NULL;
    if (kxw_parse(line, n, &rq, &err) != 0) { reply_error(c, NULL, err); return; }
    if (!(ROLE_OPS[G.role] & OPB(rq.op))) {
        char m[96];
        snprintf(m, sizeof m, "op '%s' is not available on the %s gateway", kxw_op_name(rq.op), ROLE_NAMES[G.role]);
        reply_error(c, &rq, m);
        return;
    }
    switch (rq.op) {
    case KXW_OP_HELLO: op_hello(c, &rq); break;
    case KXW_OP_PROPOSE: op_propose(c, &rq); break;
    case KXW_OP_EXECUTE: op_execute(c, &rq); break;
    case KXW_OP_STATE: op_state(c, &rq); break;
    case KXW_OP_STATS: op_stats(c, &rq); break;
    case KXW_OP_ESCALATIONS: push_escalations(c, &rq); break;
    case KXW_OP_RESOLVE: op_resolve(c, &rq); break;
    case KXW_OP_SIM: op_sim(c, &rq); break;
    case KXW_OP_LEDGER_INFO: op_ledger_info(c, &rq); break;
    case KXW_OP_LEDGER: op_ledger(c, &rq); break;
    case KXW_OP_POLICY: op_policy(c, &rq); break;
    case KXW_OP_SUBSCRIBE: {
        *obs_hz = rq.hz < 1 ? 1 : rq.hz > 50 ? 50 : rq.hz;
        out_t *o = malloc(sizeof *o);
        if (!o) return;
        begin(o, "subscribed", &rq);
        kx_jw_key(&o->w, "hz"); kx_jw_int(&o->w, *obs_hz);
        finish(c, o, 1);
        free(o);
        break;
    }
    default: reply_error(c, &rq, "unsupported op"); break;
    }
}

/* Observer: push telemetry at hz and stats at 1 Hz between requests. */
static void observer_tick(conn_t *c, uint64_t *next_tel, uint64_t *next_stats, uint32_t hz) {
    uint64_t now = mono_ns();
    if (now >= *next_tel) {
        out_t *o = malloc(sizeof *o);
        if (o) {
            begin(o, "telemetry", NULL);
            kx_jw_key(&o->w, "t_ms"); kx_jw_int(&o->w, realtime_ms());
            emit_state(o);
            finish(c, o, 1);
            free(o);
        }
        *next_tel = now + 1000000000ull / hz;
    }
    if (now >= *next_stats) {
        op_stats(c, NULL);
        *next_stats = now + 1000000000ull;
    }
}

static void *client(void *arg) {
    conn_t *c = arg;
    notifier_t nt = { c, -1, -1 };
    pthread_t nth;
    int have_notifier = 0;
    if (G.role == ROLE_HMI) {
        nt.chid = ChannelCreate(_NTO_CHF_PRIVATE);
        nt.coid = nt.chid == -1 ? -1 : ConnectAttach(0, 0, nt.chid, _NTO_SIDE_CHANNEL, 0);
        if (nt.coid != -1 && pthread_create(&nth, NULL, notifier, &nt) == 0) have_notifier = 1;
        else reply_error(c, NULL, "cannot subscribe to escalations");
    }
    char buf[KXW_LINE_MAX + 1];
    size_t have = 0;
    int overflow = 0;
    uint32_t hz = 10;
    uint64_t next_tel = 0, next_stats = 0;
    while (!c->dead) {
        if (G.role == ROLE_OBSERVER) {
            observer_tick(c, &next_tel, &next_stats, hz);
            uint64_t now = mono_ns(), wake = next_tel < next_stats ? next_tel : next_stats;
            uint64_t us = wake > now ? (wake - now) / 1000u : 0;
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(c->fd, &rf);
            struct timeval tv = { (time_t)(us / 1000000u), (suseconds_t)(us % 1000000u) };
            int s = select(c->fd + 1, &rf, NULL, NULL, &tv);
            if (s < 0 && errno != EINTR) break;
            if (s <= 0) continue;
        }
        ssize_t r = recv(c->fd, buf + have, sizeof buf - 1 - have, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        have += (size_t)r;
        size_t start = 0;
        for (size_t i = 0; i < have; i++) {
            if (buf[i] != '\n') continue;
            if (!overflow && i > start) handle(c, buf + start, i - start, &hz);
            overflow = 0;
            start = i + 1;
        }
        memmove(buf, buf + start, have - start);
        have -= start;
        if (have == sizeof buf - 1) {                   /* a line longer than the bound: refuse and drop it */
            if (!overflow) reply_error(c, NULL, "line too long (max 4096 bytes)");
            overflow = 1;
            have = 0;
        }
    }
    c->dead = 1;
    if (have_notifier) {
        MsgSendPulse(nt.coid, -1, PULSE_QUIT, 0);
        pthread_join(nth, NULL);
    }
    if (nt.coid != -1) ConnectDetach(nt.coid);
    if (nt.chid != -1) ChannelDestroy(nt.chid);
    close(c->fd);
    pthread_mutex_destroy(&c->wlock);
    free(c);
    atomic_fetch_sub(&G.clients, 1);
    return NULL;
}

int main(int argc, char **argv) {
    G.role = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--role") && i + 1 < argc) {
            i++;
            for (int r = 0; r < ROLE__COUNT; r++) if (!strcmp(argv[i], ROLE_NAMES[r])) G.role = r;
        } else if (!strcmp(argv[i], "-p") && i + 1 < argc) G.port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) G.max_clients = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-v")) G.verbose = 1;
        else { G.role = -1; break; }
    }
    if (G.role < 0) {
        fprintf(stderr, "usage: kxgw --role agent|hmi|observer|world [-p port] [-c max_clients] [-v]\n");
        return 2;
    }
    if (G.port <= 0) G.port = ROLE_PORTS[G.role];
    if (G.max_clients <= 0) G.max_clients = ROLE_MAX_CLIENTS[G.role];
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);

    struct sched_param sp;
    int policy;
    pthread_getschedparam(pthread_self(), &policy, &sp);
    G.prio = sp.sched_priority;
    /* the name lookup needs read access to the policy, which a non-root process
     * lacks on a --secpol=secure image: fall back to the kernel's type id */
    const char *tn = secpol_get_type_name(NULL, secpol_type_id());
    if (tn && tn[0]) snprintf(G.type_name, sizeof G.type_name, "%s", tn);
    else snprintf(G.type_name, sizeof G.type_name, "type_id:%d", (int)secpol_type_id());

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)G.port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (s < 0 || setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 8) != 0) {
        fprintf(stderr, "kxgw[%s]: cannot listen on :%d: %s\n", ROLE_NAMES[G.role], G.port, strerror(errno));
        return 1;
    }
    printf("kxgw[%s]: listening on :%d pid=%d uid=%d prio=%d type=%s max_clients=%d\n", ROLE_NAMES[G.role], G.port,
           getpid(), (int)getuid(), G.prio, G.type_name[0] ? G.type_name : "(none)", G.max_clients);

    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 256 * 1024);
    for (;;) {
        int fd = accept(s, NULL, NULL);
        if (fd < 0) { if (errno != EINTR) usleep(10000); continue; }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (atomic_fetch_add(&G.clients, 1) >= G.max_clients) {
            atomic_fetch_sub(&G.clients, 1);
            static const char busy[] = "{\"kind\":\"error\",\"error\":\"gateway busy (too many clients)\",\"done\":true}\n";
            (void)send(fd, busy, sizeof busy - 1, 0);
            close(fd);
            continue;
        }
        conn_t *c = calloc(1, sizeof *c);
        pthread_t th;
        if (c == NULL) { close(fd); atomic_fetch_sub(&G.clients, 1); continue; }
        c->fd = fd;
        pthread_mutex_init(&c->wlock, NULL);
        if (pthread_create(&th, &at, client, c) != 0) {
            close(fd);
            pthread_mutex_destroy(&c->wlock);
            free(c);
            atomic_fetch_sub(&G.clients, 1);
        }
    }
}
