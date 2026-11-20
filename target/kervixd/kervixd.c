/*
 * kervixd: the Kervix execution authority (QNX 8.0 resource manager).
 *
 * Channels (one dispatch_t each, so secpol can type them; spike S1):
 *   agent    /dev/kervix/intent  PROPOSE -> kx_decision_t (+ single-use grant on ALLOW)
 *   observer /dev/kervix/stats   text counters + PROPOSE latency histogram (read-only
 *            channel of its own: an observer can read it and still never propose)
 *   actuator /dev/kervix/redeem  REDEEM (grant -> OK | GRANT_*), EFFECT (outcome)
 *   hmi      /dev/kervix/escalations  LIST / SUBSCRIBE / RESOLVE (driver approvals)
 *   agent    AWAIT(escalation id): deferred reply until the driver resolves or it times out
 *
 * Every decision is computed by libkxcore's pure kx_eval() on a seqlock
 * snapshot of vsimd telemetry (mapped READ-ONLY). Caller identity comes from
 * the kernel-stamped message info (pid + secpol type), never from the payload.
 * Grant ids and the per-boot grant key come from qcrypto's DRBG; a restart
 * therefore invalidates every outstanding grant (fail-closed).
 *
 * Every lifecycle event is recorded as a signed AAC capsule by the ledger
 * writer (kxledger.c); "no audit, no action" feeds constitution K3.
 *
 * usage: kervixd [-V vehicle_id] [-T tenant_uuid] [-A max_telemetry_age_ms] [-D datadir]
 *                [-R ledger_queue] [-S slow_ms (test)] [-v]
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <qcrypto/qcrypto.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>
#include <time.h>
#include <unistd.h>

#include "kervix/grant.h"
#include "kervix/intent.h"
#include "kervix/kervix_abi.h"
#include "kervix/policy.h"
#include "kervix/seqlock.h"
#include "kxledger.h"

#define HIST_BUCKETS 20 /* log2 microseconds: [0,1) [1,2) [2,4) ... */

static struct {
    pthread_mutex_t     lock;           /* QNX mutex: priority inheritance */
    kx_policy_t         policy;
    kx_grant_table_t    grants;
    qcrypto_ctx_t      *rng;
    const kx_telemetry_shm_t *shm;
    char                vehicle_id[48];
    char                tenant_id[40];
    uint64_t            max_age_ns;
    uint32_t            next_escalation;
    int                 verbose;
    uint64_t            cps;            /* ClockCycles per second */
    uint64_t            boot_ns;
    /* stats */
    uint64_t            proposals, by_verdict[4], by_reason[256], redeem_ok, redeem_fail[256];
    uint64_t            effects_ok, effects_fail, reaped;
    uint64_t            esc_created, esc_approved, esc_denied, esc_expired, esc_reblocked;
    uint32_t            awaiting_effect;    /* redeemed grants whose EFFECT record is still due */
    uint64_t            hist[HIST_BUCKETS], lat_min_ns, lat_max_ns;
} K = { .lock = PTHREAD_MUTEX_INITIALIZER, .lat_min_ns = UINT64_MAX };

/* ---- escalations (pending human decisions) ---- */
enum { ESC_FREE = 0, ESC_PENDING, ESC_RESOLVED };
typedef struct {
    uint8_t       state;
    uint32_t      id;
    kx_intent_t   in;
    kx_client_t   proposer;
    uint8_t       intent_hash[32];
    int16_t       rule_index;
    uint16_t      reason;           /* why a human is needed */
    uint64_t      deadline_ns, forget_ns;
    int           waiter;           /* rcvid of a REPLY-blocked AWAIT, 0 = none */
    kx_decision_t outcome;          /* valid when RESOLVED */
} esc_t;
static esc_t g_esc[KX_MAX_ESCALATIONS];

typedef struct { int active; int rcvid; void *ocb; struct sigevent ev; } sub_t;
#define MAX_HMI_SUBS 4
static sub_t g_hmi_subs[MAX_HMI_SUBS];

typedef struct {
    const char            *path;
    int                    chan;        /* index into g_disp */
    resmgr_connect_funcs_t cf;
    resmgr_io_funcs_t      io;
    iofunc_attr_t          attr;
} node_t;
enum { CH_AGENT = 0, CH_ACT, CH_HMI, CH_OBS, CH__COUNT };
enum { N_INTENT = 0, N_STATS, N_REDEEM, N_ESC, N__COUNT };
static dispatch_t *g_disp[CH__COUNT];
static node_t g_nodes[N__COUNT] = {
    { .path = KX_PATH_INTENT, .chan = CH_AGENT },
    { .path = KX_PATH_STATS, .chan = CH_OBS },     /* read-only channel: observers can never propose */
    { .path = KX_PATH_REDEEM, .chan = CH_ACT },
    { .path = KX_PATH_ESCALATIONS, .chan = CH_HMI },
};

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
static const char *reason_name(uint16_t r) {
    const kx_reason_spec_t *s = kx_catalog_reason(r);
    return s ? s->name : "?";
}
/* Fill the common part of a capsule record. */
static void rec_init(kx_capsule_rec_t *r, uint8_t event, const kx_intent_t *in, kx_client_t who) {
    memset(r, 0, sizeof *r);
    r->event = event;
    r->rule_index = -1;
    r->timestamp_ms = realtime_ms();
    memcpy(r->policy_hash, K.policy.hash, 32);
    r->client_pid = who.pid;
    r->client_type = who.type_id;
    if (in) { r->has_intent = 1; r->intent = *in; }
}

/* Slots that must stay free for records still owed: one terminal record per
 * outstanding grant (effect, refusal or expiry) and per grant awaiting its effect. */
static uint32_t owed(void) { return K.grants.outstanding + K.awaiting_effect; }

static int rng_bytes(uint8_t *buf, size_t n) {
    return qcrypto_rng_bytes(K.rng, buf, n) == QCRYPTO_R_EOK ? 0 : -1;
}

/* Telemetry snapshot; on any problem return one that K1 will judge stale. */
static void telemetry(kx_telemetry_t *t) {
    memset(t, 0, sizeof *t);
    if (K.shm == NULL) {
        int fd = shm_open(KX_TELEMETRY_SHM_NAME, O_RDONLY, 0);
        if (fd != -1) {
            void *p = mmap(NULL, sizeof(kx_telemetry_shm_t), PROT_READ, MAP_SHARED, fd, 0);
            close(fd);
            if (p != MAP_FAILED) K.shm = p;
        }
    }
    if (K.shm == NULL || kx_seqlock_read(K.shm, t, 16) != 0) memset(t, 0, sizeof *t); /* mono_ns 0 => stale */
}

/* ------------------------------------------------------------ handlers */

static void record_latency(uint64_t ns) {
    uint64_t us = ns / 1000u;
    int b = 0;
    while (b < HIST_BUCKETS - 1 && us >= (1ull << b)) b++;
    K.hist[b]++;
    if (ns < K.lat_min_ns) K.lat_min_ns = ns;
    if (ns > K.lat_max_ns) K.lat_max_ns = ns;
}

static esc_t *esc_find(uint32_t id) {
    for (int i = 0; i < KX_MAX_ESCALATIONS; i++) if (g_esc[i].state != ESC_FREE && g_esc[i].id == id) return &g_esc[i];
    return NULL;
}

/* Doorbell to the driver's HMI. Called with K.lock held. */
static void ring_hmi(void) {
    for (int i = 0; i < MAX_HMI_SUBS; i++) {
        if (g_hmi_subs[i].active && MsgDeliverEvent(g_hmi_subs[i].rcvid, &g_hmi_subs[i].ev) == -1) g_hmi_subs[i].active = 0;
    }
}

/* Deferred reply to an AWAIT devctl. */
static void reply_decision(int rcvid, const kx_decision_t *d) {
    struct { struct _io_devctl_reply o; kx_decision_t d; } r;
    memset(&r, 0, sizeof r);
    r.o.nbytes = sizeof r.d;
    r.d = *d;
    MsgReply(rcvid, EOK, &r, sizeof r);
}

/* Resolve a pending escalation (K.lock held). approve: 1 approve, 0 deny, -1 timeout.
 * Approval never grants blindly: the policy is re-evaluated on live telemetry. */
static void esc_resolve(esc_t *e, int approve, const char *approver) {
    kx_decision_t *d = &e->outcome;
    memset(d, 0, sizeof *d);
    d->abi = KX_ABI_VERSION;
    d->escalation_id = e->id;
    d->rule_index = -1;
    memcpy(d->intent_hash, e->intent_hash, 32);
    memcpy(d->policy_hash, K.policy.hash, 32);
    uint64_t now = mono_ns();
    if (approve < 0) {
        d->verdict = KX_VERDICT_BLOCK; d->reason = KX_R_ESCALATION_TIMEOUT; K.esc_expired++;
    } else if (approve == 0) {
        d->verdict = KX_VERDICT_BLOCK; d->reason = KX_R_HUMAN_DENIED; K.esc_denied++;
    } else {
        kx_telemetry_t tel;
        telemetry(&tel);
        kx_eval_env_t env = { now, realtime_ms(), K.max_age_ns, (uint8_t)kxl_healthy() };
        kx_eval_result_t r;
        kx_eval(&K.policy, &e->in, &tel, &env, &r);
        if (kxl_free() < 2u + owed()) { r.verdict = KX_VERDICT_BLOCK; r.reason = KX_R_LEDGER_PRESSURE; r.gate = KX_GATE_K3_LEDGER; }
        d->telemetry_seq = tel.seq;
        int still_ok = r.verdict == KX_VERDICT_ALLOW ||
                       (r.verdict == KX_VERDICT_ESCALATE && r.rule_index == e->rule_index);
        if (!still_ok) {               /* the situation changed while the driver decided */
            d->verdict = KX_VERDICT_BLOCK; d->reason = r.reason; d->gate = r.gate; d->rule_index = r.rule_index;
            K.esc_reblocked++;
        } else {
            uint8_t gid[16];
            uint16_t gr = rng_bytes(gid, sizeof gid) == 0
                              ? kx_grant_issue(&K.grants, &e->in, e->intent_hash, K.policy.hash, r.rule_index,
                                               r.grant_ttl_ms, e->proposer, gid, now, &d->grant)
                              : KX_R_LEDGER_PRESSURE;
            d->verdict = gr == KX_R_OK ? KX_VERDICT_ALLOW : KX_VERDICT_BLOCK;
            d->reason = gr == KX_R_OK ? KX_R_HUMAN_APPROVED : gr;
            d->rule_index = r.rule_index;
            K.esc_approved++;
        }
    }
    if (d->rule_index >= 0) memcpy(d->rule_id, K.policy.rules[d->rule_index].id, KX_RULE_ID_LEN);
    K.by_verdict[d->verdict & 3]++;
    K.by_reason[d->reason & 0xff]++;
    e->state = ESC_RESOLVED;
    e->forget_ns = now + 60ull * 1000000000ull;
    {
        kx_capsule_rec_t rec;
        rec_init(&rec, KX_EV_ESC_RESOLVED, &e->in, e->proposer);
        rec.verdict = d->verdict; rec.reason = d->reason; rec.gate = d->gate; rec.rule_index = d->rule_index;
        memcpy(rec.rule_id, d->rule_id, sizeof rec.rule_id);
        memcpy(rec.intent_hash, e->intent_hash, 32);
        rec.escalation_id = e->id;
        rec.human = approve >= 0;
        if (approver) snprintf(rec.approver, sizeof rec.approver, "%s", approver);
        if (d->verdict == KX_VERDICT_ALLOW) { rec.has_grant = 1; memcpy(rec.grant_id, d->grant.grant_id, 16); }
        kxl_submit(&rec, owed());
    }
    if (e->waiter) { reply_decision(e->waiter, d); e->waiter = 0; }
    if (K.verbose) printf("kervixd: escalation #%u %s by %s -> %s\n", e->id,
                          approve < 0 ? "timed out" : approve ? "approved" : "denied", approver ? approver : "-",
                          reason_name(d->reason));
    ring_hmi();
}

static void propose(resmgr_context_t *ctp, const kx_intent_t *in, kx_decision_t *d) {
    uint64_t c0 = ClockCycles();
    kx_client_t client = { ctp->info.type_id, ctp->info.pid };
    memset(d, 0, sizeof *d);
    d->abi = KX_ABI_VERSION;

    kx_telemetry_t tel;
    telemetry(&tel);
    uint64_t now = mono_ns();
    int64_t now_ms = realtime_ms();

    pthread_mutex_lock(&K.lock);
    kx_eval_env_t env = { now, now_ms, K.max_age_ns, (uint8_t)kxl_healthy() };
    kx_eval_result_t r;
    kx_eval(&K.policy, in, &tel, &env, &r);
    /* no audit, no action: an ALLOW/ESCALATE needs room for its capsule before a grant exists */
    if ((r.verdict == KX_VERDICT_ALLOW || r.verdict == KX_VERDICT_ESCALATE) && kxl_free() < 2u + owed()) {
        r.verdict = KX_VERDICT_BLOCK;
        r.reason = KX_R_LEDGER_PRESSURE;
        r.gate = KX_GATE_K3_LEDGER;
        r.rule_index = -1;
    }

    kx_intent_ctx_t ictx = { K.tenant_id, K.vehicle_id, "ai_agent", now_ms };
    if (kx_validate_intent(in) == KX_R_OK) kx_intent_hash(in, &ictx, d->intent_hash);

    if (r.verdict == KX_VERDICT_ALLOW) {
        uint8_t gid[16];
        uint16_t gr = rng_bytes(gid, sizeof gid) == 0
                          ? kx_grant_issue(&K.grants, in, d->intent_hash, K.policy.hash, r.rule_index,
                                           r.grant_ttl_ms, client, gid, now, &d->grant)
                          : KX_R_LEDGER_PRESSURE; /* no CSPRNG, no grant */
        if (gr != KX_R_OK) { r.verdict = KX_VERDICT_BLOCK; r.reason = gr; }
    } else if (r.verdict == KX_VERDICT_ESCALATE) {
        esc_t *e = NULL;
        for (int i = 0; i < KX_MAX_ESCALATIONS && e == NULL; i++) if (g_esc[i].state == ESC_FREE) e = &g_esc[i];
        if (e == NULL) {
            r.verdict = KX_VERDICT_BLOCK;
            r.reason = KX_R_ESCALATION_QUEUE_FULL;
        } else {
            memset(e, 0, sizeof *e);
            e->state = ESC_PENDING;
            e->id = ++K.next_escalation;
            e->in = *in;
            e->proposer = client;
            memcpy(e->intent_hash, d->intent_hash, 32);
            e->rule_index = r.rule_index;
            e->reason = r.reason;
            e->deadline_ns = now + (uint64_t)r.esc_timeout_ms * 1000000ull;
            d->escalation_id = e->id;
            K.esc_created++;
            ring_hmi();
        }
    }
    d->verdict = r.verdict;
    d->gate = r.gate;
    d->reason = r.reason;
    d->rule_index = r.rule_index;
    if (r.rule_index >= 0) memcpy(d->rule_id, K.policy.rules[r.rule_index].id, KX_RULE_ID_LEN);
    memcpy(d->policy_hash, K.policy.hash, 32);
    d->telemetry_seq = tel.seq;

    uint64_t ns = (ClockCycles() - c0) * 1000000000ull / K.cps;
    d->eval_ns = (uint32_t)(ns > UINT32_MAX ? UINT32_MAX : ns);

    kx_capsule_rec_t rec;                       /* recorded as received, valid or not */
    rec_init(&rec, KX_EV_DECISION, in, client);
    rec.verdict = d->verdict; rec.gate = d->gate; rec.reason = d->reason; rec.rule_index = d->rule_index;
    memcpy(rec.rule_id, d->rule_id, sizeof rec.rule_id);
    rec.captured_at_ms = now_ms;
    memcpy(rec.intent_hash, d->intent_hash, 32);
    rec.has_telemetry = 1; rec.telemetry = tel; rec.env = env;
    rec.escalation_id = d->escalation_id;
    rec.eval_ns = d->eval_ns;
    if (d->verdict == KX_VERDICT_ALLOW) { rec.has_grant = 1; memcpy(rec.grant_id, d->grant.grant_id, 16); }
    kxl_submit(&rec, owed());
    K.proposals++;
    K.by_verdict[d->verdict & 3]++;
    K.by_reason[d->reason & 0xff]++;
    record_latency(ns);
    pthread_mutex_unlock(&K.lock);

    if (K.verbose) {
        printf("kervixd: PROPOSE pid=%d type=%u action=%u -> %s %s rule=%s seq=%" PRIu64 " %u ns\n",
               client.pid, client.type_id, in->action,
               d->verdict == KX_VERDICT_ALLOW ? "ALLOW" : d->verdict == KX_VERDICT_ESCALATE ? "ESCALATE" : "BLOCK",
               reason_name(d->reason), d->rule_id[0] ? d->rule_id : "-", tel.seq, d->eval_ns);
    }
}

static int io_devctl(resmgr_context_t *ctp, io_devctl_t *msg, void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    int st = iofunc_devctl_default(ctp, msg, ocb);
    if (st != _RESMGR_DEFAULT) return st;
    void *data = _DEVCTL_DATA(msg->i);
    node_t *node = NULL;
    for (int i = 0; i < N__COUNT; i++) if (ocb->attr == &g_nodes[i].attr) node = &g_nodes[i];

    switch (msg->i.dcmd) {
    case KX_DCMD_PROPOSE: {
        if (node != &g_nodes[N_INTENT]) return ENOTTY;
        kx_intent_t in;
        memcpy(&in, data, sizeof in);
        kx_decision_t d;
        propose(ctp, &in, &d);
        memcpy(data, &d, sizeof d);
        memset(&msg->o, 0, sizeof msg->o);
        msg->o.nbytes = sizeof d;
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o + sizeof d);
    }
    case KX_DCMD_AWAIT: {
        if (node != &g_nodes[N_INTENT]) return ENOTTY;
        kx_await_req_t aw;
        memcpy(&aw, data, sizeof aw);
        pthread_mutex_lock(&K.lock);
        esc_t *e = esc_find(aw.escalation_id);
        int rc = EOK;
        if (e == NULL) rc = ENOENT;
        else if (e->proposer.pid != ctp->info.pid || e->proposer.type_id != ctp->info.type_id) rc = EPERM; /* only the proposer */
        else if (e->state == ESC_PENDING && e->waiter) rc = EBUSY;
        if (rc != EOK) { pthread_mutex_unlock(&K.lock); return rc; }
        if (e->state == ESC_RESOLVED) {
            kx_decision_t d = e->outcome;
            pthread_mutex_unlock(&K.lock);
            memcpy(data, &d, sizeof d);
            memset(&msg->o, 0, sizeof msg->o);
            msg->o.nbytes = sizeof d;
            return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o + sizeof d);
        }
        e->waiter = ctp->rcvid;              /* stays REPLY-blocked in the kernel */
        pthread_mutex_unlock(&K.lock);
        return _RESMGR_NOREPLY;
    }
    case KX_DCMD_ESC_LIST: {
        if (node != &g_nodes[N_ESC]) return ENOTTY;
        static kx_esc_list_t L;
        memset(&L, 0, sizeof L);
        pthread_mutex_lock(&K.lock);
        uint64_t now = mono_ns();
        for (int i = 0; i < KX_MAX_ESCALATIONS && L.n < KX_ESC_LIST_MAX; i++) {
            esc_t *e = &g_esc[i];
            if (e->state != ESC_PENDING) continue;
            kx_esc_info_t *x = &L.e[L.n++];
            x->escalation_id = e->id;
            x->reason = e->reason;
            x->remaining_ms = e->deadline_ns > now ? (int32_t)((e->deadline_ns - now) / 1000000u) : 0;
            x->proposer_pid = e->proposer.pid;
            memcpy(x->rule_id, K.policy.rules[e->rule_index].id, KX_RULE_ID_LEN);
            x->intent = e->in;
        }
        pthread_mutex_unlock(&K.lock);
        memcpy(data, &L, sizeof L);
        memset(&msg->o, 0, sizeof msg->o);
        msg->o.nbytes = sizeof L;
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o + sizeof L);
    }
    case KX_DCMD_ESC_RESOLVE: {
        if (node != &g_nodes[N_ESC]) return ENOTTY;
        kx_resolve_req_t rr;
        memcpy(&rr, data, sizeof rr);
        rr.approver[sizeof rr.approver - 1] = '\0';
        pthread_mutex_lock(&K.lock);
        esc_t *e = esc_find(rr.escalation_id);
        int rc = e == NULL ? ENOENT : e->state != ESC_PENDING ? EALREADY : EOK;
        if (rc == EOK) {
            char who[64];
            snprintf(who, sizeof who, "%s(pid %d)", rr.approver[0] ? rr.approver : "hmi", ctp->info.pid);
            esc_resolve(e, rr.approve ? 1 : 0, who);
        }
        pthread_mutex_unlock(&K.lock);
        if (rc != EOK) return rc;
        memset(&msg->o, 0, sizeof msg->o);
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    case KX_DCMD_ESC_SUBSCRIBE: {
        if (node != &g_nodes[N_ESC]) return ENOTTY;
        int slot = -1;
        pthread_mutex_lock(&K.lock);
        for (int i = 0; i < MAX_HMI_SUBS; i++) {
            if (g_hmi_subs[i].active && g_hmi_subs[i].ocb == ocb) { slot = i; break; }
            if (!g_hmi_subs[i].active && slot < 0) slot = i;
        }
        if (slot >= 0) {
            g_hmi_subs[slot].active = 1;
            g_hmi_subs[slot].rcvid = ctp->rcvid;
            g_hmi_subs[slot].ocb = ocb;
            memcpy(&g_hmi_subs[slot].ev, data, sizeof(struct sigevent));
        }
        pthread_mutex_unlock(&K.lock);
        if (slot < 0) return EBUSY;
        memset(&msg->o, 0, sizeof msg->o);
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    case KX_DCMD_REDEEM: {
        if (node != &g_nodes[N_REDEEM]) return ENOTTY;
        kx_redeem_req_t rq;
        memcpy(&rq, data, sizeof rq);
        kx_telemetry_t tel;
        telemetry(&tel);
        pthread_mutex_lock(&K.lock);
        uint32_t outstanding_before = K.grants.outstanding;
        uint16_t reason = kx_grant_redeem(&K.grants, &rq.grant, &rq.command, rq.presenter, mono_ns(),
                                          &K.policy, &tel);
        int consumed = K.grants.outstanding < outstanding_before; /* this call ended an outstanding grant */
        if (reason == KX_R_OK) K.awaiting_effect++;
        if (reason == KX_R_OK) K.redeem_ok++; else K.redeem_fail[reason & 0xff]++;
        if (reason != KX_R_OK) {
            kx_capsule_rec_t rec;
            rec_init(&rec, KX_EV_GRANT_REFUSED, &rq.command, rq.presenter);
            rec.reason = reason;
            rec.has_grant = 1;
            memcpy(rec.grant_id, rq.grant.grant_id, 16);
            memcpy(rec.intent_hash, rq.grant.intent_hash, 32);
            kxl_submit(&rec, consumed ? 0 : owed());   /* terminal for a live grant; otherwise an attempt */
        }
        pthread_mutex_unlock(&K.lock);
        if (K.verbose) printf("kervixd: REDEEM by actuator pid=%d for presenter pid=%d -> %s\n",
                              ctp->info.pid, rq.presenter.pid, reason_name(reason));
        memset(&msg->o, 0, sizeof msg->o);
        msg->o.ret_val = reason;
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    case KX_DCMD_EFFECT: {
        if (node != &g_nodes[N_REDEEM]) return ENOTTY;
        kx_effect_t e;
        memcpy(&e, data, sizeof e);
        pthread_mutex_lock(&K.lock);
        if (e.ok) K.effects_ok++; else K.effects_fail++;
        if (K.awaiting_effect) K.awaiting_effect--;
        const kx_grant_slot_t *slot = kx_grant_find(&K.grants, e.grant_id);
        if (slot != NULL) {
            kx_client_t who = { slot->grant.proposer_type, slot->grant.proposer_pid };
            kx_capsule_rec_t rec;
            rec_init(&rec, KX_EV_EFFECT, &slot->intent, who);
            rec.effect_ok = e.ok;
            rec.reason = e.ok ? KX_R_OK : KX_R_ACTUATOR_FAILED;
            rec.has_grant = 1;
            memcpy(rec.grant_id, e.grant_id, 16);
            memcpy(rec.intent_hash, slot->grant.intent_hash, 32);
            memcpy(rec.request_digest, e.request_digest, 32);
            memcpy(rec.response_digest, e.response_digest, 32);
            kxl_submit(&rec, 0);                         /* terminal: uses its reserved slot */
        }
        pthread_mutex_unlock(&K.lock);
        if (K.verbose) printf("kervixd: EFFECT action=%u %s\n", e.action, e.ok ? "confirmed" : "FAILED");
        memset(&msg->o, 0, sizeof msg->o);
        return _RESMGR_PTR(ctp, &msg->o, sizeof msg->o);
    }
    default:
        return ENOSYS;
    }
}

static int io_read(resmgr_context_t *ctp, io_read_t *msg, void *ocb_v) {
    iofunc_ocb_t *ocb = ocb_v;
    int st = iofunc_read_verify(ctp, msg, ocb, NULL);
    if (st != EOK) return st;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    if (ocb->attr != &g_nodes[N_STATS].attr && ocb->attr != &g_nodes[N_ESC].attr) return EBADF;
    if (ocb->offset > 0) { _IO_SET_READ_NBYTES(ctp, 0); return _RESMGR_NPARTS(0); }

    static char buf[4096];
    size_t o = 0;
#define OUT(...) do { if (o < sizeof buf) o += (size_t)snprintf(buf + o, sizeof buf - o, __VA_ARGS__); } while (0)
    if (ocb->attr == &g_nodes[N_ESC].attr) {
        pthread_mutex_lock(&K.lock);
        uint64_t now = mono_ns();
        int n = 0;
        for (int i = 0; i < KX_MAX_ESCALATIONS; i++) {
            esc_t *e = &g_esc[i];
            if (e->state != ESC_PENDING) continue;
            const kx_action_spec_t *a = kx_catalog_action(e->in.action);
            OUT("#%u  %-26s %-22s rule=%s  actor=%s  pid=%d  %.1fs left\n", e->id, a ? a->name : "?",
                reason_name(e->reason), K.policy.rules[e->rule_index].id, e->in.actor_id, e->proposer.pid,
                e->deadline_ns > now ? (double)(e->deadline_ns - now) / 1e9 : 0.0);
            n++;
        }
        if (n == 0) OUT("(no pending escalations)\n");
        pthread_mutex_unlock(&K.lock);
        size_t m = o < msg->i.nbytes ? o : msg->i.nbytes;
        ocb->offset += (off_t)m;
        _IO_SET_READ_NBYTES(ctp, (long)m);
        MsgReply(ctp->rcvid, (long)m, buf, m);
        return _RESMGR_NOREPLY;
    }
    kx_telemetry_t tel;
    telemetry(&tel);
    pthread_mutex_lock(&K.lock);
    uint64_t now = mono_ns();
    OUT("kervixd  uptime %" PRIu64 " s  policy %s v%u.%u.%u  hash %02x%02x%02x%02x…\n",
        (uint64_t)((now - K.boot_ns) / 1000000000ull), K.policy.policy_id, K.policy.version >> 16, (K.policy.version >> 8) & 0xff,
        K.policy.version & 0xff, K.policy.hash[0], K.policy.hash[1], K.policy.hash[2], K.policy.hash[3]);
    if (tel.mono_ns) OUT("telemetry seq %" PRIu64 "  age %.1f ms\n", tel.seq, (double)(now - tel.mono_ns) / 1e6);
    else OUT("telemetry UNAVAILABLE (all safety actions blocked)\n");
    OUT("proposals %" PRIu64 "  ALLOW %" PRIu64 "  ESCALATE %" PRIu64 "  BLOCK %" PRIu64 "\n", K.proposals,
        K.by_verdict[KX_VERDICT_ALLOW], K.by_verdict[KX_VERDICT_ESCALATE], K.by_verdict[KX_VERDICT_BLOCK]);
    for (int r = 0; r < 256; r++) if (K.by_reason[r]) OUT("  reason %-24s %" PRIu64 "\n", reason_name((uint16_t)r), K.by_reason[r]);
    OUT("grants outstanding %u  redeemed %" PRIu64 "  expired(reaped) %" PRIu64 "\n", K.grants.outstanding, K.redeem_ok, K.reaped);
    for (int r = 0; r < 256; r++) if (K.redeem_fail[r]) OUT("  refused %-23s %" PRIu64 "\n", reason_name((uint16_t)r), K.redeem_fail[r]);
    OUT("effects confirmed %" PRIu64 "  failed %" PRIu64 "\n", K.effects_ok, K.effects_fail);
    { char ls[320]; kxl_status(ls, sizeof ls); OUT("%s", ls); }
    OUT("escalations created %" PRIu64 "  approved %" PRIu64 "  denied %" PRIu64 "  timed-out %" PRIu64
        "  re-blocked-on-approval %" PRIu64 "\n", K.esc_created, K.esc_approved, K.esc_denied, K.esc_expired, K.esc_reblocked);
    if (K.proposals) {
        OUT("PROPOSE latency (in-server): min %.1f us  max %.1f us\n", (double)K.lat_min_ns / 1e3, (double)K.lat_max_ns / 1e3);
        uint64_t total = 0, acc = 0;
        for (int b = 0; b < HIST_BUCKETS; b++) total += K.hist[b];
        int p50 = -1, p99 = -1;
        for (int b = 0; b < HIST_BUCKETS; b++) {
            acc += K.hist[b];
            if (p50 < 0 && acc * 100 >= total * 50) p50 = b;
            if (p99 < 0 && acc * 100 >= total * 99) p99 = b;
        }
        OUT("  p50 < %u us   p99 < %u us   (log2 buckets)\n", 1u << p50, 1u << p99);
        for (int b = 0; b < HIST_BUCKETS; b++) {
            if (K.hist[b]) OUT("  [%6u, %6u) us  %" PRIu64 "\n", b ? 1u << (b - 1) : 0u, 1u << b, K.hist[b]);
        }
    }
    pthread_mutex_unlock(&K.lock);
    size_t n = o < msg->i.nbytes ? o : msg->i.nbytes;
    ocb->offset += (off_t)n;
    _IO_SET_READ_NBYTES(ctp, (long)n);
    MsgReply(ctp->rcvid, (long)n, buf, n);
    return _RESMGR_NOREPLY;
}

/* A client REPLY-blocked in AWAIT asked to unblock (signal, timeout, kill):
 * the kernel cannot release it until we reply, so release it now. The
 * escalation stays pending; the agent may AWAIT again. Without this, a
 * waiting gateway could not be stopped until the driver answered. */
static int io_unblock(resmgr_context_t *ctp, io_pulse_t *msg, void *ocb_v) {
    int rcvid = msg->value.sival_int;   /* _PULSE_CODE_UNBLOCK: value = the blocked client's rcvid */
    pthread_mutex_lock(&K.lock);
    int found = 0;
    for (int i = 0; i < KX_MAX_ESCALATIONS; i++) {
        if (g_esc[i].state == ESC_PENDING && g_esc[i].waiter == rcvid) {
            g_esc[i].waiter = 0;
            found = 1;
        }
    }
    pthread_mutex_unlock(&K.lock);
    if (K.verbose) printf("kervixd: unblock request for rcvid %d (%s)\n", rcvid, found ? "released AWAIT" : "not ours");
    if (found) {
        MsgError(rcvid, EINTR);
        return _RESMGR_NOREPLY;
    }
    return iofunc_unblock_default(ctp, msg, ocb_v);
}

static int io_close_ocb(resmgr_context_t *ctp, void *reserved, void *ocb_v) {
    pthread_mutex_lock(&K.lock);
    for (int i = 0; i < MAX_HMI_SUBS; i++) if (g_hmi_subs[i].ocb == ocb_v) g_hmi_subs[i].active = 0;
    pthread_mutex_unlock(&K.lock);
    return iofunc_close_ocb_default(ctp, reserved, ocb_v);
}

/* ------------------------------------------------------------ threads */

static void *serve(void *arg) {
    dispatch_t *dpp = arg;
    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    for (;;) {
        if (dispatch_block(ctp) == NULL) continue;
        dispatch_handler(ctp);
    }
    return NULL;
}

static void *reaper(void *arg) {
    (void)arg;
    for (;;) {
        usleep(20000);
        pthread_mutex_lock(&K.lock);
        uint64_t now = mono_ns();
        uint8_t ids[32][16];
        uint32_t n = kx_grant_reap(&K.grants, now, ids, 32);
        K.reaped += n;
        for (uint32_t i = 0; i < n && i < 32; i++) {
            const kx_grant_slot_t *slot = kx_grant_find(&K.grants, ids[i]);
            if (slot == NULL) continue;
            kx_client_t who = { slot->grant.proposer_type, slot->grant.proposer_pid };
            kx_capsule_rec_t rec;
            rec_init(&rec, KX_EV_GRANT_EXPIRED, &slot->intent, who);
            rec.reason = KX_R_GRANT_EXPIRED;
            rec.has_grant = 1;
            memcpy(rec.grant_id, ids[i], 16);
            memcpy(rec.intent_hash, slot->grant.intent_hash, 32);
            kxl_submit(&rec, 0);                         /* terminal: uses its reserved slot */
        }
        for (int i = 0; i < KX_MAX_ESCALATIONS; i++) {
            esc_t *e = &g_esc[i];
            if (e->state == ESC_PENDING && now > e->deadline_ns) esc_resolve(e, -1, NULL); /* fail closed */
            else if (e->state == ESC_RESOLVED && now > e->forget_ns) e->state = ESC_FREE;
        }
        pthread_mutex_unlock(&K.lock);
        if (n && K.verbose) printf("kervixd: %u grant(s) expired unused\n", n);
    }
    return NULL;
}

int main(int argc, char **argv) {
    snprintf(K.vehicle_id, sizeof K.vehicle_id, "veh-demo-0001");
    snprintf(K.tenant_id, sizeof K.tenant_id, "6f1c2b9e-4d3a-4c8b-9a7e-2b1d0c3e4f5a");
    unsigned max_age_ms = 50, ring = 1024, slow_ms = 0;
    const char *datadir = "/data/kervix";
    unsigned restart = 0;
    char restart_cause[16] = "";
    int opt;
    while ((opt = getopt(argc, argv, "V:T:A:D:R:S:X:v")) != -1) {
        if (opt == 'V') snprintf(K.vehicle_id, sizeof K.vehicle_id, "%s", optarg);
        else if (opt == 'T') snprintf(K.tenant_id, sizeof K.tenant_id, "%s", optarg);
        else if (opt == 'A') max_age_ms = (unsigned)atoi(optarg);
        else if (opt == 'v') K.verbose = 1;
        else if (opt == 'D') datadir = optarg;
        else if (opt == 'R') ring = (unsigned)atoi(optarg);
        else if (opt == 'S') slow_ms = (unsigned)atoi(optarg);
        else if (opt == 'X') {                       /* set by kx-supervisor: <restart>:<cause> */
            char *colon = strchr(optarg, ':');
            restart = (unsigned)strtoul(optarg, NULL, 10);
            if (colon) {
                size_t n = 0;                        /* recorded in canonical JSON: [A-Za-z0-9_] only */
                for (const char *c = colon + 1; *c && n < sizeof restart_cause - 1; c++)
                    if ((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_') restart_cause[n++] = *c;
                restart_cause[n] = '\0';
            }
            if (!restart_cause[0]) snprintf(restart_cause, sizeof restart_cause, "unknown");
        }
        else { fprintf(stderr, "usage: kervixd [-V vehicle_id] [-T tenant_uuid] [-A max_age_ms] [-D datadir] [-R queue] [-S slow_ms] [-X restart:cause] [-v]\n"); return 2; }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    K.max_age_ns = (uint64_t)max_age_ms * 1000000ull;
    K.cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    K.boot_ns = mono_ns();

    /* fail closed if any trust anchor is missing */
    if (kx_policy_build_default(&K.policy) != 0) { fprintf(stderr, "kervixd: policy failed to build\n"); return 1; }
    qcrypto_rng_args_t ra;
    memset(&ra, 0, sizeof ra);
    ra.drbg.pstr = (const uint8_t *)"kervixd-grant-key";
    ra.drbg.pstrsize = 17;
    uint8_t key[KX_GRANT_KEY_LEN];
    if (qcrypto_init(QCRYPTO_INIT_LAZY, NULL) != QCRYPTO_R_EOK ||
        qcrypto_rng_request("drbg-ctr-256", NULL, 0, &K.rng) != QCRYPTO_R_EOK ||
        qcrypto_rng_init(K.rng, &ra) != QCRYPTO_R_EOK || rng_bytes(key, sizeof key) != 0) {
        fprintf(stderr, "kervixd: no CSPRNG (qcrypto drbg-ctr-256): refusing to start\n");
        return 1;
    }
    kx_grant_table_init(&K.grants, key);
    qcrypto_memclear(key, sizeof key);

    kxl_config_t lc = { datadir, K.vehicle_id, K.tenant_id, ring, slow_ms, K.verbose, { 0 }, restart, { 0 } };
    memcpy(lc.policy_hash, K.policy.hash, 32);
    memcpy(lc.restart_cause, restart_cause, sizeof lc.restart_cause);
    if (kxl_open(&lc) != 0) { fprintf(stderr, "kervixd: ledger unavailable: refusing to start (no audit, no action)\n"); return 1; }

    for (int c = 0; c < CH__COUNT; c++) {
        if ((g_disp[c] = dispatch_create()) == NULL) { perror("kervixd: dispatch_create"); return 1; }
    }
    for (int i = 0; i < N__COUNT; i++) {
        node_t *n = &g_nodes[i];
        iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &n->cf, _RESMGR_IO_NFUNCS, &n->io);
        n->io.devctl = io_devctl;
        n->io.read = io_read;
        n->io.close_ocb = io_close_ocb;
        n->io.unblock = io_unblock;
        iofunc_attr_init(&n->attr, S_IFCHR | (i == N_STATS ? 0444 : 0666), NULL, NULL);
        resmgr_attr_t ra2;
        memset(&ra2, 0, sizeof ra2);
        ra2.nparts_max = 1;
        ra2.msg_max_size = 8192; /* ESC_LIST carries up to 16 intents */
        if (secpol_resmgr_attach(NULL, g_disp[n->chan], &ra2, n->path, _FTYPE_ANY, 0, &n->cf, &n->io, &n->attr, NULL) == -1) {
            fprintf(stderr, "kervixd: attach %s: %s\n", n->path, strerror(errno));
            return 1;
        }
    }
    secpol_transition_type(NULL, NULL, 0); /* kervix_t -> kervix_run_t when a policy is in force */

    pthread_t th;
    for (int c = 0; c < CH__COUNT; c++) pthread_create(&th, NULL, serve, g_disp[c]);
    pthread_create(&th, NULL, reaper, NULL);
    printf("kervixd: ready vehicle=%s policy=%s hash=%02x%02x%02x%02x… telemetry_max_age=%ums pid=%d\n",
           K.vehicle_id, K.policy.policy_id, K.policy.hash[0], K.policy.hash[1], K.policy.hash[2],
           K.policy.hash[3], max_age_ms, getpid());
    pthread_join(th, NULL);
    return 0;
}
