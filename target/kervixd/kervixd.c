/*
 * kervixd: the Kervix execution authority (QNX 8.0 resource manager).
 *
 * Channels (one dispatch_t each, so secpol can type them; spike S1):
 *   agent    /dev/kervix/intent  PROPOSE -> kx_decision_t (+ single-use grant on ALLOW)
 *            /dev/kervix/stats   text counters + PROPOSE latency histogram
 *   actuator /dev/kervix/redeem  REDEEM (grant -> OK | GRANT_*), EFFECT (outcome)
 *
 * Every decision is computed by libkxcore's pure kx_eval() on a seqlock
 * snapshot of vsimd telemetry (mapped READ-ONLY). Caller identity comes from
 * the kernel-stamped message info (pid + secpol type), never from the payload.
 * Grant ids and the per-boot grant key come from qcrypto's DRBG; a restart
 * therefore invalidates every outstanding grant (fail-closed).
 *
 * usage: kervixd [-V vehicle_id] [-T tenant_uuid] [-A max_telemetry_age_ms] [-v]
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
    uint64_t            hist[HIST_BUCKETS], lat_min_ns, lat_max_ns;
} K = { .lock = PTHREAD_MUTEX_INITIALIZER, .lat_min_ns = UINT64_MAX };

typedef struct {
    const char            *path;
    int                    chan;        /* index into g_disp */
    resmgr_connect_funcs_t cf;
    resmgr_io_funcs_t      io;
    iofunc_attr_t          attr;
} node_t;
enum { CH_AGENT = 0, CH_ACT, CH__COUNT };
enum { N_INTENT = 0, N_STATS, N_REDEEM, N__COUNT };
static dispatch_t *g_disp[CH__COUNT];
static node_t g_nodes[N__COUNT] = {
    { .path = KX_PATH_INTENT, .chan = CH_AGENT },
    { .path = KX_PATH_STATS, .chan = CH_AGENT },
    { .path = KX_PATH_REDEEM, .chan = CH_ACT },
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
    kx_eval_env_t env = { now, now_ms, K.max_age_ns, 1 /* ledger arrives in M2 */ };
    kx_eval_result_t r;
    kx_eval(&K.policy, in, &tel, &env, &r);

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
        d->escalation_id = ++K.next_escalation; /* human-resolution queue: escalation milestone */
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
    case KX_DCMD_REDEEM: {
        if (node != &g_nodes[N_REDEEM]) return ENOTTY;
        kx_redeem_req_t rq;
        memcpy(&rq, data, sizeof rq);
        kx_telemetry_t tel;
        telemetry(&tel);
        pthread_mutex_lock(&K.lock);
        uint16_t reason = kx_grant_redeem(&K.grants, &rq.grant, &rq.command, rq.presenter, mono_ns(),
                                          &K.policy, &tel);
        if (reason == KX_R_OK) K.redeem_ok++; else K.redeem_fail[reason & 0xff]++;
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
        pthread_mutex_unlock(&K.lock); /* capsule ledger records effects in M2 */
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
    if (ocb->attr != &g_nodes[N_STATS].attr) return EBADF;
    if (ocb->offset > 0) { _IO_SET_READ_NBYTES(ctp, 0); return _RESMGR_NPARTS(0); }

    static char buf[4096];
    size_t o = 0;
#define OUT(...) do { if (o < sizeof buf) o += (size_t)snprintf(buf + o, sizeof buf - o, __VA_ARGS__); } while (0)
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
        uint32_t n = kx_grant_reap(&K.grants, mono_ns(), NULL, 0); /* "expired" capsules arrive in M2 */
        K.reaped += n;
        pthread_mutex_unlock(&K.lock);
        if (n && K.verbose) printf("kervixd: %u grant(s) expired unused\n", n);
    }
    return NULL;
}

int main(int argc, char **argv) {
    snprintf(K.vehicle_id, sizeof K.vehicle_id, "veh-demo-0001");
    snprintf(K.tenant_id, sizeof K.tenant_id, "6f1c2b9e-4d3a-4c8b-9a7e-2b1d0c3e4f5a");
    unsigned max_age_ms = 50;
    int opt;
    while ((opt = getopt(argc, argv, "V:T:A:v")) != -1) {
        if (opt == 'V') snprintf(K.vehicle_id, sizeof K.vehicle_id, "%s", optarg);
        else if (opt == 'T') snprintf(K.tenant_id, sizeof K.tenant_id, "%s", optarg);
        else if (opt == 'A') max_age_ms = (unsigned)atoi(optarg);
        else if (opt == 'v') K.verbose = 1;
        else { fprintf(stderr, "usage: kervixd [-V vehicle_id] [-T tenant_uuid] [-A max_age_ms] [-v]\n"); return 2; }
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

    for (int c = 0; c < CH__COUNT; c++) {
        if ((g_disp[c] = dispatch_create()) == NULL) { perror("kervixd: dispatch_create"); return 1; }
    }
    for (int i = 0; i < N__COUNT; i++) {
        node_t *n = &g_nodes[i];
        iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &n->cf, _RESMGR_IO_NFUNCS, &n->io);
        n->io.devctl = io_devctl;
        n->io.read = io_read;
        iofunc_attr_init(&n->attr, S_IFCHR | (i == N_STATS ? 0444 : 0666), NULL, NULL);
        resmgr_attr_t ra2;
        memset(&ra2, 0, sizeof ra2);
        ra2.nparts_max = 1;
        ra2.msg_max_size = 4096;
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
