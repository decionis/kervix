/*
 * kxctl: Kervix on-target operator CLI (grows with each milestone).
 *
 *   kxctl telemetry                 print the latest snapshot (shm, read-only)
 *   kxctl telemetry --watch <sec>   subscribe to the 100 Hz doorbell; report rate,
 *                                   sequence order, freshness and K2 plausibility
 *   kxctl sim <command words...>    send a command to /dev/sdv/sim/ctl
 *   kxctl sim-apply <action> [k=v]  apply an actuation effect via /dev/sdv/sim/actuate
 *   kxctl propose [opts] <action> [k=v...]   ask Kervix; prints the decision
 *        --actor ID       actor id (default "agent:kxctl")
 *        --exec           execute the granted command via /dev/sdv/actuators
 *        --replay         execute a second time with the same grant (must be SPENT)
 *        --delay-ms N     wait before executing (expiry tests)
 *        --sim "CMD"      send a simulator command between grant and execution (TOCTOU tests)
 *        --forge          flip one bit of the grant MAC before executing
 *        --mutate k=v     execute a different parameter value than was granted
 *        --save-grant F   write grant+command to F (for `kxctl execute` from another process)
 *        --await          on ESCALATE, block until the driver resolves it (or it times out)
 *   kxctl execute --grant F         present a saved grant (a DIFFERENT process: binding test)
 *   kxctl stats                     authority counters + PROPOSE latency histogram
 *   kxctl dossier export <dir>      export the signed ledger for offline verification (kervix-verify)
 *   kxctl dossier tail [N]          last N capsules (default 10)
 *   kxctl escalations               pending driver decisions (the HMI's view)
 *   kxctl approve <id> [--as NAME]  driver approves (re-evaluated on live telemetry first)
 *   kxctl deny <id> [--as NAME]     driver denies
 *
 * Exit status: 0 ok/ALLOW/executed, 1 check failed or execution refused,
 *              2 usage/IO error, 3 ESCALATE, 4 BLOCK.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/neutrino.h>
#include <time.h>
#include <unistd.h>

#include "kervix/cose.h"
#include "kervix/kervix_abi.h"
#include "kervix/ledger.h"
#include "kervix/sha256.h"
#include "kervix/policy.h"
#include "kervix/seqlock.h"
#include "kervix/vsim_abi.h"

static int usage(void);
static int parse_action(int argc, char **argv, kx_intent_t *in);
static int cmd_sim(int argc, char **argv);

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static const kx_telemetry_shm_t *map_telemetry(void) {
    int fd = shm_open(KX_TELEMETRY_SHM_NAME, O_RDONLY, 0);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s (is vsimd running?)\n", KX_TELEMETRY_SHM_NAME, strerror(errno)); return NULL; }
    void *p = mmap(NULL, sizeof(kx_telemetry_shm_t), PROT_READ, MAP_SHARED, fd, 0); /* read-only by design */
    close(fd);
    return p == MAP_FAILED ? NULL : p;
}

static int cmd_telemetry_once(void) {
    const kx_telemetry_shm_t *shm = map_telemetry();
    kx_telemetry_t t;
    memset(&t, 0, sizeof t);
    if (shm == NULL || kx_seqlock_read(shm, &t, 64) != 0) return 2;
    uint64_t age = now_ns() - t.mono_ns;
    printf("seq %" PRIu64 "  age %" PRIu64 ".%03" PRIu64 " ms  writer pid %u  plausible %s\n", t.seq,
           age / 1000000u, age / 1000u % 1000u, shm->writer_pid, kx_telemetry_plausible(&t) ? "yes" : "NO");
    for (int f = 0; f < KX_TF__COUNT; f++) {
        const kx_tfield_spec_t *s = &kx_catalog_tfields[f];
        printf("  %-18s %6d", s->name, t.v[f]);
        if (f == KX_TF_GEAR && t.v[f] >= 0 && t.v[f] < KX_GEAR__COUNT) printf(" (%s)", kx_enum_gear[t.v[f]]);
        printf("   %s\n", s->vss ? s->vss : "(Kervix extension)");
    }
    return 0;
}

static int cmd_telemetry_watch(unsigned seconds) {
    const kx_telemetry_shm_t *shm = map_telemetry();
    if (shm == NULL) return 2;
    int fd = open(KX_VSIM_PATH_TELEMETRY, O_RDONLY);
    int chid = ChannelCreate(_NTO_CHF_PRIVATE);
    int self = ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0);
    if (fd == -1 || chid == -1 || self == -1) { perror("kxctl: subscribe setup"); return 2; }
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, self, SIGEV_PULSE_PRIO_INHERIT, _PULSE_CODE_MINAVAIL, 0);
    if (MsgRegisterEvent(&ev, fd) == -1) { perror("kxctl: MsgRegisterEvent"); return 2; }
    int rc = devctl(fd, KX_DCMD_TEL_SUBSCRIBE, &ev, sizeof ev, NULL);
    if (rc != EOK) { fprintf(stderr, "kxctl: subscribe: %s\n", strerror(rc)); return 2; }

    uint64_t pulses = 0, samples = 0, regress = 0, implausible = 0, missed_reads = 0, gaps = 0;
    uint64_t max_age = 0, last_seq = 0, timeouts = 0;
    int32_t vmin = INT32_MAX, vmax = INT32_MIN;
    uint64_t t_end = now_ns() + (uint64_t)seconds * 1000000000ull, t_start = now_ns();
    while (now_ns() < t_end) {
        struct _pulse p;
        uint64_t to = 200000000ull; /* 200 ms: a stalled publisher shows up as timeouts */
        TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &to, NULL);
        if (MsgReceivePulse(chid, &p, sizeof p, NULL) == -1) { timeouts++; continue; }
        pulses++;
        kx_telemetry_t t;
        memset(&t, 0, sizeof t);
        if (kx_seqlock_read(shm, &t, 16) != 0) { missed_reads++; continue; }
        uint64_t n = now_ns();
        uint64_t age = n > t.mono_ns ? n - t.mono_ns : 0;
        if (age > max_age) max_age = age;
        if (last_seq && t.seq < last_seq) regress++;
        if (last_seq && t.seq > last_seq + 1) gaps += t.seq - last_seq - 1;
        if (t.seq != last_seq) samples++;
        last_seq = t.seq;
        if (!kx_telemetry_plausible(&t)) implausible++;
        if (t.v[KX_TF_SPEED_DKPH] < vmin) vmin = t.v[KX_TF_SPEED_DKPH];
        if (t.v[KX_TF_SPEED_DKPH] > vmax) vmax = t.v[KX_TF_SPEED_DKPH];
    }
    devctl(fd, KX_DCMD_TEL_UNSUBSCRIBE, NULL, 0, NULL);
    double secs = (double)(now_ns() - t_start) / 1e9;
    printf("watch %.1fs: pulses=%" PRIu64 " rate=%.1fHz samples=%" PRIu64 " seq_regressions=%" PRIu64
           " seq_gaps=%" PRIu64 " implausible=%" PRIu64 " max_age_ms=%.1f read_misses=%" PRIu64
           " timeouts=%" PRIu64 " speed_dkph=[%d..%d] last_seq=%" PRIu64 "\n",
           secs, pulses, (double)pulses / secs, samples, regress, gaps, implausible, (double)max_age / 1e6,
           missed_reads, timeouts, vmin == INT32_MAX ? 0 : vmin, vmax == INT32_MIN ? 0 : vmax, last_seq);
    return regress == 0 ? 0 : 1;
}

static int cmd_sim(int argc, char **argv) {
    char line[128] = "";
    for (int i = 0; i < argc; i++) {
        if (strlen(line) + strlen(argv[i]) + 2 >= sizeof line) { fprintf(stderr, "kxctl: command too long\n"); return 2; }
        if (i) strcat(line, " ");
        strcat(line, argv[i]);
    }
    int fd = open(KX_VSIM_PATH_CTL, O_RDWR);
    if (fd == -1) { perror("kxctl: " KX_VSIM_PATH_CTL); return 2; }
    ssize_t w = write(fd, line, strlen(line));
    int werr = errno;
    char reply[300] = "";
    int fd2 = open(KX_VSIM_PATH_CTL, O_RDONLY);  /* fresh open: reply is served from offset 0 */
    ssize_t r = fd2 == -1 ? -1 : read(fd2, reply, sizeof reply - 1);
    if (r > 0) reply[r] = '\0';
    printf("%s", reply);
    close(fd2);
    close(fd);
    if (w < 0) { if (werr != EINVAL) fprintf(stderr, "kxctl: write: %s\n", strerror(werr)); return 1; }
    return 0;
}

/* <action name> [key=value ...]; values are integers or enum names */
static int parse_action(int argc, char **argv, kx_intent_t *in) {
    memset(in, 0, sizeof *in);
    in->abi = KX_ABI_VERSION;
    const kx_action_spec_t *a = NULL;
    for (int i = 0; i < KX_ACTION_COUNT; i++) {
        if (!strcmp(kx_catalog_actions[i].name, argv[0])) a = &kx_catalog_actions[i];
    }
    if (a == NULL) { fprintf(stderr, "kxctl: unknown action '%s'\n", argv[0]); return -1; }
    in->action = a->id;
    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (eq == NULL) { fprintf(stderr, "kxctl: expected key=value, got '%s'\n", argv[i]); return -1; }
        *eq = '\0';
        const kx_param_spec_t *ps = NULL;
        for (int k = 0; k < a->n_params; k++) if (!strcmp(a->params[k].name, argv[i])) ps = &a->params[k];
        if (ps == NULL) { fprintf(stderr, "kxctl: %s has no parameter '%s'\n", a->name, argv[i]); return -1; }
        const char *v = eq + 1;
        if (ps->type == KX_PT_DIGEST) {
            if (strncmp(v, "sha256:", 7) == 0) v += 7;
            if (strlen(v) != 64) { fprintf(stderr, "kxctl: %s must be sha256:<64 hex>\n", ps->name); return -1; }
            for (int b = 0; b < 32; b++) { unsigned x; sscanf(v + 2 * b, "%2x", &x); in->digest[b] = (uint8_t)x; }
            in->has_digest = 1;
            continue;
        }
        int64_t val;
        char *end;
        val = strtoll(v, &end, 10);
        if (*end != '\0' && ps->type == KX_PT_ENUM) {
            val = -1;
            for (int64_t e = ps->min; e <= ps->max; e++) if (!strcmp(ps->enum_values[e], v)) val = e;
            if (val < 0) { fprintf(stderr, "kxctl: bad value '%s' for %s\n", v, ps->name); return -1; }
        } else if (*end != '\0') {
            fprintf(stderr, "kxctl: bad integer '%s' for %s\n", v, ps->name);
            return -1;
        }
        in->p[in->n_params].key = ps->key;
        in->p[in->n_params].val = val;
        in->n_params++;
    }
    return 0;
}

static int cmd_sim_apply(int argc, char **argv) {
    kx_intent_t in;
    if (parse_action(argc, argv, &in) != 0) return 2;
    int fd = open(KX_VSIM_PATH_ACTUATE, O_RDWR);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s\n", KX_VSIM_PATH_ACTUATE, strerror(errno)); return 2; }
    int rc = devctl(fd, KX_DCMD_SIM_APPLY, &in, sizeof in, NULL);
    close(fd);
    if (rc != EOK) { fprintf(stderr, "kxctl: apply: %s\n", strerror(rc)); return 1; }
    printf("applied %s\n", argv[0]);
    return 0;
}


static const char *rname(uint16_t r) {
    const kx_reason_spec_t *s = kx_catalog_reason(r);
    return s ? s->name : "?";
}
static const char *rtext(uint16_t r) {
    const kx_reason_spec_t *s = kx_catalog_reason(r);
    return s ? s->text : "";
}
static void hexs(const uint8_t *b, size_t n, char *out) { for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", b[i]); }

static int random_uuid(uint8_t u[16]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1 || read(fd, u, 16) != 16) { if (fd != -1) close(fd); return -1; }
    close(fd);
    u[6] = (uint8_t)((u[6] & 0x0f) | 0x40); /* v4 */
    u[8] = (uint8_t)((u[8] & 0x3f) | 0x80); /* RFC 4122 variant */
    return 0;
}

static uint16_t execute_req(const kx_grant_t *g, const kx_intent_t *cmd) {
    int fd = open(KX_PATH_ACTUATORS, O_RDWR);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s\n", KX_PATH_ACTUATORS, strerror(errno)); return KX_R_AUTHORITY_UNAVAILABLE; }
    kx_execute_req_t rq;
    memset(&rq, 0, sizeof rq);
    rq.grant = *g;
    rq.command = *cmd;
    int ret = -1;
    int rc = devctl(fd, KX_DCMD_EXECUTE, &rq, sizeof rq, &ret);
    close(fd);
    return rc == EOK ? (uint16_t)ret : KX_R_AUTHORITY_UNAVAILABLE;
}

static int report_exec(const char *label, uint16_t r) {
    printf("%-8s %s%s%s\n", label, r == KX_R_OK ? "EXECUTED" : "REFUSED ", r == KX_R_OK ? "" : "  ", r == KX_R_OK ? "" : rname(r));
    if (r != KX_R_OK) printf("         %s\n", rtext(r));
    return r == KX_R_OK ? 0 : 1;
}

static int cmd_propose(int argc, char **argv) {
    const char *actor = "agent:kxctl", *sim = NULL, *save = NULL, *mutate = NULL;
    int exec = 0, replay = 0, forge = 0, await_esc = 0;
    long delay_ms = 0;
    int i = 0;
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++) {
        if (!strcmp(argv[i], "--exec")) exec = 1;
        else if (!strcmp(argv[i], "--replay")) exec = replay = 1;
        else if (!strcmp(argv[i], "--forge")) exec = forge = 1;
        else if (!strcmp(argv[i], "--actor") && i + 1 < argc) actor = argv[++i];
        else if (!strcmp(argv[i], "--delay-ms") && i + 1 < argc) { delay_ms = atol(argv[++i]); exec = 1; }
        else if (!strcmp(argv[i], "--sim") && i + 1 < argc) { sim = argv[++i]; exec = 1; }
        else if (!strcmp(argv[i], "--mutate") && i + 1 < argc) { mutate = argv[++i]; exec = 1; }
        else if (!strcmp(argv[i], "--save-grant") && i + 1 < argc) save = argv[++i];
        else if (!strcmp(argv[i], "--await")) await_esc = 1;
        else { fprintf(stderr, "kxctl: unknown option %s\n", argv[i]); return 2; }
    }
    if (i >= argc) return usage();
    kx_intent_t in;
    if (parse_action(argc - i, argv + i, &in) != 0) return 2;
    snprintf(in.actor_id, sizeof in.actor_id, "%s", actor);
    if (random_uuid(in.intent_id) != 0) { perror("kxctl: /dev/urandom"); return 2; }

    int fd = open(KX_PATH_INTENT, O_RDWR);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s (is kervixd running?)\n", KX_PATH_INTENT, strerror(errno)); return 2; }
    union { kx_intent_t in; kx_decision_t d; } u;
    memset(&u, 0, sizeof u);
    u.in = in;
    uint64_t t0 = now_ns();
    int rc = devctl(fd, KX_DCMD_PROPOSE, &u, sizeof u.d, NULL);
    uint64_t rtt = now_ns() - t0;
    if (rc != EOK) { close(fd); fprintf(stderr, "kxctl: PROPOSE: %s\n", strerror(rc)); return 2; }
    kx_decision_t d = u.d;
    const char *v = d.verdict == KX_VERDICT_ALLOW ? "ALLOW" : d.verdict == KX_VERDICT_ESCALATE ? "ESCALATE" : "BLOCK";
    char ih[65], gh[33];
    hexs(d.intent_hash, 32, ih);
    printf("%-8s %s  rule=%s  reason=%s\n", v, argv[i], d.rule_id[0] ? d.rule_id : "-", rname(d.reason));
    printf("         %s\n", rtext(d.reason));
    printf("         intent sha256:%.16s…  telemetry seq %llu  eval %.1f us  round-trip %.1f us\n", ih,
           (unsigned long long)d.telemetry_seq, d.eval_ns / 1e3, rtt / 1e3);
    if (d.verdict == KX_VERDICT_ESCALATE) printf("         escalation #%u awaiting the driver\n", d.escalation_id);
    if (d.verdict == KX_VERDICT_ESCALATE && await_esc) {
        union { kx_await_req_t aw; kx_decision_t d; } w;
        memset(&w, 0, sizeof w);
        w.aw.escalation_id = d.escalation_id;
        uint64_t tw = now_ns();
        rc = devctl(fd, KX_DCMD_AWAIT, &w, sizeof w.d, NULL); /* REPLY-blocked until resolved */
        if (rc != EOK) { close(fd); fprintf(stderr, "kxctl: AWAIT: %s\n", strerror(rc)); return 2; }
        d = w.d;
        v = d.verdict == KX_VERDICT_ALLOW ? "ALLOW" : d.verdict == KX_VERDICT_ESCALATE ? "ESCALATE" : "BLOCK";
        printf("%-8s escalation #%u resolved after %.1f s  rule=%s  reason=%s\n", v, d.escalation_id,
               (double)(now_ns() - tw) / 1e9, d.rule_id[0] ? d.rule_id : "-", rname(d.reason));
        printf("         %s\n", rtext(d.reason));
    }
    close(fd);
    if (d.verdict != KX_VERDICT_ALLOW) return d.verdict == KX_VERDICT_ESCALATE ? 3 : 4;

    hexs(d.grant.grant_id, 16, gh);
    printf("         grant %s…  ttl %llu ms  single-use\n", gh,
           (unsigned long long)((d.grant.not_after_mono_ns - d.grant.issued_mono_ns) / 1000000u));
    if (save) {
        FILE *f = fopen(save, "wb");
        kx_execute_req_t rq;
        memset(&rq, 0, sizeof rq);
        rq.grant = d.grant;
        rq.command = in;
        if (f == NULL || fwrite(&rq, sizeof rq, 1, f) != 1) { perror("kxctl: save-grant"); return 2; }
        fclose(f);
    }
    if (!exec) return 0;
    if (sim) {
        char simline[128];
        snprintf(simline, sizeof simline, "%s", sim);
        char *words[8]; int nw = 0;
        for (char *t = strtok(simline, " "); t && nw < 8; t = strtok(NULL, " ")) words[nw++] = t;
        if (cmd_sim(nw, words) != 0) return 2;
    }
    if (delay_ms > 0) usleep((useconds_t)delay_ms * 1000u);
    kx_grant_t g = d.grant;
    kx_intent_t cmd = in;
    if (forge) g.mac[7] ^= 0x01;
    if (mutate) {
        char m[64];
        snprintf(m, sizeof m, "%s", mutate);
        char *argv2[2] = { argv[i], m };
        kx_intent_t alt;
        if (parse_action(2, argv2, &alt) != 0 || alt.n_params != 1) return 2;
        for (int k = 0; k < cmd.n_params; k++) if (cmd.p[k].key == alt.p[0].key) cmd.p[k].val = alt.p[0].val;
    }
    int r1 = report_exec("execute", execute_req(&g, &cmd));
    if (!replay) return r1;
    return report_exec("replay", execute_req(&g, &cmd)) == 0 ? 1 : r1; /* a replay that executes is a failure */
}

static int cmd_execute(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[0], "--grant")) return usage();
    FILE *f = fopen(argv[1], "rb");
    kx_execute_req_t rq;
    if (f == NULL || fread(&rq, sizeof rq, 1, f) != 1) { perror("kxctl: --grant"); return 2; }
    fclose(f);
    return report_exec("execute", execute_req(&rq.grant, &rq.command));
}

static int cmd_await(const char *id) {
    int fd = open(KX_PATH_INTENT, O_RDWR);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s\n", KX_PATH_INTENT, strerror(errno)); return 2; }
    union { kx_await_req_t aw; kx_decision_t d; } w;
    memset(&w, 0, sizeof w);
    w.aw.escalation_id = (uint32_t)strtoul(id[0] == '#' ? id + 1 : id, NULL, 10);
    int rc = devctl(fd, KX_DCMD_AWAIT, &w, sizeof w.d, NULL);
    close(fd);
    if (rc != EOK) {
        fprintf(stderr, "kxctl: await #%u: %s\n", w.aw.escalation_id,
                rc == EPERM ? "only the proposing process may await its escalation" : strerror(rc));
        return 1;
    }
    printf("%s escalation #%u reason=%s\n", w.d.verdict == KX_VERDICT_ALLOW ? "ALLOW" : "BLOCK", w.d.escalation_id, rname(w.d.reason));
    return 0;
}

static int cmd_escalations(void) {
    int fd = open(KX_PATH_ESCALATIONS, O_RDONLY);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s\n", KX_PATH_ESCALATIONS, strerror(errno)); return 2; }
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) return 2;
    buf[n] = '\0';
    fputs(buf, stdout);
    return 0;
}

static int cmd_resolve(int argc, char **argv, int approve) {
    if (argc != 1 && !(argc == 3 && !strcmp(argv[1], "--as"))) return usage();
    kx_resolve_req_t rr;
    memset(&rr, 0, sizeof rr);
    rr.escalation_id = (uint32_t)strtoul(argv[0][0] == '#' ? argv[0] + 1 : argv[0], NULL, 10);
    rr.approve = (uint8_t)approve;
    snprintf(rr.approver, sizeof rr.approver, "%s", argc == 3 ? argv[2] : "hmi:kxctl");
    int fd = open(KX_PATH_ESCALATIONS, O_RDWR);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s\n", KX_PATH_ESCALATIONS, strerror(errno)); return 2; }
    int rc = devctl(fd, KX_DCMD_ESC_RESOLVE, &rr, sizeof rr, NULL);
    close(fd);
    if (rc != EOK) {
        fprintf(stderr, "kxctl: escalation #%u: %s\n", rr.escalation_id,
                rc == ENOENT ? "no such escalation" : rc == EALREADY ? "already resolved" : strerror(rc));
        return 1;
    }
    printf("escalation #%u %s by %s\n", rr.escalation_id, approve ? "APPROVED" : "DENIED", rr.approver);
    return 0;
}

#define KX_DATADIR "/data/kervix"

/* Load the ledger file and walk its valid prefix. */
static uint8_t *load_ledger(size_t *n) {
    const char *path = KX_DATADIR "/ledger/ledger.kxl";
    int fd = open(path, O_RDONLY);
    struct stat st;
    if (fd == -1 || fstat(fd, &st) == -1) { fprintf(stderr, "kxctl: %s: %s\n", path, strerror(errno)); return NULL; }
    uint8_t *buf = malloc((size_t)st.st_size + 1);
    ssize_t r = buf ? read(fd, buf, (size_t)st.st_size) : -1;
    close(fd);
    if (r != st.st_size) { free(buf); return NULL; }
    *n = (size_t)st.st_size;
    return buf;
}

typedef int (*rec_fn)(void *arg, const kx_ledger_hdr_t *h, const char *capsule, const uint8_t *env);
static uint64_t walk(const uint8_t *buf, size_t n, rec_fn fn, void *arg) {
    size_t off = 0;
    uint64_t count = 0;
    while (n - off >= KX_LEDGER_HDR_LEN) {
        kx_ledger_hdr_t h;
        if (kx_ledger_hdr_decode(buf + off, &h) != 0) break;
        size_t total = KX_LEDGER_HDR_LEN + h.capsule_len + KX_COSE_ENVELOPE_LEN;
        if (n - off < total) break;
        const char *cap = (const char *)buf + off + KX_LEDGER_HDR_LEN;
        const uint8_t *env = buf + off + KX_LEDGER_HDR_LEN + h.capsule_len;
        if (!kx_ledger_crc_ok(buf + off, &h, cap, env)) break;
        if (fn && fn(arg, &h, cap, env) != 0) return count;
        count++;
        off += total;
    }
    return count;
}

typedef struct { FILE *caps, *envs; kx_sha256_t hc, he; uint64_t first, last; uint8_t head[32]; } export_t;
static int export_one(void *arg, const kx_ledger_hdr_t *h, const char *capsule, const uint8_t *env) {
    export_t *x = arg;
    char b64[260];
    size_t bn = kx_base64url(env, KX_COSE_ENVELOPE_LEN, b64);
    fwrite(capsule, 1, h->capsule_len, x->caps); fputc('\n', x->caps);
    fwrite(b64, 1, bn, x->envs); fputc('\n', x->envs);
    kx_sha256_update(&x->hc, capsule, h->capsule_len); kx_sha256_update(&x->hc, "\n", 1);
    kx_sha256_update(&x->he, b64, bn); kx_sha256_update(&x->he, "\n", 1);
    if (!x->first) x->first = h->seq;
    x->last = h->seq;
    memcpy(x->head, h->capsule_id, 32);
    return 0;
}

static int sha256_file(const char *path, char out[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    kx_sha256_t s;
    kx_sha256_init(&s);
    uint8_t b[4096], d[32];
    size_t r;
    while ((r = fread(b, 1, sizeof b, f)) > 0) kx_sha256_update(&s, b, r);
    fclose(f);
    kx_sha256_final(&s, d);
    kx_hex(d, 32, out);
    return 0;
}

static int cmd_dossier(int argc, char **argv) {
    size_t n;
    if (argc >= 1 && !strcmp(argv[0], "tail")) {
        int want = argc >= 2 ? atoi(argv[1]) : 10;
        uint8_t *buf = load_ledger(&n);
        if (!buf) return 2;
        uint64_t total = walk(buf, n, NULL, NULL);
        uint64_t skip = total > (uint64_t)want ? total - (uint64_t)want : 0, i = 0;
        size_t off = 0;
        while (i < total) {
            kx_ledger_hdr_t h;
            kx_ledger_hdr_decode(buf + off, &h);
            char *cap = (char *)buf + off + KX_LEDGER_HDR_LEN;
            if (i >= skip) {
                char tmp[KX_CAPSULE_JCS_MAX + 1];
                memcpy(tmp, cap, h.capsule_len); tmp[h.capsule_len] = '\0';
                char ev[24] = "?", rs[40] = "?", vc[24] = "(authorized)", ac[40] = "", idh[17];
                char *p;
                if ((p = strstr(tmp, "\"event\":\""))) sscanf(p + 9, "%23[^\"]", ev);
                if ((p = strstr(tmp, "\"reason\":\""))) sscanf(p + 10, "%39[^\"]", rs);
                if ((p = strstr(tmp, "\"verdict_class\":\""))) sscanf(p + 17, "%23[^\"]", vc);
                if ((p = strstr(tmp, "\"intent\":{\"action\":\""))) sscanf(p + 20, "%39[^\"]", ac);
                kx_hex(h.capsule_id, 8, idh);
                printf("#%-5llu %s…  %-14s %-20s %-26s %s\n", (unsigned long long)h.seq, idh, vc, ev, rs, ac);
            }
            off += KX_LEDGER_HDR_LEN + h.capsule_len + KX_COSE_ENVELOPE_LEN;
            i++;
        }
        printf("(%llu capsule(s) in ledger, %zu bytes)\n", (unsigned long long)total, n);
        free(buf);
        return 0;
    }
    if (argc != 2 || strcmp(argv[0], "export")) return usage();
    const char *dir = argv[1];
    mkdir(dir, 0755);
    uint8_t *buf = load_ledger(&n);
    if (!buf) return 2;
    char pc[512], pe[512], pj[512], pm[512];
    snprintf(pc, sizeof pc, "%s/capsules.jsonl", dir);
    snprintf(pe, sizeof pe, "%s/envelopes.txt", dir);
    snprintf(pj, sizeof pj, "%s/vehicle.jwk.json", dir);
    snprintf(pm, sizeof pm, "%s/manifest.json", dir);
    export_t x;
    memset(&x, 0, sizeof x);
    x.caps = fopen(pc, "wb");
    x.envs = fopen(pe, "wb");
    if (!x.caps || !x.envs) { perror("kxctl: export"); return 2; }
    kx_sha256_init(&x.hc);
    kx_sha256_init(&x.he);
    uint64_t count = walk(buf, n, export_one, &x);
    fclose(x.caps);
    fclose(x.envs);
    free(buf);
    /* public key */
    int in = open(KX_DATADIR "/keys/vehicle.jwk.json", O_RDONLY);
    char jwk[512];
    ssize_t jn = in == -1 ? -1 : read(in, jwk, sizeof jwk);
    if (in != -1) close(in);
    FILE *jf = fopen(pj, "wb");
    if (jn <= 0 || !jf) { fprintf(stderr, "kxctl: vehicle.jwk.json missing\n"); return 2; }
    fwrite(jwk, 1, (size_t)jn, jf);
    fclose(jf);
    char hc[65], he[65], hj[65], head[65];
    sha256_file(pc, hc); sha256_file(pe, he); sha256_file(pj, hj);
    kx_hex(x.head, 32, head);
    FILE *mf = fopen(pm, "wb");
    if (!mf) return 2;
    fprintf(mf, "{\"files\":{\"capsules.jsonl\":\"sha256:%s\",\"envelopes.txt\":\"sha256:%s\",\"vehicle.jwk.json\":\"sha256:%s\"},"
                "\"first_seq\":%llu,\"format\":\"kervix.dossier/1\",\"head_capsule_id\":\"%s\",\"last_seq\":%llu,\"records\":%llu}\n",
            hc, he, hj, (unsigned long long)x.first, head, (unsigned long long)x.last, (unsigned long long)count);
    fclose(mf);
    printf("exported %llu capsule(s) (seq %llu..%llu, head %.16s…) to %s\n", (unsigned long long)count,
           (unsigned long long)x.first, (unsigned long long)x.last, head, dir);
    return 0;
}

static int cmd_stats(void) {
    int fd = open(KX_PATH_STATS, O_RDONLY);
    if (fd == -1) { fprintf(stderr, "kxctl: %s: %s\n", KX_PATH_STATS, strerror(errno)); return 2; }
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) return 2;
    buf[n] = '\0';
    fputs(buf, stdout);
    return 0;
}

static int usage(void) {
    fprintf(stderr, "usage:\n  kxctl telemetry [--watch <seconds>]\n  kxctl sim <command...>   (kxctl sim help)\n"
                    "  kxctl sim-apply <action> [key=value...]\n"
                    "  kxctl propose [--exec|--await|--replay|--forge|--delay-ms N|--sim CMD|--mutate k=v|--save-grant F|--actor ID]\n"
                    "                <action> [key=value...]\n"
                    "  kxctl execute --grant F\n  kxctl stats\n"
                    "  kxctl escalations | approve <id> [--as NAME] | deny <id> [--as NAME]\n"
                    "  kxctl dossier export <dir> | dossier tail [N]\n");
    return 2;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "telemetry")) {
        if (argc == 2) return cmd_telemetry_once();
        if (argc == 4 && !strcmp(argv[2], "--watch")) return cmd_telemetry_watch((unsigned)atoi(argv[3]));
        return usage();
    }
    if (!strcmp(argv[1], "sim") && argc >= 3) return cmd_sim(argc - 2, argv + 2);
    if (!strcmp(argv[1], "sim-apply") && argc >= 3) return cmd_sim_apply(argc - 2, argv + 2);
    if (!strcmp(argv[1], "propose") && argc >= 3) return cmd_propose(argc - 2, argv + 2);
    if (!strcmp(argv[1], "execute")) return cmd_execute(argc - 2, argv + 2);
    if (!strcmp(argv[1], "stats")) return cmd_stats();
    if (!strcmp(argv[1], "dossier") && argc >= 3) return cmd_dossier(argc - 2, argv + 2);
    if (!strcmp(argv[1], "escalations")) return cmd_escalations();
    if (!strcmp(argv[1], "await") && argc == 3) return cmd_await(argv[2]);
    if (!strcmp(argv[1], "approve") && argc >= 3) return cmd_resolve(argc - 2, argv + 2, 1);
    if (!strcmp(argv[1], "deny") && argc >= 3) return cmd_resolve(argc - 2, argv + 2, 0);
    return usage();
}
