/*
 * kx-bench: real-time behaviour of the execution authority, measured on target.
 *
 *  1. PROPOSE closed loop: N sequential proposals; client round trip (ClockCycles)
 *     and kervixd's own in-server time (decision.eval_ns).
 *  2. PROPOSE + EXECUTE closed loop: grant, redeem through sdv_actuatord, actuate.
 *  3. HMI under an agent flood: the driver HMI's round trip on its own channel
 *     (ESC_LIST, priority 30) measured idle, then while F threads at the agent's
 *     priority (10) flood PROPOSE as fast as they can. Priority inheritance and
 *     one thread pool per channel should keep the HMI flat.
 *
 * Runs as operator_t (the one type allowed on both the agent and the HMI
 * channel). The flood uses an action the policy BLOCKs (no grants pile up);
 * under flood the ledger may drop those non-terminal records, and counts them.
 *
 *   kx-bench [-n proposals] [-f flood_threads] [-s flood_seconds] [--json]
 *
 * On QEMU/TCG every number is emulated and NOT representative; headline numbers
 * come from the Raspberry Pi 4 (decision H3). The ratio flood/idle is the
 * meaningful result under emulation.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "kervix/kervix_abi.h"

static uint64_t cps;
static double us_of(uint64_t cycles) { return (double)cycles * 1e6 / (double)cps; }

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}
typedef struct { double p50, p99, max, mean; uint64_t n; } dist_t;
static dist_t dist(uint64_t *v, uint64_t n, int cycles) {
    dist_t d = { 0, 0, 0, 0, n };
    if (n == 0) return d;
    qsort(v, n, sizeof *v, cmp_u64);
    double sum = 0;
    for (uint64_t i = 0; i < n; i++) sum += cycles ? us_of(v[i]) : (double)v[i] / 1e3;
#define VAL(x) (cycles ? us_of(x) : (double)(x) / 1e3)
    d.p50 = VAL(v[n / 2]);
    d.p99 = VAL(v[(n * 99) / 100 >= n ? n - 1 : (n * 99) / 100]);
    d.max = VAL(v[n - 1]);
    d.mean = sum / (double)n;
#undef VAL
    return d;
}
static void print_dist(const char *what, dist_t d) {
    printf("  %-46s n=%-6" PRIu64 " p50 %8.1f us  p99 %8.1f us  max %8.1f us\n", what, d.n, d.p50, d.p99, d.max);
}

static void set_prio(int prio) {
    struct sched_param sp = { .sched_priority = prio };
    pthread_setschedparam(pthread_self(), SCHED_RR, &sp);
}

static kx_intent_t intent_of(uint16_t action) {
    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.abi = KX_ABI_VERSION;
    in.action = action;
    snprintf(in.actor_id, sizeof in.actor_id, "agent:kx-bench");
    for (int i = 0; i < 16; i++) in.intent_id[i] = (uint8_t)rand();
    in.intent_id[6] = (uint8_t)((in.intent_id[6] & 0x0f) | 0x40);
    in.intent_id[8] = (uint8_t)((in.intent_id[8] & 0x3f) | 0x80);
    return in;
}
static kx_intent_t climate(int dc) {
    kx_intent_t in = intent_of(KX_ACT_CABIN_CLIMATE_SET);
    in.n_params = 1;
    in.p[0].key = KX_P_TEMP_DC;
    in.p[0].val = dc;
    return in;
}
static kx_intent_t blocked(void) {             /* BLOCK SERVICE_MODE_REQUIRED outside the workshop */
    kx_intent_t in = intent_of(KX_ACT_CHASSIS_BRAKE_CALIBRATION_WRITE);
    in.has_digest = 1;
    memset(in.digest, 0x42, 32);
    return in;
}

static int propose(int fd, const kx_intent_t *in, kx_decision_t *d) {
    union { kx_intent_t in; kx_decision_t d; } u;
    memset(&u, 0, sizeof u);
    u.in = *in;
    int rc = devctl(fd, KX_DCMD_PROPOSE, &u, sizeof u.d, NULL);
    if (rc == EOK) *d = u.d;
    return rc;
}

/* ---------------------------------------------------------------- flood */
static atomic_int flooding;
static atomic_ullong flood_count, flood_errors;
static void *flood_thread(void *arg) {
    (void)arg;
    set_prio(10);                                   /* the agent gateway's priority */
    int fd = open(KX_PATH_INTENT, O_RDWR);
    if (fd == -1) { atomic_fetch_add(&flood_errors, 1); return NULL; }
    kx_intent_t in = blocked();
    while (atomic_load(&flooding)) {
        kx_decision_t d;
        in.intent_id[0]++;
        if (propose(fd, &in, &d) == EOK) atomic_fetch_add(&flood_count, 1);
        else atomic_fetch_add(&flood_errors, 1);
    }
    close(fd);
    return NULL;
}

/* HMI probe: ESC_LIST round trips on the HMI channel at priority 30, every 2 ms, for `ms` */
static uint64_t hmi_probe(uint64_t *out, uint64_t cap, int ms) {
    int fd = open(KX_PATH_ESCALATIONS, O_RDWR);
    if (fd == -1) { perror("kx-bench: " KX_PATH_ESCALATIONS); return 0; }
    static kx_esc_list_t l;
    uint64_t n = 0;
    uint64_t end = ClockCycles() + (uint64_t)ms * (cps / 1000);
    while (ClockCycles() < end && n < cap) {
        uint64_t t0 = ClockCycles();
        if (devctl(fd, KX_DCMD_ESC_LIST, &l, sizeof l, NULL) == EOK) out[n++] = ClockCycles() - t0;
        usleep(2000);
    }
    close(fd);
    return n;
}

/* The ledger line from /dev/kervix/stats (queue fill, health, drops). */
static int ledger_line(char *out, size_t cap) {
    char stats[4096];
    int sfd = open(KX_PATH_STATS, O_RDONLY);
    ssize_t sn = sfd == -1 ? -1 : read(sfd, stats, sizeof stats - 1);
    if (sfd != -1) close(sfd);
    if (sn <= 0) return -1;
    stats[sn] = '\0';
    char *l = strstr(stats, "ledger ");
    if (!l) return -1;
    snprintf(out, cap, "%.*s", (int)strcspn(l, "\n"), l);
    return 0;
}
/* Wait until the signer has drained the queue (K3 back-pressure is live, not latched). */
static double drain(void) {
    uint64_t t0 = ClockCycles();
    char l[512];
    for (int i = 0; i < 600; i++) {
        unsigned q = 0, cap = 1;
        if (ledger_line(l, sizeof l) == 0) {
            const char *p = strstr(l, "queue ");
            if (p) sscanf(p, "queue %u/%u", &q, &cap);
            if (strncmp(l, "ledger OK", 9) == 0 && q * 20u < cap) break;
        }
        usleep(100000);
    }
    return us_of(ClockCycles() - t0) / 1e6;
}

int main(int argc, char **argv) {
    int n = 2000, flood_threads = 4, flood_s = 5, json = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-n") && i + 1 < argc) n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-f") && i + 1 < argc) flood_threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i + 1 < argc) flood_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json")) json = 1;
        else { fprintf(stderr, "usage: kx-bench [-n proposals] [-f flood_threads] [-s flood_seconds] [--json]\n"); return 2; }
    }
    if (n < 10 || n > 1000000 || flood_threads < 1 || flood_threads > 64 || flood_s < 1 || flood_s > 600) return 2;
    setvbuf(stdout, NULL, _IOLBF, 0);
    cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    srand((unsigned)ClockCycles());
    struct utsname u;
    uname(&u);
    printf("kx-bench: %s %s %s %s, %u CPU(s)\n", u.sysname, u.release, u.machine, u.nodename, (unsigned)_syspage_ptr->num_cpu);
    printf("          %s\n\n", strstr(u.nodename, "qemu") ? "QEMU/TCG: EMULATED, absolute numbers NOT representative (ratios are)" : "native hardware");

    int fd = open(KX_PATH_INTENT, O_RDWR);
    if (fd == -1) { fprintf(stderr, "kx-bench: %s: %s (is kervixd running?)\n", KX_PATH_INTENT, strerror(errno)); return 1; }
    set_prio(10);

    /* 1. PROPOSE closed loop */
    uint64_t *rtt = calloc((size_t)n, sizeof *rtt), *srv = calloc((size_t)n, sizeof *srv);
    if (!rtt || !srv) return 1;
    uint64_t ok = 0, verdicts[4] = { 0 }, pressure = 0;
    for (int i = 0; i < n; i++) {
        kx_intent_t in = (i % 2) ? climate(160 + i % 120) : blocked();
        kx_decision_t d;
        uint64_t t0 = ClockCycles();
        int rc = propose(fd, &in, &d);
        uint64_t t1 = ClockCycles();
        if (rc != EOK) continue;
        rtt[ok] = t1 - t0;
        srv[ok] = d.eval_ns;
        ok++;
        if (d.verdict < 4) verdicts[d.verdict]++;
        if (d.reason == KX_R_LEDGER_PRESSURE) pressure++;
    }
    dist_t d_rtt = dist(rtt, ok, 1), d_srv = dist(srv, ok, 0);
    printf("1. PROPOSE, closed loop, 1 client at priority 10 (ALLOW %" PRIu64 ", BLOCK %" PRIu64 ")\n", verdicts[KX_VERDICT_ALLOW], verdicts[KX_VERDICT_BLOCK]);
    print_dist("in kervixd (validate, hash, policy, grant, enqueue)", d_srv);
    print_dist("client round trip (MsgSend .. reply)", d_rtt);
    if (pressure)
        printf("  %" PRIu64 " ALLOWs became BLOCK LEDGER_PRESSURE: the signer fell behind (K3, \"no audit, no action\")\n", pressure);
    printf("  ledger drained in %.1f s\n", drain());

    /* 2. PROPOSE + EXECUTE (redeem through the actuator) */
    int m = n / 4 < 50 ? 50 : n / 4;
    uint64_t *exe = calloc((size_t)m, sizeof *exe), ex_ok = 0, ex_pressure = 0;
    static uint64_t why[256];
    int afd = open(KX_PATH_ACTUATORS, O_RDWR);
    for (int i = 0; afd != -1 && exe && i < m; i++) {
        kx_intent_t in = climate(180 + i % 60);
        kx_decision_t d;
        uint64_t t0 = ClockCycles();
        if (propose(fd, &in, &d) != EOK) continue;
        if (d.reason == KX_R_LEDGER_PRESSURE) { ex_pressure++; usleep(5000); continue; }
        if (d.verdict != KX_VERDICT_ALLOW) { if (d.reason < 256) why[d.reason]++; continue; }
        kx_execute_req_t rq;
        memset(&rq, 0, sizeof rq);
        rq.grant = d.grant;
        rq.command = in;
        int ret = -1;
        if (devctl(afd, KX_DCMD_EXECUTE, &rq, sizeof rq, &ret) == EOK && ret == KX_R_OK) exe[ex_ok++] = ClockCycles() - t0;
        else if (ret >= 0 && ret < 256) why[ret]++;
        usleep(5000);                               /* human-scale action rate (~200/s), not a flood */
    }
    if (afd != -1) close(afd);
    printf("\n2. PROPOSE + EXECUTE (grant, redeem with interlock re-check, actuate), closed loop\n");
    dist_t d_exe = dist(exe, ex_ok, 1);
    print_dist("client round trip, propose -> actuated", d_exe);
    printf("  %" PRIu64 " of %d attempts executed; %" PRIu64 " held back by K3 (each action is 2 signed capsules)\n", ex_ok, m, ex_pressure);
    for (int r = 0; r < 256; r++) if (why[r]) printf("  not executed: %-24s %" PRIu64 "\n", kx_catalog_reason((uint16_t)r) ? kx_catalog_reason((uint16_t)r)->name : "?", why[r]);
    drain();

    /* 3. HMI latency, idle vs agent flood */
    enum { PROBES = 20000 };
    static uint64_t idle[PROBES], busy[PROBES];
    set_prio(30);                                   /* the driver HMI gateway's priority */
    uint64_t ni = hmi_probe(idle, PROBES, flood_s * 1000);
    atomic_store(&flooding, 1);
    pthread_t th[64];
    for (int i = 0; i < flood_threads; i++) pthread_create(&th[i], NULL, flood_thread, NULL);
    usleep(200000);                                 /* let the flood saturate */
    uint64_t c0 = atomic_load(&flood_count), t0 = ClockCycles();
    uint64_t nb = hmi_probe(busy, PROBES, flood_s * 1000);
    double secs = us_of(ClockCycles() - t0) / 1e6;
    uint64_t flood_n = atomic_load(&flood_count) - c0;
    atomic_store(&flooding, 0);
    for (int i = 0; i < flood_threads; i++) pthread_join(th[i], NULL);
    dist_t di = dist(idle, ni, 1), db = dist(busy, nb, 1);
    printf("\n3. driver HMI round trip (priority 30, own channel) vs an agent PROPOSE flood (priority 10)\n");
    print_dist("HMI, authority idle", di);
    char lbl[96];
    snprintf(lbl, sizeof lbl, "HMI, %d agent threads flooding (%.0f proposals/s)", flood_threads, (double)flood_n / secs);
    print_dist(lbl, db);
    printf("  HMI p99 under flood / idle: %.2fx   (flood errors: %llu)\n", di.p99 > 0 ? db.p99 / di.p99 : 0.0,
           (unsigned long long)atomic_load(&flood_errors));

    char l[512];
    if (ledger_line(l, sizeof l) == 0) printf("\nright after the flood: %s\n", l);
    double dt = drain();
    if (ledger_line(l, sizeof l) == 0) printf("after %.1f s:          %s\n", dt, l);
    if (json)
        printf("{\"machine\":\"%s\",\"node\":\"%s\",\"propose_server_us\":{\"p50\":%.1f,\"p99\":%.1f,\"max\":%.1f,\"n\":%" PRIu64 "},"
               "\"propose_rtt_us\":{\"p50\":%.1f,\"p99\":%.1f,\"max\":%.1f},\"propose_execute_us\":{\"p50\":%.1f,\"p99\":%.1f,\"max\":%.1f,\"n\":%" PRIu64 "},"
               "\"hmi_idle_us\":{\"p50\":%.1f,\"p99\":%.1f,\"max\":%.1f},\"hmi_flood_us\":{\"p50\":%.1f,\"p99\":%.1f,\"max\":%.1f},"
               "\"flood_threads\":%d,\"flood_per_s\":%.0f}\n",
               u.machine, u.nodename, d_srv.p50, d_srv.p99, d_srv.max, d_srv.n, d_rtt.p50, d_rtt.p99, d_rtt.max, d_exe.p50, d_exe.p99,
               d_exe.max, d_exe.n, di.p50, di.p99, di.max, db.p50, db.p99, db.max, flood_threads, (double)flood_n / secs);
    close(fd);
    return 0;
}
