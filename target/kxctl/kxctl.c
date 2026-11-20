/*
 * kxctl: Kervix on-target operator CLI (grows with each milestone).
 *
 *   kxctl telemetry                 print the latest snapshot (shm, read-only)
 *   kxctl telemetry --watch <sec>   subscribe to the 100 Hz doorbell; report rate,
 *                                   sequence order, freshness and K2 plausibility
 *   kxctl sim <command words...>    send a command to /dev/sdv/sim/ctl
 *   kxctl sim-apply <action> [k=v]  apply an actuation effect via /dev/sdv/sim/actuate
 *
 * Exit status: 0 ok, 1 check/command failed, 2 usage/IO error.
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <time.h>
#include <unistd.h>

#include "kervix/policy.h"
#include "kervix/seqlock.h"
#include "kervix/vsim_abi.h"

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

static int usage(void) {
    fprintf(stderr, "usage:\n  kxctl telemetry [--watch <seconds>]\n  kxctl sim <command...>   (kxctl sim help)\n"
                    "  kxctl sim-apply <action> [key=value...]\n");
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
    return usage();
}
