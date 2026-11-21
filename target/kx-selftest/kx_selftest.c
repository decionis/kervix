/*
 * kx-selftest: every safety and security scenario of Kervix, run on the
 * target itself, as one PASS/FAIL table (product feature X2; journeys J1-J6).
 *
 * It drives the REAL roles exactly as deployed: each check runs the real tools
 * under the role's own secpol type and uid (`on -T agentgw_t -u 400:400 kxctl`,
 * the driver HMI as hmigw_t, the test operator as operator_t, kx-rogue as the
 * agent). Nothing is mocked: kervixd decides, sdv_actuatord actuates, vsimd
 * reports. kx-selftest only sets the scene (scenario), runs the step, and checks
 * what the system answered and what the vehicle then reported.
 *
 *   kx-selftest [-d bindir] [-q]      exit status: number of FAILed checks
 *     -q  quick: skip the slow checks (escalation timeout, crash recovery)
 *
 * The signed dossier of the run is exported to /tmp/kx-selftest-dossier for
 * offline verification on a laptop (J6: kervix-verify; tests/target/selftest.sh).
 * Run it as root: it needs to start the roles under their types. On an image
 * without a security policy the kernel-enforcement checks are reported SKIP.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define OUT_MAX 16384

static char BIN[256] = "/system/bin/kervix";
static char AG[512], OP[512], HMI[512], ROGUE[512];
static int secpol_on, quick;
static int n_pass, n_fail, n_skip, n_check;
static int64_t t_start;

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Run a shell command; capture stdout+stderr into out; return its exit status (or -1). */
static int sh(char *out, size_t cap, const char *fmt, ...) {
    char cmd[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    char full[2100];
    snprintf(full, sizeof full, "%s 2>&1", cmd);
    FILE *p = popen(full, "r");
    if (!p) { if (cap) out[0] = '\0'; return -1; }
    size_t n = 0;
    if (cap) {
        while (n + 1 < cap) {
            size_t r = fread(out + n, 1, cap - 1 - n, p);
            if (r == 0) break;
            n += r;
        }
        out[n] = '\0';
    }
    char sink[256];
    while (fread(sink, 1, sizeof sink, p) > 0) {}
    int st = pclose(p);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
static int has(const char *out, const char *needle) { return strstr(out, needle) != NULL; }

static const char *cur_journey = "";
static int64_t t_check;
static void begin(const char *journey) { cur_journey = journey; t_check = now_ms(); }
static void result(int ok, const char *what, const char *detail) {
    n_check++;
    if (ok) n_pass++; else n_fail++;
    printf("%3d  %-9s %-62s %s %6lld ms\n", n_check, cur_journey, what, ok ? "PASS" : "FAIL", (long long)(now_ms() - t_check));
    if (!ok && detail) {
        /* first lines of what the system said, indented */
        char d[600];
        snprintf(d, sizeof d, "%s", detail);
        int lines = 0;
        for (char *l = strtok(d, "\n"); l && lines < 6; l = strtok(NULL, "\n"), lines++) printf("               | %s\n", l);
    }
    t_check = now_ms();
}
static void skip(const char *what, const char *why) {
    n_check++;
    n_skip++;
    printf("%3d  %-9s %-62s SKIP  (%s)\n", n_check, cur_journey, what, why);
    t_check = now_ms();
}

/* telemetry field value via the operator's read-only view; INT32_MIN if unavailable */
static int tel(const char *field) {
    char out[OUT_MAX];
    if (sh(out, sizeof out, "%s telemetry", OP) != 0) return -2147483647 - 1;
    char key[48];
    snprintf(key, sizeof key, "\n  %s ", field);
    char *p = strstr(out, key);
    if (!p) return -2147483647 - 1;
    return atoi(p + strlen(key));
}
static int wait_tel(const char *field, int value, int timeout_ms) {
    int64_t t0 = now_ms();
    while (now_ms() - t0 < timeout_ms) {
        if (tel(field) == value) return 1;
        usleep(250000);
    }
    return 0;
}
static int wait_tel_above(const char *field, int min, int timeout_ms) {
    int64_t t0 = now_ms();
    while (now_ms() - t0 < timeout_ms) {
        if (tel(field) > min) return 1;
        usleep(250000);
    }
    return 0;
}
static void sim(const char *cmd) {
    char out[512];
    sh(out, sizeof out, "%s sim %s", OP, cmd);
}
static int park(void) {
    sim("stall 0");
    sim("spoof off");
    sim("scenario park");
    return wait_tel("speed_dkph", 0, 40000) && wait_tel("gear", 0, 10000);
}
/* the 8 s OTA flash immobilizes the car: wait until it is idle again */
static void ota_idle(void) { wait_tel("ota_state", 0, 15000); }

/* ---------------------------------------------------------------- checks */

static void check_boot(void) {
    char out[OUT_MAX];
    begin("boot");
    sh(out, sizeof out, "pidin -f an_ 2>/dev/null | grep -E 'vsimd|kervixd|sdv_actuatord|kx-supervisor|kxgw'");
    int daemons = has(out, "vsimd") && has(out, "kervixd") && has(out, "sdv_actuatord");
    if (!secpol_on) {
        result(daemons, "vsimd, kervixd, sdv_actuatord running", out);
        skip("each daemon in its own secpol type, privilege dropped", "no security policy in force");
    } else {
        result(daemons, "vsimd, kervixd, sdv_actuatord running", out);
        result(has(out, "vsim_run_t") && has(out, "kervix_run_t") && has(out, "actuator_run_t"),
               "daemons dropped privilege after init (*_run_t types)", out);
    }
    result(has(out, "kx-supervisor"), "kx-supervisor watches the authority", out);
    int gws = 0;
    for (const char *p = out; (p = strstr(p, "kxgw")) != NULL; p += 4) gws++;
    if (secpol_on)
        result(gws >= 4 && has(out, "agentgw_t") && has(out, "hmigw_t") && has(out, "obsgw_t") && has(out, "worldgw_t"),
               "4 network gateways, each its own type (agent/hmi/observer/world)", out);
    else
        result(gws >= 4, "4 network gateways running", out);
    sh(out, sizeof out, "%s stats", OP);
    result(has(out, "ledger OK"), "signed ledger healthy (K3: no audit, no action)", out);
}

static void check_j1(void) {
    char out[OUT_MAX];
    begin("J1");
    sim("scenario city");
    wait_tel("gear", 3, 20000);
    sh(out, sizeof out, "%s propose --exec cabin.climate.set temp_dc=225", AG);
    result(has(out, "ALLOW") && has(out, "execute  EXECUTED"), "driving: agent sets cabin 22.5 C -> ALLOW, actuated", out);
    usleep(100000);
    int v = tel("hvac_setpoint_dc");
    char d[64];
    snprintf(d, sizeof d, "hvac_setpoint_dc=%d", v);
    result(v == 225, "vehicle reports the new setpoint (telemetry)", d);
}

static void check_j2(void) {
    char out[OUT_MAX];
    begin("J2");
    sim("scenario highway");
    wait_tel("gear", 3, 20000);
    sh(out, sizeof out, "%s propose --exec ota.ecu.flash ecu=brake image_digest=sha256:%s", AG,
       "0101010101010101010101010101010101010101010101010101010101010101");
    result(has(out, "BLOCK") && has(out, "R156_NOT_SAFE_STATE") && !has(out, "EXECUTED"),
           "brake ECU flash at speed -> BLOCK R156_NOT_SAFE_STATE, nothing actuated", out);
    wait_tel_above("speed_dkph", 900, 30000);
    sh(out, sizeof out, "%s propose --exec cabin.window.set window=rear_left pos_pct=100", AG);
    result(has(out, "ESCALATE") && has(out, "WINDOW_HIGH_SPEED") && !has(out, "EXECUTED"),
           "window fully open above 80 km/h -> ESCALATE to the driver, not actuated", out);
    const char *e = strstr(out, "escalation #");
    if (e) sh(NULL, 0, "%s deny %d --as hmi:kx-selftest", HMI, atoi(e + 12));   /* tidy up: not part of J3 */
}

/* agent proposes in the background and AWAITs; the HMI resolves (or nobody, hmi_cmd NULL);
 * returns the escalation id and the agent's full output once it has exited.
 * The background job is started with system(), not popen(): a child would
 * inherit popen's pipe and keep it open for the whole await. */
static int escalate(const char *opts, const char *action, const char *args, const char *hmi_cmd, char *agent_out, size_t cap, char *list, size_t lcap) {
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "rm -f /tmp/kx-selftest-agent.out; ( %s propose --await %s %s %s; echo \"|||$?\" ) > /tmp/kx-selftest-agent.out 2>&1 < /dev/null &",
             AG, opts, action, args);
    if (system(cmd) == -1) return -1;
    char needle[96];
    snprintf(needle, sizeof needle, "  %s ", action);
    int id = -1;
    for (int i = 0; i < 50 && id < 0; i++) {
        usleep(200000);
        sh(list, lcap, "%s escalations", HMI);
        for (char *l = list; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
            char *eol = strchr(l, '\n');
            if (l[0] == '#' && strstr(l, needle) && (!eol || strstr(l, needle) < eol)) { id = atoi(l + 1); break; }
        }
    }
    if (id >= 0 && hmi_cmd) sh(NULL, 0, "%s %s %d --as hmi:kx-selftest", HMI, hmi_cmd, id);
    for (int i = 0; i < 250; i++) {                  /* up to 50 s: the longest rule timeout is 30 s */
        sh(agent_out, cap, "cat /tmp/kx-selftest-agent.out");
        if (has(agent_out, "|||")) break;
        usleep(200000);
    }
    return id;
}

static void check_j3(void) {
    char out[OUT_MAX], list[OUT_MAX];
    begin("J3");
    sim("scenario charging");
    wait_tel("gear", 0, 40000);
    wait_tel("charging", 1, 10000);
    int id = escalate("--exec", "ota.ecu.flash", "ecu=brake image_digest=sha256:0101010101010101010101010101010101010101010101010101010101010101",
                      "approve", out, sizeof out, list, sizeof list);
    result(id >= 0 && has(list, "ota.ecu.flash") && has(list, "DRIVER_CONSENT"), "parked + charging: OTA -> ESCALATE, the HMI sees it", list);
    result(has(out, "HUMAN_APPROVED") && has(out, "execute  EXECUTED"), "driver approves -> fresh grant -> actuated", out);
    usleep(200000);
    result(tel("ota_state") == 1, "vehicle reports the OTA flash in progress", NULL);
    ota_idle();

    id = escalate("", "telematics.location.share", "recipient=fleet_operator duration_s=600", "deny", out, sizeof out, list, sizeof list);
    result(id >= 0 && has(out, "HUMAN_DENIED") && !has(out, "EXECUTED"), "driver denies location sharing -> BLOCK HUMAN_DENIED", out);

    if (quick) {
        skip("nobody answers -> BLOCK ESCALATION_TIMEOUT (fail closed)", "-q");
    } else {
        escalate("", "adas.acc.set_speed", "target_kph=125", NULL, out, sizeof out, list, sizeof list);
        result(has(out, "ESCALATION_TIMEOUT"), "nobody answers -> BLOCK ESCALATION_TIMEOUT (fail closed)", out);
    }
}

static void check_grants(void) {
    char out[OUT_MAX];
    begin("grants");
    if (!park()) { result(0, "vehicle parks for the grant checks", NULL); return; }
    sh(out, sizeof out, "%s propose --replay cabin.climate.set temp_dc=230", AG);
    result(has(out, "execute  EXECUTED") && has(out, "REFUSED   GRANT_SPENT"), "replayed grant -> GRANT_SPENT (single use)", out);
    sh(out, sizeof out, "%s propose --forge cabin.climate.set temp_dc=190", AG);
    result(has(out, "REFUSED   GRANT_MAC"), "forged grant (1 MAC bit) -> GRANT_MAC", out);
    sh(out, sizeof out, "%s propose --delay-ms 700 light.hazard.set on=0", AG);
    result(has(out, "REFUSED   GRANT_EXPIRED"), "grant presented after its TTL -> GRANT_EXPIRED", out);
    sh(out, sizeof out, "%s propose --mutate door=front_right body.door.unlock door=front_left", AG);
    result(has(out, "REFUSED   GRANT_PARAMS"), "granted door A, actuate door B -> GRANT_PARAMS", out);
    sh(out, sizeof out, "%s propose --save-grant /tmp/kx-selftest-g.bin cabin.climate.set temp_dc=215 && %s execute --grant /tmp/kx-selftest-g.bin",
       OP, OP);
    result(has(out, "REFUSED   GRANT_BINDING"), "grant presented by another process -> GRANT_BINDING", out);
    /* the operator proposes here because the test moves the car (--sim) between grant and redeem;
     * the agent's type may not touch the simulator (secpol) */
    sh(out, sizeof out, "%s propose --sim 'scenario highway' --delay-ms 150 body.door.unlock door=front_right", OP);
    result(has(out, "REFUSED   GRANT_INTERLOCK"), "car drives off between grant and redeem -> GRANT_INTERLOCK", out);
    park();
}

static void check_constitution(void) {
    char out[OUT_MAX];
    begin("K1/K2");
    sim("stall 1");
    usleep(300000);
    sh(out, sizeof out, "%s propose body.door.unlock door=front_left", AG);
    result(has(out, "BLOCK") && has(out, "TELEMETRY_STALE"), "telemetry stops -> BLOCK TELEMETRY_STALE (K1)", out);
    sim("stall 0");
    usleep(300000);
    sim("spoof speed_dkph 600");
    usleep(200000);
    sh(out, sizeof out, "%s propose body.door.unlock door=front_left", AG);
    result(has(out, "BLOCK") && has(out, "TELEMETRY_IMPLAUSIBLE"), "spoofed state (P at 60 km/h) -> BLOCK TELEMETRY_IMPLAUSIBLE (K2)", out);
    sim("spoof off");
    usleep(200000);
    sh(out, sizeof out, "%s propose brake.disable", AG);
    result(has(out, "unknown action") || has(out, "BLOCK"), "action outside the catalog -> refused", out);
}

/* F12: the agent's principal is rate-limited per action; the operator and other actions are not */
static void check_rate(void) {
    char out[OUT_MAX];
    begin("F12");
    sh(out, sizeof out, "for i in 1 2 3 4 5 6 7 8 9 10; do %s propose light.hazard.set on=1; done", AG);
    int limited = 0, allowed = 0;
    for (const char *q = out; (q = strstr(q, "RATE_LIMITED")) != NULL; q++) limited++;
    for (const char *q = out; (q = strstr(q, "ALLOW")) != NULL; q++) allowed++;
    char what[112];
    snprintf(what, sizeof what, "agent floods hazard lights: %d ALLOW, then BLOCK RATE_LIMITED x%d", allowed, limited);
    result(allowed >= 1 && limited >= 2 && strstr(out, "ALLOW") < strstr(out, "RATE_LIMITED"), what, out);
    sh(out, sizeof out, "%s propose light.hazard.set on=0; %s propose cabin.climate.set temp_dc=215", OP, AG);
    result(!has(out, "RATE_LIMITED") && has(out, "ALLOW"), "same action by the operator, another action by the agent: not limited", out);
}

static int kervixd_pid(void) {
    char out[256];
    sh(out, sizeof out, "pidin -p kervixd -F '%%a' 2>/dev/null | tail -1");
    return atoi(out);
}

static void check_j4(void) {
    char out[OUT_MAX];
    begin("J4");
    sh(out, sizeof out, "%s --kervixd-pid %d", ROGUE, kervixd_pid());
    if (!secpol_on) {
        skip("kx-rogue as the deployed agent: every attack refused", "no security policy in force");
        return;
    }
    const char *p = strstr(out, "kx-rogue: ");
    int open_n = -1;
    while (p && strstr(p + 1, "kx-rogue: ")) p = strstr(p + 1, "kx-rogue: ");
    if (p) sscanf(p, "kx-rogue: %d attack", &open_n);
    int kernel = 0;
    for (const char *q = out; (q = strstr(q, "BLOCKED  kernel")) != NULL; q++) kernel++;
    char what[96];
    snprintf(what, sizeof what, "kx-rogue as the deployed agent: %d/10 attacks open, %d kernel-refused", open_n < 0 ? 10 : open_n, kernel);
    result(open_n == 0 && kernel >= 7, what, out);
    sh(out, sizeof out, "%s propose light.hazard.set on=1 2>&1; on -T agentgw_t -u 400:400 cat /dev/sdv/actuators/raw", AG);
    result(has(out, "/dev/sdv/actuators/raw: Operation not permitted"), "raw actuator path: kernel refuses the connect (EPERM)", out);
}

static void check_j5(void) {
    char out[OUT_MAX];
    begin("J5");
    if (quick) { skip("kill -9 the authority: fail closed, supervised restart", "-q"); return; }
    int before = kervixd_pid();
    if (before <= 0) { result(0, "kervixd running before the crash", NULL); return; }
    sh(NULL, 0, "slay -9 -f kervixd");
    int64_t t_kill = now_ms();
    sh(out, sizeof out, "%s propose --exec cabin.climate.set temp_dc=200", AG);
    int locked = !has(out, "EXECUTED");
    int64_t back = -1;
    while (now_ms() - t_kill < 15000) {
        sh(out, sizeof out, "%s propose cabin.climate.set temp_dc=205", AG);
        if (has(out, "ALLOW")) { back = now_ms() - t_kill; break; }
        usleep(20000);
    }
    result(locked, "authority killed (-9): actuation locked while it is gone", out);
    char what[96];
    snprintf(what, sizeof what, "supervisor restarts it: deciding again after %lld ms (wall, incl. tooling)", (long long)back);
    result(back >= 0 && kervixd_pid() != before, what, out);
    sh(out, sizeof out, "grep 'authority back in' /tmp/kervixd.log | tail -1");
    if (out[0]) printf("               | %s", out);
}

static void check_denials(void) {
    char out[OUT_MAX];
    begin("secpol");
    if (!secpol_on) { skip("no secpol denials for any legitimate role", "no security policy in force"); return; }
    /* secure image: the monitor's refusal log; open image: the kernel log. The red-team
     * refusals (kx-rogue, and the raw-path probe) are the expected ones. */
    sh(out, sizeof out,
       "{ on -T operator_t cat /dev/secpolgenerate/errors 2>/dev/null; slog2info 2>/dev/null | grep secpolgenerate; } | "
       "grep -E 'type:(vsim|kervix|actuator|agentgw|hmigw|operator|supervisor|obsgw|worldgw)' | grep -v -E 'kx-rogue|^.*cat \\(pid' | sort -u");
    result(out[0] == '\0', "no secpol refusals for any legitimate role (red team excluded)", out);
}

static void check_j6(void) {
    char out[OUT_MAX];
    begin("J6");
    sh(out, sizeof out, "rm -rf /tmp/kx-selftest-dossier; %s dossier export /tmp/kx-selftest-dossier", OP);
    result(has(out, "exported"), "signed dossier exported for offline verification (kervix-verify)", out);
    if (has(out, "exported")) printf("               | %s", out);
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "d:q")) != -1) {
        if (opt == 'd') snprintf(BIN, sizeof BIN, "%s", optarg);
        else if (opt == 'q') quick = 1;
        else { fprintf(stderr, "usage: kx-selftest [-d bindir] [-q]\n"); return 2; }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    t_start = now_ms();
    char out[OUT_MAX];
    /* is a security policy in force? (`on -T` only works with one) */
    secpol_on = sh(out, sizeof out, "on -T operator_t true") == 0;
    if (secpol_on) {
        snprintf(AG, sizeof AG, "on -T agentgw_t -u 400:400 %s/kxctl", BIN);
        snprintf(OP, sizeof OP, "on -T operator_t %s/kxctl", BIN);
        snprintf(HMI, sizeof HMI, "on -T hmigw_t %s/kxctl", BIN);
        snprintf(ROGUE, sizeof ROGUE, "on -T agentgw_t -u 400:400 %s/kx-rogue", BIN);
    } else {
        snprintf(AG, sizeof AG, "on -u 400:400 %s/kxctl", BIN);
        snprintf(OP, sizeof OP, "%s/kxctl", BIN);
        snprintf(HMI, sizeof HMI, "%s/kxctl", BIN);
        snprintf(ROGUE, sizeof ROGUE, "on -u 400:400 %s/kx-rogue", BIN);
    }
    sh(out, sizeof out, "uname -a");
    out[strcspn(out, "\n")] = '\0';
    printf("kx-selftest: Kervix on %s\n", out);
    printf("             security policy: %s%s\n\n", secpol_on ? "in force" : "NONE (kernel-enforcement checks skipped)", quick ? " · quick mode" : "");
    printf("  #  journey   %-62s result   time\n", "check");

    check_boot();
    check_j1();
    check_j2();
    check_j3();
    check_grants();
    check_constitution();
    check_rate();
    check_j4();
    check_j5();
    check_denials();
    check_j6();
    park();

    printf("\nkx-selftest: %d/%d PASS, %d FAIL, %d SKIP in %.1f s\n", n_pass, n_check, n_fail, n_skip, (double)(now_ms() - t_start) / 1000.0);
    printf("SELFTEST RESULT: %s\n", n_fail ? "FAIL" : "PASS");
    return n_fail > 255 ? 255 : n_fail;
}
