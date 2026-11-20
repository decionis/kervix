/*
 * kx-supervisor: keeps the execution authority (kervixd) running, fail-closed.
 *
 *  - starts kervixd under its own secpol type (default kervix_t) with posix_spawn
 *  - kervixd's stdout/stderr come back through a pipe and are forwarded to the
 *    supervisor's stdout, so the authority inherits no file connection (an
 *    inherited connection is never checked by secpol: see codelab/NOTES.md)
 *  - when kervixd ends, the vehicle is already safe: the actuator refuses
 *    everything (AUTHORITY_UNAVAILABLE) and every outstanding grant dies with
 *    the per-boot grant key. The supervisor restarts it at once with
 *    -X <restart>:<cause>, so the new epoch capsule records why it began, and
 *    reports how long the authority was gone (end of old -> "ready" of new)
 *  - crash loop (more than -n restarts within -w seconds): stops restarting.
 *    The authority stays DOWN and actuation stays locked. A supervisor that
 *    restarts a crashing authority forever would hide the fault.
 *
 * usage: kx-supervisor [-t type] [-n max_restarts] [-w window_s] -- /path/kervixd [args...]
 */
#include <errno.h>
#include <fcntl.h>
#include <secpol/secpol.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define MAX_ARGS 32

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void cause_of(int status, char *out, size_t cap) {
    static const struct { int sig; const char *name; } S[] = {
        { SIGKILL, "SIGKILL" }, { SIGSEGV, "SIGSEGV" }, { SIGABRT, "SIGABRT" }, { SIGTERM, "SIGTERM" },
        { SIGBUS, "SIGBUS" },   { SIGILL, "SIGILL" },   { SIGFPE, "SIGFPE" },   { SIGINT, "SIGINT" },
    };
    if (WIFSIGNALED(status)) {
        for (size_t i = 0; i < sizeof S / sizeof S[0]; i++)
            if (S[i].sig == WTERMSIG(status)) { snprintf(out, cap, "%s", S[i].name); return; }
        snprintf(out, cap, "SIG%d", WTERMSIG(status));
    } else if (WIFEXITED(status)) {
        snprintf(out, cap, "exit%d", WEXITSTATUS(status));
    } else {
        snprintf(out, cap, "unknown");
    }
}

/* Spawn argv under `type`; *out_fd receives the read end of its stdout/stderr pipe. */
static pid_t start(char *const argv[], const char *type, int *out_fd) {
    int p[2];
    if (pipe(p) != 0) return -1;
    fcntl(p[0], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, p[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fa, p[1], STDERR_FILENO);
    if (p[1] > STDERR_FILENO) posix_spawn_file_actions_addclose(&fa, p[1]);
    posix_spawnattr_init(&at);
    /* No-op without a policy in force; with one, the kernel checks settypeid */
    if (type && type[0] && secpol_posix_spawnattr_settypeid(NULL, &at, type, SECPOL_TYPE_NAME) != 0 && errno != ENOTSUP)
        fprintf(stderr, "kx-supervisor: cannot select type %s: %s\n", type, strerror(errno));
    pid_t pid = -1;
    int rc = posix_spawn(&pid, argv[0], &fa, &at, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&at);
    close(p[1]);
    if (rc != 0) {
        fprintf(stderr, "kx-supervisor: spawn %s as %s: %s\n", argv[0], type ? type : "-", strerror(rc));
        close(p[0]);
        return -1;
    }
    *out_fd = p[0];
    return pid;
}

int main(int argc, char **argv) {
    const char *type = "kervix_t";
    unsigned max_restarts = 5, window_s = 60;
    int opt;
    while ((opt = getopt(argc, argv, "t:n:w:")) != -1) {
        if (opt == 't') type = optarg;
        else if (opt == 'n') max_restarts = (unsigned)atoi(optarg);
        else if (opt == 'w') window_s = (unsigned)atoi(optarg);
        else goto usage;
    }
    if (optind >= argc || argc - optind > MAX_ARGS - 3) goto usage;
    setvbuf(stdout, NULL, _IOLBF, 0);

    char *args[MAX_ARGS];
    int n = 0;
    for (int i = optind; i < argc; i++) args[n++] = argv[i];
    char xarg[40];
    uint64_t restarts_at[64] = { 0 };               /* ring of restart times (crash-loop window) */
    unsigned restart = 0;
    char cause[16] = "";
    uint64_t t_end = 0;

    printf("kx-supervisor: supervising %s as %s (fail closed after %u restarts in %u s) pid=%d\n",
           args[0], type, max_restarts, window_s, getpid());
    for (;;) {
        int k = n;
        if (restart) {
            snprintf(xarg, sizeof xarg, "%u:%s", restart, cause);
            args[k++] = "-X";
            args[k++] = xarg;
        }
        args[k] = NULL;
        uint64_t t_spawn = now_ns();
        int fd = -1;
        pid_t pid = start(args, type, &fd);
        int status = 0;
        if (pid > 0) {
            FILE *f = fdopen(fd, "r");
            char line[512];
            int ready = 0;
            while (f && fgets(line, sizeof line, f)) {
                fputs(line, stdout);
                if (!ready && strstr(line, "kervixd: ready")) {
                    ready = 1;
                    uint64_t t = now_ns();
                    if (restart)
                        printf("kx-supervisor: authority back in %.1f ms after %s (restart #%u, pid %d; spawn->ready %.1f ms)\n",
                               (double)(t - t_end) / 1e6, cause, restart, pid, (double)(t - t_spawn) / 1e6);
                    else
                        printf("kx-supervisor: kervixd ready in %.1f ms (pid %d)\n", (double)(t - t_spawn) / 1e6, pid);
                }
            }
            t_end = now_ns();                         /* pipe EOF: the authority is gone */
            if (f) fclose(f);
            while (waitpid(pid, &status, 0) == -1 && errno == EINTR) {}
            cause_of(status, cause, sizeof cause);
            printf("kx-supervisor: kervixd pid %d ended (%s): actuation locked (AUTHORITY_UNAVAILABLE) until it is back\n",
                   pid, cause);
        } else {
            t_end = now_ns();
            snprintf(cause, sizeof cause, "spawn_failed");
        }

        /* crash-loop guard: count restarts inside the window, including this one */
        restarts_at[restart % 64] = t_end;
        restart++;
        unsigned recent = 0;
        for (unsigned i = 0; i < restart && i < 64; i++)
            if (t_end - restarts_at[i] <= (uint64_t)window_s * 1000000000ull) recent++;
        if (recent > max_restarts) {
            printf("kx-supervisor: crash loop (%u restarts in %u s): NOT restarting. Authority stays DOWN; "
                   "actuation stays locked (fail closed). Operator action required.\n", recent - 1, window_s);
            return 3;
        }
    }

usage:
    fprintf(stderr, "usage: kx-supervisor [-t type] [-n max_restarts] [-w window_s] -- /path/kervixd [args...]\n");
    return 2;
}
