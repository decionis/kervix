/*
 * Spike S4: minimal stand-in for `kxgw --role <role>`.
 * Listens on TCP <port> via io-sock; for each connection reads one line and
 * answers one JSON line with what the process ACTUALLY runs as: role, pid,
 * scheduling priority, secpol type, ms since boot, and the echoed line.
 * Started at boot from post_start.custom, so its readiness time is the
 * boot-to-gateway latency the host can observe through QEMU port forwards.
 *
 *   s4_gw <role> <port>
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <secpol/secpol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long ms_since_boot(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); /* QNX: monotonic starts at boot */
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: s4_gw <role> <port>\n"); return 2; }
    const char *role = argv[1];
    int port = atoi(argv[2]);
    setvbuf(stdout, NULL, _IOLBF, 0);

    int policy; struct sched_param sp;
    pthread_getschedparam(pthread_self(), &policy, &sp);
    const char *type = secpol_get_type_name(NULL, secpol_type_id());

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 8) != 0) {
        printf("kxgw[%s] FAILED to listen on :%d: %s\n", role, port, strerror(errno));
        return 1;
    }
    printf("kxgw[%s] listening on :%d pid=%d prio=%d type=%s t_boot_ms=%ld\n", role, port, getpid(),
           sp.sched_priority, type ? type : "(none)", ms_since_boot());

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        char line[128] = { 0 };
        ssize_t n = read(c, line, sizeof line - 1);
        if (n > 0) {
            line[n] = '\0';
            line[strcspn(line, "\r\n")] = '\0';
            for (char *p = line; *p; p++) if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) *p = '?';
        }
        char out[320];
        int len = snprintf(out, sizeof out,
                           "{\"role\":\"%s\",\"pid\":%d,\"prio\":%d,\"type\":\"%s\",\"t_boot_ms\":%ld,\"echo\":\"%s\"}\n",
                           role, getpid(), sp.sched_priority, type ? type : "", ms_since_boot(), line);
        (void)write(c, out, (size_t)len);
        close(c);
    }
}
