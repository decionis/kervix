/* kervixd ledger subsystem. See kxledger.h. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <qcrypto/qcrypto.h>
#include <qcrypto/qcrypto_keys.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/neutrino.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "kervix/cose.h"
#include "kervix/ledger.h"
#include "kervix/sha256.h"
#include "kxledger.h"

#define WRITER_PRIO     15
#define FSYNC_EVERY     64
#define FSYNC_MAX_NS    (20ull * 1000000ull)
#define GRANT_MAP       256
#define SIG_ALG         "eddsa-pure"

static struct {
    kxl_config_t       cfg;
    char               dir_keys[256], dir_ledger[256], path_ledger[300];
    kx_capsule_ctx_t   ctx;
    qcrypto_key_t     *priv;
    uint8_t            pk[32];
    char               kid[48];
    int                fd;
    /* ring (MPSC: producers hold kervixd's state lock; writer pops) */
    pthread_mutex_t    lock;
    pthread_cond_t     cv;
    kx_capsule_rec_t  *ring;
    uint32_t           cap, head, tail, count;
    /* writer state */
    uint64_t           last_seq, written, dropped, unsynced, fsyncs;
    uint8_t            last_id[32];
    int                have_head, healthy;
    uint64_t           first_unsynced_ns;
    struct { uint8_t grant[16]; uint8_t capsule[32]; } gmap[GRANT_MAP];
    uint32_t           gmap_next;
    uint64_t           quarantined;
} L = { .lock = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .fd = -1 };

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

/* ------------------------------------------------------------ key */

static int write_file(const char *path, const void *data, size_t n, mode_t mode, int exclusive) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | (exclusive ? O_EXCL : 0), mode);
    if (fd == -1) return -1;
    int ok = write(fd, data, n) == (ssize_t)n && fsync(fd) == 0;
    close(fd);
    return ok ? 0 : -1;
}

static int load_or_create_key(void) {
    char path[320];
    snprintf(path, sizeof path, "%s/vehicle.key", L.dir_keys);
    qcrypto_ctx_t *kctx = NULL;
    if (qcrypto_keygen_request("ed25519", NULL, 0, &kctx) != QCRYPTO_R_EOK) return -1;
    uint8_t der[128];
    int fd = open(path, O_RDONLY);
    if (fd != -1) {
        ssize_t n = read(fd, der, sizeof der);
        close(fd);
        if (n <= 0 || qcrypto_privkey_from_mem(kctx, &L.priv, der, (size_t)n, QCRYPTO_KEY_FMT_DER) != QCRYPTO_R_EOK) {
            fprintf(stderr, "kervixd: cannot load %s: refusing to run with an unknown key\n", path);
            return -1;
        }
        qcrypto_memclear(der, sizeof der);
        if (L.cfg.verbose) printf("kervixd: vehicle key loaded from %s\n", path);
    } else {
        qcrypto_key_args_t ka;
        memset(&ka, 0, sizeof ka);
        qcrypto_key_t *pub0 = NULL;
        size_t dn = sizeof der;
        if (qcrypto_keypair_init(kctx, &ka) != QCRYPTO_R_EOK ||
            qcrypto_keypair_generate(kctx, &pub0, &L.priv) != QCRYPTO_R_EOK ||
            qcrypto_privkey_to_mem(kctx, L.priv, der, &dn, QCRYPTO_KEY_FMT_DER) != QCRYPTO_R_EOK ||
            write_file(path, der, dn, 0400, 1) != 0) {
            fprintf(stderr, "kervixd: cannot create vehicle key %s: %s\n", path, strerror(errno));
            return -1;
        }
        qcrypto_memclear(der, sizeof der);
        if (pub0) qcrypto_release_key(pub0);
        printf("kervixd: generated new vehicle key %s (Ed25519, mode 0400)\n", path);
    }
    qcrypto_key_t *pub = NULL;
    uint8_t spki[64];
    size_t sn = sizeof spki;
    if (qcrypto_pubkey_from_privkey(kctx, L.priv, &pub) != QCRYPTO_R_EOK ||
        qcrypto_pubkey_to_mem(kctx, pub, spki, &sn, QCRYPTO_KEY_FMT_DER) != QCRYPTO_R_EOK || sn != 44) {
        return -1;
    }
    memcpy(L.pk, spki + 12, 32);
    qcrypto_release_key(pub);
    qcrypto_release_ctx(kctx);

    /* JWK + RFC 7638 thumbprint as kid */
    char x[48], thumb_in[160], jwk[256];
    kx_base64url(L.pk, 32, x);
    int tn = snprintf(thumb_in, sizeof thumb_in, "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"%s\"}", x);
    uint8_t th[32];
    kx_sha256(thumb_in, (size_t)tn, th);
    kx_base64url(th, 32, L.kid);
    int jn = snprintf(jwk, sizeof jwk, "{\"keys\":[{\"alg\":\"EdDSA\",\"crv\":\"Ed25519\",\"kid\":\"%s\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"%s\"}]}\n", L.kid, x);
    snprintf(path, sizeof path, "%s/vehicle.jwk.json", L.dir_keys);
    unlink(path);
    if (write_file(path, jwk, (size_t)jn, 0444, 0) != 0) return -1;
    return 0;
}

/* ------------------------------------------------------------ recovery */

static int recover(void) {
    L.fd = open(L.path_ledger, O_RDWR | O_CREAT, 0640);
    if (L.fd == -1) return -1;
    struct stat st;
    if (fstat(L.fd, &st) == -1) return -1;
    size_t size = (size_t)st.st_size;
    uint64_t records = 0;
    size_t valid = 0;
    if (size > 0) {
        uint8_t *buf = malloc(size);               /* init-time only */
        if (buf == NULL || pread(L.fd, buf, size, 0) != (ssize_t)size) { free(buf); return -1; }
        valid = kx_ledger_scan(buf, size, &records, &L.last_seq, L.last_id);
        if (valid < size) {                        /* torn or corrupt tail: move aside, never silently drop */
            char q[340];
            snprintf(q, sizeof q, "%s/quarantine-%02x%02x%02x%02x.bin", L.dir_ledger,
                     L.ctx.epoch_id[0], L.ctx.epoch_id[1], L.ctx.epoch_id[2], L.ctx.epoch_id[3]);
            write_file(q, buf + valid, size - valid, 0440, 0);
            L.quarantined = size - valid;
            if (ftruncate(L.fd, (off_t)valid) == -1 || fsync(L.fd) == -1) { free(buf); return -1; }
            printf("kervixd: ledger recovery: quarantined %zu torn byte(s) to %s\n", size - valid, q);
        }
        free(buf);
    }
    L.have_head = records > 0;
    if (lseek(L.fd, 0, SEEK_END) == -1) return -1;
    printf("kervixd: ledger %s: %" PRIu64 " record(s), last seq %" PRIu64 "\n", L.path_ledger, records, L.last_seq);
    return 0;
}

/* ------------------------------------------------------------ writer */

static const uint8_t *gmap_find(const uint8_t grant[16]) {
    for (uint32_t i = 0; i < GRANT_MAP; i++) if (memcmp(L.gmap[i].grant, grant, 16) == 0) return L.gmap[i].capsule;
    return NULL;
}
static void gmap_put(const uint8_t grant[16], const uint8_t capsule[32]) {
    memcpy(L.gmap[L.gmap_next].grant, grant, 16);
    memcpy(L.gmap[L.gmap_next].capsule, capsule, 32);
    L.gmap_next = (L.gmap_next + 1) % GRANT_MAP;
}

static int sign_envelope(const uint8_t id[32], uint8_t env[KX_COSE_ENVELOPE_LEN]) {
    uint8_t ss[KX_COSE_SIG_STRUCTURE_LEN], sig[64];
    size_t sl = sizeof sig;
    kx_cose_sig_structure(L.pk, id, ss);
    qcrypto_ctx_t *c = NULL;                       /* contexts are single-use after a one-shot op (S3) */
    qcrypto_signature_args_t sa;
    memset(&sa, 0, sizeof sa);
    sa.mode = QCRYPTO_SIGNATURE_SIGN;
    int ok = qcrypto_signature_request(SIG_ALG, NULL, 0, &c) == QCRYPTO_R_EOK &&
             qcrypto_signature_init(c, L.priv, &sa) == QCRYPTO_R_EOK &&
             qcrypto_signature_sign_oneshot(c, ss, sizeof ss, sig, &sl) == QCRYPTO_R_EOK && sl == 64;
    if (c) qcrypto_release_ctx(c);
    if (!ok) return -1;
    kx_cose_envelope(L.pk, id, sig, env);
    return 0;
}

static int write_record(kx_capsule_rec_t *r) {
    static char json[KX_CAPSULE_JCS_MAX];
    uint8_t id[32], env[KX_COSE_ENVELOPE_LEN], hdr[KX_LEDGER_HDR_LEN];
    const uint8_t *parent = L.have_head ? L.last_id : NULL;
    kx_relation_t rel = parent ? KX_REL_FOLLOWS : KX_REL_NONE;
    const uint8_t *ref = NULL;
    if (r->event == KX_EV_EPOCH && parent) rel = KX_REL_EPOCH_OPENS;
    if (r->event == KX_EV_EFFECT && r->has_grant) {
        ref = gmap_find(r->grant_id);
        if (ref && parent && memcmp(ref, parent, 32) == 0) rel = KX_REL_CONFIRMS;
    }
    r->ledger_seq = L.last_seq + 1;
    int n = kx_capsule_build(r, &L.ctx, parent, rel, ref, json, sizeof json, id);
    if (n < 0) { fprintf(stderr, "kervixd: ledger: capsule build failed (event %u)\n", r->event); return -1; }
    if (sign_envelope(id, env) != 0) { fprintf(stderr, "kervixd: ledger: signing failed\n"); return -1; }
    kx_ledger_frame(hdr, r->ledger_seq, id, json, (uint32_t)n, env);
    struct iovec iov[3];
    SETIOV(&iov[0], hdr, sizeof hdr);
    SETIOV(&iov[1], json, (size_t)n);
    SETIOV(&iov[2], env, sizeof env);
    ssize_t want = (ssize_t)(sizeof hdr + (size_t)n + sizeof env);
    if (writev(L.fd, iov, 3) != want) { fprintf(stderr, "kervixd: ledger: write failed: %s\n", strerror(errno)); return -1; }
    L.last_seq = r->ledger_seq;
    memcpy(L.last_id, id, 32);
    L.have_head = 1;
    L.written++;
    if (!L.unsynced) L.first_unsynced_ns = mono_ns();
    L.unsynced++;
    int grants_record = (r->event == KX_EV_DECISION && r->verdict == KX_VERDICT_ALLOW) ||
                        (r->event == KX_EV_ESC_RESOLVED && r->verdict == KX_VERDICT_ALLOW);
    if (grants_record && r->has_grant) gmap_put(r->grant_id, id);
    return 0;
}

static void maybe_fsync(int force) {
    if (!L.unsynced) return;
    if (force || L.unsynced >= FSYNC_EVERY || mono_ns() - L.first_unsynced_ns >= FSYNC_MAX_NS) {
        if (fsync(L.fd) == -1) { fprintf(stderr, "kervixd: ledger: fsync: %s\n", strerror(errno)); L.healthy = 0; }
        L.unsynced = 0;
        L.fsyncs++;
    }
}

static void *writer(void *arg) {
    (void)arg;
    struct sched_param sp = { .sched_priority = WRITER_PRIO };
    pthread_setschedparam(pthread_self(), SCHED_RR, &sp);
    static kx_capsule_rec_t rec;
    for (;;) {
        pthread_mutex_lock(&L.lock);
        while (L.count == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            ts.tv_nsec += 20000000;
            if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
            if (pthread_cond_timedwait(&L.cv, &L.lock, &ts) == ETIMEDOUT) {
                pthread_mutex_unlock(&L.lock);
                maybe_fsync(1);                     /* idle: make everything durable */
                pthread_mutex_lock(&L.lock);
            }
        }
        rec = L.ring[L.tail];
        pthread_mutex_unlock(&L.lock);              /* build + sign + write without holding the ring */

        if (L.cfg.slow_ms) usleep(L.cfg.slow_ms * 1000u);
        int rc = write_record(&rec);

        pthread_mutex_lock(&L.lock);
        L.tail = (L.tail + 1) % L.cap;
        L.count--;
        if (rc != 0) L.healthy = 0;                 /* K3: no audit, no action */
        pthread_mutex_unlock(&L.lock);
        maybe_fsync(0);
    }
    return NULL;
}

/* ------------------------------------------------------------ API */

uint32_t kxl_free(void) {
    pthread_mutex_lock(&L.lock);
    uint32_t f = L.cap - L.count;
    pthread_mutex_unlock(&L.lock);
    return f;
}

int kxl_submit(const kx_capsule_rec_t *rec, uint32_t keep_free) {
    pthread_mutex_lock(&L.lock);
    if (L.cap - L.count < 1u + keep_free) {
        L.dropped++;                                /* never an action: actions hold reserved slots */
        pthread_mutex_unlock(&L.lock);
        return -1;
    }
    L.ring[L.head] = *rec;
    if (L.ring[L.head].timestamp_ms == 0) L.ring[L.head].timestamp_ms = realtime_ms();
    if (!memcmp(L.ring[L.head].policy_hash, (uint8_t[32]){ 0 }, 32)) memcpy(L.ring[L.head].policy_hash, L.cfg.policy_hash, 32);
    L.head = (L.head + 1) % L.cap;
    L.count++;
    pthread_cond_signal(&L.cv);
    pthread_mutex_unlock(&L.lock);
    return 0;
}

int kxl_healthy(void) {
    pthread_mutex_lock(&L.lock);
    int ok = L.healthy && L.count * 10u < L.cap * 9u;  /* trip K3 at 90% */
    pthread_mutex_unlock(&L.lock);
    return ok;
}

void kxl_status(char *buf, size_t cap) {
    pthread_mutex_lock(&L.lock);
    char head[17];
    kx_hex(L.last_id, 8, head);
    snprintf(buf, cap, "ledger %s  records %" PRIu64 " (this boot %" PRIu64 ")  head seq %" PRIu64 " %s…  queue %u/%u  dropped %" PRIu64
             "  fsyncs %" PRIu64 "  kid %.12s…  quarantined %" PRIu64 " B\n",
             L.healthy && L.count * 10u < L.cap * 9u ? "OK" : "UNHEALTHY (K3 blocks safety actions)", L.last_seq,
             L.written, L.last_seq, L.have_head ? head : "-", L.count, L.cap, L.dropped, L.fsyncs, L.kid, L.quarantined);
    pthread_mutex_unlock(&L.lock);
}

int kxl_open(const kxl_config_t *cfg) {
    L.cfg = *cfg;
    L.cap = cfg->ring_cap ? cfg->ring_cap : 1024;
    L.ring = calloc(L.cap, sizeof *L.ring);         /* init-time only */
    if (L.ring == NULL) return -1;
    snprintf(L.dir_keys, sizeof L.dir_keys, "%s/keys", cfg->datadir);
    snprintf(L.dir_ledger, sizeof L.dir_ledger, "%s/ledger", cfg->datadir);
    snprintf(L.path_ledger, sizeof L.path_ledger, "%s/ledger.kxl", L.dir_ledger);
    mkdir(cfg->datadir, 0755);
    mkdir(L.dir_keys, 0700);
    mkdir(L.dir_ledger, 0750);
    L.ctx.vehicle_id = cfg->vehicle_id;
    L.ctx.tenant_id = cfg->tenant_id;
    qcrypto_ctx_t *rng = NULL;
    qcrypto_rng_args_t ra;
    memset(&ra, 0, sizeof ra);
    ra.drbg.pstr = (const uint8_t *)"kervixd-epoch";
    ra.drbg.pstrsize = 13;
    if (qcrypto_rng_request("drbg-ctr-256", NULL, 0, &rng) != QCRYPTO_R_EOK || qcrypto_rng_init(rng, &ra) != QCRYPTO_R_EOK ||
        qcrypto_rng_bytes(rng, L.ctx.epoch_id, 32) != QCRYPTO_R_EOK) {
        return -1;
    }
    qcrypto_release_ctx(rng);
    if (load_or_create_key() != 0 || recover() != 0) return -1;
    L.healthy = 1;

    kx_capsule_rec_t e;
    memset(&e, 0, sizeof e);
    e.event = KX_EV_EPOCH;
    e.reason = KX_R_AUTHORITY_EPOCH;
    e.quarantined_bytes = L.quarantined;
    e.restart = cfg->restart;
    memcpy(e.restart_cause, cfg->restart_cause, sizeof e.restart_cause);
    e.client_pid = getpid();
    kxl_submit(&e, 0);

    pthread_t th;
    if (pthread_create(&th, NULL, writer, NULL) != 0) return -1;
    char eh[17];
    kx_hex(L.ctx.epoch_id, 8, eh);
    printf("kervixd: ledger open, epoch %s…, vehicle key kid %s\n", eh, L.kid);
    return 0;
}
