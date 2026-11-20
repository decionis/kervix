/*
 * Spike S3: can QNX's qcrypto (openssl-3 plugin) do what the Kervix ledger
 * needs?  Ed25519 sign/verify with an imported key, fresh key generation,
 * raw public-key export, and a DRBG for grant ids / grant MAC keys.
 *
 * Decisive test: Ed25519 is deterministic, so signing the draft-04 Producer
 * Envelope Sig_structure with the RFC 8032 test key must reproduce the
 * PINNED vector's signature byte-for-byte (same vector spike S5 used).
 * Output: "PASS|FAIL <check>" lines, then "S3 RESULT: PASS|FAIL".
 */
#include <inttypes.h>
#include <qcrypto/qcrypto.h>
#include <qcrypto/qcrypto_error.h>
#include <qcrypto/qcrypto_keys.h>
#include <stdio.h>
#include <string.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>

static int failures;
static void check(int ok, const char *what, const char *detail) {
    printf("%s  %s%s%s\n", ok ? "PASS" : "FAIL", what, detail ? "  — " : "", detail ? detail : "");
    if (!ok) failures++;
}
static void hex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}
static int unhex(const char *s, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}
#define QC(call, what)                                                                     \
    do {                                                                                   \
        int _r = (call);                                                                   \
        if (_r != QCRYPTO_R_EOK) {                                                         \
            printf("FAIL  %s  — %s (%d)\n", what, qcrypto_strerror(_r), _r);               \
            failures++;                                                                    \
            goto out;                                                                      \
        }                                                                                  \
    } while (0)

/* Pinned draft-04 Producer Envelope vector (Decionis interop/scitt/aac-v04). */
static const char *SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
static const char *PUB  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static const char *CID  = "eea9ad9434749a6771a88fefed0a116fec88e05dbf88f3f807dd547b17efe914";
static const char *SIG  = "0c9ff70e4cab6d02cee0be0a6fc49ce7bfd63333d7474d943a497d9bfc0f0b81"
                          "50a328ba57bee10a0ce19ddf28e31a199038ff2886042392e22c5d063474e30d";
static const char CT[] = "application/agent-action-capsule-id";
/* qcrypto names: key type "ed25519", signature algorithm "eddsa-pure" (PureEdDSA, RFC 8032) */
#define SIG_ALG "eddsa-pure"

/* Sig_structure = ["Signature1", bstr protected, bstr h'', bstr payload] (fixed shape) */
static size_t sig_structure(const uint8_t pk[32], const uint8_t cid[32], uint8_t *out) {
    uint8_t prot[76];
    size_t p = 0;
    prot[p++] = 0xa3; prot[p++] = 0x01; prot[p++] = 0x27; prot[p++] = 0x03;
    prot[p++] = 0x78; prot[p++] = (uint8_t)(sizeof CT - 1);
    memcpy(prot + p, CT, sizeof CT - 1); p += sizeof CT - 1;
    prot[p++] = 0x04; prot[p++] = 0x58; prot[p++] = 0x20;
    memcpy(prot + p, pk, 32); p += 32;
    size_t o = 0;
    out[o++] = 0x84; out[o++] = 0x6a; memcpy(out + o, "Signature1", 10); o += 10;
    out[o++] = 0x58; out[o++] = (uint8_t)p; memcpy(out + o, prot, p); o += p;
    out[o++] = 0x40;
    out[o++] = 0x58; out[o++] = 0x20; memcpy(out + o, cid, 32); o += 32;
    return o;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    qcrypto_ctx_t *kctx = NULL, *sctx = NULL, *vctx = NULL, *rctx = NULL, *dctx = NULL, *gctx = NULL;
    qcrypto_key_t *priv = NULL, *pub = NULL, *gpriv = NULL, *gpub = NULL;
    uint8_t seed[32], pk_expect[32], cid[32], sig_expect[64], buf[160], sig[64], tmp[128];
    char hx[129];
    unhex(SEED, seed, 32); unhex(PUB, pk_expect, 32); unhex(CID, cid, 32); unhex(SIG, sig_expect, 64);

    QC(qcrypto_init(QCRYPTO_INIT_LAZY, NULL), "qcrypto_init");
    check(qcrypto_signature_supported(SIG_ALG, NULL, 0) == QCRYPTO_R_EOK, "eddsa-pure signature supported", NULL);
    check(qcrypto_keygen_supported("ed25519", NULL, 0) == QCRYPTO_R_EOK, "ed25519 keygen supported", NULL);
    check(qcrypto_rng_supported("drbg-ctr-256", NULL, 0) == QCRYPTO_R_EOK, "drbg-ctr-256 supported", NULL);

    /* 1. import the RFC 8032 seed as PKCS#8 DER (same encoding Node/OpenSSL use) */
    static const uint8_t pkcs8_prefix[16] = { 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                                              0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };
    uint8_t der[48];
    memcpy(der, pkcs8_prefix, 16); memcpy(der + 16, seed, 32);
    QC(qcrypto_keygen_request("ed25519", NULL, 0, &kctx), "keygen_request(ed25519)");
    QC(qcrypto_privkey_from_mem(kctx, &priv, der, sizeof der, QCRYPTO_KEY_FMT_DER), "privkey_from_mem(PKCS#8 DER)");
    QC(qcrypto_pubkey_from_privkey(kctx, priv, &pub), "pubkey_from_privkey");

    /* 2. raw public key export: SPKI DER is a fixed 12-byte prefix + 32-byte key */
    size_t ksz = sizeof tmp;
    QC(qcrypto_pubkey_to_mem(kctx, pub, tmp, &ksz, QCRYPTO_KEY_FMT_DER), "pubkey_to_mem(DER)");
    check(ksz == 44 && memcmp(tmp + 12, pk_expect, 32) == 0, "derived public key == RFC 8032 test vector", NULL);

    /* 3. decisive: reproduce the pinned COSE_Sign1 signature */
    size_t n = sig_structure(pk_expect, cid, buf);
    qcrypto_signature_args_t sa;
    memset(&sa, 0, sizeof sa);
    sa.mode = QCRYPTO_SIGNATURE_SIGN;
    QC(qcrypto_signature_request(SIG_ALG, NULL, 0, &sctx), "signature_request(ed25519)");
    QC(qcrypto_signature_init(sctx, priv, &sa), "signature_init(sign)");
    size_t slen = sizeof sig;
    QC(qcrypto_signature_sign_oneshot(sctx, buf, n, sig, &slen), "sign_oneshot");
    hex(sig, 64, hx);
    check(slen == 64 && memcmp(sig, sig_expect, 64) == 0,
          "Ed25519 over draft-04 Sig_structure == PINNED vector (byte-for-byte)", hx);

    /* 4. verify, including a tampered message */
    memset(&sa, 0, sizeof sa);
    sa.mode = QCRYPTO_SIGNATURE_VERIFY;
    QC(qcrypto_signature_request(SIG_ALG, NULL, 0, &vctx), "signature_request(verify)");
    QC(qcrypto_signature_init(vctx, pub, &sa), "signature_init(verify)");
    int status = -1;
    QC(qcrypto_signature_verify_oneshot(vctx, buf, n, sig, slen, &status), "verify_oneshot");
    /* `status` values are undocumented: calibrate "accept" on the pinned,
     * independently verified (spike S5, Node) signature, then require a
     * tampered message to produce a different outcome. */
    int good_status = status;
    buf[n - 1] ^= 1; /* flip one bit of the capsule id */
    int bad_status = -12345;
    /* a context is single-use after a one-shot op (-412 otherwise): fresh ctx */
    qcrypto_ctx_t *tctx = NULL;
    QC(qcrypto_signature_request(SIG_ALG, NULL, 0, &tctx), "signature_request(verify tampered)");
    QC(qcrypto_signature_init(tctx, pub, &sa), "signature_init(verify tampered)");
    int vr = qcrypto_signature_verify_oneshot(tctx, buf, n, sig, slen, &bad_status);
    qcrypto_release_ctx(tctx);
    printf("INFO  verify status: pinned-valid=%d tampered=%d (call rc=%d)\n", good_status, bad_status, vr);
    check(good_status == 1, "verify(pinned valid signature) accepted (status 1)", NULL);
    check(vr == QCRYPTO_R_EOK && bad_status != good_status, "verify(tampered) rejected by the signature check itself", NULL);
    buf[n - 1] ^= 1;

    /* 5. DRBG: grant ids and per-boot MAC keys */
    qcrypto_rng_args_t ra;
    memset(&ra, 0, sizeof ra);
    ra.drbg.pstr = (const uint8_t *)"kervix-grant"; ra.drbg.pstrsize = 12;
    QC(qcrypto_rng_request("drbg-ctr-256", NULL, 0, &rctx), "rng_request(drbg-ctr-256)");
    QC(qcrypto_rng_init(rctx, &ra), "rng_init");
    uint8_t r1[32], r2[32];
    QC(qcrypto_rng_bytes(rctx, r1, sizeof r1), "rng_bytes #1");
    QC(qcrypto_rng_bytes(rctx, r2, sizeof r2), "rng_bytes #2");
    int zero = 1;
    for (int i = 0; i < 32; i++) if (r1[i]) zero = 0;
    check(!zero && memcmp(r1, r2, 32) != 0, "DRBG produces distinct non-zero output", NULL);

    /* 6. fresh vehicle key: generate, export raw pubkey, sign/verify round trip */
    QC(qcrypto_keygen_request("ed25519", NULL, 0, &gctx), "keygen_request(fresh)");
    {
        qcrypto_key_args_t ka;
        memset(&ka, 0, sizeof ka); /* Ed25519 has no parameters */
        QC(qcrypto_keypair_init(gctx, &ka), "keypair_init");
    }
    QC(qcrypto_keypair_generate(gctx, &gpub, &gpriv), "keypair_generate");
    ksz = sizeof tmp;
    QC(qcrypto_pubkey_to_mem(gctx, gpub, tmp, &ksz, QCRYPTO_KEY_FMT_DER), "pubkey_to_mem(fresh)");
    check(ksz == 44 && memcmp(tmp + 12, pk_expect, 32) != 0, "fresh key exports a 32-byte raw public key", NULL);
    {
        qcrypto_ctx_t *s2 = NULL, *v2 = NULL;
        memset(&sa, 0, sizeof sa); sa.mode = QCRYPTO_SIGNATURE_SIGN;
        QC(qcrypto_signature_request(SIG_ALG, NULL, 0, &s2), "sign ctx (fresh)");
        QC(qcrypto_signature_init(s2, gpriv, &sa), "sign init (fresh)");
        n = sig_structure(tmp + 12, cid, buf);
        slen = sizeof sig;
        QC(qcrypto_signature_sign_oneshot(s2, buf, n, sig, &slen), "sign (fresh)");
        memset(&sa, 0, sizeof sa); sa.mode = QCRYPTO_SIGNATURE_VERIFY;
        QC(qcrypto_signature_request(SIG_ALG, NULL, 0, &v2), "verify ctx (fresh)");
        QC(qcrypto_signature_init(v2, gpub, &sa), "verify init (fresh)");
        status = -1;
        QC(qcrypto_signature_verify_oneshot(v2, buf, n, sig, slen, &status), "verify (fresh)");
        check(status == good_status, "fresh key sign/verify round trip", NULL);

        /* 7. rough cost of one envelope signature incl. per-op context setup
         *    (contexts are single-use after a one-shot op). QEMU/TCG: indicative only. */
        uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
        int ok_ops = 0;
        uint64_t t0 = ClockCycles();
        for (int i = 0; i < 200; i++) {
            qcrypto_ctx_t *c = NULL;
            qcrypto_signature_args_t a2;
            memset(&a2, 0, sizeof a2);
            a2.mode = QCRYPTO_SIGNATURE_SIGN;
            slen = sizeof sig;
            if (qcrypto_signature_request(SIG_ALG, NULL, 0, &c) == QCRYPTO_R_EOK &&
                qcrypto_signature_init(c, gpriv, &a2) == QCRYPTO_R_EOK &&
                qcrypto_signature_sign_oneshot(c, buf, n, sig, &slen) == QCRYPTO_R_EOK && slen == 64) {
                ok_ops++;
            }
            if (c) qcrypto_release_ctx(c);
        }
        uint64_t dt = ClockCycles() - t0;
        check(ok_ops == 200, "200/200 envelope signatures with per-op contexts", NULL);
        printf("INFO  ed25519 envelope sign: %" PRIu64 " us/op (request+init+sign+release; emulated on QEMU)\n",
               dt * 1000000u / cps / 200u);
        qcrypto_release_ctx(s2);
        qcrypto_release_ctx(v2);
    }

    /* 8. qcrypto SHA-256 agrees with FIPS 180-4 "abc" */
    {
        uint8_t d[32]; size_t dl = sizeof d;
        QC(qcrypto_digest_request("sha256", NULL, 0, &dctx), "digest_request(sha256)");
        QC(qcrypto_digest(dctx, (const uint8_t *)"abc", 3, d, &dl), "digest(abc)");
        hex(d, 32, hx);
        check(strcmp(hx, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
              "qcrypto sha256(abc) == FIPS 180-4", NULL);
    }

out:
    if (priv) qcrypto_release_key(priv);
    if (pub) qcrypto_release_key(pub);
    if (gpriv) qcrypto_release_key(gpriv);
    if (gpub) qcrypto_release_key(gpub);
    if (sctx) qcrypto_release_ctx(sctx);
    if (vctx) qcrypto_release_ctx(vctx);
    if (rctx) qcrypto_release_ctx(rctx);
    if (dctx) qcrypto_release_ctx(dctx);
    if (kctx) qcrypto_release_ctx(kctx);
    if (gctx) qcrypto_release_ctx(gctx);
    qcrypto_uninit();
    printf("S3 RESULT: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
