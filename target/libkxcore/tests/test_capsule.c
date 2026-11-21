/* Capsules + COSE envelope + base64url.
 *   test_capsule          unit tests
 *   test_capsule --emit [--lie]  one JSON line per capsule of a realistic stream
 *                         (--lie: one decision contradicts the policy, everything else valid):
 *       {"capsule": <capsule>, "text": "<exact bytes>", "envelope_unsigned": "<hex, sig zeroed>",
 *        "sig_structure": "<hex>"}
 *   tests/conformance/capsule-parity.mjs checks them with @decionis/verify and
 *   signs each sig_structure with the RFC 8032 key to verify the envelopes. */
#include <string.h>

#include "kervix/capsule.h"
#include "kervix/cose.h"
#include "kervix/intent.h"
#include "kervix/sha256.h"
#include "kx_test.h"

#define MS 1000000ull
#define NOW_NS (9000ull * MS)
#define NOW_MS 1795000000000LL

static kx_policy_t POL;
/* RFC 8032 test 1 public key: Node signs with the matching seed in the conformance check */
static const uint8_t PK[32] = { 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                                0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a };

static int unhex(const char *s, uint8_t *o, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = s[2 * i + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else return -1;
        }
        o[i] = (uint8_t)v;
    }
    return 0;
}

static kx_telemetry_t parked(void) {
    kx_telemetry_t t;
    memset(&t, 0, sizeof t);
    t.seq = 4242; t.mono_ns = NOW_NS - 3 * MS;
    t.v[KX_TF_GEAR] = KX_GEAR_P; t.v[KX_TF_PARK_BRAKE] = 1; t.v[KX_TF_SOC_DPCT] = 620;
    t.v[KX_TF_DRIVER_PRESENT] = 1; t.v[KX_TF_DOORS_LOCKED_MASK] = 15; t.v[KX_TF_HVAC_SETPOINT_DC] = 210;
    t.v[KX_TF_CHARGE_LIMIT_PCT] = 80;
    return t;
}
static kx_telemetry_t driving(void) {
    kx_telemetry_t t = parked();
    t.v[KX_TF_SPEED_DKPH] = 1100; t.v[KX_TF_GEAR] = KX_GEAR_D; t.v[KX_TF_PARK_BRAKE] = 0;
    return t;
}
static kx_intent_t intent(uint16_t action, uint8_t n) {
    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.abi = KX_ABI_VERSION;
    in.action = action;
    strcpy(in.actor_id, "agent:cabin-copilot");
    static const uint8_t u[16] = { 0x0b, 0x6c, 0x1e, 0x2a, 0x7f, 0x3d, 0x4a, 0x9b, 0x8c, 0x1d, 0, 0, 0, 0, 0, 0 };
    memcpy(in.intent_id, u, 16);
    in.intent_id[15] = n;
    return in;
}
static void addp(kx_intent_t *in, uint16_t k, int64_t v) { in->p[in->n_params].key = k; in->p[in->n_params++].val = v; }

static const kx_intent_ctx_t ICTX = { "6f1c2b9e-4d3a-4c8b-9a7e-2b1d0c3e4f5a", "veh-demo-0001", "ai_agent", NOW_MS };

/* A DECISION record exactly as kervixd would build it: real kx_eval on (intent, telemetry, env). */
static kx_capsule_rec_t decision(const kx_intent_t *in, const kx_telemetry_t *tel, uint8_t ledger_ok) {
    kx_capsule_rec_t r;
    memset(&r, 0, sizeof r);
    r.event = KX_EV_DECISION;
    r.has_intent = r.has_telemetry = 1;
    r.intent = *in;
    r.telemetry = *tel;
    r.env = (kx_eval_env_t){ NOW_NS, NOW_MS, 50 * MS, ledger_ok };
    r.captured_at_ms = NOW_MS;
    r.timestamp_ms = NOW_MS;
    kx_eval_result_t e;
    kx_eval(&POL, in, tel, &r.env, &e);
    r.verdict = e.verdict; r.gate = e.gate; r.reason = e.reason; r.rule_index = e.rule_index;
    if (e.rule_index >= 0) memcpy(r.rule_id, POL.rules[e.rule_index].id, KX_RULE_ID_LEN);
    if (kx_validate_intent(in) == KX_R_OK) kx_intent_hash(in, &ICTX, r.intent_hash);
    memcpy(r.policy_hash, POL.hash, 32);
    r.eval_ns = 2410; r.client_pid = 4242; r.client_type = 7;
    if (r.verdict == KX_VERDICT_ALLOW) { r.has_grant = 1; memset(r.grant_id, 0xa5, 16); r.grant_id[15] = in->intent_id[15]; }
    return r;
}

typedef struct { kx_capsule_rec_t rec; kx_relation_t rel; int parent; int ref; } step_t;
#define MAX_STEPS 24
static step_t S[MAX_STEPS];
static int NS;
static uint8_t IDS[MAX_STEPS][32];
static char JSON[MAX_STEPS][KX_CAPSULE_JCS_MAX];

static void push(kx_capsule_rec_t r, kx_relation_t rel, int parent, int ref) {
    r.ledger_seq = (uint64_t)NS + 1;
    if (!r.timestamp_ms) r.timestamp_ms = NOW_MS + NS;
    if (!memcmp(r.policy_hash, (uint8_t[32]){ 0 }, 32)) memcpy(r.policy_hash, POL.hash, 32);
    S[NS++] = (step_t){ r, rel, parent, ref };
}

static void build_stream(void) {
    NS = 0;
    kx_capsule_rec_t e;
    kx_telemetry_t p = parked(), d = driving();
    kx_intent_t door = intent(KX_ACT_BODY_DOOR_UNLOCK, 1); addp(&door, KX_P_DOOR, KX_DOOR_FRONT_LEFT);
    kx_intent_t ota = intent(KX_ACT_OTA_ECU_FLASH, 2); addp(&ota, KX_P_ECU, KX_ECU_BRAKE); ota.has_digest = 1; memset(ota.digest, 1, 32);
    kx_intent_t clim = intent(KX_ACT_CABIN_CLIMATE_SET, 3); addp(&clim, KX_P_TEMP_DC, 225);
    kx_intent_t loc = intent(KX_ACT_TELEMATICS_LOCATION_SHARE, 4); addp(&loc, KX_P_RECIPIENT, KX_RECIPIENT_FLEET_OPERATOR); addp(&loc, KX_P_DURATION_S, 3600);

    memset(&e, 0, sizeof e); e.event = KX_EV_EPOCH; e.reason = KX_R_AUTHORITY_EPOCH;
    push(e, KX_REL_NONE, -1, -1);                                                     /* 0 epoch (genesis) */
    push(decision(&door, &p, 1), KX_REL_FOLLOWS, 0, -1);                              /* 1 ALLOW */
    e = S[1].rec; e.event = KX_EV_EFFECT; e.effect_ok = 1; e.has_telemetry = 0;
    memset(e.request_digest, 0x11, 32); memset(e.response_digest, 0x22, 32);
    push(e, KX_REL_CONFIRMS, 1, 1);                                                   /* 2 effect confirms #1 */
    push(decision(&ota, &d, 1), KX_REL_FOLLOWS, 2, -1);                               /* 3 BLOCK R156 */
    push(decision(&ota, &p, 1), KX_REL_FOLLOWS, 3, -1);                               /* 4 ESCALATE */
    S[4].rec.escalation_id = 7;
    e = S[4].rec; e.event = KX_EV_ESC_RESOLVED; e.verdict = KX_VERDICT_ALLOW; e.reason = KX_R_HUMAN_APPROVED;
    e.human = 1; strcpy(e.approver, "hmi:driver-seat(pid 99)"); e.has_grant = 1; memset(e.grant_id, 0x77, 16);
    push(e, KX_REL_FOLLOWS, 4, -1);                                                   /* 5 approved */
    push(decision(&clim, &d, 1), KX_REL_FOLLOWS, 5, -1);                              /* 6 ALLOW climate */
    kx_telemetry_t stale = p; stale.mono_ns = NOW_NS - 200 * MS;
    push(decision(&door, &stale, 1), KX_REL_FOLLOWS, 6, -1);                          /* 7 BLOCK K1 */
    e = S[6].rec; e.event = KX_EV_EFFECT; e.effect_ok = 1; e.has_telemetry = 0;
    memset(e.request_digest, 0x33, 32); memset(e.response_digest, 0x44, 32);
    push(e, KX_REL_FOLLOWS, 7, 6);                                                    /* 8 effect cites #6 */
    e = S[1].rec; e.event = KX_EV_GRANT_REFUSED; e.reason = KX_R_GRANT_SPENT; e.has_telemetry = 0;
    push(e, KX_REL_FOLLOWS, 8, -1);                                                   /* 9 replay refused */
    e = S[6].rec; e.event = KX_EV_GRANT_EXPIRED; e.reason = KX_R_GRANT_EXPIRED; e.has_telemetry = 0;
    push(e, KX_REL_FOLLOWS, 9, -1);                                                   /* 10 expired unused */
    push(decision(&loc, &p, 1), KX_REL_FOLLOWS, 10, -1);                             /* 11 ESCALATE location */
    S[11].rec.escalation_id = 8;
    e = S[11].rec; e.event = KX_EV_ESC_RESOLVED; e.verdict = KX_VERDICT_BLOCK; e.reason = KX_R_HUMAN_DENIED;
    e.human = 1; strcpy(e.approver, "hmi:driver-seat");
    push(e, KX_REL_FOLLOWS, 11, -1);                                                  /* 12 denied */
    kx_intent_t loc2 = intent(KX_ACT_TELEMATICS_LOCATION_SHARE, 6); addp(&loc2, KX_P_RECIPIENT, KX_RECIPIENT_ROADSIDE_ASSIST); addp(&loc2, KX_P_DURATION_S, 600);
    push(decision(&loc2, &p, 1), KX_REL_FOLLOWS, 12, -1);                            /* 13 ESCALATE location */
    S[13].rec.escalation_id = 9;
    e = S[13].rec; e.event = KX_EV_ESC_RESOLVED; e.verdict = KX_VERDICT_BLOCK; e.reason = KX_R_ESCALATION_TIMEOUT;
    push(e, KX_REL_FOLLOWS, 13, -1);                                                  /* 14 timed out */
    kx_intent_t ota2 = intent(KX_ACT_OTA_ECU_FLASH, 7); addp(&ota2, KX_P_ECU, KX_ECU_ADAS); ota2.has_digest = 1; memset(ota2.digest, 2, 32);
    push(decision(&ota2, &p, 1), KX_REL_FOLLOWS, 14, -1);                            /* 15 ESCALATE ota */
    S[15].rec.escalation_id = 10;
    e = S[15].rec; e.event = KX_EV_ESC_RESOLVED; e.verdict = KX_VERDICT_BLOCK; e.reason = KX_R_R156_NOT_SAFE_STATE;
    e.human = 1; strcpy(e.approver, "hmi:driver-seat");
    push(e, KX_REL_FOLLOWS, 15, -1);                                                  /* 16 approved but re-blocked */
    e = S[6].rec; e.event = KX_EV_EFFECT; e.effect_ok = 0; e.reason = KX_R_ACTUATOR_FAILED; e.has_telemetry = 0; memset(e.request_digest, 0x55, 32);
    push(e, KX_REL_FOLLOWS, 16, 6);                                                   /* 17 actuator failed */
    kx_intent_t bad = intent(KX_ACT_CABIN_CLIMATE_SET, 5); addp(&bad, KX_P_TEMP_DC, 999);
    push(decision(&bad, &p, 1), KX_REL_FOLLOWS, 17, -1);                              /* 18 BLOCK K4 (recorded as received) */
    memset(&e, 0, sizeof e); e.event = KX_EV_EPOCH; e.reason = KX_R_AUTHORITY_EPOCH; e.quarantined_bytes = 117; e.restart = 2; memcpy(e.restart_cause, "SIGKILL", 8);
    push(e, KX_REL_EPOCH_OPENS, 18, -1);                                              /* 19 restart epoch */
    /* escalation ids restart at 1 per epoch: #7 again, legitimately, after the restart */
    kx_intent_t loc3 = intent(KX_ACT_TELEMATICS_LOCATION_SHARE, 8); addp(&loc3, KX_P_RECIPIENT, KX_RECIPIENT_EMERGENCY_CONTACT); addp(&loc3, KX_P_DURATION_S, 900);
    push(decision(&loc3, &p, 1), KX_REL_FOLLOWS, 19, -1);                            /* 20 ESCALATE #7 (new epoch) */
    S[20].rec.escalation_id = 7;
    e = S[20].rec; e.event = KX_EV_ESC_RESOLVED; e.verdict = KX_VERDICT_BLOCK; e.reason = KX_R_HUMAN_DENIED;
    e.human = 1; strcpy(e.approver, "hmi:driver-seat");
    push(e, KX_REL_FOLLOWS, 20, -1);                                                  /* 21 denied */
    memset(&e, 0, sizeof e); e.event = KX_EV_POLICY; e.reason = KX_R_POLICY_ACTIVATED; e.human = 1;
    memcpy(e.prev_policy_hash, POL.hash, 32); memset(e.policy_hash, 0xb2, 32);
    strcpy(e.approver, "author:policy-team approver:safety-board");
    push(e, KX_REL_FOLLOWS, 21, -1);                                                  /* 22 signed policy activated */
}

static kx_capsule_ctx_t ctx(void) {
    kx_capsule_ctx_t c = { "veh-demo-0001", "6f1c2b9e-4d3a-4c8b-9a7e-2b1d0c3e4f5a", { 0 } };
    memset(c.epoch_id, 0xe1, 32);
    return c;
}

static int build_all(void) {
    kx_capsule_ctx_t c = ctx();
    for (int i = 0; i < NS; i++) {
        const uint8_t *parent = S[i].parent >= 0 ? IDS[S[i].parent] : NULL;
        const uint8_t *ref = S[i].ref >= 0 ? IDS[S[i].ref] : NULL;
        if (S[i].rec.event == KX_EV_EPOCH && i > 0) memset(c.epoch_id, 0xe2, 32); /* new epoch after restart */
        if (kx_capsule_build(&S[i].rec, &c, parent, S[i].rel, ref, JSON[i], sizeof JSON[i], IDS[i]) < 0) {
            fprintf(stderr, "capsule %d failed to build\n", i);
            return -1;
        }
    }
    return 0;
}

/* lie: record the OTA-at-110-km/h decision (#3) as ALLOW, then hash and chain
 * everything validly: what a compromised authority holding the key could sign */
static int emit(int lie) {
    build_stream();
    if (lie == 2) {           /* the recorded intent hash does not belong to the recorded intent */
        S[1].rec.intent_hash[0] ^= 0xff;
        S[2].rec.intent_hash[0] ^= 0xff;
    }
    if (lie == 3) {           /* escalation #9 resolved a second time in the same epoch */
        S[16].rec.escalation_id = 9;
    }
    if (lie == 1) {
        S[3].rec.verdict = KX_VERDICT_ALLOW;
        S[3].rec.reason = KX_R_OK;
        S[3].rec.has_grant = 1;
        memset(S[3].rec.grant_id, 0x99, 16);
    }
    if (build_all() != 0) return 1;
    for (int i = 0; i < NS; i++) {
        uint8_t ss[KX_COSE_SIG_STRUCTURE_LEN], env[KX_COSE_ENVELOPE_LEN], zero[64] = { 0 };
        kx_cose_sig_structure(PK, IDS[i], ss);
        kx_cose_envelope(PK, IDS[i], zero, env);
        printf("{\"capsule\":%s,\"text\":\"", JSON[i]);
        for (const char *c = JSON[i]; *c; c++) { if (*c == '"' || *c == '\\') putchar('\\'); putchar(*c); }
        printf("\",\"sig_structure\":\"");
        for (size_t k = 0; k < sizeof ss; k++) printf("%02x", ss[k]);
        printf("\",\"envelope_unsigned\":\"");
        for (size_t k = 0; k < sizeof env; k++) printf("%02x", env[k]);
        printf("\"}\n");
    }
    return 0;
}

static void test_cose_and_b64(void) {
    /* pinned draft-04 Producer Envelope vector */
    uint8_t cid[32], sig[64], env[KX_COSE_ENVELOPE_LEN], expect[KX_COSE_ENVELOPE_LEN];
    unhex("eea9ad9434749a6771a88fefed0a116fec88e05dbf88f3f807dd547b17efe914", cid, 32);
    unhex("0c9ff70e4cab6d02cee0be0a6fc49ce7bfd63333d7474d943a497d9bfc0f0b8150a328ba57bee10a0ce19ddf28e31a199038ff2886042392e22c5d063474e30d", sig, 64);
    unhex("d284584ca301270378236170706c69636174696f6e2f6167656e742d616374696f6e2d63617073756c652d6964045820d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511aa05820eea9ad9434749a6771a88fefed0a116fec88e05dbf88f3f807dd547b17efe91458400c9ff70e4cab6d02cee0be0a6fc49ce7bfd63333d7474d943a497d9bfc0f0b8150a328ba57bee10a0ce19ddf28e31a199038ff2886042392e22c5d063474e30d",
          expect, KX_COSE_ENVELOPE_LEN);
    kx_cose_envelope(PK, cid, sig, env);
    KX_CHECK(memcmp(env, expect, KX_COSE_ENVELOPE_LEN) == 0);

    char b[16];
    struct { const char *in, *out; } v[] = { { "", "" }, { "f", "Zg" }, { "fo", "Zm8" }, { "foo", "Zm9v" },
                                             { "foob", "Zm9vYg" }, { "fooba", "Zm9vYmE" }, { "foobar", "Zm9vYmFy" } };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        KX_CHECK(kx_base64url((const uint8_t *)v[i].in, strlen(v[i].in), b) == strlen(v[i].out));
        KX_CHECK_STR(b, v[i].out);
    }
    const uint8_t uu[3] = { 0xfb, 0xff, 0xbf };   /* url alphabet: '-' and '_' instead of '+' and '/' */
    kx_base64url(uu, 3, b);
    KX_CHECK_STR(b, "-_-_");
}

static void test_capsules(void) {
    build_stream();
    KX_CHECK(build_all() == 0);
    /* identity = sha256(capsule without capsule_id); recompute by removing the member */
    for (int i = 0; i < NS; i++) {
        char pre[KX_CAPSULE_JCS_MAX];
        const char *k = strstr(JSON[i], ",\"capsule_id\":\"");
        KX_CHECK(k != NULL);
        if (!k) continue;
        size_t a = (size_t)(k - JSON[i]), L = strlen(",\"capsule_id\":\"") + 64 + 1;
        memcpy(pre, JSON[i], a);
        strcpy(pre + a, JSON[i] + a + L);
        uint8_t h[32];
        kx_sha256(pre, strlen(pre), h);
        KX_CHECK(memcmp(h, IDS[i], 32) == 0);
    }
    /* deterministic */
    uint8_t first[MAX_STEPS][32];
    memcpy(first, IDS, sizeof first);
    build_all();
    KX_CHECK(memcmp(first, IDS, sizeof first) == 0);
    /* any change to the evidence changes the identity */
    S[3].rec.telemetry.v[KX_TF_SPEED_DKPH] = 0;
    build_all();
    KX_CHECK(memcmp(first[3], IDS[3], 32) != 0);
    build_stream();
    build_all();

    /* spot checks against the frozen mapping */
    KX_CHECK(strstr(JSON[1], "\"effect\":{\"irreversibility_class\":\"two_way\",\"status\":\"planned\",\"type\":\"vehicle.body.door.unlock\"}") != NULL);
    KX_CHECK(strstr(JSON[1], "\"verdict_class\"") == NULL);                       /* ALLOW: authorized, not executed */
    KX_CHECK(strstr(JSON[2], "\"relation\":\"confirms\"") && strstr(JSON[2], "\"verdict_class\":\"executed\""));
    KX_CHECK(strstr(JSON[2], "\"references\"") == NULL);                          /* parent is the decision */
    KX_CHECK(strstr(JSON[8], "\"citation_purpose\":\"responds_to\""));            /* decision is not the parent */
    KX_CHECK(strstr(JSON[3], "\"verdict_class\":\"blocked\"") && strstr(JSON[3], "\"reason\":\"R156_NOT_SAFE_STATE\""));
    KX_CHECK(strstr(JSON[5], "\"approver\":\"human\"") && strstr(JSON[5], "\"human_disposed\":true"));
    KX_CHECK(strstr(JSON[7], "com.kervix.constitution.k1_stale"));
    KX_CHECK(strstr(JSON[16], "\"verdict_class\":\"blocked\"") && strstr(JSON[16], "\"approver\":\"policy\""));
    KX_CHECK(strstr(JSON[17], "\"status\":\"failed\"") && strstr(JSON[17], "\"effect_mode\":\"dispatched_unconfirmed\""));
    KX_CHECK(strstr(JSON[19], "\"relation\":\"epoch_opens\"") && strstr(JSON[19], "\"quarantined_bytes\":117"));
    /* a supervisor restart is recorded, in JCS key order (reason < recovery < ...) */
    KX_CHECK(strstr(JSON[19], "\"reason\":\"AUTHORITY_EPOCH\",\"recovery\":{\"cause\":\"SIGKILL\",\"restart\":2}") != NULL);
    KX_CHECK(strstr(JSON[0], "\"recovery\"") == NULL);                    /* first start: no recovery */
    KX_CHECK(strstr(JSON[12], "\"verdict_class\":\"denied\"") && strstr(JSON[14], "\"verdict_class\":\"expired\""));
    KX_CHECK(strstr(JSON[0], "\"ledger_mode\":\"standalone\"") && strstr(JSON[0], "\"chain\"") == NULL);
    /* policy activation: fyi, approved by humans (author + approver), authority = the NEW policy */
    KX_CHECK(strstr(JSON[22], "\"action_id\":\"policy:b2b2b2b2b2b2b2b2\"") && strstr(JSON[22], "\"action_type\":\"fyi\""));
    KX_CHECK(strstr(JSON[22], "\"approver\":\"human\"") && strstr(JSON[22], "\"verdict_class\":\"resolved\"") && strstr(JSON[22], "\"human_disposed\":true"));
    KX_CHECK(strstr(JSON[22], "\"authority\":\"sha256:b2b2") && strstr(JSON[22], "\"previous_policy_hash\":\"sha256:8539d711"));
    KX_CHECK(strstr(JSON[22], "\"event\":\"policy_activated\"") && strstr(JSON[22], "\"reason\":\"POLICY_ACTIVATED\""));

    /* REPLAY: every recorded decision reproduces bit-for-bit from its evidence */
    int decisions = 0;
    for (int i = 0; i < NS; i++) {
        if (S[i].rec.event != KX_EV_DECISION) continue;
        decisions++;
        kx_eval_result_t r;
        kx_capsule_replay(&POL, &S[i].rec, &r);
        KX_CHECK(r.verdict == S[i].rec.verdict && r.reason == S[i].rec.reason && r.rule_index == S[i].rec.rule_index);
    }
    KX_CHECK(decisions == 10);  /* steps 1,3,4,6,7,11,13,15,18,20 */

    /* invalid records never produce a capsule */
    char out[KX_CAPSULE_JCS_MAX];
    uint8_t id[32];
    kx_capsule_ctx_t c = ctx();
    kx_capsule_rec_t r = S[1].rec;
    r.event = 0;                  KX_CHECK(kx_capsule_build(&r, &c, NULL, KX_REL_NONE, NULL, out, sizeof out, id) == -1);
    r = S[1].rec; r.has_intent = 0; KX_CHECK(kx_capsule_build(&r, &c, NULL, KX_REL_NONE, NULL, out, sizeof out, id) == -1);
    r = S[1].rec; r.timestamp_ms = -1; KX_CHECK(kx_capsule_build(&r, &c, NULL, KX_REL_NONE, NULL, out, sizeof out, id) == -1);
    r = S[1].rec;                 KX_CHECK(kx_capsule_build(&r, &c, NULL, KX_REL_NONE, NULL, out, 256, id) == -1);
}

int main(int argc, char **argv) {
    if (kx_policy_build_default(&POL) != 0) return 1;
    if (argc > 1 && strcmp(argv[1], "--emit") == 0)
        return emit(argc > 2 && strcmp(argv[2], "--lie") == 0 ? 1 : argc > 2 && strcmp(argv[2], "--lie-hash") == 0 ? 2
                    : argc > 2 && strcmp(argv[2], "--lie-twice") == 0 ? 3 : 0);
    test_cose_and_b64();
    test_capsules();
    KX_TEST_DONE();
}
