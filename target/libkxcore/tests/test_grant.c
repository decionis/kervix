/* Grant table: one test per security property in kervix/grant.h, plus a
 * randomized sweep proving no grant is ever redeemed twice. */
#include <string.h>

#include "kervix/policy.h"
#include "kervix/grant.h"
#include "kx_test.h"

#define MS 1000000ull
#define T0 (5000ull * MS)

static kx_policy_t POL;
static kx_grant_table_t T; /* ~250 KB: static */
static const kx_client_t AGENT = { 7, 4242 };
static const kx_client_t OTHER = { 7, 4343 };   /* same type, different process */
static const kx_client_t ROGUE = { 9, 4242 };   /* same pid number, different type */
static const uint8_t KEY[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const uint8_t PHASH[32] = { 0xaa, 0xbb, 0xcc };

static kx_telemetry_t parked(void) {
    kx_telemetry_t t;
    memset(&t, 0, sizeof t);
    t.mono_ns = T0;
    t.v[KX_TF_GEAR] = KX_GEAR_P;
    t.v[KX_TF_PARK_BRAKE] = 1;
    t.v[KX_TF_SOC_DPCT] = 600;
    t.v[KX_TF_DRIVER_PRESENT] = 1;
    t.v[KX_TF_HVAC_SETPOINT_DC] = 210;
    t.v[KX_TF_CHARGE_LIMIT_PCT] = 80;
    return t;
}
static kx_intent_t door(uint8_t which) {
    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.abi = KX_ABI_VERSION;
    in.action = KX_ACT_BODY_DOOR_UNLOCK;
    strcpy(in.actor_id, "agent:cabin-copilot");
    in.intent_id[6] = 0x40; in.intent_id[8] = 0x80; in.intent_id[15] = which;
    in.n_params = 1;
    in.p[0].key = KX_P_DOOR;
    in.p[0].val = which % KX_DOOR__COUNT;
    return in;
}
static void gid(uint8_t id[16], uint32_t n) {
    memset(id, 0x5a, 16);
    id[0] = (uint8_t)n; id[1] = (uint8_t)(n >> 8); id[2] = (uint8_t)(n >> 16); id[3] = (uint8_t)(n >> 24);
}

/* Issue a door-unlock grant via the real policy path. */
static kx_grant_t issue(uint32_t n, const kx_intent_t *in, uint32_t ttl_ms, uint64_t now) {
    kx_telemetry_t tel = parked();
    kx_eval_env_t env = { now, 0, 50 * MS, 1 };
    kx_eval_result_t r;
    KX_CHECK(kx_eval(&POL, in, &tel, &env, &r) == KX_VERDICT_ALLOW);
    uint8_t ih[32] = { (uint8_t)n }, id[16];
    gid(id, n);
    kx_grant_t g;
    memset(&g, 0, sizeof g);
    KX_CHECK(kx_grant_issue(&T, in, ih, PHASH, r.rule_index, ttl_ms, AGENT, id, now, &g) == KX_R_OK);
    return g;
}

static uint16_t redeem(const kx_grant_t *g, const kx_intent_t *cmd, kx_client_t who, uint64_t now,
                       const kx_telemetry_t *tel) {
    return kx_grant_redeem(&T, g, cmd, who, now, &POL, tel);
}

static void test_happy_and_replay(void) {
    kx_grant_table_init(&T, KEY);
    kx_intent_t in = door(1);
    kx_telemetry_t tel = parked();
    kx_grant_t g = issue(1, &in, 250, T0);
    KX_CHECK(T.outstanding == 1);
    KX_CHECK(g.not_after_mono_ns == T0 + 250 * MS);
    KX_CHECK(redeem(&g, &in, AGENT, T0 + 10 * MS, &tel) == KX_R_OK);
    KX_CHECK(T.outstanding == 0);
    KX_CHECK(redeem(&g, &in, AGENT, T0 + 11 * MS, &tel) == KX_R_GRANT_SPENT);   /* replay */
}

static void test_forgery(void) {
    kx_grant_table_init(&T, KEY);
    kx_intent_t in = door(2);
    kx_telemetry_t tel = parked();
    kx_grant_t g = issue(2, &in, 250, T0);
    /* flipping any authenticated byte breaks the MAC */
    const size_t fields[] = { 0, 16, 48, 80, 88, 92, 96, 104, 112, 120 };
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        kx_grant_t f = g;
        ((uint8_t *)&f)[fields[i]] ^= 0x01;
        KX_CHECK(redeem(&f, &in, AGENT, T0 + MS, &tel) == KX_R_GRANT_MAC);
    }
    /* stretching the deadline is a forgery, not an extension */
    kx_grant_t f = g;
    f.not_after_mono_ns += 1000 * MS;
    KX_CHECK(redeem(&f, &in, AGENT, T0 + MS, &tel) == KX_R_GRANT_MAC);
    /* forgery attempts do not consume the genuine grant */
    KX_CHECK(redeem(&g, &in, AGENT, T0 + MS, &tel) == KX_R_OK);

    /* a different authority instance (restart = new key) rejects old grants */
    kx_grant_t g2 = issue(3, &in, 250, T0);
    uint8_t key2[32];
    memcpy(key2, KEY, 32);
    key2[0] ^= 0xff;
    kx_grant_table_init(&T, key2);
    KX_CHECK(redeem(&g2, &in, AGENT, T0 + MS, &tel) == KX_R_GRANT_MAC);
}

static void test_unknown_and_expiry(void) {
    kx_grant_table_init(&T, KEY);
    kx_intent_t in = door(3);
    kx_telemetry_t tel = parked();
    kx_grant_t g = issue(4, &in, 250, T0);
    /* validly MAC'd but never issued by this table (e.g. reaped tombstone) */
    kx_grant_table_t saved = T;
    kx_grant_table_init(&T, KEY);
    KX_CHECK(redeem(&g, &in, AGENT, T0 + MS, &tel) == KX_R_GRANT_UNKNOWN);
    T = saved;

    KX_CHECK(redeem(&g, &in, AGENT, T0 + 250 * MS, &tel) == KX_R_OK);            /* deadline inclusive */
    kx_grant_t late = issue(5, &in, 250, T0);
    KX_CHECK(redeem(&late, &in, AGENT, T0 + 251 * MS, &tel) == KX_R_GRANT_EXPIRED);
    KX_CHECK(redeem(&late, &in, AGENT, T0 + 252 * MS, &tel) == KX_R_GRANT_EXPIRED); /* consumed, still "expired" */

    /* reaper: expires outstanding grants, reports their ids, later forgets tombstones */
    kx_grant_t a = issue(6, &in, 100, T0);
    kx_grant_t b = issue(7, &in, 900, T0);
    uint8_t ids[4][16];
    KX_CHECK(kx_grant_reap(&T, T0 + 500 * MS, ids, 4) == 1);
    KX_CHECK(memcmp(ids[0], a.grant_id, 16) == 0);
    /* regression (found on QNX): a grant reaped before presentation is EXPIRED, not SPENT */
    KX_CHECK(redeem(&a, &in, AGENT, T0 + 501 * MS, &tel) == KX_R_GRANT_EXPIRED);
    KX_CHECK(redeem(&b, &in, AGENT, T0 + 501 * MS, &tel) == KX_R_OK);
    kx_grant_reap(&T, T0 + 100 * MS + KX_GRANT_TOMBSTONE_NS + 1, NULL, 0);
    KX_CHECK(redeem(&a, &in, AGENT, T0 + KX_GRANT_TOMBSTONE_NS + 200 * MS, &tel) == KX_R_GRANT_UNKNOWN);
}

static void test_exactness_and_binding(void) {
    kx_grant_table_init(&T, KEY);
    kx_intent_t in = door(1);           /* front_right */
    kx_telemetry_t tel = parked();

    kx_grant_t g = issue(8, &in, 250, T0);
    kx_intent_t other_door = door(2);   /* agent got approval for one door, tries another */
    KX_CHECK(redeem(&g, &other_door, AGENT, T0 + MS, &tel) == KX_R_GRANT_PARAMS);
    KX_CHECK(redeem(&g, &in, AGENT, T0 + 2 * MS, &tel) == KX_R_GRANT_SPENT);      /* burned */

    g = issue(9, &in, 250, T0);
    kx_intent_t wrong_action = in;
    wrong_action.action = KX_ACT_LIGHT_HAZARD_SET;
    KX_CHECK(redeem(&g, &wrong_action, AGENT, T0 + MS, &tel) == KX_R_GRANT_PARAMS);

    g = issue(10, &in, 250, T0);        /* stolen grant presented by another process */
    KX_CHECK(redeem(&g, &in, OTHER, T0 + MS, &tel) == KX_R_GRANT_BINDING);
    g = issue(11, &in, 250, T0);        /* ... or by a process of another secpol type */
    KX_CHECK(redeem(&g, &in, ROGUE, T0 + MS, &tel) == KX_R_GRANT_BINDING);

    /* params digest: order-independent, value/digest sensitive */
    kx_intent_t w1, w2;
    memset(&w1, 0, sizeof w1);
    w1.action = KX_ACT_CABIN_WINDOW_SET;
    w1.n_params = 2;
    w1.p[0].key = KX_P_WINDOW; w1.p[0].val = 1;
    w1.p[1].key = KX_P_POS_PCT; w1.p[1].val = 40;
    w2 = w1;
    w2.p[0] = w1.p[1]; w2.p[1] = w1.p[0];
    uint8_t d1[32], d2[32];
    kx_params_digest(&w1, d1); kx_params_digest(&w2, d2);
    KX_CHECK(memcmp(d1, d2, 32) == 0);
    w2.p[0].val = 41; kx_params_digest(&w2, d2);
    KX_CHECK(memcmp(d1, d2, 32) != 0);
    kx_intent_t o1 = door(0), o2;
    o1.has_digest = 1; memset(o1.digest, 7, 32);
    o2 = o1; o2.digest[31] ^= 1;
    kx_params_digest(&o1, d1); kx_params_digest(&o2, d2);
    KX_CHECK(memcmp(d1, d2, 32) != 0);
}

static void test_interlock_toctou(void) {
    kx_grant_table_init(&T, KEY);
    kx_intent_t in = door(1);
    kx_grant_t g = issue(12, &in, 250, T0);   /* authorized while parked */
    kx_telemetry_t moving = parked();
    moving.v[KX_TF_GEAR] = KX_GEAR_D;
    moving.v[KX_TF_SPEED_DKPH] = 50;          /* car pulls away before actuation */
    KX_CHECK(redeem(&g, &in, AGENT, T0 + 100 * MS, &moving) == KX_R_GRANT_INTERLOCK);
    kx_telemetry_t tel = parked();
    KX_CHECK(redeem(&g, &in, AGENT, T0 + 101 * MS, &tel) == KX_R_GRANT_SPENT);   /* no second chance */
}

static void test_capacity(void) {
    kx_grant_table_init(&T, KEY);
    kx_intent_t in = door(1);
    uint8_t ih[32] = { 0 }, id[16];
    kx_grant_t g;
    uint32_t ok = 0;
    for (uint32_t n = 0; n < KX_GRANT_SLOTS; n++) {
        gid(id, 1000 + n);
        if (kx_grant_issue(&T, &in, ih, PHASH, 0, 250, AGENT, id, T0, &g) == KX_R_OK) ok++;
    }
    KX_CHECK(ok == KX_GRANT_SLOTS && T.outstanding == KX_GRANT_SLOTS);
    gid(id, 99999);
    KX_CHECK(kx_grant_issue(&T, &in, ih, PHASH, 0, 250, AGENT, id, T0, &g) == KX_R_GRANT_TABLE_FULL);
    gid(id, 1000); /* duplicate id is refused, never overwritten */
    KX_CHECK(kx_grant_issue(&T, &in, ih, PHASH, 0, 250, AGENT, id, T0, &g) == KX_R_GRANT_TABLE_FULL);
    /* after expiry + tombstone grace the slots are reusable */
    KX_CHECK(kx_grant_reap(&T, T0 + 300 * MS, NULL, 0) == KX_GRANT_SLOTS);
    kx_grant_reap(&T, T0 + 300 * MS + KX_GRANT_TOMBSTONE_NS, NULL, 0);
    gid(id, 99999);
    KX_CHECK(kx_grant_issue(&T, &in, ih, PHASH, 0, 250, AGENT, id, T0 + KX_GRANT_TOMBSTONE_NS + 400 * MS, &g) == KX_R_OK);
}

static uint64_t rng = 0x243F6A8885A308D3ull;
static uint32_t rnd(uint32_t n) {
    rng = rng * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)((rng >> 33) % n);
}

static void test_never_twice(void) {
    kx_grant_table_init(&T, KEY);
    kx_telemetry_t tel = parked();
    static kx_grant_t issued[4096];
    static uint8_t used[4096];
    uint32_t n_issued = 0, double_ok = 0;
    uint64_t now = T0;
    uint8_t ih[32] = { 0 }, id[16];
    kx_intent_t in = door(1);
    kx_eval_env_t env = { T0, 0, 50 * MS, 1 };
    kx_eval_result_t r;
    kx_eval(&POL, &in, &tel, &env, &r);
    for (int step = 0; step < 100000; step++) {
        now += rnd(3) * MS;
        tel.mono_ns = now;
        uint32_t op = rnd(10);
        if (op < 4 && n_issued < 4096) {
            gid(id, 50000 + n_issued);
            if (kx_grant_issue(&T, &in, ih, PHASH, r.rule_index, 1 + rnd(400), AGENT, id, now, &issued[n_issued]) == KX_R_OK) {
                n_issued++;
            }
        } else if (op < 9 && n_issued > 0) {
            uint32_t k = rnd(n_issued);
            kx_client_t who = rnd(8) == 0 ? OTHER : AGENT;
            if (redeem(&issued[k], &in, who, now, &tel) == KX_R_OK) {
                if (used[k]) double_ok++;
                used[k] = 1;
            }
        } else {
            kx_grant_reap(&T, now, NULL, 0);
        }
    }
    KX_CHECK(double_ok == 0);
    if (double_ok) fprintf(stderr, "  %u grants redeemed twice!\n", double_ok);
}

int main(void) {
    KX_CHECK(kx_policy_build_default(&POL) == 0);
    test_happy_and_replay();
    test_forgery();
    test_unknown_and_expiry();
    test_exactness_and_binding();
    test_interlock_toctou();
    test_capacity();
    test_never_twice();
    KX_TEST_DONE();
}
