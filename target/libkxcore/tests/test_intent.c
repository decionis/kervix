/* JCS writer, deterministic formatting and the Agent-Safe Intent binding.
 *   test_intent          run unit tests
 *   test_intent --emit   print one JSON line per vector:
 *                        {"canonical": <binding text>, "hash": "sha256:<hex>"}
 *                        for independent checking with @decionis/verify
 *                        (tests/conformance/intent-parity.mjs). */
#include <string.h>

#include "kervix/intent.h"
#include "kervix/jcs.h"
#include "kervix/sha256.h"
#include "kx_test.h"

static const kx_intent_ctx_t CTX = {
    "6f1c2b9e-4d3a-4c8b-9a7e-2b1d0c3e4f5a", "veh-3f9a2c71", "ai_agent", 1795000000123LL,
};

static kx_intent_t base(uint16_t action, uint8_t last) {
    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.abi = KX_ABI_VERSION;
    in.action = action;
    strcpy(in.actor_id, "agent:cabin-copilot");
    static const uint8_t u[16] = { 0x0b, 0x6c, 0x1e, 0x2a, 0x7f, 0x3d, 0x4a, 0x9b,
                                   0x8c, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(in.intent_id, u, 16);
    in.intent_id[15] = last;
    return in;
}
static void add(kx_intent_t *in, uint16_t key, int64_t v) {
    in->p[in->n_params].key = key;
    in->p[in->n_params].val = v;
    in->n_params++;
}

/* The vectors shared with the conformance check. */
static int vectors(kx_intent_t *out, int max) {
    int n = 0;
    kx_intent_t v;
    v = base(KX_ACT_CABIN_CLIMATE_SET, 1); add(&v, KX_P_TEMP_DC, 225); out[n++] = v;
    v = base(KX_ACT_CABIN_WINDOW_SET, 2); add(&v, KX_P_POS_PCT, 80); add(&v, KX_P_WINDOW, KX_WINDOW_REAR_LEFT); out[n++] = v;
    v = base(KX_ACT_LIGHT_HAZARD_SET, 3); add(&v, KX_P_ON, 1); out[n++] = v;
    v = base(KX_ACT_OTA_ECU_FLASH, 4); add(&v, KX_P_ECU, KX_ECU_BRAKE); v.has_digest = 1;
        for (int i = 0; i < 32; i++) v.digest[i] = (uint8_t)(i * 7 + 1);
        v.expires_rt_ms = 1795000004000LL; out[n++] = v;
    v = base(KX_ACT_TELEMATICS_LOCATION_SHARE, 5); add(&v, KX_P_DURATION_S, 3600);
        add(&v, KX_P_RECIPIENT, KX_RECIPIENT_FLEET_OPERATOR); strcpy(v.actor_id, "agent:\"quoted\\path\""); out[n++] = v;
    v = base(KX_ACT_VEHICLE_IMMOBILIZER_ENGAGE, 6); out[n++] = v;  /* no params */
    (void)max;
    return n;
}

static int emit(void) {
    kx_intent_t vs[16];
    int n = vectors(vs, 16);
    for (int i = 0; i < n; i++) {
        char buf[KX_INTENT_JCS_MAX];
        uint8_t h[32];
        char hx[65];
        if (kx_intent_jcs(&vs[i], &CTX, buf, sizeof buf) < 0 || kx_intent_hash(&vs[i], &CTX, h) != 0) {
            fprintf(stderr, "vector %d failed\n", i);
            return 1;
        }
        kx_hex(h, 32, hx);
        /* the canonical text is itself valid JSON: embed it as a raw value */
        printf("{\"canonical\":%s,\"text\":\"", buf);
        for (const char *p = buf; *p; p++) {
            if (*p == '"' || *p == '\\') putchar('\\');
            putchar(*p);
        }
        printf("\",\"hash\":\"sha256:%s\"}\n", hx);
    }
    return 0;
}

static void test_writer(void) {
    char b[64];
    kx_jw_t w;

    kx_jw_init(&w, b, sizeof b);
    kx_jw_obj_begin(&w);
    kx_jw_key(&w, "a"); kx_jw_int(&w, -42);
    kx_jw_key(&w, "b"); kx_jw_arr_begin(&w); kx_jw_bool(&w, 1); kx_jw_null(&w); kx_jw_str(&w, "q\"\\"); kx_jw_arr_end(&w);
    kx_jw_key(&w, "c"); kx_jw_obj_begin(&w); kx_jw_obj_end(&w);
    kx_jw_obj_end(&w);
    KX_CHECK(kx_jw_ok(&w));
    KX_CHECK_STR(b, "{\"a\":-42,\"b\":[true,null,\"q\\\"\\\\\"],\"c\":{}}");

    kx_jw_init(&w, b, sizeof b);   /* integers: 0, extremes of the JS-safe range */
    kx_jw_arr_begin(&w); kx_jw_int(&w, 0); kx_jw_int(&w, KX_JW_MAX_SAFE_INT); kx_jw_int(&w, -KX_JW_MAX_SAFE_INT); kx_jw_arr_end(&w);
    KX_CHECK(kx_jw_ok(&w));
    KX_CHECK_STR(b, "[0,9007199254740991,-9007199254740991]");

    kx_jw_init(&w, b, sizeof b);   /* unsafe integer -> error */
    kx_jw_arr_begin(&w); kx_jw_int(&w, KX_JW_MAX_SAFE_INT + 1); kx_jw_arr_end(&w);
    KX_CHECK(!kx_jw_ok(&w));

    kx_jw_init(&w, b, sizeof b);   /* non-ASCII / control chars -> error, never silently escaped */
    kx_jw_str(&w, "caf\xc3\xa9");
    KX_CHECK(!kx_jw_ok(&w));
    kx_jw_init(&w, b, sizeof b);
    kx_jw_str(&w, "a\nb");
    KX_CHECK(!kx_jw_ok(&w));

    kx_jw_init(&w, b, 8);          /* overflow is sticky */
    kx_jw_str(&w, "0123456789");
    KX_CHECK(!kx_jw_ok(&w));

    kx_jw_init(&w, b, sizeof b);   /* structural misuse */
    kx_jw_obj_begin(&w); kx_jw_key(&w, "k"); kx_jw_key(&w, "k2");
    KX_CHECK(!kx_jw_ok(&w));
    kx_jw_init(&w, b, sizeof b);
    kx_jw_obj_begin(&w);
    KX_CHECK(!kx_jw_ok(&w));       /* unclosed */
    kx_jw_init(&w, b, sizeof b);
    kx_jw_int(&w, 1); kx_jw_int(&w, 2);
    KX_CHECK(!kx_jw_ok(&w));       /* two top-level values */
    kx_jw_init(&w, b, sizeof b);
    for (int i = 0; i <= KX_JW_MAX_DEPTH; i++) kx_jw_arr_begin(&w);
    KX_CHECK(!kx_jw_ok(&w));       /* depth bound */
}

static void test_formatting(void) {
    char t[25], u[37];
    KX_CHECK(kx_fmt_rfc3339_ms(0, t) == 0);             KX_CHECK_STR(t, "1970-01-01T00:00:00.000Z");
    KX_CHECK(kx_fmt_rfc3339_ms(951782400000LL, t) == 0); KX_CHECK_STR(t, "2000-02-29T00:00:00.000Z");
    KX_CHECK(kx_fmt_rfc3339_ms(1709251199999LL, t) == 0); KX_CHECK_STR(t, "2024-02-29T23:59:59.999Z");
    KX_CHECK(kx_fmt_rfc3339_ms(1795000000123LL, t) == 0); KX_CHECK_STR(t, "2026-11-18T11:06:40.123Z");
    KX_CHECK(kx_fmt_rfc3339_ms(253402300799999LL, t) == 0); KX_CHECK_STR(t, "9999-12-31T23:59:59.999Z");
    KX_CHECK(kx_fmt_rfc3339_ms(-1, t) == -1);
    KX_CHECK(kx_fmt_rfc3339_ms(253402300800000LL, t) == -1);

    uint8_t id[16] = { 0x0b, 0x6c, 0x1e, 0x2a, 0x7f, 0x3d, 0x4a, 0x9b, 0x8c, 0x1d, 0, 0, 0, 0, 0xab, 0xcd };
    kx_fmt_uuid(id, u);
    KX_CHECK_STR(u, "0b6c1e2a-7f3d-4a9b-8c1d-00000000abcd");
    KX_CHECK(kx_uuid_valid(id));
    id[6] = 0x0a; KX_CHECK(!kx_uuid_valid(id));   /* version 0 */
    id[6] = 0x9a; KX_CHECK(!kx_uuid_valid(id));   /* version 9 */
    id[6] = 0x4a; id[8] = 0xcc; KX_CHECK(!kx_uuid_valid(id)); /* variant 11 */
}

static void test_binding(void) {
    kx_intent_t vs[16];
    int n = vectors(vs, 16);
    char buf[KX_INTENT_JCS_MAX];

    /* exact canonical bytes for the simplest vector */
    KX_CHECK(kx_intent_jcs(&vs[0], &CTX, buf, sizeof buf) > 0);
    KX_CHECK_STR(buf,
        "{\"action\":{\"parameters\":{\"temp_dc\":225},\"resource\":\"vehicle/veh-3f9a2c71\",\"type\":\"cabin.climate.set\"},"
        "\"actor\":{\"id\":\"agent:cabin-copilot\",\"type\":\"ai_agent\"},"
        "\"captured_at\":\"2026-11-18T11:06:40.123Z\","
        "\"context\":{\"idempotency_key\":\"0b6c1e2a-7f3d-4a9b-8c1d-000000000001\"},"
        "\"downstream_target\":{\"environment\":\"vehicle\",\"operation\":\"cabin.climate.set\",\"system\":\"sdv_actuatord\"},"
        "\"expires_at\":\"2026-11-18T11:06:45.123Z\","
        "\"intent_id\":\"0b6c1e2a-7f3d-4a9b-8c1d-000000000001\","
        "\"protocol_version\":\"agent-safe.intent/1\","
        "\"tenant_id\":\"6f1c2b9e-4d3a-4c8b-9a7e-2b1d0c3e4f5a\"}");

    /* parameters are sorted by name regardless of input order */
    KX_CHECK(kx_intent_jcs(&vs[1], &CTX, buf, sizeof buf) > 0);
    KX_CHECK(strstr(buf, "\"parameters\":{\"pos_pct\":80,\"window\":\"rear_left\"}") != NULL);
    /* digest rendering and caller expiry */
    KX_CHECK(kx_intent_jcs(&vs[3], &CTX, buf, sizeof buf) > 0);
    KX_CHECK(strstr(buf, "\"image_digest\":\"sha256:01080f161d") != NULL);
    KX_CHECK(strstr(buf, "\"expires_at\":\"2026-11-18T11:06:44.000Z\"") != NULL);

    /* every vector hashes apart, and any single-field mutation changes the hash */
    uint8_t h[16][32];
    for (int i = 0; i < n; i++) KX_CHECK(kx_intent_hash(&vs[i], &CTX, h[i]) == 0);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++) KX_CHECK(memcmp(h[i], h[j], 32) != 0);
    uint8_t m[32];
    kx_intent_t mut = vs[0];
    mut.p[0].val = 226;
    kx_intent_hash(&mut, &CTX, m); KX_CHECK(memcmp(m, h[0], 32) != 0);
    kx_intent_ctx_t c2 = CTX; c2.captured_at_ms += 1;
    kx_intent_hash(&vs[0], &c2, m); KX_CHECK(memcmp(m, h[0], 32) != 0);
    c2 = CTX; c2.vehicle_id = "veh-other";
    kx_intent_hash(&vs[0], &c2, m); KX_CHECK(memcmp(m, h[0], 32) != 0);
    mut = vs[3]; mut.digest[31] ^= 1;
    kx_intent_hash(&mut, &CTX, m); KX_CHECK(memcmp(m, h[3], 32) != 0);

    /* determinism */
    kx_intent_hash(&vs[0], &CTX, m); KX_CHECK(memcmp(m, h[0], 32) == 0);

    /* invalid inputs never bind */
    mut = vs[0]; mut.p[0].val = 999;            /* out of range */
    KX_CHECK(kx_intent_jcs(&mut, &CTX, buf, sizeof buf) == -1);
    mut = vs[0]; mut.intent_id[6] = 0;          /* not a UUID */
    KX_CHECK(kx_intent_jcs(&mut, &CTX, buf, sizeof buf) == -1);
    KX_CHECK(kx_intent_jcs(&vs[0], &CTX, buf, 64) == -1); /* too small */
    c2 = CTX; c2.captured_at_ms = -5;
    KX_CHECK(kx_intent_jcs(&vs[0], &c2, buf, sizeof buf) == -1);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--emit") == 0) return emit();
    test_writer();
    test_formatting();
    test_binding();
    KX_TEST_DONE();
}
