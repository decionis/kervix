/* kxgw wire format: the gateway's parser of untrusted bytes (host unit tests). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../wire.h"
#include "kervix/catalog_gen.h"
#include "kx_test.h"

static int parse(const char *s, kxw_req_t *rq, const char **err) { return kxw_parse(s, strlen(s), rq, err); }

static int rejects(const char *s, const char *why) {
    kxw_req_t rq;
    const char *err = NULL;
    int rc = parse(s, &rq, &err);
    if (rc == 0) { fprintf(stderr, "accepted: %s\n", s); return 0; }
    if (why && (err == NULL || strstr(err, why) == NULL)) { fprintf(stderr, "%s -> '%s' (wanted '%s')\n", s, err ? err : "(null)", why); return 0; }
    return 1;
}

static void test_propose(void) {
    kxw_req_t rq;
    const char *err = NULL;
    const char *line = "{\"op\":\"propose\",\"id\":\"r-1\",\"action\":\"ota.ecu.flash\",\"actor\":\"agent:cabin-copilot\","
                       "\"intent_id\":\"0f8e2a4c-1b3d-4e5f-8a9b-0c1d2e3f4a5b\",\"expires_at_ms\":1795000000000,"
                       "\"params\":{\"ecu\":\"brake\",\"image_digest\":\"sha256:0101010101010101010101010101010101010101010101010101010101010101\"},"
                       "\"exec\":true,\"await\":false}\r\n";
    KX_CHECK(parse(line, &rq, &err) == 0);
    KX_CHECK(rq.op == KXW_OP_PROPOSE);
    KX_CHECK_STR(rq.id, "r-1");
    KX_CHECK_STR(rq.action, "ota.ecu.flash");
    KX_CHECK(rq.exec == 1 && rq.await_esc == 0);
    KX_CHECK(rq.has_intent_id && rq.intent_id[0] == 0x0f && rq.intent_id[15] == 0x5b);
    KX_CHECK(rq.expires_at_ms == 1795000000000LL);
    KX_CHECK(rq.n_params == 2);

    kx_intent_t in;
    KX_CHECK(kxw_to_intent(&rq, &in, &err) == 0);
    KX_CHECK(in.abi == KX_ABI_VERSION && in.action == KX_ACT_OTA_ECU_FLASH);
    KX_CHECK(in.n_params == 1 && in.p[0].key == KX_P_ECU && in.p[0].val == KX_ECU_BRAKE);
    KX_CHECK(in.has_digest && in.digest[0] == 1 && in.digest[31] == 1);
    KX_CHECK(strcmp(in.actor_id, "agent:cabin-copilot") == 0);

    /* integer, boolean, enum by index */
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"cabin.climate.set\",\"params\":{\"temp_dc\":215}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) == 0 && in.p[0].key == KX_P_TEMP_DC && in.p[0].val == 215);
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"light.hazard.set\",\"params\":{\"on\":true}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) == 0 && in.p[0].val == 1);
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"body.door.unlock\",\"params\":{\"door\":2}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) == 0 && in.p[0].val == 2);
    /* out-of-range integers are NOT rejected here: kervixd decides and records them (K4) */
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"cabin.climate.set\",\"params\":{\"temp_dc\":9999}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) == 0 && in.p[0].val == 9999);

    /* catalog errors */
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"brake.disable\"}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) != 0 && strstr(err, "unknown action"));
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"body.door.unlock\",\"params\":{\"door\":\"trunk\"}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) != 0 && strstr(err, "enum"));
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"body.door.unlock\",\"params\":{\"speed\":1}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) != 0 && strstr(err, "unknown parameter"));
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"ota.ecu.flash\",\"params\":{\"ecu\":\"brake\",\"image_digest\":\"sha256:zz\"}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) != 0 && strstr(err, "digest"));
    KX_CHECK(parse("{\"op\":\"propose\",\"action\":\"cabin.climate.set\",\"params\":{\"temp_dc\":\"warm\"}}", &rq, &err) == 0);
    KX_CHECK(kxw_to_intent(&rq, &in, &err) != 0);
}

static void test_other_ops(void) {
    kxw_req_t rq;
    const char *err = NULL;
    KX_CHECK(parse("{\"op\":\"hello\"}", &rq, &err) == 0 && rq.op == KXW_OP_HELLO);
    KX_CHECK(parse("  { \"op\" : \"state\" }  ", &rq, &err) == 0 && rq.op == KXW_OP_STATE);
    KX_CHECK(parse("{\"op\":\"execute\",\"grant_id\":\"00112233445566778899aabbccddeeff\"}", &rq, &err) == 0);
    KX_CHECK(rq.has_grant_id && rq.grant_id[0] == 0x00 && rq.grant_id[15] == 0xff);
    KX_CHECK(parse("{\"op\":\"resolve\",\"escalation_id\":7,\"approve\":false,\"approver\":\"hmi:driver\"}", &rq, &err) == 0);
    KX_CHECK(rq.escalation_id == 7 && rq.has_approve && rq.approve == 0 && !strcmp(rq.approver, "hmi:driver"));
    KX_CHECK(parse("{\"op\":\"subscribe\",\"hz\":20}", &rq, &err) == 0 && rq.hz == 20);
    KX_CHECK(parse("{\"op\":\"sim\",\"cmd\":\"scenario highway\"}", &rq, &err) == 0 && !strcmp(rq.cmd, "scenario highway"));
    KX_CHECK(parse("{\"op\":\"sim\",\"cmd\":\"say \\\"hi\\\" \\\\ \\/\"}", &rq, &err) == 0 && !strcmp(rq.cmd, "say \"hi\" \\ /"));
    KX_CHECK(strcmp(kxw_op_name(KXW_OP_RESOLVE), "resolve") == 0);
    KX_CHECK(parse("{\"op\":\"ledger\",\"from_seq\":42,\"max\":100}", &rq, &err) == 0 && rq.op == KXW_OP_LEDGER && rq.from_seq == 42 && rq.max == 100);
    KX_CHECK(parse("{\"op\":\"ledger_info\"}", &rq, &err) == 0 && rq.op == KXW_OP_LEDGER_INFO);
    KX_CHECK(parse("{\"op\":\"policy\",\"name\":\"4e400c092656d11a\"}", &rq, &err) == 0 && !strcmp(rq.name, "4e400c092656d11a"));
}

static void test_rejects(void) {
    KX_CHECK(rejects("", "JSON object"));
    KX_CHECK(rejects("[1]", "JSON object"));
    KX_CHECK(rejects("{}", "missing op"));
    KX_CHECK(rejects("{\"op\":\"fly\"}", "unknown op"));
    KX_CHECK(rejects("{\"op\":\"hello\",\"op\":\"state\"}", "duplicate key"));
    KX_CHECK(rejects("{\"op\":\"hello\",\"admin\":true}", "unknown key"));
    KX_CHECK(rejects("{\"op\":\"hello\"} {\"op\":\"hello\"}", "trailing"));
    KX_CHECK(rejects("{\"op\":\"hello\"", "expected ',' or '}'"));
    KX_CHECK(rejects("{\"op\":\"hello\",}", "expected a string"));
    KX_CHECK(rejects("{\"op\":\"hel", "unterminated"));
    KX_CHECK(rejects("{\"op\":\"propose\"}", "needs an action"));
    KX_CHECK(rejects("{\"op\":\"execute\"}", "needs a grant_id"));
    KX_CHECK(rejects("{\"op\":\"execute\",\"grant_id\":\"0011\"}", "32 hex"));
    KX_CHECK(rejects("{\"op\":\"resolve\",\"escalation_id\":1}", "needs escalation_id and approve"));
    KX_CHECK(rejects("{\"op\":\"sim\"}", "needs a cmd"));
    KX_CHECK(rejects("{\"op\":\"policy\",\"name\":\"../../keys/x\"}", "16 hex"));
    KX_CHECK(rejects("{\"op\":\"ledger\",\"from_seq\":0}", ">= 1"));
    KX_CHECK(rejects("{\"op\":\"ledger\",\"max\":5000}", "out of range"));
    KX_CHECK(rejects("{\"op\":\"hello\",\"id\":\"a b\"}", "id may only"));
    KX_CHECK(rejects("{\"op\":\"propose\",\"action\":\"x\",\"intent_id\":\"nope\"}", "UUID"));
    /* strings: printable ASCII only, no \u escapes, bounded */
    KX_CHECK(rejects("{\"op\":\"sim\",\"cmd\":\"a\\u0041\"}", "escape"));
    KX_CHECK(rejects("{\"op\":\"sim\",\"cmd\":\"a\\nb\"}", "escape"));
    KX_CHECK(rejects("{\"op\":\"sim\",\"cmd\":\"caf\xc3\xa9\"}", "non-ASCII"));
    KX_CHECK(rejects("{\"op\":\"sim\",\"cmd\":\"a\tb\"}", "non-printable"));
    KX_CHECK(rejects("{\"op\":\"hello\",\"actor\":\"0123456789012345678901234567890123456789\"}", "too long"));
    /* numbers: integers in the safe range only */
    KX_CHECK(rejects("{\"op\":\"subscribe\",\"hz\":1.5}", "integers only"));
    KX_CHECK(rejects("{\"op\":\"subscribe\",\"hz\":1e3}", "integers only"));
    KX_CHECK(rejects("{\"op\":\"subscribe\",\"hz\":012}", "leading zero"));
    KX_CHECK(rejects("{\"op\":\"subscribe\",\"hz\":-1}", "out of range"));
    KX_CHECK(rejects("{\"op\":\"subscribe\",\"hz\":99999999999999999999}", "out of range"));
    KX_CHECK(rejects("{\"op\":\"propose\",\"action\":\"a\",\"params\":{\"x\":9007199254740992}}", "out of range"));
    KX_CHECK(rejects("{\"op\":\"propose\",\"action\":\"a\",\"expires_at_ms\":-5}", ">= 0"));
    KX_CHECK(rejects("{\"op\":\"hello\",\"exec\":1}", "true or false"));
    KX_CHECK(rejects("{\"op\":\"hello\",\"exec\":null}", "true or false"));
    /* params: one level, scalars, bounded, no duplicates */
    KX_CHECK(rejects("{\"op\":\"propose\",\"action\":\"a\",\"params\":[1]}", "object"));
    KX_CHECK(rejects("{\"op\":\"propose\",\"action\":\"a\",\"params\":{\"x\":{\"y\":1}}}", "integer"));
    KX_CHECK(rejects("{\"op\":\"propose\",\"action\":\"a\",\"params\":{\"x\":1,\"x\":2}}", "duplicate param"));
    KX_CHECK(rejects("{\"op\":\"propose\",\"action\":\"a\",\"params\":{\"a\":1,\"b\":1,\"c\":1,\"d\":1,\"e\":1,\"f\":1,\"g\":1,\"h\":1,\"i\":1}}",
                     "too many params"));
    /* length bound */
    static char big[KXW_LINE_MAX + 64];
    memset(big, ' ', sizeof big - 1);
    big[0] = '{';
    memcpy(big + sizeof big - 16, "\"op\":\"hello\"}", 13);
    big[sizeof big - 3] = '\0';
    KX_CHECK(rejects(big, "too long"));
}

/* Every prefix of a valid request must be rejected without reading past it. */
static void test_truncation(void) {
    const char *line = "{\"op\":\"propose\",\"id\":\"r1\",\"action\":\"cabin.window.set\",\"params\":{\"window\":\"rear_left\",\"pos_pct\":40},\"exec\":true}";
    size_t n = strlen(line);
    int all = 1;
    for (size_t k = 0; k < n; k++) {
        char buf[256];
        memcpy(buf, line, k); /* no NUL: the parser must honour n */
        kxw_req_t rq;
        const char *err;
        if (kxw_parse(buf, k, &rq, &err) == 0) { all = 0; fprintf(stderr, "prefix %zu accepted\n", k); }
    }
    KX_CHECK(all);
    kxw_req_t rq;
    const char *err;
    KX_CHECK(kxw_parse(line, n, &rq, &err) == 0);
}

static void test_emit(void) {
    kx_decision_t d;
    memset(&d, 0, sizeof d);
    d.verdict = KX_VERDICT_ALLOW;
    d.reason = KX_R_OK;
    memcpy(d.rule_id, "climate-any", 11);
    d.intent_hash[0] = 0xab;
    d.grant.grant_id[0] = 0x12;
    d.grant.issued_mono_ns = 1000000000ull;
    d.grant.not_after_mono_ns = 1500000000ull;
    d.telemetry_seq = 42;
    d.eval_ns = 7000;
    char buf[2048];
    kx_jw_t w;
    kx_jw_init(&w, buf, sizeof buf);
    kx_jw_obj_begin(&w);
    kxw_emit_decision(&w, &d);
    kx_jw_obj_end(&w);
    KX_CHECK(kx_jw_ok(&w));
    KX_CHECK(strstr(buf, "\"verdict\":\"ALLOW\""));
    KX_CHECK(strstr(buf, "\"reason\":\"OK\""));
    KX_CHECK(strstr(buf, "\"rule\":\"climate-any\""));
    KX_CHECK(strstr(buf, "\"gate\":\"RULE\""));
    KX_CHECK(strstr(buf, "\"intent_hash\":\"sha256:ab00"));
    KX_CHECK(strstr(buf, "\"grant_id\":\"12000000000000000000000000000000\""));
    KX_CHECK(strstr(buf, "\"grant_ttl_ms\":500"));
    KX_CHECK(strstr(buf, "\"telemetry_seq\":42"));
    KX_CHECK(strstr(buf, "escalation_id") == NULL);

    kx_intent_t in;
    memset(&in, 0, sizeof in);
    in.action = KX_ACT_OTA_ECU_FLASH;
    memcpy(in.actor_id, "agent:x", 7);
    in.n_params = 1;
    in.p[0].key = KX_P_ECU;
    in.p[0].val = KX_ECU_BMS;
    in.has_digest = 1;
    in.digest[0] = 0xcd;
    kx_jw_init(&w, buf, sizeof buf);
    kx_jw_obj_begin(&w);
    kxw_emit_intent(&w, "intent", &in);
    kx_jw_obj_end(&w);
    KX_CHECK(kx_jw_ok(&w));
    KX_CHECK(strstr(buf, "\"action\":\"ota.ecu.flash\""));
    KX_CHECK(strstr(buf, "\"ecu\":\"bms\""));
    KX_CHECK(strstr(buf, "\"image_digest\":\"sha256:cd00"));

    kx_telemetry_t t;
    memset(&t, 0, sizeof t);
    t.seq = 9;
    t.v[KX_TF_SPEED_DKPH] = 1100;
    t.v[KX_TF_GEAR] = KX_GEAR_D;
    kx_jw_init(&w, buf, sizeof buf);
    kx_jw_obj_begin(&w);
    kxw_emit_telemetry(&w, "telemetry", &t);
    kx_jw_obj_end(&w);
    KX_CHECK(kx_jw_ok(&w));
    KX_CHECK(strstr(buf, "\"speed_dkph\":1100"));
    KX_CHECK(strstr(buf, "\"gear\":3"));
    KX_CHECK(strstr(buf, "\"seq\":9"));

    /* the round trip: what the gateway emits for an intent, it parses back */
    kx_jw_init(&w, buf, sizeof buf);
    kx_jw_obj_begin(&w);
    kx_jw_key(&w, "op"); kx_jw_str(&w, "propose");
    kx_jw_key(&w, "action"); kx_jw_str(&w, "ota.ecu.flash");
    kx_jw_key(&w, "params");
    kx_jw_obj_begin(&w);
    kx_jw_key(&w, "ecu"); kx_jw_str(&w, "bms");
    kxw_emit_hex(&w, "image_digest", "sha256:", in.digest, 32);
    kx_jw_obj_end(&w);
    kx_jw_obj_end(&w);
    KX_CHECK(kx_jw_ok(&w));
    kxw_req_t rq;
    const char *err;
    kx_intent_t back;
    KX_CHECK(kxw_parse(buf, strlen(buf), &rq, &err) == 0 && kxw_to_intent(&rq, &back, &err) == 0);
    KX_CHECK(back.p[0].val == KX_ECU_BMS && memcmp(back.digest, in.digest, 32) == 0);
}

static void test_text(void) {
    const char txt[] = "kervixd  uptime 3 s  hash 0a1b\xe2\x80\xa6\nline\ttwo \xc3\xa9\x01\n\nlast";
    char buf[512];
    kx_jw_t w;
    kx_jw_init(&w, buf, sizeof buf);
    kx_jw_obj_begin(&w);
    kxw_emit_text(&w, "text", txt, sizeof txt - 1);
    kx_jw_obj_end(&w);
    KX_CHECK(kx_jw_ok(&w));
    KX_CHECK_STR(buf, "{\"text\":[\"kervixd  uptime 3 s  hash 0a1b...\",\"line two ??\",\"\",\"last\"]}");
}

int main(void) {
    test_text();
    test_propose();
    test_other_ops();
    test_rejects();
    test_truncation();
    test_emit();
    KX_TEST_DONE();
}
