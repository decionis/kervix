/* Execution grants. See kervix/grant.h. */
#include <stdint.h>
#include <string.h>

#include "kervix/grant.h"
#include "kervix/sha256.h"

/* ------------------------------------------------------------ packing */

static uint8_t *put_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); return p + 2; }
static uint8_t *put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); return p + 4; }
static uint8_t *put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); return p + 8; }
static uint8_t *put_bytes(uint8_t *p, const uint8_t *b, size_t n) { memcpy(p, b, n); return p + n; }

/* MAC input: explicit little-endian packing, never memcpy of the struct
 * (padding and endianness must not be part of the authenticated bytes). */
/* domain(16) id(16) intent(32) params(32) policy(8) action(2) type(4) pid(4) issued(8) not_after(8) */
#define KX_GRANT_MAC_INPUT_LEN (16 + 16 + 32 + 32 + 8 + 2 + 4 + 4 + 8 + 8)
#define FSZ(f) sizeof(((kx_grant_t *)0)->f)
/* The packed size must track the struct: a new or resized field fails the build. */
_Static_assert(KX_GRANT_MAC_INPUT_LEN == 16 + FSZ(grant_id) + FSZ(intent_hash) + FSZ(params_digest) +
                   FSZ(policy_hash8) + FSZ(action) + FSZ(proposer_type) + FSZ(proposer_pid) +
                   FSZ(issued_mono_ns) + FSZ(not_after_mono_ns),
               "grant MAC input layout out of sync with kx_grant_t");
_Static_assert(sizeof(kx_grant_t) == KX_GRANT_MAC_INPUT_LEN - 16 + FSZ(mac) + FSZ(_pad) + FSZ(_pad2),
               "kx_grant_t has fields not covered by the MAC");

static void grant_mac(const uint8_t key[KX_GRANT_KEY_LEN], const kx_grant_t *g, uint8_t out[32]) {
    uint8_t buf[KX_GRANT_MAC_INPUT_LEN];
    uint8_t *p = buf;
    p = put_bytes(p, (const uint8_t *)"kervix.grant/1\0\0", 16); /* domain separation */
    p = put_bytes(p, g->grant_id, 16);
    p = put_bytes(p, g->intent_hash, 32);
    p = put_bytes(p, g->params_digest, 32);
    p = put_bytes(p, g->policy_hash8, 8);
    p = put_u16(p, g->action);
    p = put_u32(p, g->proposer_type);
    p = put_u32(p, (uint32_t)g->proposer_pid);
    p = put_u64(p, g->issued_mono_ns);
    p = put_u64(p, g->not_after_mono_ns);
    kx_hmac_sha256(key, KX_GRANT_KEY_LEN, buf, (size_t)(p - buf), out);
}

void kx_params_digest(const kx_intent_t *in, uint8_t out[32]) {
    /* sort (key, val) pairs by key: n <= KX_MAX_PARAMS, insertion sort */
    kx_param_t ps[KX_MAX_PARAMS];
    uint8_t n = in->n_params <= KX_MAX_PARAMS ? in->n_params : KX_MAX_PARAMS;
    for (uint8_t i = 0; i < n; i++) {
        kx_param_t v = in->p[i];
        uint8_t k = i;
        while (k > 0 && ps[k - 1].key > v.key) { ps[k] = ps[k - 1]; k--; }
        ps[k] = v;
    }
    uint8_t buf[16 + 2 + 1 + KX_MAX_PARAMS * 10 + 1 + 32];
    uint8_t *p = put_bytes(buf, (const uint8_t *)"kervix.command/1", 16);
    p = put_u16(p, in->action);
    *p++ = n;
    for (uint8_t i = 0; i < n; i++) {
        p = put_u16(p, ps[i].key);
        p = put_u64(p, (uint64_t)ps[i].val);
    }
    *p++ = in->has_digest ? 1 : 0;
    if (in->has_digest) p = put_bytes(p, in->digest, 32);
    kx_sha256(buf, (size_t)(p - buf), out);
}

/* ------------------------------------------------------------ table */

static uint32_t home(const uint8_t id[16]) {
    uint32_t h = (uint32_t)id[0] | (uint32_t)id[1] << 8 | (uint32_t)id[2] << 16 | (uint32_t)id[3] << 24;
    return h % KX_GRANT_SLOTS;
}

/* Find the slot holding grant_id (OUTSTANDING or SPENT), or NULL. */
static kx_grant_slot_t *find(kx_grant_table_t *t, const uint8_t id[16]) {
    uint32_t h = home(id);
    for (uint32_t i = 0; i < KX_GRANT_SLOTS; i++) {
        kx_grant_slot_t *s = &t->slots[(h + i) % KX_GRANT_SLOTS];
        if (s->state == KX_SLOT_FREE) return NULL;          /* end of probe chain */
        if ((s->state == KX_SLOT_OUTSTANDING || s->state == KX_SLOT_SPENT || s->state == KX_SLOT_EXPIRED) &&
            memcmp(s->grant.grant_id, id, 16) == 0) {
            return s;
        }
    }
    return NULL;
}

const kx_grant_slot_t *kx_grant_find(const kx_grant_table_t *t, const uint8_t grant_id[16]) {
    return find((kx_grant_table_t *)(uintptr_t)t, grant_id);
}

void kx_grant_table_init(kx_grant_table_t *t, const uint8_t key[KX_GRANT_KEY_LEN]) {
    memset(t, 0, sizeof *t);
    memcpy(t->key, key, KX_GRANT_KEY_LEN);
}

uint16_t kx_grant_issue(kx_grant_table_t *t, const kx_intent_t *in, const uint8_t intent_hash[32],
                        const uint8_t policy_hash[32], int16_t rule_index, uint32_t ttl_ms,
                        kx_client_t proposer, const uint8_t grant_id[16], uint64_t now_ns,
                        kx_grant_t *out) {
    if (find(t, grant_id) != NULL) return KX_R_GRANT_TABLE_FULL; /* id collision: refuse, never overwrite */
    uint32_t h = home(grant_id);
    kx_grant_slot_t *slot = NULL;
    for (uint32_t i = 0; i < KX_GRANT_SLOTS; i++) {
        kx_grant_slot_t *s = &t->slots[(h + i) % KX_GRANT_SLOTS];
        if (s->state == KX_SLOT_FREE || s->state == KX_SLOT_DELETED) { slot = s; break; }
    }
    if (slot == NULL) return KX_R_GRANT_TABLE_FULL;

    kx_grant_t g;
    memset(&g, 0, sizeof g);
    memcpy(g.grant_id, grant_id, 16);
    memcpy(g.intent_hash, intent_hash, 32);
    kx_params_digest(in, g.params_digest);
    memcpy(g.policy_hash8, policy_hash, 8);
    g.action = in->action;
    g.proposer_type = proposer.type_id;
    g.proposer_pid = proposer.pid;
    g.issued_mono_ns = now_ns;
    g.not_after_mono_ns = now_ns + (uint64_t)ttl_ms * 1000000u;
    grant_mac(t->key, &g, g.mac);

    slot->state = KX_SLOT_OUTSTANDING;
    slot->rule_index = rule_index;
    slot->forget_after_ns = g.not_after_mono_ns + KX_GRANT_TOMBSTONE_NS;
    slot->grant = g;
    slot->intent = *in;
    t->outstanding++;
    *out = g;
    return KX_R_OK;
}

static void consume(kx_grant_table_t *t, kx_grant_slot_t *s) {
    s->state = KX_SLOT_SPENT;
    if (t->outstanding > 0) t->outstanding--;
}
static void expire(kx_grant_table_t *t, kx_grant_slot_t *s) {
    s->state = KX_SLOT_EXPIRED;
    if (t->outstanding > 0) t->outstanding--;
}

uint16_t kx_grant_redeem(kx_grant_table_t *t, const kx_grant_t *presented, const kx_intent_t *command,
                         kx_client_t presenter, uint64_t now_ns, const kx_policy_t *pol,
                         const kx_telemetry_t *tel) {
    /* 1. authenticity: constant-time compare of a MAC recomputed over the presented fields */
    uint8_t mac[32];
    grant_mac(t->key, presented, mac);
    if (!kx_ct_equal(mac, presented->mac, 32)) return KX_R_GRANT_MAC;

    /* 2./3. issued by this authority instance and not yet used */
    kx_grant_slot_t *s = find(t, presented->grant_id);
    if (s == NULL) return KX_R_GRANT_UNKNOWN;
    if (s->state == KX_SLOT_SPENT) return KX_R_GRANT_SPENT;
    if (s->state == KX_SLOT_EXPIRED) return KX_R_GRANT_EXPIRED;   /* reaped before presentation */

    /* From here on every outcome consumes the grant (fail-closed). */
    if (now_ns > s->grant.not_after_mono_ns) { expire(t, s); return KX_R_GRANT_EXPIRED; }

    uint8_t cmd[32];
    kx_params_digest(command, cmd);
    if (command->action != s->grant.action || !kx_ct_equal(cmd, s->grant.params_digest, 32)) {
        consume(t, s);
        return KX_R_GRANT_PARAMS;
    }
    if (presenter.pid != s->grant.proposer_pid || presenter.type_id != s->grant.proposer_type) {
        consume(t, s);
        return KX_R_GRANT_BINDING;
    }
    if (!kx_interlock_ok(pol, s->rule_index, &s->intent, tel)) {
        consume(t, s);
        return KX_R_GRANT_INTERLOCK;
    }
    consume(t, s);
    return KX_R_OK;
}

uint32_t kx_grant_reap(kx_grant_table_t *t, uint64_t now_ns, uint8_t (*expired_ids)[16], uint32_t max) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < KX_GRANT_SLOTS; i++) {
        kx_grant_slot_t *s = &t->slots[i];
        if (s->state == KX_SLOT_OUTSTANDING && now_ns > s->grant.not_after_mono_ns) {
            if (expired_ids != NULL && n < max) memcpy(expired_ids[n], s->grant.grant_id, 16);
            n++;
            expire(t, s);
        } else if ((s->state == KX_SLOT_SPENT || s->state == KX_SLOT_EXPIRED) && now_ns > s->forget_after_ns) {
            s->state = KX_SLOT_DELETED; /* keeps probe chains intact */
        }
    }
    return n;
}
