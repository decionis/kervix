/*
 * Execution grants: single-use, time-bound, proposer-bound authorizations
 * issued by kervixd for an ALLOW (or a human-approved ESCALATE) and redeemed
 * exactly once by sdv_actuatord just before actuation.
 *
 * Security properties (each has a test in tests/test_grant.c):
 *   - authenticity  HMAC-SHA256 under a per-boot key that never leaves kervixd
 *                   (a restart invalidates every outstanding grant: fail-closed)
 *   - single use    redemption consumes the grant; replays are GRANT_SPENT
 *   - freshness     CLOCK_MONOTONIC deadline; late redemption is GRANT_EXPIRED
 *   - exactness     the command must match the authorized params digest
 *   - binding       only the client that proposed may have it executed
 *   - TOCTOU        the rule's interlock is re-evaluated on live telemetry
 * Any failed redemption also CONSUMES the grant: the agent must propose
 * again and be re-evaluated on fresh state.
 *
 * Not thread-safe: kervixd serializes access (single owner thread or lock).
 * Bounded: fixed slots, open addressing, no allocation, constant loop bounds.
 */
#ifndef KERVIX_GRANT_H
#define KERVIX_GRANT_H

#include <stdint.h>

#include "kervix/abi.h"
#include "kervix/policy.h"

#define KX_GRANT_SLOTS         512u
#define KX_GRANT_KEY_LEN       32u
/* Spent/expired grants are remembered this long past their deadline so a
 * replay is reported precisely (SPENT) rather than as UNKNOWN. */
#define KX_GRANT_TOMBSTONE_NS  (60ull * 1000000000ull)

/* Executor identity as stamped by the kernel on the message that carried the
 * EXECUTE request (ctp->info: pid + secpol type id). */
typedef kx_client_id_t kx_client_t;

/* SPENT and EXPIRED are tombstones kept for the grace period so a late
 * presentation is reported precisely (replay vs. too late). */
typedef enum { KX_SLOT_FREE = 0, KX_SLOT_OUTSTANDING, KX_SLOT_SPENT, KX_SLOT_DELETED, KX_SLOT_EXPIRED } kx_slot_state_t;

typedef struct {
    uint8_t     state;          /* kx_slot_state_t */
    uint8_t     _pad;
    int16_t     rule_index;     /* rule whose interlock must hold at redemption */
    uint32_t    _pad2;
    uint64_t    forget_after_ns;
    kx_grant_t  grant;
    kx_intent_t intent;         /* for interlock predicates that read params */
} kx_grant_slot_t;

typedef struct {
    uint8_t         key[KX_GRANT_KEY_LEN];
    uint32_t        outstanding;
    uint32_t        _pad;
    kx_grant_slot_t slots[KX_GRANT_SLOTS];
} kx_grant_table_t;

/* Deterministic digest of the exact command an intent authorizes:
 * action + params sorted by key + digest flag/bytes (packed little-endian). */
void kx_params_digest(const kx_intent_t *in, uint8_t out[32]);

/* key: 32 bytes from the CSPRNG at kervixd start. */
void kx_grant_table_init(kx_grant_table_t *t, const uint8_t key[KX_GRANT_KEY_LEN]);

/* Issue a grant for an evaluated intent. grant_id: 16 CSPRNG bytes (caller).
 * Returns KX_R_OK, or KX_R_GRANT_TABLE_FULL (caller must BLOCK). */
uint16_t kx_grant_issue(kx_grant_table_t *t, const kx_intent_t *in, const uint8_t intent_hash[32],
                        const uint8_t policy_hash[32], int16_t rule_index, uint32_t ttl_ms,
                        kx_client_t proposer, const uint8_t grant_id[16], uint64_t now_ns,
                        kx_grant_t *out);

/* Redeem: checks run in this fixed order, the first failure wins:
 *   MAC, UNKNOWN, SPENT, EXPIRED, PARAMS, BINDING, INTERLOCK.
 * `command` is the action/params the executor is about to perform;
 * `presenter` is who asked the executor to perform it.
 * Returns KX_R_OK (grant consumed, actuate now) or a KX_R_GRANT_* reason. */
uint16_t kx_grant_redeem(kx_grant_table_t *t, const kx_grant_t *presented, const kx_intent_t *command,
                         kx_client_t presenter, uint64_t now_ns, const kx_policy_t *pol,
                         const kx_telemetry_t *tel);

/* Expire outstanding grants past their deadline (each becomes a tombstone) and
 * free tombstones past their grace period. Writes up to `max` expired grant
 * ids to `expired_ids` (for "expired" capsules). Returns how many expired. */
uint32_t kx_grant_reap(kx_grant_table_t *t, uint64_t now_ns, uint8_t (*expired_ids)[16], uint32_t max);

#endif /* KERVIX_GRANT_H */
