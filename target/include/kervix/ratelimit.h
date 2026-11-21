/*
 * F12: rate limits per (principal, action), as a GCRA token bucket.
 *
 * The principal is the secpol type the QNX kernel stamps on the proposer's
 * messages (ctp->info.type_id), never the agent's self-declared actor_id,
 * which an agent could rotate to dodge the limit. Limits come from the catalog
 * (catalog.yaml `rate`), so they are part of the vehicle's constitution: a
 * signed policy cannot loosen them.
 *
 * GCRA in integer nanoseconds (no floating point, no clock read): with
 * T = 60 s / per_min and tau = (burst - 1) * T, a proposal at time `now`
 * conforms iff tat <= now + tau, and then tat' = max(tat, now) + T.
 * A fresh bucket has tat = 0. kx_rl_step() is pure: kervixd, the host tests
 * and the WebAssembly verifier run the same code, and every limited-or-not
 * outcome is replayed from the tat recorded in the decision capsule.
 */
#ifndef KERVIX_RATELIMIT_H
#define KERVIX_RATELIMIT_H

#include <stdint.h>
#include "kervix/catalog_gen.h"

#define KX_RL_MAX_TYPES 8u   /* distinct principals tracked per epoch */

typedef struct {
    uint32_t type_id[KX_RL_MAX_TYPES];
    uint32_t n_types;
    uint64_t tat[KX_RL_MAX_TYPES][KX_ACTION_MAX_ID + 1];
} kx_rl_t;

typedef struct {
    uint8_t  limited;     /* 1 = over the limit: BLOCK RATE_LIMITED */
    uint8_t  overflow;    /* 1 = no bucket left for this principal (fail closed, limited) */
    uint16_t burst, per_min;
    uint64_t tat_before;  /* bucket state the decision was made on (recorded as evidence) */
} kx_rl_result_t;

/* Pure GCRA step. Returns 1 = conforms (*tat_after = max(tat, now) + T),
 * 0 = limited (*tat_after = tat), -1 = invalid limit (burst or per_min 0). */
int kx_rl_step(uint16_t burst, uint16_t per_min, uint64_t tat, uint64_t now_ns, uint64_t *tat_after);

void kx_rl_init(kx_rl_t *rl);

/* Charge one proposal. Returns 1 = within the limit (charged), 0 = limited,
 * -1 = the action has no limit (nothing to record). */
int kx_rl_take(kx_rl_t *rl, uint32_t type_id, uint16_t action, uint64_t now_ns, kx_rl_result_t *out);

#endif /* KERVIX_RATELIMIT_H */
