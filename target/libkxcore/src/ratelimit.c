/* F12 rate limiter: GCRA token bucket per (principal type, action). See kervix/ratelimit.h. */
#include <string.h>

#include "kervix/ratelimit.h"

int kx_rl_step(uint16_t burst, uint16_t per_min, uint64_t tat, uint64_t now_ns, uint64_t *tat_after) {
    if (burst == 0 || per_min == 0) return -1;
    const uint64_t t = 60000000000ull / per_min;
    const uint64_t tau = (uint64_t)(burst - 1u) * t;
    if (tat > now_ns + tau) { *tat_after = tat; return 0; }
    *tat_after = (tat > now_ns ? tat : now_ns) + t;
    return 1;
}

void kx_rl_init(kx_rl_t *rl) { memset(rl, 0, sizeof *rl); }

int kx_rl_take(kx_rl_t *rl, uint32_t type_id, uint16_t action, uint64_t now_ns, kx_rl_result_t *out) {
    memset(out, 0, sizeof *out);
    const kx_action_spec_t *a = kx_catalog_action(action);
    if (a == NULL || a->rate_burst == 0 || a->rate_per_min == 0) return -1;
    out->burst = a->rate_burst;
    out->per_min = a->rate_per_min;
    uint32_t i = 0;
    while (i < rl->n_types && rl->type_id[i] != type_id) i++;
    if (i == rl->n_types) {
        if (rl->n_types == KX_RL_MAX_TYPES) { out->limited = out->overflow = 1; return 0; }
        rl->type_id[rl->n_types++] = type_id;
    }
    uint64_t *tat = &rl->tat[i][action];
    out->tat_before = *tat;
    int ok = kx_rl_step(a->rate_burst, a->rate_per_min, *tat, now_ns, tat);
    out->limited = ok != 1;
    return ok == 1 ? 1 : 0;
}
