/* F12 rate limiter: GCRA semantics, independence of keys, fail-closed overflow,
 * and a long randomized run checked against a reference token bucket. */
#include <string.h>

#include "kervix/ratelimit.h"
#include "kx_test.h"

#define S 1000000000ull
#define T0 (1000ull * S)

static kx_rl_t RL;

static void test_step(void) {
    uint64_t after = 0;
    KX_CHECK(kx_rl_step(0, 6, 0, T0, &after) == -1);
    KX_CHECK(kx_rl_step(3, 0, 0, T0, &after) == -1);
    /* burst 3, 6/min: T = 10 s, tau = 20 s */
    KX_CHECK(kx_rl_step(3, 6, 0, T0, &after) == 1 && after == T0 + 10 * S);
    KX_CHECK(kx_rl_step(3, 6, T0 + 30 * S, T0 + 10 * S, &after) == 1 && after == T0 + 40 * S);   /* tat == now + tau */
    KX_CHECK(kx_rl_step(3, 6, T0 + 30 * S + 1, T0 + 10 * S, &after) == 0 && after == T0 + 30 * S + 1);
}

static void test_burst_then_refill(void) {
    kx_rl_init(&RL);
    kx_rl_result_t r;
    const uint16_t A = KX_ACT_TELEMATICS_LOCATION_SHARE;
    const kx_action_spec_t *a = kx_catalog_action(A);
    KX_CHECK(a != NULL && a->rate_burst >= 1 && a->rate_per_min >= 1);
    const uint64_t T = 60ull * S / a->rate_per_min;
    for (uint16_t i = 0; i < a->rate_burst; i++) {
        KX_CHECK(kx_rl_take(&RL, 7, A, T0, &r) == 1);
        KX_CHECK(!r.limited && r.burst == a->rate_burst && r.per_min == a->rate_per_min);
        KX_CHECK(r.tat_before == (i == 0 ? 0 : T0 + (uint64_t)i * T));
    }
    KX_CHECK(kx_rl_take(&RL, 7, A, T0, &r) == 0 && r.limited && !r.overflow);
    uint64_t before = r.tat_before;
    KX_CHECK(kx_rl_take(&RL, 7, A, T0 + T - 1, &r) == 0 && r.tat_before == before);  /* a limited call does not charge */
    KX_CHECK(kx_rl_take(&RL, 7, A, T0 + T, &r) == 1);                                 /* one token back after T */
    KX_CHECK(kx_rl_take(&RL, 7, A, T0 + T, &r) == 0);
    /* independent keys: another principal, another action */
    KX_CHECK(kx_rl_take(&RL, 9, A, T0, &r) == 1 && r.tat_before == 0);
    KX_CHECK(kx_rl_take(&RL, 7, KX_ACT_CABIN_CLIMATE_SET, T0, &r) == 1 && r.tat_before == 0);
    /* idle for long enough: the full burst is available again, no more */
    uint64_t later = T0 + 3600 * S;
    int ok = 0;
    for (int i = 0; i < a->rate_burst + 5; i++) ok += kx_rl_take(&RL, 7, A, later, &r) == 1;
    KX_CHECK(ok == a->rate_burst);
}

static void test_unknown_and_overflow(void) {
    kx_rl_init(&RL);
    kx_rl_result_t r;
    KX_CHECK(kx_rl_take(&RL, 7, 0, T0, &r) == -1);
    KX_CHECK(kx_rl_take(&RL, 7, 999, T0, &r) == -1);
    for (uint32_t t = 0; t < KX_RL_MAX_TYPES; t++) KX_CHECK(kx_rl_take(&RL, 100 + t, KX_ACT_CABIN_CLIMATE_SET, T0, &r) == 1);
    KX_CHECK(kx_rl_take(&RL, 999, KX_ACT_CABIN_CLIMATE_SET, T0, &r) == 0 && r.limited && r.overflow);   /* fail closed */
    KX_CHECK(kx_rl_take(&RL, 100, KX_ACT_CABIN_CLIMATE_SET, T0, &r) == 1);                              /* known keys unaffected */
}

/* reference: a classic token bucket in exact rational arithmetic (tokens scaled by T) */
static void test_against_reference(void) {
    kx_rl_init(&RL);
    const uint16_t A = KX_ACT_CABIN_WINDOW_SET;
    const kx_action_spec_t *a = kx_catalog_action(A);
    const uint64_t T = 60ull * S / a->rate_per_min, cap = (uint64_t)a->rate_burst * T;
    uint64_t level = cap, last = T0, now = T0, seed = 12345;
    int mism = 0, limited = 0;
    for (int i = 0; i < 20000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        now += (seed >> 33) % (2 * T / a->rate_burst + 1);
        level += now - last; if (level > cap) level = cap; last = now;
        int want = level >= T;
        if (want) level -= T;
        kx_rl_result_t r;
        int got = kx_rl_take(&RL, 7, A, now, &r) == 1;
        mism += got != want;
        limited += !got;
    }
    KX_CHECK(mism == 0);
    KX_CHECK(limited > 0);
}

int main(void) {
    test_step();
    test_burst_then_refill();
    test_unknown_and_overflow();
    test_against_reference();
    KX_TEST_DONE();
}
