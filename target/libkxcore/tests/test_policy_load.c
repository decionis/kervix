/* kx_policy_load on the canonical body compiled by host/kxpolicy from
 * policies/default.yaml (tests/fixtures/policy-default.body): it must load to
 * exactly the built-in policy, and reject every malformed variant without
 * reading out of bounds (run under ASan in CI). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kervix/policy.h"
#include "kx_test.h"

static kx_policy_t A, B;

int main(void) {
    FILE *f = fopen(KX_FIXTURE_DIR "/policy-default.body", "rb");
    KX_CHECK(f != NULL);
    if (!f) KX_TEST_DONE();
    static uint8_t body[KX_POLICY_BODY_MAX + 16];
    uint32_t n = (uint32_t)fread(body, 1, sizeof body, f);
    fclose(f);
    KX_CHECK(n > KX_POLICY_BODY_HDR);

    KX_CHECK(kx_policy_build_default(&A) == 0);
    KX_CHECK(kx_policy_load(&B, body, n) == 0);
    KX_CHECK(memcmp(A.hash, B.hash, 32) == 0);           /* YAML (compiled) == built-in C */
    KX_CHECK(B.n_rules == A.n_rules && B.n_preds == A.n_preds);
    KX_CHECK(strcmp(B.policy_id, "kervix-default") == 0);

    int all = 1;
    for (uint32_t k = 0; k < n; k++) if (kx_policy_load(&B, body, k) == 0) all = 0;   /* every truncation */
    KX_CHECK(all);
    body[n] = 0;
    KX_CHECK(kx_policy_load(&B, body, n + 1) != 0);       /* trailing byte */
    KX_CHECK(kx_policy_load(&B, body, KX_POLICY_BODY_MAX + 1) != 0);

    /* every single-byte corruption: rejected, or loaded as a DIFFERENT policy (never the same hash) */
    int same = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t save = body[i];
        body[i] ^= 0x5a;
        if (kx_policy_load(&B, body, n) == 0 && memcmp(A.hash, B.hash, 32) == 0) same++;
        body[i] = save;
    }
    KX_CHECK(same == 0);
    KX_CHECK(kx_policy_load(&B, body, n) == 0);
    KX_TEST_DONE();
}
