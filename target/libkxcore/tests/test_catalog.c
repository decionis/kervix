/* Sanity tests for the generated catalog tables. */
#include "kervix/catalog_gen.h"
#include "kx_test.h"

int main(void) {
    /* every action resolves by id and has consistent params */
    for (int i = 0; i < KX_ACTION_COUNT; i++) {
        const kx_action_spec_t *a = &kx_catalog_actions[i];
        KX_CHECK(kx_catalog_action(a->id) == a);
        KX_CHECK(a->n_params <= KX_CATALOG_MAX_PARAMS);
        int digests = 0;
        for (int p = 0; p < a->n_params; p++) {
            const kx_param_spec_t *ps = &a->params[p];
            KX_CHECK(ps->key > 0 && ps->key < KX_PARAM_KEY_COUNT);
            KX_CHECK_STR(kx_catalog_param_names[ps->key], ps->name);
            KX_CHECK(kx_catalog_param(a, ps->key) == ps);
            if (ps->type == KX_PT_DIGEST) digests++;
            else KX_CHECK(ps->min <= ps->max);
            KX_CHECK((ps->type == KX_PT_ENUM) == (ps->enum_values != NULL));
        }
        KX_CHECK(digests <= 1);
    }

    /* unknown ids are rejected (default-deny starts here) */
    KX_CHECK(kx_catalog_action(0) == NULL);
    KX_CHECK(kx_catalog_action(KX_ACTION_MAX_ID + 1) == NULL);
    KX_CHECK(kx_catalog_action(0xFFFF) == NULL);

    /* spot checks against catalog.yaml */
    const kx_action_spec_t *ota = kx_catalog_action(KX_ACT_OTA_ECU_FLASH);
    KX_CHECK(ota != NULL);
    if (ota) {
        KX_CHECK_STR(ota->name, "ota.ecu.flash");
        KX_CHECK(ota->irreversibility == KX_IRR_ONE_WAY_CONSEQUENTIAL);
        KX_CHECK(ota->safety == KX_SAFETY_SAFETY);
        const kx_param_spec_t *ecu = kx_catalog_param(ota, KX_P_ECU);
        KX_CHECK(ecu != NULL && ecu->type == KX_PT_ENUM && ecu->max == KX_ECU__COUNT - 1);
        if (ecu) KX_CHECK_STR(ecu->enum_values[KX_ECU_BRAKE], "brake");
        KX_CHECK(kx_catalog_param(ota, KX_P_TEMP_DC) == NULL);
    }

    /* reasons */
    const kx_reason_spec_t *r = kx_catalog_reason(KX_R_R156_NOT_SAFE_STATE);
    KX_CHECK(r != NULL);
    if (r) KX_CHECK_STR(r->name, "R156_NOT_SAFE_STATE");
    KX_CHECK(kx_catalog_reason(KX_R_OK) != NULL);
    KX_CHECK(kx_catalog_reason(9) == NULL);    /* gap in the id space */
    KX_CHECK(kx_catalog_reason(65535) == NULL);

    /* telemetry */
    KX_CHECK_STR(kx_catalog_tfields[KX_TF_SPEED_DKPH].vss, "Vehicle.Speed");
    KX_CHECK(kx_catalog_tfields[KX_TF_SERVICE_MODE].vss == NULL); /* Kervix extension */
    KX_CHECK(kx_catalog_tfields[KX_TF_GEAR].max == KX_GEAR__COUNT - 1);

    KX_TEST_DONE();
}
