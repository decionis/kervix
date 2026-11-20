/* Agent-Safe Intent v1 binding + hash. See kervix/intent.h. */
#include <string.h>

#include "kervix/intent.h"
#include "kervix/jcs.h"
#include "kervix/policy.h"
#include "kervix/sha256.h"

int64_t kx_intent_expires_ms(const kx_intent_t *in, const kx_intent_ctx_t *ctx) {
    return in->expires_rt_ms != 0 ? in->expires_rt_ms : ctx->captured_at_ms + KX_INTENT_DEFAULT_TTL_MS;
}

typedef struct { const char *name; const kx_param_spec_t *spec; const kx_param_t *val; } pslot_t;

int kx_intent_jcs(const kx_intent_t *in, const kx_intent_ctx_t *ctx, char *out, size_t cap) {
    if (in == NULL || ctx == NULL || ctx->tenant_id == NULL || ctx->vehicle_id == NULL ||
        ctx->actor_type == NULL || kx_validate_intent(in) != KX_R_OK) {
        return -1;
    }
    const kx_action_spec_t *a = kx_catalog_action(in->action);

    /* gather parameters (scalar + digest) and sort by name: <= 6, insertion sort */
    pslot_t ps[KX_CATALOG_MAX_PARAMS];
    uint8_t n = 0;
    for (uint8_t i = 0; i < a->n_params && i < KX_CATALOG_MAX_PARAMS; i++) {
        const kx_param_spec_t *spec = &a->params[i];
        const kx_param_t *val = NULL;
        if (spec->type != KX_PT_DIGEST) {
            for (uint8_t j = 0; j < in->n_params; j++) {
                if (in->p[j].key == spec->key) val = &in->p[j];
            }
            if (val == NULL) return -1;
        }
        pslot_t s = { spec->name, spec, val };
        uint8_t k = n++;
        while (k > 0 && strcmp(ps[k - 1].name, s.name) > 0) { ps[k] = ps[k - 1]; k--; }
        ps[k] = s;
    }

    char captured[25], expires[25], intent_id[37], digest_hex[65], digest_str[72];
    if (kx_fmt_rfc3339_ms(ctx->captured_at_ms, captured) != 0) return -1;
    if (kx_fmt_rfc3339_ms(kx_intent_expires_ms(in, ctx), expires) != 0) return -1;
    kx_fmt_uuid(in->intent_id, intent_id);

    char resource[96];
    size_t vl = strlen(ctx->vehicle_id);
    if (vl == 0 || vl > sizeof resource - 9) return -1;
    memcpy(resource, "vehicle/", 8);
    memcpy(resource + 8, ctx->vehicle_id, vl + 1);

    kx_jw_t w;
    kx_jw_init(&w, out, cap);
    kx_jw_obj_begin(&w);
      kx_jw_key(&w, "action");
      kx_jw_obj_begin(&w);
        kx_jw_key(&w, "parameters");
        kx_jw_obj_begin(&w);
        for (uint8_t i = 0; i < n; i++) {
            kx_jw_key(&w, ps[i].name);
            switch (ps[i].spec->type) {
            case KX_PT_INT:  kx_jw_int(&w, ps[i].val->val); break;
            case KX_PT_BOOL: kx_jw_bool(&w, ps[i].val->val != 0); break;
            case KX_PT_ENUM: kx_jw_str(&w, ps[i].spec->enum_values[ps[i].val->val]); break;
            case KX_PT_DIGEST:
                kx_hex(in->digest, 32, digest_hex);
                memcpy(digest_str, "sha256:", 7);
                memcpy(digest_str + 7, digest_hex, 65);
                kx_jw_str(&w, digest_str);
                break;
            default: return -1;
            }
        }
        kx_jw_obj_end(&w);
        kx_jw_key(&w, "resource");  kx_jw_str(&w, resource);
        kx_jw_key(&w, "type");      kx_jw_str(&w, a->name);
      kx_jw_obj_end(&w);
      kx_jw_key(&w, "actor");
      kx_jw_obj_begin(&w);
        kx_jw_key(&w, "id");   kx_jw_str(&w, in->actor_id);
        kx_jw_key(&w, "type"); kx_jw_str(&w, ctx->actor_type);
      kx_jw_obj_end(&w);
      kx_jw_key(&w, "captured_at"); kx_jw_str(&w, captured);
      kx_jw_key(&w, "context");
      kx_jw_obj_begin(&w);
        kx_jw_key(&w, "idempotency_key"); kx_jw_str(&w, intent_id);
      kx_jw_obj_end(&w);
      kx_jw_key(&w, "downstream_target");
      kx_jw_obj_begin(&w);
        kx_jw_key(&w, "environment"); kx_jw_str(&w, "vehicle");
        kx_jw_key(&w, "operation");   kx_jw_str(&w, a->name);
        kx_jw_key(&w, "system");      kx_jw_str(&w, "sdv_actuatord");
      kx_jw_obj_end(&w);
      kx_jw_key(&w, "expires_at");       kx_jw_str(&w, expires);
      kx_jw_key(&w, "intent_id");        kx_jw_str(&w, intent_id);
      kx_jw_key(&w, "protocol_version"); kx_jw_str(&w, KX_INTENT_PROTOCOL);
      kx_jw_key(&w, "tenant_id");        kx_jw_str(&w, ctx->tenant_id);
    kx_jw_obj_end(&w);
    if (!kx_jw_ok(&w)) return -1;
    return (int)w.len;
}

int kx_intent_hash(const kx_intent_t *in, const kx_intent_ctx_t *ctx, uint8_t out[32]) {
    char buf[KX_INTENT_JCS_MAX];
    int n = kx_intent_jcs(in, ctx, buf, sizeof buf);
    if (n < 0) return -1;
    kx_sha256(buf, (size_t)n, out);
    return 0;
}
