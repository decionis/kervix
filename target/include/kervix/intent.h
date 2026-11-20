/*
 * Agent-Safe Intent v1 ("agent-safe.intent/1") binding for a Kervix intent.
 *
 * Execution authority is bound to the hash of this canonical binding, and to
 * nothing looser: every single-field change yields another intent. The
 * binding is rebuilt deterministically from (kx_intent_t, kx_intent_ctx_t),
 * so the offline verifier can recompute it from a capsule's evidence.
 *
 * Shape (keys shown in canonical order):
 *   { "action": { "parameters": {...sorted}, "resource": "vehicle/<vehicle_id>", "type": "<action>" },
 *     "actor": { "id": "<actor_id>", "type": "<actor_type>" },
 *     "captured_at": "<RFC3339 ms Z>", "context": { "idempotency_key": "<intent uuid>" },
 *     "downstream_target": { "environment": "vehicle", "operation": "<action>", "system": "sdv_actuatord" },
 *     "expires_at": "<RFC3339 ms Z>", "intent_id": "<uuid>",
 *     "protocol_version": "agent-safe.intent/1", "tenant_id": "<vehicle uuid>" }
 * Parameter values: int -> integer, enum -> its catalog name, bool -> true/false,
 * digest -> "sha256:<64 hex>".
 */
#ifndef KERVIX_INTENT_H
#define KERVIX_INTENT_H

#include <stddef.h>
#include <stdint.h>

#include "kervix/abi.h"

#define KX_INTENT_PROTOCOL       "agent-safe.intent/1"
#define KX_INTENT_JCS_MAX        1536u
#define KX_INTENT_DEFAULT_TTL_MS 5000

typedef struct {
    const char *tenant_id;      /* vehicle UUID (lowercase 8-4-4-4-12) */
    const char *vehicle_id;     /* pseudonymous vehicle id, ASCII, used in action.resource */
    const char *actor_type;     /* e.g. "ai_agent" */
    int64_t     captured_at_ms; /* realtime epoch ms when Kervix received the intent */
} kx_intent_ctx_t;

/* Writes the canonical binding (NUL-terminated). Returns length, or -1 if the
 * intent is invalid for binding or the buffer is too small. */
int kx_intent_jcs(const kx_intent_t *in, const kx_intent_ctx_t *ctx, char *out, size_t cap);

/* SHA-256 over the canonical binding. Returns 0, or -1 as above. */
int kx_intent_hash(const kx_intent_t *in, const kx_intent_ctx_t *ctx, uint8_t out[32]);

/* expires_at actually bound: the caller's expiry, or captured_at + default TTL. */
int64_t kx_intent_expires_ms(const kx_intent_t *in, const kx_intent_ctx_t *ctx);

#endif /* KERVIX_INTENT_H */
