/*
 * kxgw wire format: newline-delimited JSON between the host (bridge, agent,
 * dashboard) and the QNX gateway. PORTABLE (no OS headers): built into kxgw on
 * QNX and into the host unit tests / fuzz target.
 *
 * The gateway is the only network-facing process on the target and holds no
 * authority, but it is still the parser of untrusted bytes, so the parser is
 * deliberately small and closed:
 *   - one JSON object per line, at most KXW_LINE_MAX bytes
 *   - a FIXED set of top-level keys (unknown or duplicate key = error)
 *   - values: printable-ASCII strings (escapes \" \\ \/ only), integers
 *     (|v| <= 2^53-1, no fraction/exponent), true/false
 *   - one nested object, "params" (<= KXW_MAX_PARAMS members, scalar values)
 *   - no recursion, no allocation, every loop bounded by the line length
 * Anything else is rejected with a short reason; the gateway answers with an
 * error line and nothing reaches kervixd.
 *
 * Requests:
 *   {"op":"hello"}
 *   {"op":"propose","id":"r1","action":"body.door.unlock","params":{"door":"front_left"},
 *    "actor":"agent:cabin-copilot","intent_id":"<uuid>","expires_at_ms":<epoch ms>,
 *    "exec":true,"await":true}                                  (agent)
 *   {"op":"execute","id":"r2","grant_id":"<32 hex>"}            (agent)
 *   {"op":"state"} | {"op":"stats"}                             (agent, hmi, observer)
 *   {"op":"escalations"}                                        (hmi)
 *   {"op":"resolve","escalation_id":3,"approve":true,"approver":"hmi:driver"}  (hmi)
 *   {"op":"subscribe","hz":10}                                  (observer)
 *   {"op":"sim","cmd":"scenario highway"}                       (world)
 */
#ifndef KERVIX_KXGW_WIRE_H
#define KERVIX_KXGW_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "kervix/abi.h"
#include "kervix/jcs.h"

#define KXW_LINE_MAX   4096u
#define KXW_ID_MAX     40u
#define KXW_MAX_PARAMS 8u

typedef enum {
    KXW_OP_NONE = 0,
    KXW_OP_HELLO,
    KXW_OP_PROPOSE,
    KXW_OP_EXECUTE,
    KXW_OP_STATE,
    KXW_OP_STATS,
    KXW_OP_ESCALATIONS,
    KXW_OP_RESOLVE,
    KXW_OP_SUBSCRIBE,
    KXW_OP_SIM,
    KXW_OP__COUNT
} kxw_op_t;

typedef struct {
    char    name[24];
    uint8_t is_str;
    char    str[72];      /* enum name or "sha256:<64 hex>" */
    int64_t num;          /* integer, or 0/1 for booleans */
} kxw_param_t;

typedef struct {
    uint8_t     op;                   /* kxw_op_t */
    char        id[KXW_ID_MAX];       /* client correlation id, echoed back ([A-Za-z0-9._:-]) */
    char        action[48];
    char        actor[KX_ACTOR_LEN];
    uint8_t     has_intent_id;
    uint8_t     intent_id[16];
    int64_t     expires_at_ms;        /* 0 = none */
    uint8_t     n_params;
    kxw_param_t p[KXW_MAX_PARAMS];
    uint8_t     exec, await_esc;
    uint8_t     has_grant_id;
    uint8_t     grant_id[16];
    uint32_t    escalation_id;
    uint8_t     has_approve, approve;
    char        approver[32];
    char        cmd[128];
    uint32_t    hz;
} kxw_req_t;

/* Parse one line (without or with a trailing "\n" / "\r\n"). 0 = ok; on error
 * returns -1 and points *err at a static, printable reason. */
int kxw_parse(const char *line, size_t n, kxw_req_t *rq, const char **err);

/* Build the ABI intent for a PROPOSE from the catalog: action and parameter
 * names, enum names, sha256 digests. Range checks are left to kervixd (K4), so
 * an out-of-range value is decided, recorded and BLOCKed like any other. */
int kxw_to_intent(const kxw_req_t *rq, kx_intent_t *in, const char **err);

const char *kxw_op_name(uint8_t op);
const char *kxw_verdict_name(uint8_t verdict);
const char *kxw_gate_name(uint8_t gate);

/* Emitters: write members into an OPEN object of `w` (the caller owns the braces). */
void kxw_emit_decision(kx_jw_t *w, const kx_decision_t *d);
void kxw_emit_intent(kx_jw_t *w, const char *key, const kx_intent_t *in);
void kxw_emit_telemetry(kx_jw_t *w, const char *key, const kx_telemetry_t *t);
void kxw_emit_hex(kx_jw_t *w, const char *key, const char *prefix, const uint8_t *b, size_t n);
/* Free text (stats, simulator replies) as an array of lines, made printable
 * ASCII: U+2026 becomes "...", other non-printable bytes '?'. At most 64 lines. */
void kxw_emit_text(kx_jw_t *w, const char *key, const char *text, size_t n);

#endif /* KERVIX_KXGW_WIRE_H */
