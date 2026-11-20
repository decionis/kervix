/*
 * Signed policy bundles (.kxp) and the vehicle's trust file. PORTABLE: the
 * structural parse and the acceptance rule live here; the Ed25519 check is a
 * callback (qcrypto on QNX, a stub or Node in tests).
 *
 *   bundle: "KXP1" | u32 body_len | body | u8 n_sigs | n_sigs x { u8 role | pubkey[32] | sig[64] }
 *   signed message: "kervix.policy-signature/1" 0x00 | role | sha256(body)    (59 bytes)
 *   trust file: one entry per line, "author|approver ed25519:<64 hex> <label>", '#' comments
 *
 * Acceptance (all required): one author and one approver signature; the two
 * keys differ; each key is listed in the trust file FOR ITS ROLE; both verify.
 * The body is then loaded with kx_policy_load (policy.h).
 */
#ifndef KERVIX_BUNDLE_H
#define KERVIX_BUNDLE_H

#include <stdint.h>

#include "kervix/policy.h"

#define KX_ROLE_AUTHOR   1u
#define KX_ROLE_APPROVER 2u
#define KX_BUNDLE_MAX    (8u + KX_POLICY_BODY_MAX + 1u + 2u * 97u)
#define KX_BUNDLE_MSG_LEN 59u
#define KX_TRUST_MAX     16
#define KX_TRUST_LABEL   24u

typedef struct { uint8_t role; uint8_t pub[32]; uint8_t sig[64]; } kx_bundle_sig_t;
typedef struct {
    const uint8_t  *body;              /* points into the caller's buffer */
    uint32_t        body_len;
    uint8_t         n_sigs;
    kx_bundle_sig_t sig[2];
} kx_bundle_t;

typedef struct { uint8_t role; uint8_t pub[32]; char label[KX_TRUST_LABEL]; } kx_trust_t;

/* Structure only (no crypto). 0 = well-formed. */
int  kx_bundle_parse(const uint8_t *buf, uint32_t n, kx_bundle_t *out);
/* The 59-byte message a role signs: domain | 0 | role | sha256(body). */
void kx_bundle_message(uint8_t role, const uint8_t *body, uint32_t body_len, uint8_t out[KX_BUNDLE_MSG_LEN]);
/* Trust file -> entries. Returns the count (0..max), or -1 on a malformed line. */
int  kx_trust_parse(const char *text, uint32_t n, kx_trust_t *out, int max);

/* 1 = signature valid. */
typedef int (*kx_sig_verify_fn)(const uint8_t pub[32], const uint8_t *msg, uint32_t msg_len, const uint8_t sig[64], void *ctx);
typedef enum {
    KX_BUNDLE_OK = 0,
    KX_BUNDLE_MALFORMED,
    KX_BUNDLE_MISSING_ROLE,
    KX_BUNDLE_SAME_KEY,
    KX_BUNDLE_UNTRUSTED,
    KX_BUNDLE_BAD_SIGNATURE,
} kx_bundle_verdict_t;
/* The acceptance rule. On OK, *author / *approver index the trust entries that signed. */
kx_bundle_verdict_t kx_bundle_accept(const kx_bundle_t *b, const kx_trust_t *trust, int n_trust,
                                     kx_sig_verify_fn verify, void *ctx, int *author, int *approver);
const char *kx_bundle_verdict_name(kx_bundle_verdict_t v);

#endif /* KERVIX_BUNDLE_H */
