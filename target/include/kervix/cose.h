/*
 * Draft-04 Producer Envelope: tagged COSE_Sign1 over the raw 32-byte capsule
 * id, with protected header {1: -8 (EdDSA), 3: "application/agent-action-capsule-id",
 * 4: <32-byte Ed25519 public key>} and an empty unprotected map.
 * Fixed shape, so built from a byte template; no CBOR library needed.
 * Verified byte-for-byte against the pinned Decionis vector (tests).
 */
#ifndef KERVIX_COSE_H
#define KERVIX_COSE_H

#include <stddef.h>
#include <stdint.h>

#define KX_COSE_SIG_STRUCTURE_LEN 125u /* bytes Ed25519 signs */
#define KX_COSE_ENVELOPE_LEN      181u

/* The bytes to sign: ["Signature1", protected, h'', capsule_id] */
void kx_cose_sig_structure(const uint8_t pk[32], const uint8_t capsule_id[32], uint8_t out[KX_COSE_SIG_STRUCTURE_LEN]);
/* Tagged COSE_Sign1 envelope */
void kx_cose_envelope(const uint8_t pk[32], const uint8_t capsule_id[32], const uint8_t sig[64],
                      uint8_t out[KX_COSE_ENVELOPE_LEN]);

/* RFC 4648 §5 base64url without padding. out must hold 4*ceil(n/3)+1 bytes. Returns length. */
size_t kx_base64url(const uint8_t *in, size_t n, char *out);

#endif /* KERVIX_COSE_H */
