/*
 * kervixd ledger subsystem: vehicle key, crash-safe append-only ledger and the
 * low-priority writer thread that turns lifecycle records into signed capsules.
 *
 *   <datadir>/keys/vehicle.key        Ed25519 private key, PKCS#8 DER, mode 0400
 *   <datadir>/keys/vehicle.jwk.json   public key (OKP/Ed25519, RFC 7638 thumbprint kid)
 *   <datadir>/ledger/ledger.kxl       framed records (kervix/ledger.h)
 *   <datadir>/ledger/quarantine-*.bin torn tails moved aside at recovery
 *
 * Producers (request handlers) call kxl_submit() under kervixd's state lock;
 * a bounded MPSC ring decouples them from signing and disk I/O, so recording
 * never delays a decision. "No audit, no action": kxl_healthy() feeds K3.
 */
#ifndef KERVIXD_KXLEDGER_H
#define KERVIXD_KXLEDGER_H

#include <stddef.h>
#include <stdint.h>

#include "kervix/capsule.h"

typedef struct {
    const char *datadir;
    const char *vehicle_id;
    const char *tenant_id;
    uint32_t    ring_cap;       /* records; K3 trips at 90% */
    uint32_t    slow_ms;        /* test hook: artificial delay per record (simulated slow storage) */
    int         verbose;
    uint8_t     policy_hash[32];
} kxl_config_t;

/* Load or create the vehicle key, recover the ledger, queue the epoch capsule
 * and start the writer thread (priority 15). 0 ok, -1 fatal (refuse to run). */
int  kxl_open(const kxl_config_t *cfg);
/* Free queue slots right now. */
uint32_t kxl_free(void);
/* Queue a record, keeping at least `keep_free` slots free afterwards.
 * Every action must be recorded, so the caller reserves one slot per pending
 * terminal record (outstanding grants + grants awaiting their effect) and
 * passes keep_free = 0 only for those terminal records themselves.
 * 0 queued; -1 not queued (counted as dropped; only non-terminal records,
 * i.e. decisions that changed nothing, can be dropped). */
int  kxl_submit(const kx_capsule_rec_t *rec, uint32_t keep_free);
/* K3 input: queue below 90% and no writer/storage error (latched). */
int  kxl_healthy(void);
/* One-line status for /dev/kervix/stats. */
void kxl_status(char *buf, size_t cap);

#endif /* KERVIXD_KXLEDGER_H */
