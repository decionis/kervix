/*
 * Telemetry shared-memory segment + single-writer seqlock.
 *
 * vsimd (the only writer, secpol type vsim_t) maps the segment read/write;
 * kervixd and tools map it READ-ONLY, so a compromised reader cannot forge
 * vehicle state. Readers never block the writer and never take a lock:
 *
 *   writer: seq -> odd, publish fields, seq -> even (release)
 *   reader: s1 = seq (acquire, must be even), copy, fence, s2 = seq; retry if s1 != s2
 *
 * Bounded: kx_seqlock_read() retries at most `max_tries` times and reports
 * failure instead of spinning, so the caller can fail closed (TELEMETRY_STALE).
 * The payload copy uses relaxed atomic word loads, so concurrent reads are
 * race-free in the C11 memory model, not just "usually fine".
 */
#ifndef KERVIX_SEQLOCK_H
#define KERVIX_SEQLOCK_H

#include <stdint.h>
#include <string.h>

#include "kervix/abi.h"

#define KX_TELEMETRY_SHM_NAME  "/kervix_telemetry"
#define KX_TELEMETRY_SHM_MAGIC 0x4B585431u /* "KXT1" */

typedef struct {
    uint32_t       magic;
    uint16_t       abi;
    uint16_t       n_fields;      /* KX_TF__COUNT when written */
    uint32_t       period_us;     /* publish period, informational */
    uint32_t       writer_pid;
    uint64_t       seqlock;       /* even = stable; accessed only via __atomic builtins */
    kx_telemetry_t snap;
} kx_telemetry_shm_t;

_Static_assert(sizeof(kx_telemetry_t) % sizeof(uint64_t) == 0, "word-wise copy needs 8-byte multiple");

static inline void kx_seqlock_write(kx_telemetry_shm_t *shm, const kx_telemetry_t *t) {
    uint64_t s = __atomic_load_n(&shm->seqlock, __ATOMIC_RELAXED);
    __atomic_store_n(&shm->seqlock, s + 1, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    const uint64_t *src = (const uint64_t *)(const void *)t;
    uint64_t *dst = (uint64_t *)(void *)&shm->snap;
    for (size_t i = 0; i < sizeof *t / sizeof(uint64_t); i++) __atomic_store_n(&dst[i], src[i], __ATOMIC_RELAXED);
    __atomic_store_n(&shm->seqlock, s + 2, __ATOMIC_RELEASE);
}

/* 0 on a consistent snapshot, -1 if none within max_tries (writer mid-update
 * every time, or the segment is not initialized). */
static inline int kx_seqlock_read(const kx_telemetry_shm_t *shm, kx_telemetry_t *out, unsigned max_tries) {
    if (__atomic_load_n(&shm->magic, __ATOMIC_ACQUIRE) != KX_TELEMETRY_SHM_MAGIC) return -1;
    for (unsigned n = 0; n < max_tries; n++) {
        uint64_t s1 = __atomic_load_n(&shm->seqlock, __ATOMIC_ACQUIRE);
        if (s1 & 1u) continue;
        const uint64_t *src = (const uint64_t *)(const void *)&shm->snap;
        uint64_t *dst = (uint64_t *)(void *)out;
        for (size_t i = 0; i < sizeof *out / sizeof(uint64_t); i++) dst[i] = __atomic_load_n(&src[i], __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&shm->seqlock, __ATOMIC_RELAXED) == s1) return 0;
    }
    return -1;
}

#endif /* KERVIX_SEQLOCK_H */
