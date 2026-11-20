/* Seqlock: one writer thread publishes snapshots whose fields all equal the
 * sequence number; reader threads must never observe a torn snapshot. */
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#include "kervix/seqlock.h"
#include "../../libkxcore/tests/kx_test.h"

#define WRITES 300000
static kx_telemetry_shm_t SHM;
static atomic_int done;
static atomic_long torn, reads, fails;

static void *writer(void *arg) {
    (void)arg;
    kx_telemetry_t t;
    for (uint64_t i = 1; i <= WRITES; i++) {
        t.seq = i;
        t.mono_ns = i * 7;
        for (int f = 0; f < KX_TF__COUNT; f++) t.v[f] = (int32_t)i;
        kx_seqlock_write(&SHM, &t);
    }
    atomic_store(&done, 1);
    return NULL;
}

static void *reader(void *arg) {
    (void)arg;
    kx_telemetry_t t;
    uint64_t last = 0;
    while (!atomic_load(&done)) {
        if (kx_seqlock_read(&SHM, &t, 64) != 0) { atomic_fetch_add(&fails, 1); continue; }
        atomic_fetch_add(&reads, 1);
        int ok = t.mono_ns == t.seq * 7 && t.seq >= last;
        for (int f = 0; f < KX_TF__COUNT; f++) ok &= t.v[f] == (int32_t)t.seq;
        if (!ok) atomic_fetch_add(&torn, 1);
        last = t.seq;
    }
    return NULL;
}

int main(void) {
    memset(&SHM, 0, sizeof SHM);
    kx_telemetry_t z;
    memset(&z, 0, sizeof z);
    KX_CHECK(kx_seqlock_read(&SHM, &z, 4) == -1);   /* uninitialized segment */
    SHM.magic = KX_TELEMETRY_SHM_MAGIC;
    kx_seqlock_write(&SHM, &z);

    pthread_t w, r[3];
    for (int i = 0; i < 3; i++) pthread_create(&r[i], NULL, reader, NULL);
    pthread_create(&w, NULL, writer, NULL);
    pthread_join(w, NULL);
    for (int i = 0; i < 3; i++) pthread_join(r[i], NULL);

    printf("seqlock: %ld consistent reads, %ld bounded-retry misses, %ld torn\n",
           atomic_load(&reads), atomic_load(&fails), atomic_load(&torn));
    KX_CHECK(atomic_load(&torn) == 0);
    KX_CHECK(atomic_load(&reads) > 0);
    kx_seqlock_read(&SHM, &z, 4);
    KX_CHECK(z.seq == WRITES);
    KX_TEST_DONE();
}
