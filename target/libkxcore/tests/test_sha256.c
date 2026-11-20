/* SHA-256 (FIPS 180-4 / NIST CAVS examples) and HMAC-SHA256 (RFC 4231). */
#include <string.h>

#include "kervix/sha256.h"
#include "kx_test.h"

static void check_hex(const uint8_t *d, const char *expect) {
    char hx[65];
    kx_hex(d, 32, hx);
    KX_CHECK_STR(hx, expect);
    if (strcmp(hx, expect) != 0) fprintf(stderr, "  got %s\n  exp %s\n", hx, expect);
}

int main(void) {
    uint8_t d[32];

    kx_sha256("", 0, d);
    check_hex(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    kx_sha256("abc", 3, d);
    check_hex(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    kx_sha256(m448, strlen(m448), d);
    check_hex(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* one million 'a', fed in uneven chunks to exercise buffering */
    kx_sha256_t s;
    kx_sha256_init(&s);
    char chunk[997];
    memset(chunk, 'a', sizeof chunk);
    size_t left = 1000000;
    while (left > 0) {
        size_t n = left < sizeof chunk ? left : sizeof chunk;
        kx_sha256_update(&s, chunk, n);
        left -= n;
    }
    kx_sha256_final(&s, d);
    check_hex(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    /* 55 bytes: the largest message that pads into a single block (value from shasum -a 256) */
    char b64[64];
    memset(b64, 'x', sizeof b64);
    kx_sha256(b64, 55, d);
    check_hex(d, "d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072");

    /* RFC 4231 HMAC-SHA256 test cases 1, 2, 4, 6 */
    uint8_t key[131];
    memset(key, 0x0b, 20);
    kx_hmac_sha256(key, 20, "Hi There", 8, d);
    check_hex(d, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    kx_hmac_sha256((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, d);
    check_hex(d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    for (int i = 0; i < 25; i++) key[i] = (uint8_t)(i + 1);
    uint8_t msg[50];
    memset(msg, 0xcd, sizeof msg);
    kx_hmac_sha256(key, 25, msg, sizeof msg, d);
    check_hex(d, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

    memset(key, 0xaa, 131);
    const char *t6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    kx_hmac_sha256(key, 131, t6, strlen(t6), d);
    check_hex(d, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    uint8_t a[4] = { 1, 2, 3, 4 }, b[4] = { 1, 2, 3, 4 };
    KX_CHECK(kx_ct_equal(a, b, 4) == 1);
    b[3] = 5;
    KX_CHECK(kx_ct_equal(a, b, 4) == 0);

    KX_TEST_DONE();
}
