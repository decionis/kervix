/* Minimal test harness for libkxcore host tests (no external dependencies). */
#ifndef KX_TEST_H
#define KX_TEST_H

#include <stdio.h>
#include <string.h>

static int kx_test_failures = 0;
static int kx_test_checks = 0;

#define KX_CHECK(cond)                                                        \
    do {                                                                      \
        kx_test_checks++;                                                     \
        if (!(cond)) {                                                        \
            kx_test_failures++;                                               \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
                    #cond);                                                   \
        }                                                                     \
    } while (0)

#define KX_CHECK_STR(a, b) KX_CHECK(strcmp((a), (b)) == 0)

#define KX_TEST_DONE()                                                         \
    do {                                                                       \
        printf("%d checks, %d failures\n", kx_test_checks, kx_test_failures); \
        return kx_test_failures == 0 ? 0 : 1;                                  \
    } while (0)

#endif /* KX_TEST_H */
