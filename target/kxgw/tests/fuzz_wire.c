/* libFuzzer target for the gateway's parser of untrusted bytes:
 *   clang -fsanitize=fuzzer,address,undefined ... (make fuzz-wire; CI runs it on Linux)
 * Properties: never crashes or reads out of bounds; anything accepted converts
 * (or is refused) without fault, and every emitted response is valid. */
#include <stdint.h>
#include <string.h>

#include "../wire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    kxw_req_t rq;
    const char *err = NULL;
    if (kxw_parse((const char *)data, size, &rq, &err) != 0) {
        if (err == NULL) __builtin_trap();
        return 0;
    }
    kx_intent_t in;
    if (rq.op == KXW_OP_PROPOSE && kxw_to_intent(&rq, &in, &err) == 0) {
        static char buf[4096];
        kx_jw_t w;
        kx_jw_init(&w, buf, sizeof buf);
        kx_jw_obj_begin(&w);
        kxw_emit_intent(&w, "intent", &in);
        kx_jw_obj_end(&w);
        if (!kx_jw_ok(&w)) __builtin_trap();
    }
    static char tbuf[8192];
    kx_jw_t w;
    kx_jw_init(&w, tbuf, sizeof tbuf);
    kx_jw_obj_begin(&w);
    kxw_emit_text(&w, "t", (const char *)data, size);
    kx_jw_obj_end(&w);
    return 0;
}
