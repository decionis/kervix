/*
 * Bounded canonical-JSON (RFC 8785 / JCS) writer for the closed subset Kervix
 * emits: objects, arrays, ASCII-printable strings, safe integers, booleans.
 *
 * Canonical form is the CALLER's responsibility for key order: emit object
 * keys already sorted (all Kervix keys are ASCII, so byte order equals the
 * UTF-16 order JCS requires). The writer enforces everything else: commas,
 * escaping, integer formatting, bounds. Any error is sticky: check
 * kx_jw_ok() once at the end.
 */
#ifndef KERVIX_JCS_H
#define KERVIX_JCS_H

#include <stddef.h>
#include <stdint.h>

#define KX_JW_MAX_DEPTH 8
/* JavaScript's Number.MAX_SAFE_INTEGER: JCS integers must survive a JS round trip. */
#define KX_JW_MAX_SAFE_INT 9007199254740991LL

typedef struct {
    char    *buf;
    size_t   cap, len;
    int      err;                       /* sticky */
    uint8_t  depth;
    uint8_t  first[KX_JW_MAX_DEPTH];    /* 1 = next member is the first in container */
    uint8_t  after_key;                 /* a key was just written, value pending */
} kx_jw_t;

void kx_jw_init(kx_jw_t *w, char *buf, size_t cap);
void kx_jw_obj_begin(kx_jw_t *w);
void kx_jw_obj_end(kx_jw_t *w);
void kx_jw_arr_begin(kx_jw_t *w);
void kx_jw_arr_end(kx_jw_t *w);
void kx_jw_key(kx_jw_t *w, const char *key);
void kx_jw_str(kx_jw_t *w, const char *s);
void kx_jw_strn(kx_jw_t *w, const char *s, size_t n);
void kx_jw_int(kx_jw_t *w, int64_t v);
void kx_jw_bool(kx_jw_t *w, int v);
void kx_jw_null(kx_jw_t *w);
/* 1 if no error and all containers are closed; NUL-terminates the buffer. */
int  kx_jw_ok(kx_jw_t *w);

/* Formatting helpers (no libc time functions: deterministic everywhere). */
/* "YYYY-MM-DDTHH:MM:SS.mmmZ" for epoch milliseconds (proleptic Gregorian, UTC). out >= 25 bytes. */
int  kx_fmt_rfc3339_ms(int64_t epoch_ms, char out[25]);
/* Lowercase 8-4-4-4-12. out >= 37 bytes. */
void kx_fmt_uuid(const uint8_t uuid[16], char out[37]);
/* 1 if version nibble is 1..8 and variant is RFC 4122 (Agent-Safe Intent requirement). */
int  kx_uuid_valid(const uint8_t uuid[16]);

#endif /* KERVIX_JCS_H */
