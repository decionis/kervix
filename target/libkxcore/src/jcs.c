/* Bounded JCS writer + deterministic formatting helpers. See kervix/jcs.h. */
#include <string.h>

#include "kervix/jcs.h"

static void put(kx_jw_t *w, const char *s, size_t n) {
    if (w->err) return;
    if (n > w->cap - w->len || w->cap - w->len - n < 1) { /* keep room for the final NUL */
        w->err = 1;
        return;
    }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
}
static void putc1(kx_jw_t *w, char c) { put(w, &c, 1); }

/* Comma handling for a value or key about to be written. */
static void pre_value(kx_jw_t *w, int is_key) {
    if (w->err) return;
    if (w->after_key) {
        if (is_key) { w->err = 1; return; } /* key followed by key */
        w->after_key = 0;
        return;
    }
    if (w->depth == 0) {
        if (is_key || w->len != 0) w->err = 1; /* exactly one top-level value */
        return;
    }
    if (!w->first[w->depth - 1]) putc1(w, ',');
    w->first[w->depth - 1] = 0;
}

void kx_jw_init(kx_jw_t *w, char *buf, size_t cap) {
    memset(w, 0, sizeof *w);
    w->buf = buf;
    w->cap = cap;
    if (buf == NULL || cap == 0) w->err = 1;
}

static void open_c(kx_jw_t *w, char c) {
    pre_value(w, 0);
    if (w->depth >= KX_JW_MAX_DEPTH) { w->err = 1; return; }
    putc1(w, c);
    w->first[w->depth++] = 1;
}
static void close_c(kx_jw_t *w, char c) {
    if (w->err) return;
    if (w->depth == 0 || w->after_key) { w->err = 1; return; }
    w->depth--;
    putc1(w, c);
}
void kx_jw_obj_begin(kx_jw_t *w) { open_c(w, '{'); }
void kx_jw_obj_end(kx_jw_t *w) { close_c(w, '}'); }
void kx_jw_arr_begin(kx_jw_t *w) { open_c(w, '['); }
void kx_jw_arr_end(kx_jw_t *w) { close_c(w, ']'); }

/* Strings: Kervix only emits printable ASCII (0x20..0x7E); anything else is
 * an error rather than a silent escape, so producer and verifier can never
 * disagree on Unicode handling. Escapes match ECMAScript JSON.stringify. */
static void str_body(kx_jw_t *w, const char *s, size_t n) {
    putc1(w, '"');
    for (size_t i = 0; i < n && !w->err; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20u || c > 0x7Eu) { w->err = 1; return; }
        if (c == '"' || c == '\\') putc1(w, '\\');
        putc1(w, (char)c);
    }
    putc1(w, '"');
}

void kx_jw_key(kx_jw_t *w, const char *key) {
    pre_value(w, 1);
    if (w->err) return;
    str_body(w, key, strlen(key));
    putc1(w, ':');
    w->after_key = 1;
}
void kx_jw_strn(kx_jw_t *w, const char *s, size_t n) {
    pre_value(w, 0);
    if (!w->err) str_body(w, s, n);
}
void kx_jw_str(kx_jw_t *w, const char *s) { kx_jw_strn(w, s, strlen(s)); }

void kx_jw_int(kx_jw_t *w, int64_t v) {
    pre_value(w, 0);
    if (w->err) return;
    if (v > KX_JW_MAX_SAFE_INT || v < -KX_JW_MAX_SAFE_INT) { w->err = 1; return; }
    char tmp[24];
    size_t n = 0;
    uint64_t u = v < 0 ? (uint64_t)(-v) : (uint64_t)v;
    do { tmp[n++] = (char)('0' + (u % 10u)); u /= 10u; } while (u != 0);
    if (v < 0) tmp[n++] = '-';
    for (size_t i = 0; i < n / 2; i++) { char t = tmp[i]; tmp[i] = tmp[n - 1 - i]; tmp[n - 1 - i] = t; }
    put(w, tmp, n);
}
void kx_jw_bool(kx_jw_t *w, int v) { pre_value(w, 0); if (!w->err) put(w, v ? "true" : "false", v ? 4 : 5); }
void kx_jw_null(kx_jw_t *w) { pre_value(w, 0); if (!w->err) put(w, "null", 4); }
void kx_jw_raw(kx_jw_t *w, const char *json, size_t n) {
    pre_value(w, 0);
    if (w->err) return;
    if (n == 0) { w->err = 1; return; }
    put(w, json, n);
}

int kx_jw_ok(kx_jw_t *w) {
    if (w->err || w->depth != 0 || w->after_key || w->len == 0) return 0;
    w->buf[w->len] = '\0';
    return 1;
}

/* ------------------------------------------------------------ formatting */

/* Howard Hinnant's civil_from_days: exact for the proleptic Gregorian calendar. */
static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const uint64_t doe = (uint64_t)(z - era * 146097);
    const uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t yy = (int64_t)yoe + era * 400;
    const uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const uint64_t mp = (5 * doy + 2) / 153;
    *d = (unsigned)(doy - (153 * mp + 2) / 5 + 1);
    *m = (unsigned)(mp < 10 ? mp + 3 : mp - 9);
    *y = yy + (*m <= 2);
}

static void dig(char *p, unsigned v, int n) {
    for (int i = n - 1; i >= 0; i--) { p[i] = (char)('0' + v % 10u); v /= 10u; }
}

int kx_fmt_rfc3339_ms(int64_t epoch_ms, char out[25]) {
    if (epoch_ms < 0 || epoch_ms > 253402300799999LL) return -1; /* 1970 .. 9999-12-31 */
    int64_t days = epoch_ms / 86400000LL;
    int64_t rem = epoch_ms % 86400000LL;
    int64_t y; unsigned m, d;
    civil_from_days(days, &y, &m, &d);
    unsigned hh = (unsigned)(rem / 3600000), mm = (unsigned)(rem / 60000 % 60);
    unsigned ss = (unsigned)(rem / 1000 % 60), ms = (unsigned)(rem % 1000);
    dig(out, (unsigned)y, 4); out[4] = '-'; dig(out + 5, m, 2); out[7] = '-'; dig(out + 8, d, 2);
    out[10] = 'T'; dig(out + 11, hh, 2); out[13] = ':'; dig(out + 14, mm, 2); out[16] = ':';
    dig(out + 17, ss, 2); out[19] = '.'; dig(out + 20, ms, 3); out[23] = 'Z'; out[24] = '\0';
    return 0;
}

void kx_fmt_uuid(const uint8_t u[16], char out[37]) {
    static const char hx[] = "0123456789abcdef";
    size_t o = 0;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
        out[o++] = hx[u[i] >> 4];
        out[o++] = hx[u[i] & 0x0f];
    }
    out[o] = '\0';
}

int kx_uuid_valid(const uint8_t u[16]) {
    unsigned version = u[6] >> 4, variant = u[8] >> 6;
    return version >= 1 && version <= 8 && variant == 2;
}
