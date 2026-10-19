/* ---- packet-builder runtime: implementation ------------------------------ */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef PB_RUNTIME_IMPLEMENTED
#define PB_RUNTIME_IMPLEMENTED

#if defined(__GNUC__) || defined(__clang__)
#define PB_FN static __attribute__((unused))
#else
#define PB_FN static
#endif

#define PB_TRY(e) do { pb_rc = (e); if (pb_rc != PB_OK) goto pb_fail; } while (0)
#define PB_CHECK(e) do { int pb_rc_ = (e); if (pb_rc_ != PB_OK) return pb_rc_; } while (0)

const char *pb_strerror(int rc) {
    switch (rc) {
    case PB_OK: return "ok";
    case PB_ERR_EOF: return "unexpected end of data";
    case PB_ERR_LENGTH: return "invalid length";
    case PB_ERR_RANGE: return "value out of range";
    case PB_ERR_NOMEM: return "out of memory";
    default: return "unknown error";
    }
}

void pb_reader_init(pb_reader *r, const uint8_t *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

PB_FN size_t pb_remaining_bits(const pb_reader *r) { return r->len * 8 - r->pos; }

PB_FN int pb_read_bits(pb_reader *r, unsigned width, uint64_t *out) {
    uint64_t v = 0;
    unsigned left = width;
    if (width > pb_remaining_bits(r)) return PB_ERR_EOF;
    while (left > 0) {
        unsigned off = (unsigned)(r->pos & 7);
        unsigned take = 8 - off < left ? 8 - off : left;
        unsigned bits = ((unsigned)r->data[r->pos >> 3] >> (8 - off - take)) & ((1u << take) - 1u);
        v = (v << take) | bits;
        r->pos += take;
        left -= take;
    }
    *out = v;
    return PB_OK;
}

PB_FN int pb_read_uint(pb_reader *r, unsigned nbytes, int little, uint64_t *out) {
    uint64_t v = 0;
    size_t start = r->pos >> 3;
    unsigned i;
    if ((size_t)nbytes * 8 > pb_remaining_bits(r)) return PB_ERR_EOF;
    for (i = 0; i < nbytes; i++) {
        uint8_t b = little ? r->data[start + nbytes - 1 - i] : r->data[start + i];
        v = (v << 8) | b;
    }
    r->pos += (size_t)nbytes * 8;
    *out = v;
    return PB_OK;
}

PB_FN int pb_read_bytes(pb_reader *r, uint8_t *dst, size_t n) {
    if (n > pb_remaining_bits(r) / 8) return PB_ERR_EOF;
    if (n) memcpy(dst, r->data + (r->pos >> 3), n);
    r->pos += n * 8;
    return PB_OK;
}

PB_FN int pb_skip_bits(pb_reader *r, size_t bits) {
    if (bits > pb_remaining_bits(r)) return PB_ERR_EOF;
    r->pos += bits;
    return PB_OK;
}

/* Validate a decoded element count against the data that is left. */
PB_FN int pb_count(const pb_reader *r, int64_t n, uint64_t elem_bits, size_t *out) {
    if (n < 0) return PB_ERR_LENGTH;
    if (elem_bits > 0 && (uint64_t)n > pb_remaining_bits(r) / elem_bits) return PB_ERR_LENGTH;
    *out = (size_t)n;
    return PB_OK;
}

/* Allocate a zeroed array of n elements (never returns NULL for n == 0). */
PB_FN void *pb_alloc(size_t n, size_t size) { return calloc(n ? n : 1, size); }

/* Make room for `need` elements in *ptr (capacity *cap). */
PB_FN int pb_grow(void **ptr, size_t *cap, size_t need, size_t size) {
    if (need > *cap) {
        size_t ncap = *cap ? *cap * 2 : 8;
        void *p;
        while (ncap < need) ncap *= 2;
        p = realloc(*ptr, ncap * size);
        if (!p) return PB_ERR_NOMEM;
        memset((uint8_t *)p + *cap * size, 0, (ncap - *cap) * size);
        *ptr = p;
        *cap = ncap;
    }
    return PB_OK;
}

void pb_writer_init(pb_writer *w) {
    w->buf = NULL;
    w->len = w->cap = w->pos = 0;
}

void pb_writer_free(pb_writer *w) {
    free(w->buf);
    pb_writer_init(w);
}

PB_FN int pb_writer_reserve(pb_writer *w, size_t extra) {
    if (w->len + extra > w->cap) {
        size_t ncap = w->cap ? w->cap * 2 : 64;
        uint8_t *p;
        while (ncap < w->len + extra) ncap *= 2;
        p = (uint8_t *)realloc(w->buf, ncap);
        if (!p) return PB_ERR_NOMEM;
        w->buf = p;
        w->cap = ncap;
    }
    return PB_OK;
}

PB_FN int pb_write_bits(pb_writer *w, uint64_t value, unsigned width) {
    unsigned left = width;
    PB_CHECK(pb_writer_reserve(w, width / 8 + 2));
    while (left > 0) {
        unsigned off, take;
        if ((w->pos & 7) == 0) w->buf[w->len++] = 0;
        off = (unsigned)(w->pos & 7);
        take = 8 - off < left ? 8 - off : left;
        w->buf[w->len - 1] |= (uint8_t)(((value >> (left - take)) & ((1u << take) - 1u)) << (8 - off - take));
        w->pos += take;
        left -= take;
    }
    return PB_OK;
}

PB_FN int pb_write_uint(pb_writer *w, uint64_t value, unsigned nbytes, int little) {
    unsigned i;
    PB_CHECK(pb_writer_reserve(w, nbytes));
    for (i = 0; i < nbytes; i++) {
        unsigned shift = little ? 8 * i : 8 * (nbytes - 1 - i);
        w->buf[w->len++] = (uint8_t)(value >> shift);
    }
    w->pos += (size_t)nbytes * 8;
    return PB_OK;
}

PB_FN int pb_write_bytes(pb_writer *w, const uint8_t *data, size_t n) {
    PB_CHECK(pb_writer_reserve(w, n));
    if (n) memcpy(w->buf + w->len, data, n);
    w->len += n;
    w->pos += n * 8;
    return PB_OK;
}

PB_FN int pb_write_zero_bits(pb_writer *w, int64_t bits) {
    for (; bits > 32; bits -= 32) PB_CHECK(pb_write_bits(w, 0, 32));
    if (bits > 0) PB_CHECK(pb_write_bits(w, 0, (unsigned)bits));
    return PB_OK;
}

PB_FN int pb_check_len(size_t actual, int64_t expected) {
    return (expected < 0 || (uint64_t)actual != (uint64_t)expected) ? PB_ERR_LENGTH : PB_OK;
}

PB_FN int pb_check_u(uint64_t v, unsigned width) {
    return (width < 64 && (v >> width) != 0) ? PB_ERR_RANGE : PB_OK;
}

PB_FN int pb_check_i(int64_t v, unsigned width) {
    if (width < 64) {
        int64_t lo = -(int64_t)((uint64_t)1 << (width - 1));
        int64_t hi = (int64_t)(((uint64_t)1 << (width - 1)) - 1);
        if (v < lo || v > hi) return PB_ERR_RANGE;
    }
    return PB_OK;
}

PB_FN int64_t pb_sext(uint64_t v, unsigned width) {
    if (width < 64 && ((v >> (width - 1)) & 1u)) v |= ~(uint64_t)0 << width;
    return (int64_t)v;
}

PB_FN int64_t pb_trunc(int64_t v, unsigned width, int is_signed) {
    uint64_t u;
    if (width >= 64) return v;
    u = (uint64_t)v & (((uint64_t)1 << width) - 1);
    return is_signed ? pb_sext(u, width) : (int64_t)u;
}

/* 64-bit two's complement arithmetic without signed overflow. */
PB_FN int64_t pb_add(int64_t a, int64_t b) { return (int64_t)((uint64_t)a + (uint64_t)b); }
PB_FN int64_t pb_sub(int64_t a, int64_t b) { return (int64_t)((uint64_t)a - (uint64_t)b); }
PB_FN int64_t pb_mul(int64_t a, int64_t b) { return (int64_t)((uint64_t)a * (uint64_t)b); }
PB_FN int64_t pb_div(int64_t a, int64_t b) {
    if (b == 0) return 0;
    if (b == -1) return pb_sub(0, a);
    return a / b;
}
PB_FN int64_t pb_pow(int64_t base, int64_t exp) {
    uint64_t acc = 1, b = (uint64_t)base, e;
    if (exp < 0) return 0;
    for (e = (uint64_t)exp; e > 0; e >>= 1) {
        if (e & 1u) acc *= b;
        b *= b;
    }
    return (int64_t)acc;
}
PB_FN int64_t pb_min_i(int64_t a, int64_t b) { return b < a ? b : a; }
PB_FN int64_t pb_max_i(int64_t a, int64_t b) { return b > a ? b : a; }
PB_FN double pb_min_f(double a, double b) { return b < a ? b : a; }
PB_FN double pb_max_f(double a, double b) { return b > a ? b : a; }
PB_FN int64_t pb_ftoi(double v) {
    if (v != v) return 0;
    if (v >= 9223372036854775807.0) return INT64_MAX;
    if (v <= -9223372036854775808.0) return INT64_MIN;
    return (int64_t)v;
}
PB_FN float pb_f32_from_bits(uint64_t bits) {
    uint32_t b = (uint32_t)bits;
    float f;
    memcpy(&f, &b, 4);
    return f;
}
PB_FN double pb_f64_from_bits(uint64_t bits) {
    double f;
    memcpy(&f, &bits, 8);
    return f;
}
PB_FN uint64_t pb_f32_bits(float f) {
    uint32_t b;
    memcpy(&b, &f, 4);
    return b;
}
PB_FN uint64_t pb_f64_bits(double f) {
    uint64_t b;
    memcpy(&b, &f, 8);
    return b;
}

/* Array helpers: element access (0 when out of range) and aggregates. */
#define PB_ARRAY_HELPERS(T, NAME)                                                   \
    PB_FN T pb_at_##NAME(const T *a, size_t n, int64_t i) {                        \
        return (i >= 0 && (uint64_t)i < (uint64_t)n) ? a[i] : (T)0;                 \
    }                                                                               \
    PB_FN int64_t pb_sum_##NAME(const T *a, size_t n) {                            \
        int64_t acc = 0; size_t i;                                                  \
        for (i = 0; i < n; i++) acc = pb_add(acc, (int64_t)a[i]);                   \
        return acc;                                                                 \
    }                                                                               \
    PB_FN int64_t pb_prod_##NAME(const T *a, size_t n) {                           \
        int64_t acc = 1; size_t i;                                                  \
        for (i = 0; i < n; i++) acc = pb_mul(acc, (int64_t)a[i]);                   \
        return acc;                                                                 \
    }                                                                               \
    PB_FN double pb_sumf_##NAME(const T *a, size_t n) {                            \
        double acc = 0; size_t i;                                                   \
        for (i = 0; i < n; i++) acc += (double)a[i];                                \
        return acc;                                                                 \
    }                                                                               \
    PB_FN double pb_prodf_##NAME(const T *a, size_t n) {                           \
        double acc = 1; size_t i;                                                   \
        for (i = 0; i < n; i++) acc *= (double)a[i];                                \
        return acc;                                                                 \
    }

PB_ARRAY_HELPERS(uint8_t, u8)
PB_ARRAY_HELPERS(int8_t, i8)
PB_ARRAY_HELPERS(uint16_t, u16)
PB_ARRAY_HELPERS(int16_t, i16)
PB_ARRAY_HELPERS(uint32_t, u32)
PB_ARRAY_HELPERS(int32_t, i32)
PB_ARRAY_HELPERS(uint64_t, u64)
PB_ARRAY_HELPERS(int64_t, i64)
PB_ARRAY_HELPERS(float, f32)
PB_ARRAY_HELPERS(double, f64)

#endif /* PB_RUNTIME_IMPLEMENTED */
