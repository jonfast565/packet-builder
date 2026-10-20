/* ---- packet-builder runtime: declarations -------------------------------- */

#include <stddef.h>
#include <stdint.h>

#ifndef PB_RUNTIME_DECLARED
#define PB_RUNTIME_DECLARED

enum {
    PB_OK = 0,
    PB_ERR_INCOMPLETE = -1, /* the input ended before the packet did */
    PB_ERR_INVALID = -2,    /* malformed data: a bad length, nesting too deep, ... */
    PB_ERR_RANGE = -3,      /* a value does not fit in its field */
    PB_ERR_NOMEM = -4,      /* allocation failed */
    PB_ERR_TEXT = -5,       /* a string is not valid text, or contains a NUL where none is allowed */
    PB_ERR_MISMATCH = -6,   /* a length, derived field or checksum does not match the data */
    PB_ERR_CONSTRAINT = -7  /* a value breaks a declared constraint */
};
/* Older names. */
#define PB_ERR_EOF PB_ERR_INCOMPLETE
#define PB_ERR_LENGTH PB_ERR_INVALID

#ifndef PB_MAX_DEPTH
#define PB_MAX_DEPTH 64 /* deepest packet nesting accepted */
#endif

/* The packets being decoded or encoded, innermost last, each with the field
 * it is working on (index -1 outside arrays). */
typedef struct pb_frame {
    const char *packet;
    const char *field;
    long index;
} pb_frame;

typedef struct pb_trace {
    pb_frame frames[PB_MAX_DEPTH];
    unsigned depth;
} pb_trace;

/* The first error: its code, where it happened (frames[0..depth) of the
 * trace) and, for PB_ERR_INCOMPLETE, how many more input bits are needed. */
typedef struct pb_error {
    int code;
    size_t bit_offset;
    size_t needed_bits;
    unsigned depth;
} pb_error;

/* Reads integers of any bit width (MSB-first) and byte-aligned values. */
typedef struct pb_reader {
    const uint8_t *data;
    size_t len;        /* in bytes */
    size_t pos;        /* in bits */
    size_t limit;      /* end of the readable data in bits (a window inside data) */
    size_t short_bits; /* set when a read runs out of data */
    pb_trace tr;
    pb_error err;
} pb_reader;

/* Growable output buffer; integers may be written at any bit position. */
typedef struct pb_writer {
    uint8_t *buf;
    size_t len;  /* in bytes */
    size_t cap;
    size_t pos;  /* in bits */
    pb_trace tr;
    pb_error err;
} pb_writer;

const char *pb_strerror(int rc);
void pb_reader_init(pb_reader *r, const uint8_t *data, size_t len);
void pb_writer_init(pb_writer *w);
void pb_writer_free(pb_writer *w);
/* "Packet.field[2].field: message (at bit N)" for the reader's or writer's
 * first error, written to buf (always NUL-terminated). Returns buf. */
char *pb_reader_describe(const pb_reader *r, char *buf, size_t n);
char *pb_writer_describe(const pb_writer *w, char *buf, size_t n);
/* Just the "Packet.field[2].field" part. */
char *pb_reader_path(const pb_reader *r, char *buf, size_t n);
char *pb_writer_path(const pb_writer *w, char *buf, size_t n);

#endif /* PB_RUNTIME_DECLARED */
