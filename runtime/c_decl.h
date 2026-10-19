/* ---- packet-builder runtime: declarations -------------------------------- */

#include <stddef.h>
#include <stdint.h>

#ifndef PB_RUNTIME_DECLARED
#define PB_RUNTIME_DECLARED

enum {
    PB_OK = 0,
    PB_ERR_EOF = -1,     /* input ended in the middle of a field */
    PB_ERR_LENGTH = -2,  /* a length is negative, too large, or does not match */
    PB_ERR_RANGE = -3,   /* a value does not fit in its bit width */
    PB_ERR_NOMEM = -4,   /* allocation failed */
    PB_ERR_TEXT = -5     /* a string is not valid UTF-8, or contains a NUL where none is allowed */
};

/* Reads integers of any bit width (MSB-first) and byte-aligned values. */
typedef struct pb_reader {
    const uint8_t *data;
    size_t len;  /* in bytes */
    size_t pos;  /* in bits */
} pb_reader;

/* Growable output buffer; integers may be written at any bit position. */
typedef struct pb_writer {
    uint8_t *buf;
    size_t len;  /* in bytes */
    size_t cap;
    size_t pos;  /* in bits */
} pb_writer;

const char *pb_strerror(int rc);
void pb_reader_init(pb_reader *r, const uint8_t *data, size_t len);
void pb_writer_init(pb_writer *w);
void pb_writer_free(pb_writer *w);

#endif /* PB_RUNTIME_DECLARED */
