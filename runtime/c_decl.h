/* ---- packet-builder runtime: declarations -------------------------------- */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

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
    unsigned version; /* protocol version; 0 until set */
} pb_trace;

/* The first error: its code, where it happened (frames[0..depth) of the
 * trace) and, for PB_ERR_INCOMPLETE, how many more input bits are needed. */
typedef struct pb_error {
    int code;
    size_t bit_offset;
    size_t needed_bits;
    unsigned depth;
    const char *msg; /* why a source could not be read (PB_ERR_INVALID), or NULL */
} pb_error;

/* Fills buf with the n input bytes at offset and returns 0, or sets *msg
 * (a string that outlives the reader) and returns nonzero. */
typedef int (*pb_fetch_fn)(void *user, uint64_t offset, uint8_t *buf, size_t n, const char **msg);

/* Input read on demand (a file, a stream that can seek): len bytes, loaded
 * a page at a time by fetch. Only the pages a decode touches are fetched:
 * fields a view skips are never read. Pages stay loaded until
 * pb_source_free, so zero-copy pointers into the input remain valid. */
typedef struct pb_source {
    uint8_t *buf;    /* len bytes, zero until their page is fetched */
    uint8_t *loaded; /* one flag per page */
    size_t len, page;
    pb_fetch_fn fetch;
    void *user;
} pb_source;

/* Reads integers of any bit width (MSB-first) and byte-aligned values. */
typedef struct pb_reader {
    const uint8_t *data;
    pb_source *src;    /* where data comes from, or NULL for a buffer */
    size_t len;        /* in bytes */
    size_t pos;        /* in bits */
    size_t limit;      /* end of the readable data in bits (a window inside data) */
    size_t short_bits; /* set when a read runs out of data */
    unsigned windows;  /* windows open */
    pb_trace tr;
    pb_error err;
} pb_reader;

/* Where a reader was before pb_jump_to. */
typedef struct pb_jump {
    size_t pos, limit;
    unsigned windows;
} pb_jump;

/* A packet placed at an offset (`at`): its bytes, and the trace naming the
 * field for errors. */
typedef struct pb_placed {
    size_t at; /* in bytes */
    uint8_t *data;
    size_t len;
    pb_trace tr;
} pb_placed;

/* Growable output buffer; integers may be written at any bit position. */
typedef struct pb_writer {
    uint8_t *buf;
    size_t len;  /* in bytes */
    size_t cap;
    size_t pos;  /* in bits */
    pb_trace tr;
    pb_error err;
    size_t base; /* where buf goes in the output, in bits (sub writers) */
    pb_placed *placed; /* written by pb_writer_finish */
    size_t nplaced, capplaced;
} pb_writer;

const char *pb_strerror(int rc);
void pb_reader_init(pb_reader *r, const uint8_t *data, size_t len);
/* A source of len bytes read in pages of `page` bytes by fetch(user, ...).
 * Returns PB_OK or PB_ERR_NOMEM. */
int pb_source_init(pb_source *s, size_t len, size_t page, pb_fetch_fn fetch, void *user);
/* A source reading `f` (which must stay open), in pages of 4096 bytes.
 * Returns PB_OK, PB_ERR_INVALID if f cannot seek, or PB_ERR_NOMEM. */
int pb_source_open(pb_source *s, FILE *f);
void pb_source_free(pb_source *s);
/* A reader that fetches its input from src as it goes. */
void pb_reader_from_source(pb_reader *r, pb_source *src);
void pb_writer_init(pb_writer *w);
void pb_writer_free(pb_writer *w);
/* Write every placed packet at its offset: past the end (zero-filling the
 * gap), or over bytes that must already match (PB_ERR_MISMATCH). Encoders
 * call it before returning the buffer. */
int pb_writer_finish(pb_writer *w);
/* "Packet.field[2].field: message (at bit N)" for the reader's or writer's
 * first error, written to buf (always NUL-terminated). Returns buf. */
char *pb_reader_describe(const pb_reader *r, char *buf, size_t n);
char *pb_writer_describe(const pb_writer *w, char *buf, size_t n);
/* Just the "Packet.field[2].field" part. */
char *pb_reader_path(const pb_reader *r, char *buf, size_t n);
char *pb_writer_path(const pb_writer *w, char *buf, size_t n);

#endif /* PB_RUNTIME_DECLARED */
