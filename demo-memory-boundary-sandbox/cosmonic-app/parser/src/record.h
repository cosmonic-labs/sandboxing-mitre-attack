/* record.h — a small, bounds-checked record parser. */
#ifndef RECORD_H
#define RECORD_H

#include <stddef.h>
#include <stdint.h>

/* Wire format (little-endian):
 *
 *   offset 0   "RC01"          magic
 *   offset 4   u16 length      number of payload bytes that follow
 *   offset 6   payload         `length` bytes of printable ASCII
 */
#define RECORD_MAGIC "RC01"
#define RECORD_HEADER_LEN 6
/* The largest payload the parser accepts. */
#define RECORD_FIELD_CAP 64

enum record_status {
  RECORD_OK = 0,
  RECORD_ERR_TRUNCATED,   /* shorter than the header */
  RECORD_ERR_MAGIC,       /* does not start with "RC01" */
  RECORD_ERR_LENGTH,      /* declared length disagrees with the bytes received */
  RECORD_ERR_TOO_LONG,    /* payload longer than RECORD_FIELD_CAP */
  RECORD_ERR_CHARSET      /* payload has a byte outside printable ASCII */
};

struct record {
  size_t declared_len;                 /* length field from the header */
  size_t received_len;                 /* payload bytes actually received */
  size_t field_len;                    /* bytes copied into `field` */
  char field[RECORD_FIELD_CAP + 1];    /* the payload, NUL-terminated */
};

/* Parse one record. Every length is checked before any byte is copied, so a
 * record that does not fit is refused and nothing is written past `field`. */
enum record_status record_parse(const uint8_t *bytes, size_t len, struct record *out);

/* A short human-readable reason for a status. */
const char *record_status_text(enum record_status status);

#endif
