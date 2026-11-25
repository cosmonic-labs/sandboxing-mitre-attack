/* record.c — the bounds-checked record parser behind the `parser` component.
 *
 * This build is deliberately a CORRECT parser. It checks the declared length
 * against both the bytes it received and the capacity of its buffer before it
 * copies anything, and refuses a record that does not fit. */
#include "record.h"

#include <string.h>

enum record_status record_parse(const uint8_t *bytes, size_t len, struct record *out) {
  memset(out, 0, sizeof *out);

  if (bytes == NULL || len < RECORD_HEADER_LEN) {
    return RECORD_ERR_TRUNCATED;
  }
  if (memcmp(bytes, RECORD_MAGIC, 4) != 0) {
    return RECORD_ERR_MAGIC;
  }

  size_t declared = (size_t)bytes[4] | ((size_t)bytes[5] << 8);
  size_t received = len - RECORD_HEADER_LEN;
  out->declared_len = declared;
  out->received_len = received;

  /* The header must describe exactly the bytes that arrived. */
  if (declared != received) {
    return RECORD_ERR_LENGTH;
  }
  /* The bounds check: refuse anything larger than the buffer. */
  if (declared > RECORD_FIELD_CAP) {
    return RECORD_ERR_TOO_LONG;
  }

  const uint8_t *payload = bytes + RECORD_HEADER_LEN;
  for (size_t i = 0; i < declared; i++) {
    if (payload[i] < 0x20 || payload[i] > 0x7e) {
      return RECORD_ERR_CHARSET;
    }
  }

  memcpy(out->field, payload, declared);   /* declared <= RECORD_FIELD_CAP */
  out->field[declared] = '\0';
  out->field_len = declared;
  return RECORD_OK;
}

const char *record_status_text(enum record_status status) {
  switch (status) {
    case RECORD_OK:            return "ok";
    case RECORD_ERR_TRUNCATED: return "record is shorter than its 6-byte header";
    case RECORD_ERR_MAGIC:     return "record does not start with the RC01 magic";
    case RECORD_ERR_LENGTH:    return "declared length does not match the bytes received";
    case RECORD_ERR_TOO_LONG:  return "payload is longer than the 64-byte field buffer";
    case RECORD_ERR_CHARSET:   return "payload contains a byte outside printable ASCII";
  }
  return "unknown status";
}
