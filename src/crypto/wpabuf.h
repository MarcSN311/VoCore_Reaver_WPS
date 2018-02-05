/*
 * Dynamic data buffer
 * Copyright (c) 2007-2009, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef WPABUF_H
#define WPABUF_H

#include <stdint.h>
#include <string.h>

#define wpa_debug_print_timestamp()                                            \
  do {                                                                         \
  } while (0)
#define wpa_printf(args...)                                                    \
  do {                                                                         \
  } while (0)
#define wpa_hexdump(l, t, b, le)                                               \
  do {                                                                         \
  } while (0)
#define wpa_hexdump_buf(l, t, b)                                               \
  do {                                                                         \
  } while (0)
#define wpa_hexdump_key(l, t, b, le)                                           \
  do {                                                                         \
  } while (0)
#define wpa_hexdump_buf_key(l, t, b)                                           \
  do {                                                                         \
  } while (0)
#define wpa_hexdump_ascii(l, t, b, le)                                         \
  do {                                                                         \
  } while (0)
#define wpa_hexdump_ascii_key(l, t, b, le)                                     \
  do {                                                                         \
  } while (0)
#define wpa_debug_open_file(p)                                                 \
  do {                                                                         \
  } while (0)
#define wpa_debug_close_file()                                                 \
  do {                                                                         \
  } while (0)

enum { MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR };

/* Macros for handling unaligned memory accesses */

#define WPA_GET_BE16(a) ((uint16_t)(((a)[0] << 8) | (a)[1]))
#define WPA_PUT_BE16(a, val)                                                   \
  do {                                                                         \
    (a)[0] = ((uint16_t)(val)) >> 8;                                           \
    (a)[1] = ((uint16_t)(val)) & 0xff;                                         \
  } while (0)

#define WPA_GET_LE16(a) ((uint16_t)(((a)[1] << 8) | (a)[0]))
#define WPA_PUT_LE16(a, val)                                                   \
  do {                                                                         \
    (a)[1] = ((uint16_t)(val)) >> 8;                                           \
    (a)[0] = ((uint16_t)(val)) & 0xff;                                         \
  } while (0)

#define WPA_GET_BE24(a)                                                        \
  ((((uint32_t)(a)[0]) << 16) | (((uint32_t)(a)[1]) << 8) | ((uint32_t)(a)[2]))
#define WPA_PUT_BE24(a, val)                                                   \
  do {                                                                         \
    (a)[0] = (uint8_t)((((uint32_t)(val)) >> 16) & 0xff);                      \
    (a)[1] = (uint8_t)((((uint32_t)(val)) >> 8) & 0xff);                       \
    (a)[2] = (uint8_t)(((uint32_t)(val)) & 0xff);                              \
  } while (0)

#define WPA_GET_BE32(a)                                                        \
  ((((uint32_t)(a)[0]) << 24) | (((uint32_t)(a)[1]) << 16) |                   \
   (((uint32_t)(a)[2]) << 8) | ((uint32_t)(a)[3]))
#define WPA_PUT_BE32(a, val)                                                   \
  do {                                                                         \
    (a)[0] = (uint8_t)((((uint32_t)(val)) >> 24) & 0xff);                      \
    (a)[1] = (uint8_t)((((uint32_t)(val)) >> 16) & 0xff);                      \
    (a)[2] = (uint8_t)((((uint32_t)(val)) >> 8) & 0xff);                       \
    (a)[3] = (uint8_t)(((uint32_t)(val)) & 0xff);                              \
  } while (0)

#define WPA_GET_LE32(a)                                                        \
  ((((uint32_t)(a)[3]) << 24) | (((uint32_t)(a)[2]) << 16) |                   \
   (((uint32_t)(a)[1]) << 8) | ((uint32_t)(a)[0]))
#define WPA_PUT_LE32(a, val)                                                   \
  do {                                                                         \
    (a)[3] = (uint8_t)((((uint32_t)(val)) >> 24) & 0xff);                      \
    (a)[2] = (uint8_t)((((uint32_t)(val)) >> 16) & 0xff);                      \
    (a)[1] = (uint8_t)((((uint32_t)(val)) >> 8) & 0xff);                       \
    (a)[0] = (uint8_t)(((uint32_t)(val)) & 0xff);                              \
  } while (0)

#define WPA_GET_BE64(a)                                                        \
  ((((u64)(a)[0]) << 56) | (((u64)(a)[1]) << 48) | (((u64)(a)[2]) << 40) |     \
   (((u64)(a)[3]) << 32) | (((u64)(a)[4]) << 24) | (((u64)(a)[5]) << 16) |     \
   (((u64)(a)[6]) << 8) | ((u64)(a)[7]))
#define WPA_PUT_BE64(a, val)                                                   \
  do {                                                                         \
    (a)[0] = (uint8_t)(((u64)(val)) >> 56);                                    \
    (a)[1] = (uint8_t)(((u64)(val)) >> 48);                                    \
    (a)[2] = (uint8_t)(((u64)(val)) >> 40);                                    \
    (a)[3] = (uint8_t)(((u64)(val)) >> 32);                                    \
    (a)[4] = (uint8_t)(((u64)(val)) >> 24);                                    \
    (a)[5] = (uint8_t)(((u64)(val)) >> 16);                                    \
    (a)[6] = (uint8_t)(((u64)(val)) >> 8);                                     \
    (a)[7] = (uint8_t)(((u64)(val)) & 0xff);                                   \
  } while (0)

#define WPA_GET_LE64(a)                                                        \
  ((((u64)(a)[7]) << 56) | (((u64)(a)[6]) << 48) | (((u64)(a)[5]) << 40) |     \
   (((u64)(a)[4]) << 32) | (((u64)(a)[3]) << 24) | (((u64)(a)[2]) << 16) |     \
   (((u64)(a)[1]) << 8) | ((u64)(a)[0]))

/*
 * Internal data structure for wpabuf. Please do not touch this directly from
 * elsewhere. This is only defined in header file to allow inline functions
 * from this file to access data.
 */
struct wpabuf {
  size_t size;       /* total size of the allocated buffer */
  size_t used;       /* length of data in the buffer */
  uint8_t *ext_data; /* pointer to external data; NULL if data follows
                 * struct wpabuf */
  /* optionally followed by the allocated buffer */
};

int wpabuf_resize(struct wpabuf **buf, size_t add_len);
struct wpabuf *wpabuf_alloc(size_t len);
struct wpabuf *wpabuf_alloc_ext_data(uint8_t *data, size_t len);
struct wpabuf *wpabuf_alloc_copy(const void *data, size_t len);
struct wpabuf *wpabuf_dup(const struct wpabuf *src);
void wpabuf_free(struct wpabuf *buf);
void *wpabuf_put(struct wpabuf *buf, size_t len);
struct wpabuf *wpabuf_concat(struct wpabuf *a, struct wpabuf *b);
struct wpabuf *wpabuf_zeropad(struct wpabuf *buf, size_t len);
void wpabuf_printf(struct wpabuf *buf, char *fmt, ...);

/**
 * wpabuf_size - Get the currently allocated size of a wpabuf buffer
 * @buf: wpabuf buffer
 * Returns: Currently allocated size of the buffer
 */
static inline size_t wpabuf_size(const struct wpabuf *buf) { return buf->size; }

/**
 * wpabuf_len - Get the current length of a wpabuf buffer data
 * @buf: wpabuf buffer
 * Returns: Currently used length of the buffer
 */
static inline size_t wpabuf_len(const struct wpabuf *buf) { return buf->used; }

/**
 * wpabuf_tailroom - Get size of available tail room in the end of the buffer
 * @buf: wpabuf buffer
 * Returns: Tail room (in bytes) of available space in the end of the buffer
 */
static inline size_t wpabuf_tailroom(const struct wpabuf *buf) {
  return buf->size - buf->used;
}

/**
 * wpabuf_head - Get pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline const void *wpabuf_head(const struct wpabuf *buf) {
  if (buf->ext_data)
    return buf->ext_data;
  return buf + 1;
}

static inline const uint8_t *wpabuf_head_uint8_t(const struct wpabuf *buf) {
  return wpabuf_head(buf);
}

/**
 * wpabuf_mhead - Get modifiable pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline void *wpabuf_mhead(struct wpabuf *buf) {
  if (buf->ext_data)
    return buf->ext_data;
  return buf + 1;
}

static inline uint8_t *wpabuf_mhead_uint8_t(struct wpabuf *buf) {
  return wpabuf_mhead(buf);
}

static inline void wpabuf_put_uint8_t(struct wpabuf *buf, uint8_t data) {
  uint8_t *pos = wpabuf_put(buf, 1);
  *pos = data;
}

static inline void wpabuf_put_le16(struct wpabuf *buf, uint16_t data) {
  uint8_t *pos = wpabuf_put(buf, 2);
  WPA_PUT_LE16(pos, data);
}

static inline void wpabuf_put_be16(struct wpabuf *buf, uint16_t data) {
  uint8_t *pos = wpabuf_put(buf, 2);
  WPA_PUT_BE16(pos, data);
}

static inline void wpabuf_put_be24(struct wpabuf *buf, uint32_t data) {
  uint8_t *pos = wpabuf_put(buf, 3);
  WPA_PUT_BE24(pos, data);
}

static inline void wpabuf_put_be32(struct wpabuf *buf, uint32_t data) {
  uint8_t *pos = wpabuf_put(buf, 4);
  WPA_PUT_BE32(pos, data);
}

static inline void wpabuf_put_data(struct wpabuf *buf, const void *data,
                                   size_t len) {
  if (data)
    memcpy(wpabuf_put(buf, len), data, len);
}

static inline void wpabuf_put_buf(struct wpabuf *dst,
                                  const struct wpabuf *src) {
  wpabuf_put_data(dst, wpabuf_head(src), wpabuf_len(src));
}

static inline void wpabuf_set(struct wpabuf *buf, const void *data,
                              size_t len) {
  buf->ext_data = (uint8_t *)data;
  buf->size = buf->used = len;
}

static inline void wpabuf_put_str(struct wpabuf *dst, const char *str) {
  wpabuf_put_data(dst, str, strlen(str));
}

#endif /* WPABUF_H */
