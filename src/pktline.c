#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include "aigit.h"
#include "transport.h"

/*
 * Read exactly n bytes from fd, retrying on EINTR/short reads.
 */
static int read_full(int fd, void *buf, size_t n)
{
  size_t done = 0;
  while (done < n) {
    ssize_t r = read(fd, (char *)buf + done, n - done);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) return -1;
    done += (size_t)r;
  }
  return 0;
}

/*
 * Write exactly n bytes to fd, retrying on EINTR/short writes.
 */
static int write_full(int fd, const void *buf, size_t n)
{
  size_t done = 0;
  while (done < n) {
    ssize_t w = write(fd, (const char *)buf + done, n - done);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) return -1;
    done += (size_t)w;
  }
  return 0;
}

/*
 * Read one pkt-line from fd into r.
 * Returns payload length (≥0), 0 for flush-pkt, -1 on error.
 */
int pkt_read(struct pkt_reader *r)
{
  r->is_flush = 0;
  r->len = 0;

  char hex[5];
  if (read_full(r->fd, hex, 4) != 0)
    return -1;
  hex[4] = '\0';

  unsigned long pkt_len;
  char *endp;
  pkt_len = strtoul(hex, &endp, 16);
  if (endp != hex + 4)
    return -1;

  if (pkt_len == 0) {
    r->is_flush = 1;
    return 0;
  }
  if (pkt_len == 1)  /* delimiter pkt — treat like flush for our purposes */
    return 0;
  if (pkt_len < 4)
    return -1;

  size_t payload = pkt_len - 4;
  if (payload > PKT_MAX_PAYLOAD)
    return -1;

  if (read_full(r->fd, r->buf, payload) != 0)
    return -1;

  /* Strip trailing newline that git conventionally appends */
  if (payload > 0 && r->buf[payload - 1] == '\n')
    payload--;

  r->buf[payload] = '\0';
  r->len = payload;
  return (int)payload;
}

/*
 * Write a pkt-line containing `len` bytes of `data` to fd.
 */
int pkt_write(int fd, const char *data, size_t len)
{
  if (len > PKT_MAX_PAYLOAD)
    return -1;

  char hdr[5];
  unsigned total = (unsigned)(len + 4);
  snprintf(hdr, sizeof(hdr), "%04x", total);

  if (write_full(fd, hdr, 4) != 0)  return -1;
  if (len > 0 && write_full(fd, data, len) != 0) return -1;
  return 0;
}

int pkt_writef(int fd, const char *fmt, ...)
{
  char buf[PKT_MAX_PAYLOAD];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= sizeof(buf))
    return -1;
  return pkt_write(fd, buf, (size_t)n);
}

int pkt_flush(int fd)
{
  return write_full(fd, "0000", 4);
}
