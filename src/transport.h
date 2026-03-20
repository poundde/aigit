#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include "aigit.h"

/*
 * -------------------------------------------------------------------------
 * pkt-line  (RFC used by both HTTP and SSH git transports)
 * -------------------------------------------------------------------------
 *
 * Each line is prefixed with a 4-hex-digit length (including the 4 bytes
 * of the length itself).  "0000" is a flush packet.  "0001" is a delimiter.
 *
 * Max payload: 0xffff - 4 = 65531 bytes.
 */
#define PKT_MAX_PAYLOAD  65531
#define PKT_FLUSH        "0000"
#define PKT_DELIM        "0001"

struct pkt_reader {
  int     fd;
  char    buf[PKT_MAX_PAYLOAD + 1];
  size_t  len;
  int     is_flush;
};

int  pkt_read(struct pkt_reader *r);         /* returns payload len, 0=flush, -1=err */
int  pkt_write(int fd, const char *data, size_t len);
int  pkt_writef(int fd, const char *fmt, ...) __attribute__((format(printf,2,3)));
int  pkt_flush(int fd);

/*
 * -------------------------------------------------------------------------
 * PACK format
 * -------------------------------------------------------------------------
 *
 * On-wire and on-disk format for a collection of git objects:
 *
 *   "PACK" (4 bytes)
 *   version  (4 bytes, big-endian, = 2)
 *   n_objects (4 bytes, big-endian)
 *   [n_objects packed objects]
 *   SHA-1 checksum of all preceding bytes (20 bytes)
 *
 * Each packed object:
 *   type+size header (variable-length, MSB encoding)
 *   zlib-deflated object data
 *
 * We only generate non-delta (OBJ_BLOB/TREE/COMMIT) objects —
 * no REF_DELTA or OFS_DELTA — which is always valid to send.
 */
#define PACK_MAGIC    0x5041434b  /* "PACK" */
#define PACK_VERSION  2

/* Pack object type codes (wire format) */
#define PACK_OBJ_COMMIT   1
#define PACK_OBJ_TREE     2
#define PACK_OBJ_BLOB     3
#define PACK_OBJ_TAG      4
#define PACK_OBJ_OFS_DELTA 6
#define PACK_OBJ_REF_DELTA 7

/*
 * A growable byte buffer used to build pack data in memory
 * before sending it over the wire.
 */
struct pack_buf {
  uint8_t *data;
  size_t   len;
  size_t   cap;
};

int  pack_buf_init(struct pack_buf *pb);
void pack_buf_free(struct pack_buf *pb);
int  pack_buf_append(struct pack_buf *pb, const uint8_t *data, size_t len);

/*
 * Build a complete PACK containing the given set of object SHAs.
 * Fills pb with the raw pack bytes including the trailing checksum.
 */
int  pack_build(struct pack_buf *pb,
                struct sha1 *shas, size_t n_shas);

/*
 * Read a PACK from fd and store every object into the loose object store.
 * Returns 0 on success, -1 on error.
 */
int  pack_receive(int fd);

/*
 * -------------------------------------------------------------------------
 * Object enumeration
 * -------------------------------------------------------------------------
 *
 * For push we need all objects reachable from our local tip that the
 * remote doesn't already have.
 */
struct sha1_set {
  struct sha1 *items;
  size_t       count;
  size_t       cap;
};

int  sha1_set_init(struct sha1_set *s);
void sha1_set_free(struct sha1_set *s);
int  sha1_set_add(struct sha1_set *s, const struct sha1 *sha);
int  sha1_set_contains(const struct sha1_set *s, const struct sha1 *sha);

/*
 * Enumerate all objects reachable from `tip`, stopping at any commit
 * whose SHA is in `have` (the remote's known objects).
 * Results appended to `out`.
 */
int  objects_reachable_from(const struct sha1 *tip,
                              const struct sha1_set *have,
                              struct sha1_set *out);

/*
 * -------------------------------------------------------------------------
 * Transport connection
 * -------------------------------------------------------------------------
 *
 * Abstracts HTTP and SSH so push/pull logic is written once.
 */
#define TRANSPORT_HTTP  1
#define TRANSPORT_SSH   2

struct transport {
  int   type;       /* TRANSPORT_HTTP or TRANSPORT_SSH */

  /* SSH fields */
  int   ssh_in;     /* read fd  (server → client) */
  int   ssh_out;    /* write fd (client → server) */
  pid_t ssh_pid;

  /* HTTP fields */
  char  http_url[4096];   /* base URL of remote */
  char  http_host[512];
  char  http_path[2048];
  int   http_port;
  int   http_tls;         /* 1 = HTTPS */
};

int  transport_open_ssh(struct transport *t,
                         const char *user, const char *host,
                         const char *path, const char *service);
int  transport_open_http(struct transport *t,
                          const char *url, const char *service,
                          int *fd_out);   /* returns connected fd for GET */
void transport_close(struct transport *t);
int  transport_http_post(struct transport *t,
                          const char *service,
                          const uint8_t *body, size_t body_len,
                          int *fd_out);

/*
 * Parse a remote URL into components.
 * Supports:
 *   ssh://[user@]host[:port]/path
 *   git@host:path          (SCP-style SSH)
 *   http://host[:port]/path
 *   https://host[:port]/path
 */
struct remote_url {
  char  scheme[16];   /* "ssh", "http", "https", "git" */
  char  user[128];
  char  host[256];
  int   port;
  char  path[2048];
};

int  url_parse(const char *url, struct remote_url *out);

#endif /* TRANSPORT_H */
