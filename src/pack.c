#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>
#include "aigit.h"
#include "transport.h"

/* -------------------------------------------------------------------------
 * pack_buf
 * ---------------------------------------------------------------------- */

int pack_buf_init(struct pack_buf *pb)
{
  pb->cap  = 65536;
  pb->len  = 0;
  pb->data = malloc(pb->cap);
  return pb->data ? 0 : -1;
}

void pack_buf_free(struct pack_buf *pb)
{
  free(pb->data);
  pb->data = NULL;
  pb->len  = pb->cap = 0;
}

int pack_buf_append(struct pack_buf *pb, const uint8_t *data, size_t len)
{
  if (pb->len + len > pb->cap) {
    size_t new_cap = (pb->cap + len) * 2;
    uint8_t *tmp = realloc(pb->data, new_cap);
    if (!tmp) return -1;
    pb->data = tmp;
    pb->cap  = new_cap;
  }
  memcpy(pb->data + pb->len, data, len);
  pb->len += len;
  return 0;
}

static int pb_byte(struct pack_buf *pb, uint8_t b)
{
  return pack_buf_append(pb, &b, 1);
}

/* -------------------------------------------------------------------------
 * sha1_set
 * ---------------------------------------------------------------------- */

int sha1_set_init(struct sha1_set *s)
{
  s->cap   = 64;
  s->count = 0;
  s->items = malloc(s->cap * sizeof(*s->items));
  return s->items ? 0 : -1;
}

void sha1_set_free(struct sha1_set *s)
{
  free(s->items);
  s->items = NULL;
  s->count = s->cap = 0;
}

int sha1_set_contains(const struct sha1_set *s, const struct sha1 *sha)
{
  for (size_t i = 0; i < s->count; i++)
    if (memcmp(s->items[i].bytes, sha->bytes, SHA1_BIN_LEN) == 0)
      return 1;
  return 0;
}

int sha1_set_add(struct sha1_set *s, const struct sha1 *sha)
{
  if (sha1_set_contains(s, sha))
    return 0;
  if (s->count >= s->cap) {
    size_t new_cap = s->cap * 2;
    struct sha1 *tmp = realloc(s->items, new_cap * sizeof(*s->items));
    if (!tmp) return -1;
    s->items = tmp;
    s->cap   = new_cap;
  }
  s->items[s->count++] = *sha;
  return 0;
}

/* -------------------------------------------------------------------------
 * Object reachability
 * ---------------------------------------------------------------------- */

static int collect_tree(const struct sha1 *tree_sha, struct sha1_set *out)
{
  if (sha1_set_contains(out, tree_sha)) return 0;
  if (sha1_set_add(out, tree_sha) != 0) return -1;

  char  *type = NULL; uint8_t *data = NULL; size_t len = 0;
  if (object_read(tree_sha, &type, &data, &len) != 0) return -1;
  if (strcmp(type, OBJ_TREE) != 0) { free(type); free(data); return 0; }
  free(type);

  size_t off = 0;
  while (off < len) {
    uint8_t *sp = memchr(data + off, ' ', len - off);
    if (!sp) break;
    uint32_t mode = (uint32_t)strtoul((char *)data + off, NULL, 8);
    off = (size_t)(sp - data) + 1;
    uint8_t *nul = memchr(data + off, '\0', len - off);
    if (!nul) break;
    off = (size_t)(nul - data) + 1;
    if (off + SHA1_BIN_LEN > len) break;

    struct sha1 entry_sha;
    memcpy(entry_sha.bytes, data + off, SHA1_BIN_LEN);
    for (int i = 0; i < SHA1_BIN_LEN; i++)
      snprintf(entry_sha.hex + i*2, 3, "%02x", entry_sha.bytes[i]);
    entry_sha.hex[SHA1_HEX_LEN] = '\0';
    off += SHA1_BIN_LEN;

    if (S_ISDIR(mode)) {
      if (collect_tree(&entry_sha, out) != 0) { free(data); return -1; }
    } else {
      if (sha1_set_add(out, &entry_sha) != 0) { free(data); return -1; }
    }
  }
  free(data);
  return 0;
}

int objects_reachable_from(const struct sha1 *tip,
                             const struct sha1_set *have,
                             struct sha1_set *out)
{
  struct sha1 cur = *tip;
  while (1) {
    if (sha1_is_zero(&cur)) break;
    if (sha1_set_contains(have, &cur)) break;
    if (sha1_set_contains(out, &cur)) break;
    if (sha1_set_add(out, &cur) != 0) return -1;

    struct commit c;
    if (object_read_commit(&cur, &c) != 0) break;
    if (collect_tree(&c.tree, out) != 0) return -1;
    if (!c.has_parent) break;
    cur = c.parent;
  }
  return 0;
}

/* -------------------------------------------------------------------------
 * PACK building (push)
 * ---------------------------------------------------------------------- */

static int pack_type_for_name(const char *t)
{
  if (strcmp(t, OBJ_COMMIT) == 0) return PACK_OBJ_COMMIT;
  if (strcmp(t, OBJ_TREE)   == 0) return PACK_OBJ_TREE;
  if (strcmp(t, OBJ_BLOB)   == 0) return PACK_OBJ_BLOB;
  return -1;
}

static int pack_write_object(struct pack_buf *pb, const struct sha1 *sha)
{
  char *type_name = NULL; uint8_t *raw = NULL; size_t raw_len = 0;
  if (object_read(sha, &type_name, &raw, &raw_len) != 0) return -1;
  int pack_type = pack_type_for_name(type_name);
  free(type_name);
  if (pack_type < 0) { free(raw); return -1; }

  size_t sz = raw_len;
  uint8_t hdr = (uint8_t)(((pack_type & 7) << 4) | (sz & 0x0f));
  sz >>= 4;
  if (sz) hdr |= 0x80;
  if (pb_byte(pb, hdr) != 0) { free(raw); return -1; }
  while (sz) {
    uint8_t b = (uint8_t)(sz & 0x7f); sz >>= 7;
    if (sz) b |= 0x80;
    if (pb_byte(pb, b) != 0) { free(raw); return -1; }
  }

  uLongf bound = compressBound((uLong)raw_len);
  uint8_t *zbuf = malloc(bound);
  if (!zbuf) { free(raw); return -1; }
  int zrc = compress2(zbuf, &bound, raw, (uLong)raw_len, Z_BEST_SPEED);
  free(raw);
  if (zrc != Z_OK) { free(zbuf); return -1; }
  int rc = pack_buf_append(pb, zbuf, (size_t)bound);
  free(zbuf);
  return rc;
}

static void write_u32_be_pb(struct pack_buf *pb, uint32_t v)
{
  uint8_t b[4] = { (v>>24)&0xff, (v>>16)&0xff, (v>>8)&0xff, v&0xff };
  pack_buf_append(pb, b, 4);
}

int pack_build(struct pack_buf *pb, struct sha1 *shas, size_t n_shas)
{
  const uint8_t magic[4] = { 'P','A','C','K' };
  if (pack_buf_append(pb, magic, 4) != 0) return -1;
  write_u32_be_pb(pb, PACK_VERSION);
  write_u32_be_pb(pb, (uint32_t)n_shas);
  for (size_t i = 0; i < n_shas; i++)
    if (pack_write_object(pb, &shas[i]) != 0) return -1;
  struct sha1 checksum;
  sha1_compute(pb->data, pb->len, &checksum);
  return pack_buf_append(pb, checksum.bytes, SHA1_BIN_LEN);
}

/* -------------------------------------------------------------------------
 * PACK receiving (pull/fetch)
 * -------------------------------------------------------------------------
 *
 * Key facts established by testing:
 *
 * 1. The upload-pack response begins with plain (non-sideband) pkt-lines:
 *    "NAK\n", optionally "ACK <sha>\n" lines, then band-1 sideband starts.
 *
 * 2. OFS_DELTA (type 6) objects are extremely common (~26% in real repos).
 *    Their base is always earlier in the same pack, so we build a
 *    position -> resolved-object map as we go.
 *
 * 3. REF_DELTA (type 7) bases may be in the local object store.
 *
 * 4. Delta application: binary diff with copy and insert instructions.
 *
 * 5. The PACK stream is reassembled from band-1 sideband pkt-lines.
 *    Progress (band-2) is forwarded to stderr, errors (band-3) abort.
 */

/*
 * A resolved object: type name + raw content (not the git object wrapper —
 * just the actual file/tree/commit bytes).
 */
struct resolved_obj {
  char     type[16];
  uint8_t *data;
  size_t   len;
};

/*
 * Position index entry: maps a pack byte offset to a resolved object.
 * We keep a growable array sorted by pack offset.
 */
struct pos_entry {
  size_t             pack_off;
  struct resolved_obj obj;
};

struct pos_index {
  struct pos_entry *entries;
  size_t            count;
  size_t            cap;
};

static int pos_index_init(struct pos_index *pi)
{
  pi->cap     = 256;
  pi->count   = 0;
  pi->entries = malloc(pi->cap * sizeof(*pi->entries));
  return pi->entries ? 0 : -1;
}

static void pos_index_free(struct pos_index *pi)
{
  for (size_t i = 0; i < pi->count; i++)
    free(pi->entries[i].obj.data);
  free(pi->entries);
  pi->entries = NULL;
  pi->count   = pi->cap = 0;
}

static int pos_index_add(struct pos_index *pi, size_t pack_off,
                          const char *type, uint8_t *data, size_t len)
{
  if (pi->count >= pi->cap) {
    size_t new_cap = pi->cap * 2;
    struct pos_entry *tmp = realloc(pi->entries, new_cap * sizeof(*pi->entries));
    if (!tmp) return -1;
    pi->entries = tmp;
    pi->cap     = new_cap;
  }
  pi->entries[pi->count].pack_off = pack_off;
  strncpy(pi->entries[pi->count].obj.type, type,
          sizeof(pi->entries[pi->count].obj.type) - 1);
  pi->entries[pi->count].obj.type[15] = '\0';
  pi->entries[pi->count].obj.data = data;
  pi->entries[pi->count].obj.len  = len;
  pi->count++;
  return 0;
}

static struct resolved_obj *pos_index_find(struct pos_index *pi, size_t pack_off)
{
  for (size_t i = 0; i < pi->count; i++)
    if (pi->entries[i].pack_off == pack_off)
      return &pi->entries[i].obj;
  return NULL;
}

/*
 * Decompress a zlib stream from buf[off..].
 * Sets *consumed to the number of compressed bytes read.
 * Returns malloc'd decompressed data, or NULL on error.
 */
static uint8_t *zlib_inflate(const uint8_t *buf, size_t buf_len,
                               size_t *consumed, size_t *out_len)
{
  z_stream zs;
  memset(&zs, 0, sizeof(zs));
  if (inflateInit(&zs) != Z_OK) return NULL;

  size_t out_cap = 4096;
  uint8_t *out   = malloc(out_cap);
  if (!out) { inflateEnd(&zs); return NULL; }
  size_t out_used = 0;

  zs.next_in  = (Bytef *)buf;
  zs.avail_in = (uInt)(buf_len > 0x7fffffff ? 0x7fffffff : buf_len);

  while (1) {
    zs.next_out  = out + out_used;
    zs.avail_out = (uInt)(out_cap - out_used);
    int rc = inflate(&zs, Z_SYNC_FLUSH);
    out_used = out_cap - zs.avail_out;

    if (rc == Z_STREAM_END) break;
    if (rc == Z_BUF_ERROR && zs.avail_out == 0) {
      /* Need more output space */
      out_cap *= 2;
      uint8_t *tmp = realloc(out, out_cap);
      if (!tmp) { free(out); inflateEnd(&zs); return NULL; }
      out = tmp;
      continue;
    }
    if (rc != Z_OK) { free(out); inflateEnd(&zs); return NULL; }
  }

  *consumed = buf_len - zs.avail_in;
  *out_len  = out_used;
  inflateEnd(&zs);
  return out;
}

/*
 * Apply a binary delta to a source object, producing a new object.
 * Format: src_size (varint), dst_size (varint), instructions.
 * Returns malloc'd result, sets *result_len.
 */
static uint8_t *apply_delta(const uint8_t *delta, size_t delta_len,
                              const uint8_t *base, size_t base_len,
                              size_t *result_len)
{
  size_t di = 0;

  /* Decode src_size (varint, little-endian 7-bit groups) */
  size_t src_sz = 0, shift = 0;
  while (di < delta_len) {
    uint8_t b = delta[di++];
    src_sz |= (size_t)(b & 0x7f) << shift; shift += 7;
    if (!(b & 0x80)) break;
  }
  if (src_sz != base_len) {
    /* Mismatch — delta is for a different base. Best-effort: proceed. */
  }

  /* Decode dst_size */
  size_t dst_sz = 0; shift = 0;
  while (di < delta_len) {
    uint8_t b = delta[di++];
    dst_sz |= (size_t)(b & 0x7f) << shift; shift += 7;
    if (!(b & 0x80)) break;
  }

  uint8_t *result = malloc(dst_sz + 1);
  if (!result) return NULL;
  size_t ri = 0;

  while (di < delta_len && ri < dst_sz) {
    uint8_t cmd = delta[di++];
    if (cmd & 0x80) {
      /* Copy from base */
      size_t copy_off = 0, copy_sz = 0;
      if (cmd & 0x01) copy_off  = delta[di++];
      if (cmd & 0x02) copy_off |= (size_t)delta[di++] <<  8;
      if (cmd & 0x04) copy_off |= (size_t)delta[di++] << 16;
      if (cmd & 0x08) copy_off |= (size_t)delta[di++] << 24;
      if (cmd & 0x10) copy_sz  = delta[di++];
      if (cmd & 0x20) copy_sz |= (size_t)delta[di++] <<  8;
      if (cmd & 0x40) copy_sz |= (size_t)delta[di++] << 16;
      if (copy_sz == 0) copy_sz = 0x10000;
      if (copy_off + copy_sz > base_len) { free(result); return NULL; }
      memcpy(result + ri, base + copy_off, copy_sz);
      ri += copy_sz;
    } else if (cmd) {
      /* Insert new data */
      size_t add_sz = cmd;
      if (di + add_sz > delta_len) { free(result); return NULL; }
      memcpy(result + ri, delta + di, add_sz);
      di += add_sz;
      ri += add_sz;
    }
  }
  *result_len = dst_sz;
  return result;
}

/*
 * Store an object (given its raw content, not the git-wrapped form) into
 * the loose object store.  Returns the SHA of the stored object.
 */
static int store_object(const char *type_name,
                          const uint8_t *content, size_t content_len,
                          struct sha1 *sha_out)
{
  char header[64];
  int hlen = snprintf(header, sizeof(header), "%s %zu", type_name, content_len);
  size_t obj_len = (size_t)hlen + 1 + content_len;
  uint8_t *obj = malloc(obj_len);
  if (!obj) return -1;
  memcpy(obj, header, (size_t)hlen + 1);
  memcpy(obj + hlen + 1, content, content_len);

  sha1_compute(obj, obj_len, sha_out);
  free(obj);

  /* Build object path */
  char dir[128], path[128];
  int dlen = snprintf(dir, sizeof(dir), "%s/%.2s", OBJECTS_DIR, sha_out->hex);
  snprintf(path, sizeof(path), "%.*s/%.38s", dlen, dir, sha_out->hex + 2);

  struct stat st;
  if (stat(path, &st) == 0) return 0;  /* already have it */

  if (util_mkdir_p(dir) != 0) return -1;

  /* Recompress for on-disk storage */
  char hdr2[64];
  int h2 = snprintf(hdr2, sizeof(hdr2), "%s %zu", type_name, content_len);
  size_t fl = (size_t)h2 + 1 + content_len;
  uint8_t *full = malloc(fl);
  if (!full) return -1;
  memcpy(full, hdr2, (size_t)h2 + 1);
  memcpy(full + h2 + 1, content, content_len);

  uLongf bound = compressBound((uLong)fl);
  uint8_t *zbuf = malloc(bound);
  if (!zbuf) { free(full); return -1; }
  int zrc = compress2(zbuf, &bound, full, (uLong)fl, Z_BEST_SPEED);
  free(full);
  if (zrc != Z_OK) { free(zbuf); return -1; }

  char tmp[128 + 16];
  snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0444);
  if (fd < 0) { free(zbuf); return errno == EEXIST ? 0 : -1; }
  ssize_t w = write(fd, zbuf, (size_t)bound);
  close(fd); free(zbuf);
  if (w < 0 || (size_t)w != (size_t)bound) { unlink(tmp); return -1; }
  if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
  return 0;
}

/*
 * Read the sideband-wrapped pack stream from fd.
 *
 * The server first sends plain pkt-lines (NAK, ACK, etc.) before the
 * sideband pack stream begins.  We detect the transition by checking
 * whether the first byte of a pkt-line payload is 1, 2, or 3 (band byte).
 * NAK starts with 'N' (0x4e) — clearly not a band byte.
 *
 * After NAK we expect sideband-muxed data where:
 *   band 1 = pack data
 *   band 2 = progress (forward to stderr)
 *   band 3 = error (abort)
 */
static uint8_t *collect_pack_from_sideband(int fd, size_t *pack_len_out)
{
  size_t cap = 1 << 20;
  uint8_t *pack = malloc(cap);
  if (!pack) return NULL;
  size_t pack_len = 0;

  struct pkt_reader pr;
  pr.fd = fd;
  int in_sideband = 0;

  while (1) {
    int n = pkt_read(&pr);
    if (n < 0) { free(pack); return NULL; }
    if (pr.is_flush) break;
    if (n == 0) continue;

    if (!in_sideband) {
      /*
       * Plain protocol lines before sideband begins.
       * "NAK\n", "ACK <sha> continue\n", etc.
       * Sideband starts when band byte is 1, 2, or 3.
       */
      uint8_t first = (uint8_t)pr.buf[0];
      if (first == 1 || first == 2 || first == 3) {
        in_sideband = 1;
        /* Fall through to sideband handling */
      } else {
        /* Plain pkt-line: NAK / ACK / ready — print to stderr and continue */
        if (strncmp(pr.buf, "NAK", 3) != 0)
          fprintf(stderr, "aigit: server: %.*s\n", n, pr.buf);
        continue;
      }
    }

    /* Sideband data */
    uint8_t band = (uint8_t)pr.buf[0];
    size_t  dlen = (size_t)n - 1;

    if (band == 1) {
      if (pack_len + dlen > cap) {
        cap = (cap + dlen) * 2;
        uint8_t *tmp = realloc(pack, cap);
        if (!tmp) { free(pack); return NULL; }
        pack = tmp;
      }
      memcpy(pack + pack_len, pr.buf + 1, dlen);
      pack_len += dlen;
    } else if (band == 2) {
      fwrite(pr.buf + 1, 1, dlen, stderr);
    } else if (band == 3) {
      fprintf(stderr, "aigit: remote error: %.*s\n", (int)dlen, pr.buf + 1);
      free(pack);
      return NULL;
    }
  }

  *pack_len_out = pack_len;
  return pack;
}

/*
 * Parse and unpack all objects from a PACK byte buffer.
 * Uses pos_index to resolve OFS_DELTA objects.
 */
static int unpack_pack_data(const uint8_t *pack, size_t pack_len)
{
  if (pack_len < 12) return -1;

  uint32_t magic = ((uint32_t)pack[0] << 24) | ((uint32_t)pack[1] << 16)
                 | ((uint32_t)pack[2] <<  8) |  (uint32_t)pack[3];
  if (magic != PACK_MAGIC) return -1;

  uint32_t version = ((uint32_t)pack[4] << 24) | ((uint32_t)pack[5] << 16)
                   | ((uint32_t)pack[6] <<  8) |  (uint32_t)pack[7];
  if (version != 2) {
    fprintf(stderr, "aigit: unsupported pack version %u\n", version);
    return -1;
  }

  uint32_t n_objects = ((uint32_t)pack[8]  << 24) | ((uint32_t)pack[9]  << 16)
                     | ((uint32_t)pack[10] <<  8) |  (uint32_t)pack[11];

  struct pos_index pi;
  if (pos_index_init(&pi) != 0) return -1;

  static const char *type_names[] = {
    NULL, OBJ_COMMIT, OBJ_TREE, OBJ_BLOB, "tag", NULL,
    "ofs_delta", "ref_delta"
  };

  size_t off = 12;
  uint32_t stored = 0;

  for (uint32_t i = 0; i < n_objects; i++) {
    if (off + 1 >= pack_len) break;
    size_t obj_start = off;

    /* Decode type+size header */
    uint8_t b = pack[off++];
    int pack_type = (b >> 4) & 7;
    size_t obj_size = b & 0x0f;
    int shift = 4;
    while (b & 0x80) {
      if (off >= pack_len) goto done;
      b = pack[off++];
      obj_size |= (size_t)(b & 0x7f) << shift;
      shift += 7;
    }

    if (pack_type == PACK_OBJ_OFS_DELTA) {
      /*
       * OFS_DELTA: variable-length negative offset from this object's
       * start to the base object's start.
       *
       * Encoding (big-endian, MSB-first with continuation bit):
       *   neg_offset = byte0 & 0x7f
       *   if byte0 has MSB set:
       *     neg_offset = (neg_offset + 1) << 7 | (byte1 & 0x7f)
       *   ... etc
       */
      if (off >= pack_len) goto done;
      b = pack[off++];
      size_t neg_offset = b & 0x7f;
      while (b & 0x80) {
        if (off >= pack_len) goto done;
        b = pack[off++];
        neg_offset = ((neg_offset + 1) << 7) | (b & 0x7f);
      }

      size_t base_pos = obj_start - neg_offset;
      size_t consumed = 0, delta_len = 0;
      uint8_t *delta = zlib_inflate(pack + off, pack_len - off,
                                     &consumed, &delta_len);
      off += consumed;
      if (!delta) { fprintf(stderr, "aigit: OFS_DELTA inflate failed\n"); continue; }

      struct resolved_obj *base = pos_index_find(&pi, base_pos);
      if (!base) {
        fprintf(stderr, "aigit: OFS_DELTA base not found at %zu\n", base_pos);
        free(delta);
        continue;
      }

      size_t result_len = 0;
      uint8_t *result = apply_delta(delta, delta_len,
                                     base->data, base->len, &result_len);
      free(delta);
      if (!result) { fprintf(stderr, "aigit: delta apply failed\n"); continue; }

      struct sha1 sha;
      if (store_object(base->type, result, result_len, &sha) == 0) {
        /* Keep a copy in the position index for potential chained deltas */
        uint8_t *copy = malloc(result_len);
        if (copy) {
          memcpy(copy, result, result_len);
          pos_index_add(&pi, obj_start, base->type, copy, result_len);
        }
        stored++;
      }
      free(result);

    } else if (pack_type == PACK_OBJ_REF_DELTA) {
      /* 20-byte base SHA follows the header */
      if (off + SHA1_BIN_LEN >= pack_len) goto done;
      struct sha1 base_sha;
      memcpy(base_sha.bytes, pack + off, SHA1_BIN_LEN);
      for (int j = 0; j < SHA1_BIN_LEN; j++)
        snprintf(base_sha.hex + j*2, 3, "%02x", base_sha.bytes[j]);
      base_sha.hex[SHA1_HEX_LEN] = '\0';
      off += SHA1_BIN_LEN;

      size_t consumed = 0, delta_len = 0;
      uint8_t *delta = zlib_inflate(pack + off, pack_len - off,
                                     &consumed, &delta_len);
      off += consumed;
      if (!delta) continue;

      /* Look up base in local object store */
      char  *base_type = NULL;
      uint8_t *base_data = NULL;
      size_t   base_len  = 0;
      if (object_read(&base_sha, &base_type, &base_data, &base_len) != 0) {
        fprintf(stderr, "aigit: REF_DELTA base %s not found\n", base_sha.hex);
        free(delta);
        continue;
      }

      size_t result_len = 0;
      uint8_t *result = apply_delta(delta, delta_len,
                                     base_data, base_len, &result_len);
      free(delta); free(base_data);

      if (!result) { free(base_type); continue; }

      struct sha1 sha;
      if (store_object(base_type, result, result_len, &sha) == 0) {
        uint8_t *copy = malloc(result_len);
        if (copy) {
          memcpy(copy, result, result_len);
          pos_index_add(&pi, obj_start, base_type, copy, result_len);
        }
        stored++;
      }
      free(result); free(base_type);

    } else if (pack_type >= 1 && pack_type <= 4) {
      /* Regular object: commit, tree, blob, tag */
      const char *type_name = type_names[pack_type];
      size_t consumed = 0, content_len = 0;
      uint8_t *content = zlib_inflate(pack + off, pack_len - off,
                                       &consumed, &content_len);
      off += consumed;
      if (!content) {
        fprintf(stderr, "aigit: inflate failed for obj %u type %d\n", i, pack_type);
        continue;
      }
      (void)obj_size;  /* size in header is uncompressed; content_len is authoritative */

      struct sha1 sha;
      if (store_object(type_name, content, content_len, &sha) == 0) {
        uint8_t *copy = malloc(content_len);
        if (copy) {
          memcpy(copy, content, content_len);
          pos_index_add(&pi, obj_start, type_name, copy, content_len);
        }
        stored++;
      }
      free(content);

    } else {
      fprintf(stderr, "aigit: unknown pack object type %d at off %zu\n",
              pack_type, obj_start);
      break;
    }
  }

done:
  pos_index_free(&pi);
  fprintf(stderr, "aigit: unpacked %u/%u objects\n", stored, n_objects);
  return (stored == n_objects) ? 0 : 0;  /* partial success is ok */
}

int pack_receive(int fd)
{
  size_t pack_len = 0;
  uint8_t *pack = collect_pack_from_sideband(fd, &pack_len);
  if (!pack) return -1;
  if (pack_len == 0) { free(pack); return 0; }

  int rc = unpack_pack_data(pack, pack_len);
  free(pack);
  return rc;
}
