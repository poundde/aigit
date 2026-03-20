#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <zlib.h>
#include "aigit.h"

/*
 * Pack index v2 format (magic 0xff744f63)
 * ----------------------------------------
 * 4   magic     0xff744f63
 * 4   version   2
 * 4*256 fan-out table  (fan[i] = number of objects whose first byte <= i)
 * 20*N  sorted SHA-1 list
 * 4*N   CRC32 list
 * 4*N   offset list (bit 31 set → index into large-offset table)
 * 8*M   large-offset table (for offsets > 2 GiB)
 * 20    SHA-1 of pack file
 * 20    SHA-1 of this index file
 *
 * To find object with sha S:
 *   1. fan[S[0]-1] .. fan[S[0]-1] gives the range in the SHA table
 *   2. binary search the SHA table for S
 *   3. offset = offset_list[found_index]
 *
 * Pack object at offset:
 *   type+size varint header
 *   [for OFS_DELTA: negative base offset varint]
 *   [for REF_DELTA: 20-byte base SHA]
 *   zlib-deflated content
 */

#define PACK_IDX_MAGIC  0xff744f63u
#define PACK_IDX_VER2   2

/*
 * Map an open pack+index pair.  We read both files fully into memory
 * since pack files for shallow clones are usually < a few hundred MiB
 * and we need random access for OFS_DELTA resolution.
 */
struct pack_file {
  uint8_t *idx_data;
  size_t   idx_len;
  uint8_t *pack_data;
  size_t   pack_len;
  uint32_t n_objects;
};

static void pack_file_free(struct pack_file *pf)
{
  free(pf->idx_data);
  free(pf->pack_data);
  pf->idx_data = pf->pack_data = NULL;
}

static int pack_file_open(struct pack_file *pf, const char *idx_path)
{
  /* idx_path is the .idx file; derive the .pack path */
  char pack_path[MAX_PATH];
  size_t base_len = strlen(idx_path) - 4;  /* strip ".idx" */
  if (base_len >= MAX_PATH - 6) return -1;
  memcpy(pack_path, idx_path, base_len);
  memcpy(pack_path + base_len, ".pack", 6);

  size_t ilen, plen;
  pf->idx_data  = (uint8_t *)util_read_file(idx_path, &ilen);
  pf->pack_data = (uint8_t *)util_read_file(pack_path, &plen);
  pf->idx_len   = ilen;
  pf->pack_len  = plen;

  if (!pf->idx_data || !pf->pack_data) {
    pack_file_free(pf);
    return -1;
  }

  if (ilen < 8) { pack_file_free(pf); return -1; }

  uint32_t magic = ((uint32_t)pf->idx_data[0] << 24)
                 | ((uint32_t)pf->idx_data[1] << 16)
                 | ((uint32_t)pf->idx_data[2] <<  8)
                 |  (uint32_t)pf->idx_data[3];
  uint32_t ver   = ((uint32_t)pf->idx_data[4] << 24)
                 | ((uint32_t)pf->idx_data[5] << 16)
                 | ((uint32_t)pf->idx_data[6] <<  8)
                 |  (uint32_t)pf->idx_data[7];

  if (magic != PACK_IDX_MAGIC || ver != PACK_IDX_VER2) {
    pack_file_free(pf);
    return -1;
  }

  /* fan[255] = total number of objects */
  if (ilen < 8 + 256*4) { pack_file_free(pf); return -1; }
  uint32_t fan255 = ((uint32_t)pf->idx_data[8 + 255*4    ] << 24)
                  | ((uint32_t)pf->idx_data[8 + 255*4 + 1] << 16)
                  | ((uint32_t)pf->idx_data[8 + 255*4 + 2] <<  8)
                  |  (uint32_t)pf->idx_data[8 + 255*4 + 3];
  pf->n_objects = fan255;
  return 0;
}

/*
 * Binary-search the sorted SHA table in the index for `sha`.
 * Returns the index (0-based) or -1 if not found.
 */
static int idx_find_sha(const struct pack_file *pf, const uint8_t *sha)
{
  uint32_t n = pf->n_objects;
  if (n == 0) return -1;

  /*
   * Narrow the range using the fan-out table.
   * fan[i] = count of objects whose first byte is <= i.
   */
  uint32_t lo = (sha[0] == 0) ? 0
    : ((uint32_t)pf->idx_data[8 + (sha[0]-1)*4    ] << 24)
    | ((uint32_t)pf->idx_data[8 + (sha[0]-1)*4 + 1] << 16)
    | ((uint32_t)pf->idx_data[8 + (sha[0]-1)*4 + 2] <<  8)
    |  (uint32_t)pf->idx_data[8 + (sha[0]-1)*4 + 3];
  uint32_t hi = ((uint32_t)pf->idx_data[8 + sha[0]*4    ] << 24)
              | ((uint32_t)pf->idx_data[8 + sha[0]*4 + 1] << 16)
              | ((uint32_t)pf->idx_data[8 + sha[0]*4 + 2] <<  8)
              |  (uint32_t)pf->idx_data[8 + sha[0]*4 + 3];

  /* SHA table starts after 8-byte header + 256*4 fan-out table */
  const uint8_t *sha_table = pf->idx_data + 8 + 256*4;

  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    int cmp = memcmp(sha_table + mid * SHA1_BIN_LEN, sha, SHA1_BIN_LEN);
    if (cmp == 0) return (int)mid;
    if (cmp < 0)  lo = mid + 1;
    else          hi = mid;
  }
  return -1;
}

/*
 * Get the pack offset for the object at index position `idx`.
 */
static uint64_t idx_get_offset(const struct pack_file *pf, uint32_t idx)
{
  uint32_t n = pf->n_objects;
  /* offset table starts after header(8) + fan(256*4) + sha(N*20) + crc(N*4) */
  size_t off_table_off = 8 + 256*4 + (size_t)n*20 + (size_t)n*4;
  const uint8_t *ot = pf->idx_data + off_table_off;

  uint32_t raw = ((uint32_t)ot[idx*4    ] << 24)
               | ((uint32_t)ot[idx*4 + 1] << 16)
               | ((uint32_t)ot[idx*4 + 2] <<  8)
               |  (uint32_t)ot[idx*4 + 3];

  if (!(raw & 0x80000000u))
    return (uint64_t)raw;

  /* Large offset: index into 8-byte large-offset table */
  uint32_t large_idx = raw & 0x7fffffffu;
  size_t large_off = off_table_off + (size_t)n*4 + large_idx*8;
  if (large_off + 8 > pf->idx_len) return (uint64_t)-1;
  const uint8_t *lt = pf->idx_data + large_off;
  return ((uint64_t)lt[0] << 56) | ((uint64_t)lt[1] << 48)
       | ((uint64_t)lt[2] << 40) | ((uint64_t)lt[3] << 32)
       | ((uint64_t)lt[4] << 24) | ((uint64_t)lt[5] << 16)
       | ((uint64_t)lt[6] <<  8) |  (uint64_t)lt[7];
}

/*
 * Inflate a zlib stream from pack_data at byte offset `off`.
 * Writes decompressed data to *out (malloc'd, caller frees).
 * Returns number of compressed bytes consumed, or -1 on error.
 */
static ssize_t pack_inflate_at(const struct pack_file *pf, size_t off,
                                uint8_t **out, size_t *out_len)
{
  z_stream zs;
  memset(&zs, 0, sizeof(zs));
  if (inflateInit(&zs) != Z_OK) return -1;

  size_t cap = 4096;
  *out = malloc(cap);
  if (!*out) { inflateEnd(&zs); return -1; }
  *out_len = 0;

  zs.next_in  = (Bytef *)(pf->pack_data + off);
  zs.avail_in = (uInt)(pf->pack_len - off);

  while (1) {
    zs.next_out  = *out + *out_len;
    zs.avail_out = (uInt)(cap - *out_len);

    int rc = inflate(&zs, Z_SYNC_FLUSH);
    *out_len = cap - zs.avail_out;

    if (rc == Z_STREAM_END) break;
    if (rc != Z_OK && rc != Z_BUF_ERROR) {
      free(*out); *out = NULL;
      inflateEnd(&zs);
      return -1;
    }
    if (zs.avail_out == 0) {
      cap *= 2;
      uint8_t *tmp = realloc(*out, cap);
      if (!tmp) { free(*out); *out = NULL; inflateEnd(&zs); return -1; }
      *out = tmp;
    }
  }

  size_t consumed = (pf->pack_len - off) - zs.avail_in;
  inflateEnd(&zs);
  return (ssize_t)consumed;
}

/*
 * Read a pack object at `offset` from the pack file.
 * Resolves OFS_DELTA and REF_DELTA recursively.
 *
 * Returns 0 on success, fills *type_out (static string, do not free),
 * *data_out (malloc'd, caller frees), *data_len_out.
 */
static int pack_read_object_at(const struct pack_file *pf, uint64_t offset,
                                 const char **type_out,
                                 uint8_t **data_out, size_t *data_len_out);

/* Apply a REF/OFS delta to a base object */
static int apply_delta(const uint8_t *base, size_t base_len,
                        const uint8_t *delta, size_t delta_len,
                        uint8_t **out, size_t *out_len)
{
  size_t di = 0;

  /* src_size varint */
  size_t src_sz = 0; int s = 0;
  while (di < delta_len) {
    uint8_t b = delta[di++];
    src_sz |= (size_t)(b & 0x7f) << s; s += 7;
    if (!(b & 0x80)) break;
  }
  (void)src_sz;

  /* dst_size varint */
  size_t dst_sz = 0; s = 0;
  while (di < delta_len) {
    uint8_t b = delta[di++];
    dst_sz |= (size_t)(b & 0x7f) << s; s += 7;
    if (!(b & 0x80)) break;
  }

  *out = malloc(dst_sz + 1);
  if (!*out) return -1;
  *out_len = 0;

  while (di < delta_len && *out_len < dst_sz) {
    uint8_t cmd = delta[di++];
    if (cmd & 0x80) {
      /* copy from base */
      size_t cp_off = 0, cp_sz = 0;
      if (cmd & 0x01) cp_off  = delta[di++];
      if (cmd & 0x02) cp_off |= (size_t)delta[di++] << 8;
      if (cmd & 0x04) cp_off |= (size_t)delta[di++] << 16;
      if (cmd & 0x08) cp_off |= (size_t)delta[di++] << 24;
      if (cmd & 0x10) cp_sz  = delta[di++];
      if (cmd & 0x20) cp_sz |= (size_t)delta[di++] << 8;
      if (cmd & 0x40) cp_sz |= (size_t)delta[di++] << 16;
      if (cp_sz == 0) cp_sz = 0x10000;
      if (cp_off + cp_sz > base_len) { free(*out); return -1; }
      memcpy(*out + *out_len, base + cp_off, cp_sz);
      *out_len += cp_sz;
    } else if (cmd) {
      /* add new data */
      size_t add = cmd;
      if (di + add > delta_len) { free(*out); return -1; }
      memcpy(*out + *out_len, delta + di, add);
      di += add;
      *out_len += add;
    }
  }
  (*out)[*out_len] = '\0';
  return 0;
}

static int pack_read_object_at(const struct pack_file *pf, uint64_t offset,
                                 const char **type_out,
                                 uint8_t **data_out, size_t *data_len_out)
{
  if (offset >= pf->pack_len) return -1;

  size_t off = (size_t)offset;

  /* Decode type+size header */
  uint8_t b = pf->pack_data[off++];
  int pack_type = (b >> 4) & 7;
  size_t obj_size = b & 0x0f;
  int shift = 4;
  while (b & 0x80) {
    if (off >= pf->pack_len) return -1;
    b = pf->pack_data[off++];
    obj_size |= (size_t)(b & 0x7f) << shift;
    shift += 7;
  }
  (void)obj_size;  /* used for allocation hints; inflate gives us real size */

  static const char *type_names[] = {
    NULL, OBJ_COMMIT, OBJ_TREE, OBJ_BLOB, "tag", NULL, NULL, NULL
  };

  if (pack_type >= 1 && pack_type <= 4) {
    /* Non-delta object */
    uint8_t *content = NULL;
    size_t content_len = 0;
    if (pack_inflate_at(pf, off, &content, &content_len) < 0)
      return -1;
    *type_out     = type_names[pack_type];
    *data_out     = content;
    *data_len_out = content_len;
    return 0;
  }

  if (pack_type == 6) {
    /* OFS_DELTA: negative offset from current position */
    uint64_t neg_off = 0;
    b = pf->pack_data[off++];
    neg_off = b & 0x7f;
    while (b & 0x80) {
      b = pf->pack_data[off++];
      neg_off = ((neg_off + 1) << 7) | (b & 0x7f);
    }
    uint64_t base_offset = offset - neg_off;

    const char *base_type;
    uint8_t *base_data = NULL;
    size_t base_len = 0;
    if (pack_read_object_at(pf, base_offset, &base_type, &base_data, &base_len) != 0)
      return -1;

    uint8_t *delta = NULL;
    size_t delta_len = 0;
    if (pack_inflate_at(pf, off, &delta, &delta_len) < 0) {
      free(base_data); return -1;
    }

    uint8_t *result = NULL;
    size_t result_len = 0;
    int rc = apply_delta(base_data, base_len, delta, delta_len, &result, &result_len);
    free(base_data); free(delta);
    if (rc != 0) return -1;

    *type_out     = base_type;
    *data_out     = result;
    *data_len_out = result_len;
    return 0;
  }

  if (pack_type == 7) {
    /* REF_DELTA: 20-byte base SHA follows */
    if (off + SHA1_BIN_LEN > pf->pack_len) return -1;
    struct sha1 base_sha;
    memcpy(base_sha.bytes, pf->pack_data + off, SHA1_BIN_LEN);
    for (int i = 0; i < SHA1_BIN_LEN; i++)
      snprintf(base_sha.hex + i*2, 3, "%02x", base_sha.bytes[i]);
    base_sha.hex[SHA1_HEX_LEN] = '\0';
    off += SHA1_BIN_LEN;

    /* Read base from loose store or pack (recursive) */
    char *base_type_str = NULL;
    uint8_t *base_data = NULL;
    size_t base_len = 0;
    if (object_read(&base_sha, &base_type_str, &base_data, &base_len) != 0)
      return -1;

    uint8_t *delta = NULL;
    size_t delta_len = 0;
    if (pack_inflate_at(pf, off, &delta, &delta_len) < 0) {
      free(base_type_str); free(base_data); return -1;
    }

    uint8_t *result = NULL;
    size_t result_len = 0;
    int rc = apply_delta(base_data, base_len, delta, delta_len, &result, &result_len);
    free(delta); free(base_data);
    if (rc != 0) { free(base_type_str); return -1; }

    /* Determine type from the base_type_str */
    if      (strcmp(base_type_str, OBJ_COMMIT) == 0) *type_out = OBJ_COMMIT;
    else if (strcmp(base_type_str, OBJ_TREE)   == 0) *type_out = OBJ_TREE;
    else if (strcmp(base_type_str, OBJ_BLOB)   == 0) *type_out = OBJ_BLOB;
    else *type_out = "unknown";
    free(base_type_str);

    *data_out     = result;
    *data_len_out = result_len;
    return 0;
  }

  return -1;  /* unknown type */
}

/*
 * Public interface: find `sha` in any pack file under .git/objects/pack/
 * and return its content.
 *
 * Returns 0 on success (caller frees *type_out and *data_out),
 * -1 if not found in any pack.
 */
int packfile_read(const struct sha1 *sha,
                  char **type_out,
                  uint8_t **data_out, size_t *len_out)
{
  DIR *d = opendir(".git/objects/pack");
  if (!d) return -1;

  int found = -1;
  struct dirent *de;

  while (found != 0 && (de = readdir(d)) != NULL) {
    size_t nlen = strlen(de->d_name);
    if (nlen < 4 || strcmp(de->d_name + nlen - 4, ".idx") != 0)
      continue;

    char idx_path[MAX_PATH];
    snprintf(idx_path, sizeof(idx_path),
             ".git/objects/pack/%s", de->d_name);

    struct pack_file pf;
    if (pack_file_open(&pf, idx_path) != 0)
      continue;

    int idx = idx_find_sha(&pf, sha->bytes);
    if (idx >= 0) {
      uint64_t offset = idx_get_offset(&pf, (uint32_t)idx);
      const char *type_static = NULL;
      uint8_t *data = NULL;
      size_t data_len = 0;

      if (pack_read_object_at(&pf, offset, &type_static, &data, &data_len) == 0) {
        *type_out = strdup(type_static);
        *data_out = data;
        *len_out  = data_len;
        found = 0;
      }
    }

    pack_file_free(&pf);
  }

  closedir(d);
  return found;
}
