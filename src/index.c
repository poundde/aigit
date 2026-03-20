#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "aigit.h"

/*
 * The git index v2 on-disk format (simplified, no extensions):
 *
 *   4 bytes  magic "DIRC"
 *   4 bytes  version (2)
 *   4 bytes  number of entries
 *   [entries]
 *   20 bytes SHA-1 of the above
 *
 * Each entry:
 *   4  ctime_sec
 *   4  ctime_nsec
 *   4  mtime_sec
 *   4  mtime_nsec
 *   4  dev
 *   4  ino
 *   4  mode
 *   4  uid
 *   4  gid
 *   4  file_size
 *   20 sha1
 *   2  flags (lower 12 bits = path length)
 *   N  path (NUL terminated, padded to 8-byte boundary)
 */

#define ENTRY_FIXED_SIZE  (4*10 + SHA1_BIN_LEN + 2)

static int entry_cmp(const void *a, const void *b)
{
  const struct index_entry *ea = a;
  const struct index_entry *eb = b;
  return strcmp(ea->path, eb->path);
}

int index_init(struct index *idx)
{
  idx->cap     = 64;
  idx->count   = 0;
  idx->entries = malloc(idx->cap * sizeof(*idx->entries));
  return idx->entries ? 0 : -1;
}

void index_free(struct index *idx)
{
  free(idx->entries);
  idx->entries = NULL;
  idx->count   = 0;
  idx->cap     = 0;
}

static uint32_t read_u32_be(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
       | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void write_u32_be(uint8_t *p, uint32_t v)
{
  p[0] = (v >> 24) & 0xff;
  p[1] = (v >> 16) & 0xff;
  p[2] = (v >>  8) & 0xff;
  p[3] =  v        & 0xff;
}

static uint16_t read_u16_be(const uint8_t *p)
{
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write_u16_be(uint8_t *p, uint16_t v)
{
  p[0] = (v >> 8) & 0xff;
  p[1] =  v       & 0xff;
}

/*
 * Read the index from disk into idx.  If the file does not exist,
 * idx is left empty (count == 0) — that is not an error.
 */
int index_read(struct index *idx)
{
  size_t len;
  uint8_t *buf = (uint8_t *)util_read_file(INDEX_FILE, &len);
  if (!buf) {
    if (errno == ENOENT)
      return 0;  /* no index yet */
    return -1;
  }

  if (len < 12) {
    free(buf);
    return -1;
  }

  uint32_t magic   = read_u32_be(buf + 0);
  uint32_t version = read_u32_be(buf + 4);
  uint32_t count   = read_u32_be(buf + 8);

  if (magic != INDEX_MAGIC || version != INDEX_VERSION) {
    free(buf);
    return -1;
  }

  if (count > MAX_ENTRIES) {
    free(buf);
    return -1;
  }

  /* Grow the entries array if needed */
  if (count > idx->cap) {
    struct index_entry *tmp = realloc(idx->entries,
                                      count * sizeof(*idx->entries));
    if (!tmp) {
      free(buf);
      return -1;
    }
    idx->entries = tmp;
    idx->cap     = count;
  }

  size_t off = 12;
  for (uint32_t i = 0; i < count; i++) {
    if (off + ENTRY_FIXED_SIZE > len) {
      free(buf);
      return -1;
    }

    struct index_entry *e = &idx->entries[i];
    e->ctime_sec  = read_u32_be(buf + off +  0);
    e->ctime_nsec = read_u32_be(buf + off +  4);
    e->mtime_sec  = read_u32_be(buf + off +  8);
    e->mtime_nsec = read_u32_be(buf + off + 12);
    e->dev        = read_u32_be(buf + off + 16);
    e->ino        = read_u32_be(buf + off + 20);
    e->mode       = read_u32_be(buf + off + 24);
    e->uid        = read_u32_be(buf + off + 28);
    e->gid        = read_u32_be(buf + off + 32);
    e->size       = read_u32_be(buf + off + 36);
    memcpy(e->sha.bytes, buf + off + 40, SHA1_BIN_LEN);
    for (int j = 0; j < SHA1_BIN_LEN; j++)
      snprintf(e->sha.hex + j*2, 3, "%02x", e->sha.bytes[j]);
    e->sha.hex[SHA1_HEX_LEN] = '\0';
    e->flags = read_u16_be(buf + off + 40 + SHA1_BIN_LEN);

    /*
     * Index v3 extended flags: if the high bit of flags is set and the
     * index version is >= 3, an extra 2-byte flags word follows.
     * We skip it so path parsing stays aligned.
     */
    int has_extended = (version >= 3 && (e->flags & 0x8000));

    off += ENTRY_FIXED_SIZE;
    if (has_extended) off += 2;  /* skip extended flags word */

    /* Read NUL-terminated path */
    size_t path_len = 0;
    while (off + path_len < len && buf[off + path_len] != '\0')
      path_len++;

    if (path_len >= MAX_PATH) {
      free(buf);
      return -1;
    }
    memcpy(e->path, buf + off, path_len);
    e->path[path_len] = '\0';
    off += path_len + 1;

    /* Pad to next 8-byte boundary (from start of entry) */
    size_t entry_bytes = ENTRY_FIXED_SIZE + path_len + 1;
    size_t pad = (8 - (entry_bytes % 8)) % 8;
    off += pad;
  }

  idx->count = count;
  free(buf);
  return 0;
}

/*
 * Write the in-memory index to disk, including the trailing SHA-1 checksum.
 */
int index_write(const struct index *idx)
{
  /* Calculate total size */
  size_t total = 12;  /* header */
  for (size_t i = 0; i < idx->count; i++) {
    size_t plen = strlen(idx->entries[i].path);
    size_t entry_bytes = ENTRY_FIXED_SIZE + plen + 1;
    size_t pad = (8 - (entry_bytes % 8)) % 8;
    total += entry_bytes + pad;
  }
  total += SHA1_BIN_LEN;  /* trailing checksum */

  uint8_t *buf = calloc(1, total);
  if (!buf)
    return -1;

  write_u32_be(buf + 0, INDEX_MAGIC);
  write_u32_be(buf + 4, INDEX_VERSION);
  write_u32_be(buf + 8, (uint32_t)idx->count);

  size_t off = 12;
  for (size_t i = 0; i < idx->count; i++) {
    const struct index_entry *e = &idx->entries[i];
    write_u32_be(buf + off +  0, e->ctime_sec);
    write_u32_be(buf + off +  4, e->ctime_nsec);
    write_u32_be(buf + off +  8, e->mtime_sec);
    write_u32_be(buf + off + 12, e->mtime_nsec);
    write_u32_be(buf + off + 16, e->dev);
    write_u32_be(buf + off + 20, e->ino);
    write_u32_be(buf + off + 24, e->mode);
    write_u32_be(buf + off + 28, e->uid);
    write_u32_be(buf + off + 32, e->gid);
    write_u32_be(buf + off + 36, e->size);
    memcpy(buf + off + 40, e->sha.bytes, SHA1_BIN_LEN);
    write_u16_be(buf + off + 40 + SHA1_BIN_LEN, e->flags);
    off += ENTRY_FIXED_SIZE;

    size_t plen = strlen(e->path);
    memcpy(buf + off, e->path, plen);
    off += plen;
    buf[off++] = '\0';

    size_t entry_bytes = ENTRY_FIXED_SIZE + plen + 1;
    size_t pad = (8 - (entry_bytes % 8)) % 8;
    off += pad;  /* already zeroed by calloc */
  }

  /* Checksum covers everything before the trailing 20 bytes */
  struct sha1 checksum;
  sha1_compute(buf, off, &checksum);
  memcpy(buf + off, checksum.bytes, SHA1_BIN_LEN);

  int rc = util_write_file(INDEX_FILE, buf, total);
  free(buf);
  return rc;
}

/*
 * Add or update a file in the index.  Writes the blob to the object
 * store as a side effect so the data is never lost even before commit.
 */
int index_add(struct index *idx, const char *path)
{
  struct stat st;
  if (stat(path, &st) != 0)
    return -1;

  if (!S_ISREG(st.st_mode)) {
    util_warn("'%s' is not a regular file — skipping", path);
    return 0;
  }

  struct sha1 sha;
  if (object_write_blob(path, &sha) != 0)
    return -1;

  /* Update existing entry if present */
  struct index_entry *existing = index_find(idx, path);
  if (existing) {
    memcpy(&existing->sha, &sha, sizeof(sha));
    existing->ctime_sec  = (uint32_t)st.st_ctim.tv_sec;
    existing->ctime_nsec = (uint32_t)st.st_ctim.tv_nsec;
    existing->mtime_sec  = (uint32_t)st.st_mtim.tv_sec;
    existing->mtime_nsec = (uint32_t)st.st_mtim.tv_nsec;
    existing->size       = (uint32_t)st.st_size;
    return 0;
  }

  /* Grow the array if full */
  if (idx->count >= idx->cap) {
    size_t new_cap = idx->cap * 2;
    struct index_entry *tmp = realloc(idx->entries,
                                      new_cap * sizeof(*idx->entries));
    if (!tmp)
      return -1;
    idx->entries = tmp;
    idx->cap     = new_cap;
  }

  struct index_entry *e = &idx->entries[idx->count++];
  memset(e, 0, sizeof(*e));
  memcpy(&e->sha, &sha, sizeof(sha));
  strncpy(e->path, path, MAX_PATH - 1);
  e->ctime_sec  = (uint32_t)st.st_ctim.tv_sec;
  e->ctime_nsec = (uint32_t)st.st_ctim.tv_nsec;
  e->mtime_sec  = (uint32_t)st.st_mtim.tv_sec;
  e->mtime_nsec = (uint32_t)st.st_mtim.tv_nsec;
  e->dev        = (uint32_t)st.st_dev;
  e->ino        = (uint32_t)st.st_ino;
  e->mode       = (uint32_t)st.st_mode;
  e->uid        = (uint32_t)st.st_uid;
  e->gid        = (uint32_t)st.st_gid;
  e->size       = (uint32_t)st.st_size;
  e->flags      = (uint16_t)(strlen(path) & 0xfff);

  /* Keep sorted by path */
  qsort(idx->entries, idx->count, sizeof(*idx->entries), entry_cmp);
  return 0;
}

struct index_entry *index_find(struct index *idx, const char *path)
{
  /* Binary search since entries are sorted */
  size_t lo = 0, hi = idx->count;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    int cmp = strcmp(idx->entries[mid].path, path);
    if (cmp == 0)
      return &idx->entries[mid];
    if (cmp < 0)
      lo = mid + 1;
    else
      hi = mid;
  }
  return NULL;
}
