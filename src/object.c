#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>
#include "aigit.h"

/* defined in packfile.c */
int packfile_read(const struct sha1 *sha, char **type_out,
                  uint8_t **data_out, size_t *len_out);

/*
 * Build the filesystem path for a loose object given its SHA-1 hex.
 * git uses the first two hex chars as the fan-out directory:
 *   .git/objects/ab/cdef...
 */
static void object_path(const struct sha1 *sha, char *out, size_t outlen)
{
  snprintf(out, outlen, "%s/%.2s/%s",
           OBJECTS_DIR, sha->hex, sha->hex + 2);
}

/*
 * Write raw bytes as a zlib-compressed loose object file.
 *
 * The on-disk format is:
 *   zlib( "<type> <size>\0<content>" )
 *
 * The file is written with mode 0444 (read-only) to match git's behaviour.
 */
static int object_write_raw(const struct sha1 *sha,
                             const uint8_t *data, size_t len)
{
  /*
   * Object paths are always short and fixed-structure:
   *   ".git/objects/XX/YYYYYY..."  (at most ~67 chars)
   * We build dir and path directly from known-bounded inputs.
   */
  char dir[128];
  char path[128];

  /* These calls cannot truncate: OBJECTS_DIR is a short literal and
   * sha->hex is exactly SHA1_HEX_LEN characters. */
  int dlen = snprintf(dir, sizeof(dir), "%s/%.2s", OBJECTS_DIR, sha->hex);
  snprintf(path, sizeof(path), "%.*s/%.38s",
           dlen < 0 ? 0 : dlen, dir, sha->hex + 2);

  /* Idempotent: object already stored. */
  struct stat st;
  if (stat(path, &st) == 0)
    return 0;

  if (util_mkdir_p(dir) != 0)
    return -1;

  uLongf bound = compressBound((uLong)len);
  uint8_t *zbuf = malloc(bound);
  if (!zbuf)
    return -1;

  if (compress2(zbuf, &bound, data, (uLong)len, Z_BEST_SPEED) != Z_OK) {
    free(zbuf);
    return -1;
  }

  char tmp[128 + 16];
  snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());

  int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0444);
  if (fd < 0) {
    free(zbuf);
    return -1;
  }

  ssize_t n = write(fd, zbuf, (size_t)bound);
  close(fd);
  free(zbuf);

  if (n < 0 || (size_t)n != (size_t)bound) {
    unlink(tmp);
    return -1;
  }

  if (rename(tmp, path) != 0) {
    unlink(tmp);
    return -1;
  }
  return 0;
}

/*
 * Build the full object header+body, hash it, and write to disk.
 *
 * header: "<type> <content_len>\0"
 * body:   <content>
 */
static int object_store(const char *type,
                         const uint8_t *content, size_t content_len,
                         struct sha1 *out)
{
  char header[64];
  int hlen = snprintf(header, sizeof(header),
                      "%s %zu", type, content_len);
  size_t obj_len = (size_t)hlen + 1 + content_len;

  uint8_t *obj = malloc(obj_len);
  if (!obj)
    return -1;

  memcpy(obj, header, (size_t)hlen + 1);          /* include NUL */
  memcpy(obj + hlen + 1, content, content_len);

  sha1_compute(obj, obj_len, out);
  int rc = object_write_raw(out, obj, obj_len);
  free(obj);
  return rc;
}

/*
 * Read and decompress a loose object.  Fills *type_out (caller frees),
 * *data_out (caller frees), and *len_out.  The data does NOT include the
 * header; it is the raw content after the NUL separator.
 */
int object_read(const struct sha1 *sha, char **type_out,
                uint8_t **data_out, size_t *len_out)
{
  char path[256];
  object_path(sha, path, sizeof(path));

  size_t zlen;
  uint8_t *zbuf = (uint8_t *)util_read_file(path, &zlen);
  if (!zbuf) {
    /* Loose object not found — try pack files */
    return packfile_read(sha, type_out, data_out, len_out);
  }

  /* Decompress in a loop, doubling the buffer if needed. */
  uLongf raw_len = (uLong)zlen * 4 + 256;
  uint8_t *raw   = malloc(raw_len);
  if (!raw) {
    free(zbuf);
    return -1;
  }

  while (1) {
    uLongf out_len = raw_len;
    int rc = uncompress(raw, &out_len, zbuf, (uLong)zlen);
    if (rc == Z_OK) {
      raw_len = out_len;
      break;
    }
    if (rc == Z_BUF_ERROR) {
      raw_len *= 2;
      uint8_t *tmp = realloc(raw, raw_len);
      if (!tmp) {
        free(raw);
        free(zbuf);
        return -1;
      }
      raw = tmp;
      continue;
    }
    free(raw);
    free(zbuf);
    return -1;
  }
  free(zbuf);

  /* Parse "<type> <len>\0<content>" */
  uint8_t *nul = memchr(raw, 0, raw_len);
  if (!nul) {
    free(raw);
    return -1;
  }

  char header[64];
  size_t hlen = (size_t)(nul - raw);
  if (hlen >= sizeof(header)) {
    free(raw);
    return -1;
  }
  memcpy(header, raw, hlen);
  header[hlen] = '\0';

  char *sp = strchr(header, ' ');
  if (!sp) {
    free(raw);
    return -1;
  }
  *sp = '\0';

  *type_out = strdup(header);
  size_t content_len = raw_len - hlen - 1;
  *data_out = malloc(content_len + 1);
  if (!*data_out) {
    free(raw);
    free(*type_out);
    return -1;
  }
  memcpy(*data_out, nul + 1, content_len);
  (*data_out)[content_len] = '\0';
  *len_out = content_len;
  free(raw);
  return 0;
}

/*
 * Hash the contents of a regular file (for index operations) without
 * writing the object to disk.
 */
int object_hash_file(const char *path, struct sha1 *out)
{
  size_t len;
  uint8_t *content = (uint8_t *)util_read_file(path, &len);
  if (!content)
    return -1;

  char header[64];
  int hlen = snprintf(header, sizeof(header), "blob %zu", len);
  size_t obj_len = (size_t)hlen + 1 + len;
  uint8_t *obj = malloc(obj_len);
  if (!obj) {
    free(content);
    return -1;
  }
  memcpy(obj, header, (size_t)hlen + 1);
  memcpy(obj + hlen + 1, content, len);
  sha1_compute(obj, obj_len, out);
  free(obj);
  free(content);
  return 0;
}

/*
 * Write a blob object for a file and return its SHA-1.
 */
int object_write_blob(const char *path, struct sha1 *out)
{
  size_t len;
  uint8_t *content = (uint8_t *)util_read_file(path, &len);
  if (!content)
    return -1;

  int rc = object_store(OBJ_BLOB, content, len, out);
  free(content);
  return rc;
}

/*
 * Tree building — recursive, hierarchical.
 *
 * Git tree objects only contain the names of their *direct* children.
 * A file at "src/core/main.c" requires three objects:
 *   root tree  -> entry "src"      mode 040000
 *   src tree   -> entry "core"     mode 040000
 *   core tree  -> entry "main.c"   mode 100644
 *
 * Valid git file modes:
 *   100644  regular file
 *   100755  executable
 *   120000  symlink
 *   40000   directory (no leading zero in tree entries)
 *
 * We sort using git's ordering rule: directories sort as if their name
 * has a trailing '/' appended.
 */

static const char *git_mode_str(uint32_t raw_mode)
{
  if (S_ISLNK(raw_mode))       return "120000";
  if (S_ISDIR(raw_mode))       return "40000";
  if ((raw_mode & 0111) != 0)  return "100755";
  return "100644";
}

struct tentry {
  char    name[256];
  char    mode_str[8];
  uint8_t sha[SHA1_BIN_LEN];
};

static int tentry_cmp(const void *a, const void *b)
{
  const struct tentry *ta = a;
  const struct tentry *tb = b;
  char sa[260], sb[260];
  snprintf(sa, sizeof(sa), "%s%s", ta->name,
           strcmp(ta->mode_str, "40000") == 0 ? "/" : "");
  snprintf(sb, sizeof(sb), "%s%s", tb->name,
           strcmp(tb->mode_str, "40000") == 0 ? "/" : "");
  return strcmp(sa, sb);
}

static int store_tree_entries(struct tentry *ents, size_t count,
                               struct sha1 *out)
{
  size_t total = 0;
  for (size_t i = 0; i < count; i++)
    total += strlen(ents[i].mode_str) + 1
           + strlen(ents[i].name)     + 1
           + SHA1_BIN_LEN;

  if (total == 0)
    return object_store(OBJ_TREE, (uint8_t *)"", 0, out);

  uint8_t *buf = malloc(total);
  if (!buf) return -1;
  size_t off = 0;
  for (size_t i = 0; i < count; i++) {
    size_t ml = strlen(ents[i].mode_str);
    size_t nl = strlen(ents[i].name);
    memcpy(buf + off, ents[i].mode_str, ml); off += ml;
    buf[off++] = ' ';
    memcpy(buf + off, ents[i].name, nl);     off += nl;
    buf[off++] = '\0';
    memcpy(buf + off, ents[i].sha, SHA1_BIN_LEN); off += SHA1_BIN_LEN;
  }
  int rc = object_store(OBJ_TREE, buf, total, out);
  free(buf);
  return rc;
}

/*
 * Recursively build a tree object for all index entries under `prefix`.
 * `entries` is the full sorted index; [lo, hi) is the slice in scope.
 * `prefix` is the directory path we are building (empty = repo root).
 */
static int build_tree(struct index_entry *entries, size_t lo, size_t hi,
                       const char *prefix, struct sha1 *out)
{
  size_t prefix_len = strlen(prefix);

  struct tentry *children = malloc(64 * sizeof(*children));
  if (!children) return -1;
  size_t cap = 64, n = 0;

  size_t i = lo;
  while (i < hi) {
    /* Strip prefix + separator to get path relative to this dir */
    const char *rel = entries[i].path + prefix_len;
    if (*rel == '/') rel++;

    const char *slash = strchr(rel, '/');

    if (!slash) {
      /* Direct file child */
      if (n >= cap) {
        cap *= 2;
        struct tentry *tmp = realloc(children, cap * sizeof(*tmp));
        if (!tmp) { free(children); return -1; }
        children = tmp;
      }
      strncpy(children[n].name, rel, 255);
      children[n].name[255] = '\0';
      strncpy(children[n].mode_str,
              git_mode_str(entries[i].mode), 7);
      children[n].mode_str[7] = '\0';
      memcpy(children[n].sha, entries[i].sha.bytes, SHA1_BIN_LEN);
      n++;
      i++;
    } else {
      /* Subdirectory: collect all entries sharing this dirname */
      size_t dlen = (size_t)(slash - rel);
      char dirname[256];
      if (dlen >= sizeof(dirname)) dlen = sizeof(dirname) - 1;
      memcpy(dirname, rel, dlen);
      dirname[dlen] = '\0';

      /* Advance j to first entry NOT in this subdir */
      size_t j = i + 1;
      while (j < hi) {
        const char *r2 = entries[j].path + prefix_len;
        if (*r2 == '/') r2++;
        if (strncmp(r2, dirname, dlen) != 0 ||
            (r2[dlen] != '/' && r2[dlen] != '\0'))
          break;
        j++;
      }

      /* Build subtree */
      char subprefix[MAX_PATH];
      if (prefix_len == 0)
        snprintf(subprefix, sizeof(subprefix), "%s", dirname);
      else
        snprintf(subprefix, sizeof(subprefix), "%s/%s", prefix, dirname);

      struct sha1 sub_sha;
      if (build_tree(entries, i, j, subprefix, &sub_sha) != 0) {
        free(children);
        return -1;
      }

      if (n >= cap) {
        cap *= 2;
        struct tentry *tmp = realloc(children, cap * sizeof(*tmp));
        if (!tmp) { free(children); return -1; }
        children = tmp;
      }
      strncpy(children[n].name, dirname, 255);
      children[n].name[255] = '\0';
      strncpy(children[n].mode_str, "40000", 7);
      memcpy(children[n].sha, sub_sha.bytes, SHA1_BIN_LEN);
      n++;
      i = j;
    }
  }

  qsort(children, n, sizeof(*children), tentry_cmp);
  int rc = store_tree_entries(children, n, out);
  free(children);
  return rc;
}

int object_write_tree(struct index *idx, struct sha1 *out)
{
  if (idx->count == 0)
    return object_store(OBJ_TREE, (uint8_t *)"", 0, out);

  return build_tree(idx->entries, 0, idx->count, "", out);
}

/*
 * Write a commit object.  The format mirrors git's exactly so that the
 * objects are readable by git itself.
 */
int object_write_commit(const struct sha1 *tree,
                         const struct sha1 *parent, int has_parent,
                         const char *author, const char *committer,
                         int64_t when, const char *message,
                         struct sha1 *out)
{
  char buf[65536];
  int  len = 0;

  len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                  "tree %s\n", tree->hex);

  if (has_parent)
    len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                    "parent %s\n", parent->hex);

  len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                  "author %s %lld +0000\n", author, (long long)when);
  len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                  "committer %s %lld +0000\n", committer, (long long)when);
  len += snprintf(buf + len, sizeof(buf) - (size_t)len,
                  "\n%s", message);

  /* Ensure message ends with newline */
  if (len > 0 && buf[len-1] != '\n') {
    buf[len++] = '\n';
    buf[len]   = '\0';
  }

  return object_store(OBJ_COMMIT, (uint8_t *)buf, (size_t)len, out);
}

/*
 * Parse a commit object from disk into struct commit.
 */
int object_read_commit(const struct sha1 *sha, struct commit *out)
{
  char   *type = NULL;
  uint8_t *data = NULL;
  size_t   len  = 0;

  if (object_read(sha, &type, &data, &len) != 0)
    return -1;

  if (strcmp(type, OBJ_COMMIT) != 0) {
    free(type);
    free(data);
    return -1;
  }
  free(type);

  memcpy(&out->sha, sha, sizeof(*sha));
  sha1_zero(&out->parent);
  out->has_parent    = 0;
  out->author[0]     = '\0';
  out->committer[0]  = '\0';
  out->author_time   = 0;
  out->commit_time   = 0;
  out->message[0]    = '\0';

  char *text = (char *)data;
  char *end  = text + len;
  char *p    = text;

  /* Parse header lines until we hit the blank line */
  while (p < end) {
    char *nl = memchr(p, '\n', (size_t)(end - p));
    if (!nl)
      break;
    *nl = '\0';

    if (*p == '\0') {
      /* blank line — message follows */
      p = nl + 1;
      break;
    }

    if (strncmp(p, "tree ", 5) == 0) {
      strncpy(out->tree.hex, p + 5, SHA1_HEX_LEN);
      out->tree.hex[SHA1_HEX_LEN] = '\0';
      sha1_hex_to_bytes(out->tree.hex, out->tree.bytes);
    } else if (strncmp(p, "parent ", 7) == 0) {
      strncpy(out->parent.hex, p + 7, SHA1_HEX_LEN);
      out->parent.hex[SHA1_HEX_LEN] = '\0';
      sha1_hex_to_bytes(out->parent.hex, out->parent.bytes);
      out->has_parent = 1;
    } else if (strncmp(p, "author ", 7) == 0) {
      /* "author Name <email> TIMESTAMP TIMEZONE" */
      char *ts = strrchr(p + 7, '>');
      if (ts) {
        ts++;  /* skip '>' */
        while (*ts == ' ') ts++;
        out->author_time = (int64_t)atoll(ts);
      }
      /* Store everything before the timestamp as the author string */
      char *last_sp = strrchr(p + 7, ' ');
      if (last_sp) {
        char *prev_sp = last_sp - 1;
        while (prev_sp > p + 7 && *prev_sp != ' ') prev_sp--;
        if (prev_sp > p + 7) {
          size_t alen = (size_t)(prev_sp - (p + 7));
          if (alen >= sizeof(out->author)) alen = sizeof(out->author) - 1;
          memcpy(out->author, p + 7, alen);
          out->author[alen] = '\0';
        } else {
          strncpy(out->author, p + 7, sizeof(out->author) - 1);
        }
      }
    } else if (strncmp(p, "committer ", 10) == 0) {
      char *ts = strrchr(p + 10, '>');
      if (ts) {
        ts++;
        while (*ts == ' ') ts++;
        out->commit_time = (int64_t)atoll(ts);
      }
    }

    p = nl + 1;
  }

  /* Everything after the blank line is the commit message */
  if (p < end) {
    size_t mlen = (size_t)(end - p);
    if (mlen >= MAX_MSG) mlen = MAX_MSG - 1;
    memcpy(out->message, p, mlen);
    out->message[mlen] = '\0';
    /* Trim trailing newline */
    while (mlen > 0 && out->message[mlen-1] == '\n')
      out->message[--mlen] = '\0';
  }

  free(data);
  return 0;
}

/*
 * Restore all files described by a tree object to the working directory.
 *
 * prefix is either "" (repo root) or "some/dir" — it is prepended to
 * every path we write, so recursive calls pass subdirectory names.
 *
 * We do NOT delete files that are present in the working tree but absent
 * from the target tree — that is handled by the checkout command which
 * knows which files to remove by comparing the old and new trees.
 */
int object_restore_tree(const struct sha1 *tree_sha, const char *prefix)
{
  char  *type = NULL;
  uint8_t *data = NULL;
  size_t   len  = 0;

  if (object_read(tree_sha, &type, &data, &len) != 0)
    return -1;

  if (strcmp(type, OBJ_TREE) != 0) {
    free(type);
    free(data);
    return -1;
  }
  free(type);

  int rc = 0;
  size_t off = 0;

  while (off < len && rc == 0) {
    /* "<mode> <name>\0<20-byte-sha>" */
    uint8_t *sp = memchr(data + off, ' ', len - off);
    if (!sp) break;
    *sp = '\0';
    uint32_t mode = (uint32_t)strtoul((char *)data + off, NULL, 8);
    off = (size_t)(sp - data) + 1;

    uint8_t *nul = memchr(data + off, '\0', len - off);
    if (!nul) break;
    const char *name = (const char *)(data + off);
    off = (size_t)(nul - data) + 1;

    if (off + SHA1_BIN_LEN > len) break;

    struct sha1 entry_sha;
    memcpy(entry_sha.bytes, data + off, SHA1_BIN_LEN);
    for (int i = 0; i < SHA1_BIN_LEN; i++)
      snprintf(entry_sha.hex + i*2, 3, "%02x", entry_sha.bytes[i]);
    entry_sha.hex[SHA1_HEX_LEN] = '\0';
    off += SHA1_BIN_LEN;

    /* Build the full path for this entry */
    char path[MAX_PATH];
    if (prefix[0] == '\0')
      snprintf(path, sizeof(path), "%s", name);
    else
      snprintf(path, sizeof(path), "%s/%s", prefix, name);

    if (S_ISDIR(mode)) {
      /* Subtree: recurse */
      if (util_mkdir_p(path) != 0) {
        rc = -1;
        break;
      }
      rc = object_restore_tree(&entry_sha, path);
    } else {
      /* Blob: write file content to disk */
      char   *blob_type = NULL;
      uint8_t *blob_data = NULL;
      size_t   blob_len  = 0;

      if (object_read(&entry_sha, &blob_type, &blob_data, &blob_len) != 0) {
        rc = -1;
        break;
      }
      free(blob_type);

      /*
       * Ensure the parent directory exists (for files nested under
       * subdirs that were not themselves explicit tree entries).
       */
      char parent[MAX_PATH];
      snprintf(parent, sizeof(parent), "%s", path);
      char *slash = strrchr(parent, '/');
      if (slash) {
        *slash = '\0';
        util_mkdir_p(parent);
      }

      if (util_write_file(path, blob_data, blob_len) != 0)
        rc = -1;

      /* Restore the file mode (executable bit) */
      if (rc == 0)
        chmod(path, (mode_t)(mode & 0777));

      free(blob_data);
    }
  }

  free(data);
  return rc;
}
