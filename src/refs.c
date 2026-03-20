#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include "aigit.h"

/*
 * Read the current branch name from HEAD.
 *
 * HEAD contains either:
 *   "ref: refs/heads/<branch>\n"  — symbolic ref (normal case)
 *   "<40-hex-sha>\n"              — detached HEAD
 *
 * We only handle the symbolic ref case; callers treat a detached HEAD
 * as an error for commit purposes.
 */
int refs_read_head(char *branch, size_t branch_len)
{
  size_t len;
  char *buf = util_read_file(HEAD_FILE, &len);
  if (!buf)
    return -1;

  const char *prefix = "ref: refs/heads/";
  size_t prefix_len  = strlen(prefix);

  if (strncmp(buf, prefix, prefix_len) != 0) {
    free(buf);
    return -1;  /* detached HEAD */
  }

  char *nl = strchr(buf + prefix_len, '\n');
  if (nl) *nl = '\0';

  strncpy(branch, buf + prefix_len, branch_len - 1);
  branch[branch_len - 1] = '\0';
  free(buf);
  return 0;
}

/*
 * Read a ref file (e.g. "refs/heads/main") and parse its SHA-1.
 * Falls back to .git/packed-refs if no loose ref file exists.
 * Returns -1 if the ref does not exist in either location.
 */
int refs_read_ref(const char *refname, struct sha1 *out)
{
  char path[MAX_PATH];
  snprintf(path, sizeof(path), ".git/%s", refname);

  size_t len;
  char *buf = util_read_file(path, &len);
  if (buf) {
    if (len < SHA1_HEX_LEN) { free(buf); return -1; }
    memcpy(out->hex, buf, SHA1_HEX_LEN);
    out->hex[SHA1_HEX_LEN] = '\0';
    sha1_hex_to_bytes(out->hex, out->bytes);
    free(buf);
    return 0;
  }

  /*
   * Not a loose ref — search packed-refs.
   * Format: "<sha1> <refname>\n"  (lines starting with '#' are comments,
   * lines starting with '^' are peeled tags — skip both).
   */
  size_t prlen;
  char *pr = util_read_file(".git/packed-refs", &prlen);
  if (!pr)
    return -1;

  char *p = pr, *end = pr + prlen;
  int found = 0;
  while (p < end) {
    char *nl = memchr(p, '\n', (size_t)(end - p));
    size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);

    if (llen > SHA1_HEX_LEN + 1 && p[0] != '#' && p[0] != '^') {
      /* "<sha1> <refname>" */
      const char *sp = memchr(p, ' ', llen);
      if (sp && (size_t)(sp - p) == SHA1_HEX_LEN) {
        const char *rname = sp + 1;
        size_t rlen = llen - SHA1_HEX_LEN - 1;
        if (rlen == strlen(refname) &&
            memcmp(rname, refname, rlen) == 0) {
          memcpy(out->hex, p, SHA1_HEX_LEN);
          out->hex[SHA1_HEX_LEN] = '\0';
          sha1_hex_to_bytes(out->hex, out->bytes);
          found = 1;
          break;
        }
      }
    }

    p = nl ? nl + 1 : end;
  }

  free(pr);
  return found ? 0 : -1;
}

/*
 * Write a SHA-1 to a ref file.  Creates intermediate directories as needed.
 */
int refs_write_ref(const char *refname, const struct sha1 *sha)
{
  char path[MAX_PATH];
  snprintf(path, sizeof(path), ".git/%s", refname);

  /* Ensure .git/refs/heads/ exists */
  char dir[MAX_PATH];
  snprintf(dir, sizeof(dir), ".git/%s", refname);
  char *last_slash = strrchr(dir, '/');
  if (last_slash) {
    *last_slash = '\0';
    if (util_mkdir_p(dir) != 0)
      return -1;
  }

  char content[SHA1_STR_SIZE + 2];
  snprintf(content, sizeof(content), "%s\n", sha->hex);

  return util_write_file(path, (uint8_t *)content, strlen(content));
}

/*
 * Resolve HEAD to a SHA-1, following the symbolic ref chain.
 * Returns -1 if the repo has no commits yet.
 */
int refs_resolve_head(struct sha1 *out)
{
  char branch[256];
  if (refs_read_head(branch, sizeof(branch)) != 0)
    return -1;

  char refname[MAX_PATH];
  snprintf(refname, sizeof(refname), "refs/heads/%s", branch);
  return refs_read_ref(refname, out);
}

/*
 * Returns 1 if the repository has at least one commit (HEAD resolves),
 * 0 otherwise.
 */
int refs_head_exists(void)
{
  struct sha1 sha;
  return refs_resolve_head(&sha) == 0 ? 1 : 0;
}

/*
 * Overwrite HEAD to point at a branch (symbolic ref).
 * Used by checkout when switching branches.
 */
int refs_write_head(const char *branch)
{
  char content[MAX_PATH + 32];
  snprintf(content, sizeof(content), "ref: refs/heads/%s\n", branch);
  return util_write_file(HEAD_FILE, (uint8_t *)content, strlen(content));
}

/*
 * Enumerate all local branches by scanning .git/refs/heads/.
 * Returns a malloc'd array of malloc'd name strings via *names_out.
 * Caller frees with refs_list_free().
 */
int refs_list_branches(char ***names_out, size_t *count_out)
{
  DIR *d = opendir(HEADS_DIR);
  if (!d) {
    *names_out = NULL;
    *count_out = 0;
    return 0;
  }

  size_t cap   = 16;
  size_t count = 0;
  char **names = malloc(cap * sizeof(char *));
  if (!names) {
    closedir(d);
    return -1;
  }

  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.')
      continue;

    if (count >= cap) {
      cap *= 2;
      char **tmp = realloc(names, cap * sizeof(char *));
      if (!tmp) {
        refs_list_free(names, count);
        closedir(d);
        return -1;
      }
      names = tmp;
    }
    names[count] = strdup(de->d_name);
    if (!names[count]) {
      refs_list_free(names, count);
      closedir(d);
      return -1;
    }
    count++;
  }
  closedir(d);

  *names_out = names;
  *count_out = count;
  return 0;
}

void refs_list_free(char **names, size_t count)
{
  for (size_t i = 0; i < count; i++)
    free(names[i]);
  free(names);
}

/*
 * Delete a ref file.  refname is relative to .git/ (e.g. "refs/heads/foo").
 */
int refs_delete_ref(const char *refname)
{
  char path[MAX_PATH];
  snprintf(path, sizeof(path), ".git/%s", refname);
  if (unlink(path) != 0)
    return -1;
  return 0;
}
