#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include "aigit.h"

/*
 * .gitignore rule semantics (subset we implement):
 *
 *  - Blank lines and lines starting with '#' are skipped.
 *  - A leading '!' negates the pattern; a previously ignored file matching
 *    a negation rule is no longer ignored.
 *  - A trailing '/' restricts the pattern to directories only.
 *  - If the pattern contains a '/' (other than a trailing one) it is
 *    matched relative to the directory containing the .gitignore (anchored).
 *  - Otherwise the pattern is matched against the final path component at
 *    any level (unanchored).
 *  - '*' matches anything except '/'.
 *  - '**' in the middle of a pattern (e.g. "a STARSTAR b") matches zero or more
 *    path components.  We implement this with a recursive helper.
 *  - '?' matches any single character except '/'.
 *
 * We store the base_dir of the .gitignore that owns each pattern so we can
 * strip it as a prefix when doing anchored matching.
 */

int ignore_list_init(struct ignore_list *il)
{
  il->cap      = 32;
  il->count    = 0;
  il->patterns = malloc(il->cap * sizeof(*il->patterns));
  return il->patterns ? 0 : -1;
}

void ignore_list_free(struct ignore_list *il)
{
  free(il->patterns);
  il->patterns = NULL;
  il->count    = 0;
  il->cap      = 0;
}

static int ignore_list_push(struct ignore_list *il,
                              const struct ignore_pattern *pat)
{
  if (il->count >= il->cap) {
    size_t new_cap = il->cap * 2;
    struct ignore_pattern *tmp = realloc(il->patterns,
                                          new_cap * sizeof(*il->patterns));
    if (!tmp)
      return -1;
    il->patterns = tmp;
    il->cap      = new_cap;
  }
  il->patterns[il->count++] = *pat;
  return 0;
}

/*
 * Parse a single line from a .gitignore and append it to il.
 * base_dir must be the directory path that contains the .gitignore,
 * with no trailing slash (use "." for the repo root).
 */
static int parse_ignore_line(struct ignore_list *il,
                               const char *line, const char *base_dir)
{
  /* Skip blank lines and comments */
  if (line[0] == '\0' || line[0] == '#')
    return 0;

  struct ignore_pattern pat;
  memset(&pat, 0, sizeof(pat));

  const char *p = line;
  if (*p == '!') {
    pat.negate = 1;
    p++;
  }

  /* Strip trailing whitespace (but not escaped trailing space) */
  size_t plen = strlen(p);
  while (plen > 0 && (p[plen-1] == ' ' || p[plen-1] == '\t') &&
         (plen < 2 || p[plen-2] != '\\')) {
    plen--;
  }

  if (plen == 0)
    return 0;

  /* Trailing slash → dir-only pattern, strip the slash */
  if (p[plen-1] == '/') {
    pat.dir_only = 1;
    plen--;
    if (plen == 0)
      return 0;
  }

  /* A leading slash means anchored to the base_dir; strip it */
  if (p[0] == '/') {
    pat.anchored = 1;
    p++;
    plen = plen > 0 ? plen - 1 : 0;
  } else {
    /*
     * If the pattern (without leading/trailing slash) contains a '/',
     * it is also anchored.
     */
    for (size_t i = 0; i < plen; i++) {
      if (p[i] == '/') {
        pat.anchored = 1;
        break;
      }
    }
  }

  if (plen >= MAX_PATH)
    plen = MAX_PATH - 1;

  memcpy(pat.pattern, p, plen);
  pat.pattern[plen] = '\0';

  strncpy(pat.base_dir, base_dir, MAX_PATH - 1);
  pat.base_dir[MAX_PATH - 1] = '\0';

  return ignore_list_push(il, &pat);
}

/*
 * Load all rules from a .gitignore file into il.
 * gitignore_path is the full path to the file; base_dir is its directory.
 */
int ignore_list_load_file(struct ignore_list *il,
                            const char *gitignore_path,
                            const char *base_dir)
{
  size_t len;
  char *buf = util_read_file(gitignore_path, &len);
  if (!buf)
    return 0;  /* missing .gitignore is not an error */

  char *p   = buf;
  char *end = buf + len;

  while (p < end) {
    char *nl = memchr(p, '\n', (size_t)(end - p));
    size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);

    /* Copy to a NUL-terminated buffer and strip CR */
    char line[MAX_PATH];
    if (line_len >= MAX_PATH) line_len = MAX_PATH - 1;
    memcpy(line, p, line_len);
    if (line_len > 0 && line[line_len-1] == '\r')
      line_len--;
    line[line_len] = '\0';

    parse_ignore_line(il, line, base_dir);

    p = nl ? nl + 1 : end;
  }

  free(buf);
  return 0;
}

/*
 * Load the .gitignore (if any) from the given directory into il.
 */
int ignore_list_load_dir(struct ignore_list *il, const char *dir)
{
  char path[MAX_PATH];
  if (strcmp(dir, ".") == 0)
    snprintf(path, sizeof(path), ".gitignore");
  else
    snprintf(path, sizeof(path), "%s/.gitignore", dir);

  return ignore_list_load_file(il, path, dir);
}

/*
 * Match a path against a single glob pattern, handling '**'.
 *
 * We split the pattern and path on '/' and recurse when we see '**'.
 * For non-'**' components we use fnmatch(3) with FNM_NOESCAPE.
 */
static int glob_match(const char *pattern, const char *path)
{
  /*
   * Find the first '**' segment in the pattern.
   * If none, fall straight through to a plain fnmatch.
   */
  const char *dstar = strstr(pattern, "**");
  if (!dstar) {
    /*
     * No '**': use fnmatch with FNM_PATHNAME so '*' won't cross '/'.
     * Also try matching just the basename for unanchored patterns —
     * callers handle that externally, so here we do a strict match.
     */
    return fnmatch(pattern, path, FNM_PATHNAME) == 0;
  }

  /*
   * Split at the '**': match the prefix, then try every suffix of the
   * remaining path against the part after '**'.
   */
  size_t pre_len = (size_t)(dstar - pattern);
  /* prefix component up to (but not including) the '**' */
  char prefix[MAX_PATH];
  if (pre_len >= MAX_PATH) pre_len = MAX_PATH - 1;
  memcpy(prefix, pattern, pre_len);
  /* strip trailing slash from prefix */
  while (pre_len > 0 && prefix[pre_len-1] == '/')
    pre_len--;
  prefix[pre_len] = '\0';

  /* suffix: what comes after '**', strip leading slash */
  const char *suffix = dstar + 2;
  while (*suffix == '/') suffix++;

  /* Check that the path starts with the prefix (if non-empty) */
  if (pre_len > 0) {
    if (strncmp(path, prefix, pre_len) != 0)
      return 0;
    if (path[pre_len] != '/' && path[pre_len] != '\0')
      return 0;
    path += pre_len;
    if (*path == '/') path++;
  }

  if (*suffix == '\0')
    return 1;  /* "**" at end matches everything remaining */

  /* Try matching the suffix against every position in the remaining path */
  const char *p = path;
  while (1) {
    if (glob_match(suffix, p))
      return 1;
    p = strchr(p, '/');
    if (!p)
      break;
    p++;
  }
  return 0;
}

/*
 * Test whether a single pattern matches a given (repo-relative) path.
 *
 * path    — repo-relative path, e.g. "src/foo.c" or "build"
 * is_dir  — non-zero if path refers to a directory
 */
static int pattern_matches(const struct ignore_pattern *pat,
                             const char *path, int is_dir)
{
  if (pat->dir_only && !is_dir)
    return 0;

  if (pat->anchored) {
    /*
     * Build the path relative to the pattern's base_dir.
     * If base_dir is "." the path is already relative to repo root.
     */
    const char *rel = path;
    if (strcmp(pat->base_dir, ".") != 0) {
      size_t blen = strlen(pat->base_dir);
      if (strncmp(path, pat->base_dir, blen) != 0)
        return 0;
      if (path[blen] != '/')
        return 0;
      rel = path + blen + 1;
    }
    return glob_match(pat->pattern, rel);
  }

  /*
   * Unanchored: the pattern must match either the full path or any
   * single component along it.
   */
  if (glob_match(pat->pattern, path))
    return 1;

  /* Walk each component */
  const char *p = path;
  while ((p = strchr(p, '/')) != NULL) {
    p++;
    if (glob_match(pat->pattern, p))
      return 1;
  }
  return 0;
}

/*
 * Determine whether path should be ignored according to the accumulated
 * rule set.  The last matching rule wins (later rules override earlier ones),
 * and negation rules can un-ignore a path.
 *
 * Returns 1 if ignored, 0 if not.
 */
int ignore_is_ignored(const struct ignore_list *il,
                       const char *path, int is_dir)
{
  int ignored = 0;

  for (size_t i = 0; i < il->count; i++) {
    const struct ignore_pattern *pat = &il->patterns[i];
    if (pattern_matches(pat, path, is_dir)) {
      ignored = pat->negate ? 0 : 1;
    }
  }

  return ignored;
}
