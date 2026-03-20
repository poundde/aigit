#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include "aigit.h"

struct add_ctx {
  struct index       *idx;
  struct ignore_list  il;
  int                 errors;
};

/*
 * Copy src into dst[MAX_PATH], NUL-terminated, no truncation warning.
 */
static void path_copy(char dst[MAX_PATH], const char *src)
{
  size_t l = strnlen(src, MAX_PATH - 1);
  memcpy(dst, src, l);
  dst[l] = '\0';
}

/*
 * Load .gitignore rules from the repo root down to (and including) dir.
 * Rules are loaded shallowest-first so deeper rules can override shallower.
 */
static void load_ignore_rules_for_path(struct ignore_list *il,
                                        const char *dir)
{
  /*
   * Walk the path string backwards, collecting each ancestor component,
   * then reverse the list so we iterate root → leaf.
   */
  char work[MAX_PATH];
  path_copy(work, dir);

  char levels[256][MAX_PATH];
  int  depth = 0;

  char *p = work;
  while (depth < 255) {
    path_copy(levels[depth++], p);
    char *slash = strrchr(p, '/');
    if (!slash)
      break;
    *slash = '\0';
  }
  path_copy(levels[depth++], ".");

  /* Reverse: now levels[0] is "." (repo root), levels[depth-1] is dir */
  for (int i = 0, j = depth - 1; i < j; i++, j--) {
    char tmp[MAX_PATH];
    memcpy(tmp,       levels[i], MAX_PATH);
    memcpy(levels[i], levels[j], MAX_PATH);
    memcpy(levels[j], tmp,       MAX_PATH);
  }

  char last[MAX_PATH];
  last[0] = '\0';
  for (int i = 0; i < depth; i++) {
    if (strcmp(levels[i], last) == 0)
      continue;
    ignore_list_load_dir(il, levels[i]);
    path_copy(last, levels[i]);
  }
}

/*
 * Recursively walk repo_dir, staging every regular file not ignored.
 * Loads the .gitignore for repo_dir itself before scanning entries.
 */
static void add_directory(struct add_ctx *ctx, const char *repo_dir)
{
  ignore_list_load_dir(&ctx->il, repo_dir);

  DIR *d = opendir(strcmp(repo_dir, ".") == 0 ? "." : repo_dir);
  if (!d) {
    util_warn("cannot open directory '%s': %s", repo_dir, strerror(errno));
    ctx->errors++;
    return;
  }

  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    /*
     * Skip . and .. and the repo directory itself, but allow dotfiles
     * like .gitignore to be staged normally.
     */
    if (strcmp(de->d_name, ".")    == 0 ||
        strcmp(de->d_name, "..")   == 0 ||
        strcmp(de->d_name, ".git") == 0)
      continue;

    char path[MAX_PATH];
    if (strcmp(repo_dir, ".") == 0)
      snprintf(path, sizeof(path), "%s", de->d_name);
    else
      snprintf(path, sizeof(path), "%s/%s", repo_dir, de->d_name);

    struct stat st;
    if (lstat(path, &st) != 0) {
      util_warn("cannot stat '%s': %s", path, strerror(errno));
      continue;
    }

    int is_dir = S_ISDIR(st.st_mode);

    if (ignore_is_ignored(&ctx->il, path, is_dir))
      continue;

    if (is_dir) {
      add_directory(ctx, path);
    } else if (S_ISREG(st.st_mode)) {
      if (index_add(ctx->idx, path) != 0) {
        fprintf(stderr, "aigit: cannot add '%s': %s\n",
                path, strerror(errno));
        ctx->errors++;
      }
    }
  }

  closedir(d);
}

/*
 * `aigit add <path...>`
 *
 * Each argument may be a regular file or a directory.  Directories are
 * walked recursively.  Files and directories matching .gitignore rules
 * are skipped automatically.  Explicitly naming an ignored file stages it
 * with a warning (matching git's behaviour without --force).
 */
int cmd_add(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "usage: aigit add <file|dir...>\n");
    return 1;
  }

  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }

  struct index idx;
  if (index_init(&idx) != 0) {
    fprintf(stderr, "aigit: out of memory\n");
    return 1;
  }

  if (index_read(&idx) != 0) {
    fprintf(stderr, "aigit: failed to read index\n");
    index_free(&idx);
    return 1;
  }

  struct add_ctx ctx;
  ctx.idx    = &idx;
  ctx.errors = 0;
  if (ignore_list_init(&ctx.il) != 0) {
    fprintf(stderr, "aigit: out of memory\n");
    index_free(&idx);
    return 1;
  }

  /* Root .gitignore is always loaded first */
  ignore_list_load_dir(&ctx.il, ".");

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];

    struct stat st;
    if (stat(arg, &st) != 0) {
      fprintf(stderr, "aigit: cannot access '%s': %s\n",
              arg, strerror(errno));
      ctx.errors++;
      continue;
    }

    if (S_ISDIR(st.st_mode)) {
      load_ignore_rules_for_path(&ctx.il, arg);
      add_directory(&ctx, arg);
    } else if (S_ISREG(st.st_mode)) {
      if (ignore_is_ignored(&ctx.il, arg, 0))
        util_warn("'%s' is ignored; adding anyway", arg);
      if (index_add(ctx.idx, arg) != 0) {
        fprintf(stderr, "aigit: cannot add '%s': %s\n",
                arg, strerror(errno));
        ctx.errors++;
      }
    } else {
      util_warn("'%s' is not a file or directory — skipping", arg);
    }
  }

  ignore_list_free(&ctx.il);

  if (index_write(&idx) != 0) {
    fprintf(stderr, "aigit: failed to write index\n");
    index_free(&idx);
    return 1;
  }

  index_free(&idx);
  return ctx.errors ? 1 : 0;
}
