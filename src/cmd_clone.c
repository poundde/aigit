#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "aigit.h"

/*
 * `aigit clone [--depth=N] <url> [<directory>]`
 *
 * Equivalent to:
 *   mkdir <dir>
 *   cd <dir>
 *   aigit init
 *   aigit remote add origin <url>
 *   aigit pull [--depth=N]
 *
 * The directory defaults to the last component of the URL with .git stripped.
 */

static void derive_dirname(const char *url, char *out, size_t outlen)
{
  /* Find last '/' or ':' separator */
  const char *last_sep = NULL;
  for (const char *p = url; *p; p++) {
    if (*p == '/' || *p == ':')
      last_sep = p;
  }

  const char *base = last_sep ? last_sep + 1 : url;

  /* Strip .git suffix if present */
  size_t len = strlen(base);
  if (len > 4 && strcmp(base + len - 4, ".git") == 0)
    len -= 4;

  if (len == 0) {
    strncpy(out, "repo", outlen - 1);
    out[outlen - 1] = '\0';
    return;
  }

  if (len >= outlen) len = outlen - 1;
  memcpy(out, base, len);
  out[len] = '\0';
}

int cmd_clone(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr,
            "usage: aigit clone [--depth=N] <url> [<directory>]\n"
            "\n"
            "examples:\n"
            "  aigit clone git@github.com:poundde/aigit.git\n"
            "  aigit clone --branch=master --depth=1 https://github.com/torvalds/linux.git\n"
            "  aigit clone --branch master https://github.com/git/git.git mygit\n");
    return 1;
  }

  int    depth = 0;
  const char *url    = NULL;
  const char *dir    = NULL;
  const char* branch = "main";

  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "--depth=", 8) == 0) {
      depth = atoi(argv[i] + 8);
    } else if (strcmp(argv[i], "--depth") == 0 && i + 1 < argc) {
      depth = atoi(argv[++i]);
    } else if (strncmp(argv[i], "--branch=", 9) == 0) {
      branch = argv[i] + 9;
    } else if (strcmp(argv[i], "--branch") == 0 && i + 1 < argc) {
      branch = argv[++i];
    } else if (!url) {
      url = argv[i];
    } else if (!dir) {
      dir = argv[i];
    }
  }

  if (!url) {
    fprintf(stderr, "aigit clone: no URL given\n");
    return 1;
  }

  char auto_dir[MAX_PATH];
  if (!dir) {
    derive_dirname(url, auto_dir, sizeof(auto_dir));
    dir = auto_dir;
  }

  /* Create and enter the target directory */
  if (mkdir(dir, 0755) != 0) {
    if (errno == EEXIST) {
      fprintf(stderr, "aigit clone: destination '%s' already exists\n", dir);
    } else {
      fprintf(stderr, "aigit clone: cannot create '%s': %s\n",
              dir, strerror(errno));
    }
    return 1;
  }

  if (chdir(dir) != 0) {
    fprintf(stderr, "aigit clone: cannot enter '%s': %s\n",
            dir, strerror(errno));
    return 1;
  }

  printf("Cloning into '%s'...\n", dir);

  /* init */
  {
    char *init_argv[] = { "init", NULL };
    if (cmd_init(1, init_argv) != 0)
      return 1;
  }

  /* remote add origin <url> */
  {
    char *remote_argv[] = { "remote", "add", "origin", (char *)url, NULL };
    if (cmd_remote(4, remote_argv) != 0)
      return 1;
  }

  /* pull [--depth=N] */
  if (depth > 0) {
    char depth_str[32];
    snprintf(depth_str, sizeof(depth_str), "--depth=%d", depth);
    char *pull_argv[] = { "pull", depth_str, "origin", (char*)branch, NULL };
    if (cmd_pull(4, pull_argv) != 0)
      return 1;
  } else {
    char *pull_argv[] = { "pull", "origin", (char*)branch, NULL };
    if (cmd_pull(3, pull_argv) != 0)
      return 1;
  }

  return cmd_checkout(2, (char*[]){ "checkout", (char*)branch, NULL });
}
