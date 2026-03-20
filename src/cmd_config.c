#include <stdio.h>
#include <string.h>
#include "aigit.h"

/*
 * `aigit config [--global|--local] <key> [<value>]`
 *
 * Without a value: print the current setting.
 * With a value:    write it.
 *
 * --global  operates on ~/.aigitconfig
 * --local   operates on .git/config  (default when inside a repo)
 */
int cmd_config(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr,
            "usage: aigit config [--global|--local] <key> [<value>]\n"
            "\n"
            "examples:\n"
            "  aigit config --global user.name  \"raute\"\n"
            "  aigit config --global user.email \"you@example.com\"\n"
            "  aigit config user.name\n");
    return 1;
  }

  int scope = CONFIG_ANY;
  int argi  = 1;

  if (strcmp(argv[argi], "--global") == 0) {
    scope = CONFIG_GLOBAL;
    argi++;
  } else if (strcmp(argv[argi], "--local") == 0) {
    scope = CONFIG_LOCAL;
    argi++;
  }

  /* --local requires a repo */
  if (scope == CONFIG_LOCAL || scope == CONFIG_ANY) {
    if (util_find_git_dir() != 0) {
      if (scope == CONFIG_LOCAL) {
        fprintf(stderr, "aigit: not a git repository\n");
        return 1;
      }
      /* CONFIG_ANY outside a repo → fall through to global only */
      scope = CONFIG_GLOBAL;
    }
  }

  if (argi >= argc) {
    fprintf(stderr, "aigit config: no key given\n");
    return 1;
  }

  const char *key = argv[argi++];

  if (argi < argc) {
    /* Write */
    const char *value = argv[argi];
    if (config_set(scope, key, value) != 0) {
      fprintf(stderr, "aigit config: failed to write '%s'\n", key);
      return 1;
    }
    return 0;
  }

  /* Read */
  char value[512];
  if (config_get(scope, key, value, sizeof(value)) != 0) {
    fprintf(stderr, "aigit config: key '%s' not set\n", key);
    return 1;
  }
  printf("%s\n", value);
  return 0;
}
