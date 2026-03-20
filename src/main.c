#include <stdio.h>
#include <string.h>
#include "aigit.h"

struct command {
  const char *name;
  int (*fn)(int argc, char **argv);
  const char *usage;
};

static const struct command commands[] = {
  { "init",   cmd_init,   "aigit init"              },
  { "add",    cmd_add,    "aigit add <file...>"      },
  { "commit", cmd_commit, "aigit commit -m <msg>"    },
  { "status", cmd_status, "aigit status"             },
  { "diff",   cmd_diff,   "aigit diff"               },
  { "log",      cmd_log,      "aigit log"                    },
  { "branch",   cmd_branch,   "aigit branch [-d|-m] [name]"  },
  { "checkout", cmd_checkout, "aigit checkout [-b] <branch>"         },
  { "config",   cmd_config,   "aigit config [--global] <key> [<val>]"},
  { "remote",   cmd_remote,   "aigit remote [add|remove] [<n> <url>]"},
  { "push",     cmd_push,     "aigit push [<remote> [<branch>]]"      },
  { "pull",     cmd_pull,     "aigit pull [<remote> [<branch>]]"      },
  { NULL, NULL, NULL },
};

static void print_usage(void)
{
  fprintf(stderr, "usage: aigit <command> [args]\n\n");
  fprintf(stderr, "commands:\n");
  for (int i = 0; commands[i].name; i++)
    fprintf(stderr, "  %s\n", commands[i].usage);
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    print_usage();
    return 1;
  }

  const char *subcmd = argv[1];
  for (int i = 0; commands[i].name; i++) {
    if (strcmp(subcmd, commands[i].name) == 0)
      return commands[i].fn(argc - 1, argv + 1);
  }

  fprintf(stderr, "aigit: unknown command '%s'\n", subcmd);
  print_usage();
  return 1;
}
