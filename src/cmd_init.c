#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "aigit.h"

/*
 * `aigit init`
 *
 * Creates the standard .git/ skeleton:
 *   .git/
 *   .git/objects/
 *   .git/refs/
 *   .git/refs/heads/
 *   .git/HEAD        -> "ref: refs/heads/main\n"
 */
int cmd_init(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  const char *dirs[] = {
    GIT_DIR,
    OBJECTS_DIR,
    REFS_DIR,
    HEADS_DIR,
    NULL,
  };

  for (int i = 0; dirs[i]; i++) {
    if (util_mkdir_p(dirs[i]) != 0) {
      fprintf(stderr, "aigit: failed to create %s: %s\n",
              dirs[i], strerror(errno));
      return 1;
    }
  }

  const char *head_content = "ref: refs/heads/main\n";
  if (util_write_file(HEAD_FILE,
                      (const uint8_t *)head_content,
                      strlen(head_content)) != 0) {
    fprintf(stderr, "aigit: failed to write HEAD: %s\n", strerror(errno));
    return 1;
  }

  printf("Initialized empty aigit repository in .git/\n");
  return 0;
}
