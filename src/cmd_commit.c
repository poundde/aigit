#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include "aigit.h"

/*
 * `aigit commit -m <message>`
 *
 * Sequence:
 *   1. Write a tree object from the current index.
 *   2. Resolve HEAD to find the parent commit (if any).
 *   3. Write the commit object.
 *   4. Update the branch ref to point at the new commit.
 */
int cmd_commit(int argc, char **argv)
{
  const char *message = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-m") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "aigit: -m requires a message\n");
        return 1;
      }
      message = argv[++i];
    }
  }

  if (!message) {
    fprintf(stderr, "usage: aigit commit -m <message>\n");
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

  if (idx.count == 0) {
    fprintf(stderr, "aigit: nothing to commit (index is empty)\n");
    index_free(&idx);
    return 1;
  }

  struct sha1 tree;
  if (object_write_tree(&idx, &tree) != 0) {
    fprintf(stderr, "aigit: failed to write tree\n");
    index_free(&idx);
    return 1;
  }
  index_free(&idx);

  struct sha1 parent;
  int has_parent = refs_head_exists();
  if (has_parent) {
    if (refs_resolve_head(&parent) != 0) {
      fprintf(stderr, "aigit: failed to resolve HEAD\n");
      return 1;
    }
  } else {
    sha1_zero(&parent);
  }

  char *identity = util_get_identity();
  if (!identity) {
    fprintf(stderr, "aigit: failed to determine identity\n");
    return 1;
  }

  int64_t now = (int64_t)time(NULL);

  struct sha1 commit_sha;
  if (object_write_commit(&tree, &parent, has_parent,
                          identity, identity,
                          now, message, &commit_sha) != 0) {
    fprintf(stderr, "aigit: failed to write commit\n");
    free(identity);
    return 1;
  }
  free(identity);

  char branch[256];
  if (refs_read_head(branch, sizeof(branch)) != 0) {
    fprintf(stderr, "aigit: cannot determine current branch\n");
    return 1;
  }

  char refname[MAX_PATH];
  snprintf(refname, sizeof(refname), "refs/heads/%s", branch);
  if (refs_write_ref(refname, &commit_sha) != 0) {
    fprintf(stderr, "aigit: failed to update ref\n");
    return 1;
  }

  printf("[%s %s] %s\n", branch, commit_sha.hex, message);
  return 0;
}
