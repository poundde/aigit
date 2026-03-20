#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "aigit.h"

/*
 * `aigit branch`                 — list all branches, mark current with *
 * `aigit branch <name>`          — create a new branch at HEAD
 * `aigit branch -d <name>`       — delete a branch (refuses if current)
 * `aigit branch -m <old> <new>`  — rename a branch
 */

static int branch_list(void)
{
  char current[256];
  int has_current = refs_read_head(current, sizeof(current)) == 0;

  char **names = NULL;
  size_t count = 0;
  if (refs_list_branches(&names, &count) != 0) {
    fprintf(stderr, "aigit: failed to list branches\n");
    return 1;
  }

  /* Sort for stable output */
  for (size_t i = 0; i < count; i++) {
    for (size_t j = i + 1; j < count; j++) {
      if (strcmp(names[i], names[j]) > 0) {
        char *tmp  = names[i];
        names[i] = names[j];
        names[j] = tmp;
      }
    }
  }

  for (size_t i = 0; i < count; i++) {
    int is_current = has_current && strcmp(names[i], current) == 0;
    printf("%s %s\n", is_current ? "*" : " ", names[i]);
  }

  if (count == 0)
    printf("(no branches)\n");

  refs_list_free(names, count);
  return 0;
}

static int branch_create(const char *name)
{
  /* Branch name must not contain .. or start/end with / or . */
  if (strstr(name, "..") || name[0] == '/' || name[0] == '.' ||
      name[strlen(name)-1] == '/' || strchr(name, ' ')) {
    fprintf(stderr, "aigit: invalid branch name '%s'\n", name);
    return 1;
  }

  /* Check it doesn't already exist */
  char refname[MAX_PATH];
  snprintf(refname, sizeof(refname), "refs/heads/%s", name);
  struct sha1 existing;
  if (refs_read_ref(refname, &existing) == 0) {
    fprintf(stderr, "aigit: branch '%s' already exists\n", name);
    return 1;
  }

  /* New branch points at HEAD commit */
  if (!refs_head_exists()) {
    fprintf(stderr, "aigit: cannot create branch — no commits yet\n");
    return 1;
  }

  struct sha1 head;
  if (refs_resolve_head(&head) != 0) {
    fprintf(stderr, "aigit: failed to resolve HEAD\n");
    return 1;
  }

  if (refs_write_ref(refname, &head) != 0) {
    fprintf(stderr, "aigit: failed to write ref: %s\n", strerror(errno));
    return 1;
  }

  printf("Branch '%s' created at %.7s\n", name, head.hex);
  return 0;
}

static int branch_delete(const char *name)
{
  char current[256];
  if (refs_read_head(current, sizeof(current)) == 0 &&
      strcmp(current, name) == 0) {
    fprintf(stderr, "aigit: cannot delete the currently checked-out branch '%s'\n",
            name);
    return 1;
  }

  char refname[MAX_PATH];
  snprintf(refname, sizeof(refname), "refs/heads/%s", name);

  struct sha1 sha;
  if (refs_read_ref(refname, &sha) != 0) {
    fprintf(stderr, "aigit: branch '%s' not found\n", name);
    return 1;
  }

  if (refs_delete_ref(refname) != 0) {
    fprintf(stderr, "aigit: failed to delete branch '%s': %s\n",
            name, strerror(errno));
    return 1;
  }

  printf("Deleted branch '%s' (was %.7s)\n", name, sha.hex);
  return 0;
}

static int branch_rename(const char *old_name, const char *new_name)
{
  char old_ref[MAX_PATH];
  char new_ref[MAX_PATH];
  snprintf(old_ref, sizeof(old_ref), "refs/heads/%s", old_name);
  snprintf(new_ref, sizeof(new_ref), "refs/heads/%s", new_name);

  struct sha1 sha;
  if (refs_read_ref(old_ref, &sha) != 0) {
    fprintf(stderr, "aigit: branch '%s' not found\n", old_name);
    return 1;
  }

  struct sha1 check;
  if (refs_read_ref(new_ref, &check) == 0) {
    fprintf(stderr, "aigit: branch '%s' already exists\n", new_name);
    return 1;
  }

  if (refs_write_ref(new_ref, &sha) != 0) {
    fprintf(stderr, "aigit: failed to create branch '%s'\n", new_name);
    return 1;
  }

  if (refs_delete_ref(old_ref) != 0) {
    fprintf(stderr, "aigit: failed to delete old branch '%s'\n", old_name);
    refs_delete_ref(new_ref);
    return 1;
  }

  /* If we renamed the current branch, update HEAD */
  char current[256];
  if (refs_read_head(current, sizeof(current)) == 0 &&
      strcmp(current, old_name) == 0) {
    refs_write_head(new_name);
  }

  printf("Renamed branch '%s' to '%s'\n", old_name, new_name);
  return 0;
}

int cmd_branch(int argc, char **argv)
{
  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }

  /* No arguments → list */
  if (argc == 1)
    return branch_list();

  if (strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "--delete") == 0) {
    if (argc < 3) {
      fprintf(stderr, "usage: aigit branch -d <name>\n");
      return 1;
    }
    return branch_delete(argv[2]);
  }

  if (strcmp(argv[1], "-m") == 0 || strcmp(argv[1], "--move") == 0) {
    if (argc < 4) {
      fprintf(stderr, "usage: aigit branch -m <old> <new>\n");
      return 1;
    }
    return branch_rename(argv[2], argv[3]);
  }

  /* Positional: create */
  return branch_create(argv[1]);
}
