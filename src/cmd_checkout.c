#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "aigit.h"

/*
 * A flat listing of all paths in a tree object, used to compute the
 * set difference between two trees so we know which files to remove
 * when switching branches.
 */
struct tree_listing {
  char   **paths;
  size_t   count;
  size_t   cap;
};

static int tree_listing_init(struct tree_listing *tl)
{
  tl->cap   = 64;
  tl->count = 0;
  tl->paths = malloc(tl->cap * sizeof(char *));
  return tl->paths ? 0 : -1;
}

static void tree_listing_free(struct tree_listing *tl)
{
  for (size_t i = 0; i < tl->count; i++)
    free(tl->paths[i]);
  free(tl->paths);
  tl->paths = NULL;
  tl->count = 0;
}

static int tree_listing_push(struct tree_listing *tl, const char *path)
{
  if (tl->count >= tl->cap) {
    size_t new_cap = tl->cap * 2;
    char **tmp = realloc(tl->paths, new_cap * sizeof(char *));
    if (!tmp)
      return -1;
    tl->paths = tmp;
    tl->cap   = new_cap;
  }
  tl->paths[tl->count] = strdup(path);
  if (!tl->paths[tl->count])
    return -1;
  tl->count++;
  return 0;
}

/*
 * Recursively collect all file paths in a tree object into tl.
 * prefix is prepended to each path (pass "" for the root).
 */
static int collect_tree_paths(const struct sha1 *tree_sha,
                               const char *prefix,
                               struct tree_listing *tl)
{
  char  *type = NULL;
  uint8_t *data = NULL;
  size_t   len  = 0;

  if (object_read(tree_sha, &type, &data, &len) != 0)
    return -1;

  if (strcmp(type, OBJ_TREE) != 0) {
    free(type); free(data);
    return -1;
  }
  free(type);

  int rc = 0;
  size_t off = 0;

  while (off < len && rc == 0) {
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

    char path[MAX_PATH];
    if (prefix[0] == '\0')
      snprintf(path, sizeof(path), "%s", name);
    else
      snprintf(path, sizeof(path), "%s/%s", prefix, name);

    if (S_ISDIR(mode)) {
      rc = collect_tree_paths(&entry_sha, path, tl);
    } else {
      rc = tree_listing_push(tl, path);
    }
  }

  free(data);
  return rc;
}

/*
 * Return 1 if path exists in tl, 0 otherwise.
 * Linear scan is fine — trees are rarely huge.
 */
static int tree_listing_contains(const struct tree_listing *tl,
                                  const char *path)
{
  for (size_t i = 0; i < tl->count; i++) {
    if (strcmp(tl->paths[i], path) == 0)
      return 1;
  }
  return 0;
}

/*
 * Check whether the working tree has any uncommitted modifications
 * to tracked files.  We refuse to checkout if there are unsaved changes
 * to avoid silently clobbering work — matching git's behaviour.
 *
 * Returns 1 if dirty, 0 if clean.
 */
static int working_tree_is_dirty(const struct index *idx)
{
  for (size_t i = 0; i < idx->count; i++) {
    const struct index_entry *e = &idx->entries[i];
    struct stat st;
    if (stat(e->path, &st) != 0)
      return 1;  /* deleted on disk */
    struct sha1 disk_sha;
    if (object_hash_file(e->path, &disk_sha) != 0)
      return 1;
    if (strcmp(disk_sha.hex, e->sha.hex) != 0)
      return 1;
  }
  return 0;
}

/*
 * Perform the actual branch switch:
 *   1. Collect old tree file list (to know what to remove).
 *   2. Restore new tree to working directory.
 *   3. Remove files present in old tree but absent in new tree.
 *   4. Rebuild the index from the new tree.
 *   5. Update HEAD.
 */
static int do_checkout(const char *branch,
                        const struct sha1 *target_commit_sha)
{
  struct commit target;
  if (object_read_commit(target_commit_sha, &target) != 0) {
    fprintf(stderr, "aigit: failed to read target commit\n");
    return 1;
  }

  /* Collect paths in the current tree (before switch) */
  struct tree_listing old_tl;
  tree_listing_init(&old_tl);

  if (refs_head_exists()) {
    struct sha1 old_head;
    struct commit old_commit;
    if (refs_resolve_head(&old_head) == 0 &&
        object_read_commit(&old_head, &old_commit) == 0) {
      collect_tree_paths(&old_commit.tree, "", &old_tl);
    }
  }

  /* Collect paths in the new tree */
  struct tree_listing new_tl;
  tree_listing_init(&new_tl);
  collect_tree_paths(&target.tree, "", &new_tl);

  /* Restore new tree to working directory */
  if (object_restore_tree(&target.tree, "") != 0) {
    fprintf(stderr, "aigit: failed to restore working tree\n");
    tree_listing_free(&old_tl);
    tree_listing_free(&new_tl);
    return 1;
  }

  /* Remove files that were in the old tree but are not in the new tree */
  for (size_t i = 0; i < old_tl.count; i++) {
    if (!tree_listing_contains(&new_tl, old_tl.paths[i])) {
      if (unlink(old_tl.paths[i]) != 0 && errno != ENOENT)
        util_warn("could not remove '%s': %s", old_tl.paths[i], strerror(errno));
    }
  }

  tree_listing_free(&old_tl);
  tree_listing_free(&new_tl);

  /*
   * Rebuild the index to match the new tree.  We reset it fully rather
   * than trying to merge the old index — any staged changes are lost on
   * checkout, which is correct (they belonged to the other branch's state).
   */
  struct index new_idx;
  if (index_init(&new_idx) != 0) {
    fprintf(stderr, "aigit: out of memory\n");
    return 1;
  }

  /*
   * Walk the new tree, calling index_add for each file.  index_add reads
   * stat(2) data from disk and the blob SHA from the object store, so
   * the index will accurately reflect the freshly restored working tree.
   */
  struct tree_listing idx_tl;
  tree_listing_init(&idx_tl);
  collect_tree_paths(&target.tree, "", &idx_tl);

  int errors = 0;
  for (size_t i = 0; i < idx_tl.count; i++) {
    if (index_add(&new_idx, idx_tl.paths[i]) != 0) {
      util_warn("failed to index '%s'", idx_tl.paths[i]);
      errors++;
    }
  }
  tree_listing_free(&idx_tl);

  if (index_write(&new_idx) != 0) {
    fprintf(stderr, "aigit: failed to write index\n");
    index_free(&new_idx);
    return 1;
  }
  index_free(&new_idx);

  /* Finally, point HEAD at the new branch */
  if (refs_write_head(branch) != 0) {
    fprintf(stderr, "aigit: failed to update HEAD\n");
    return 1;
  }

  return errors ? 1 : 0;
}

/*
 * `aigit checkout <branch>`     — switch to an existing branch
 * `aigit checkout -b <branch>`  — create and switch to a new branch
 */
int cmd_checkout(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "usage: aigit checkout [-b] <branch>\n");
    return 1;
  }

  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }

  int create_new = 0;
  const char *branch = NULL;

  if (strcmp(argv[1], "-b") == 0) {
    if (argc < 3) {
      fprintf(stderr, "usage: aigit checkout -b <branch>\n");
      return 1;
    }
    create_new = 1;
    branch     = argv[2];
  } else {
    branch = argv[1];
  }

  /* Refuse to checkout if there are uncommitted changes */
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
  int dirty = working_tree_is_dirty(&idx);
  index_free(&idx);

  if (dirty) {
    fprintf(stderr,
            "aigit: your local changes would be overwritten by checkout.\n"
            "       commit or stash your changes before switching branches.\n");
    return 1;
  }

  /* Already on this branch? */
  char current[256];
  if (refs_read_head(current, sizeof(current)) == 0 &&
      strcmp(current, branch) == 0 && !create_new) {
    printf("Already on '%s'\n", branch);
    return 0;
  }

  char refname[MAX_PATH];
  snprintf(refname, sizeof(refname), "refs/heads/%s", branch);

  if (create_new) {
    /* Create the branch first, pointing at HEAD */
    if (!refs_head_exists()) {
      fprintf(stderr, "aigit: cannot create branch — no commits yet\n");
      return 1;
    }

    struct sha1 existing;
    if (refs_read_ref(refname, &existing) == 0) {
      fprintf(stderr, "aigit: branch '%s' already exists\n", branch);
      return 1;
    }

    struct sha1 head;
    if (refs_resolve_head(&head) != 0) {
      fprintf(stderr, "aigit: failed to resolve HEAD\n");
      return 1;
    }
    if (refs_write_ref(refname, &head) != 0) {
      fprintf(stderr, "aigit: failed to create branch '%s'\n", branch);
      return 1;
    }
  }

  /* Resolve the target commit */
  struct sha1 target_sha;
  if (refs_read_ref(refname, &target_sha) != 0) {
    fprintf(stderr, "aigit: branch '%s' not found\n", branch);
    return 1;
  }

  int rc = do_checkout(branch, &target_sha);
  if (rc == 0)
    printf("Switched to %sbranch '%s'\n", create_new ? "a new " : "", branch);
  return rc;
}
