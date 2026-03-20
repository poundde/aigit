#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include "aigit.h"

/*
 * Walk a directory recursively and call cb(path, userdata) for every
 * regular file found.  Skips the .git/ directory.
 */
struct walk_state {
  void (*cb)(const char *path, void *userdata);
  void *userdata;
};

static void walk_dir(const char *base, struct walk_state *ws)
{
  DIR *d = opendir(base);
  if (!d)
    return;

  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (strcmp(de->d_name, ".")    == 0 ||
        strcmp(de->d_name, "..")   == 0 ||
        strcmp(de->d_name, ".git") == 0)
      continue;

    char path[MAX_PATH];
    if (strcmp(base, ".") == 0)
      snprintf(path, sizeof(path), "%s", de->d_name);
    else
      snprintf(path, sizeof(path), "%s/%s", base, de->d_name);

    /* Never descend into .git/ */
    if (strcmp(path, GIT_DIR) == 0)
      continue;

    struct stat st;
    if (stat(path, &st) != 0)
      continue;

    if (S_ISDIR(st.st_mode)) {
      walk_dir(path, ws);
    } else if (S_ISREG(st.st_mode)) {
      ws->cb(path, ws->userdata);
    }
  }
  closedir(d);
}

/*
 * State threaded through the status walk.
 */
struct status_ctx {
  struct index *head_idx;   /* index of HEAD commit's tree (may be NULL) */
  struct index *stage_idx;  /* current staging index */
  int           has_head;
};

/*
 * Build an in-memory "index" from a tree SHA — used to compare
 * staged content against the last commit.
 */
static int tree_to_index(const struct sha1 *tree_sha, struct index *out)
{
  char  *type = NULL;
  uint8_t *data = NULL;
  size_t   len  = 0;

  if (object_read(tree_sha, &type, &data, &len) != 0)
    return -1;

  if (strcmp(type, OBJ_TREE) != 0) {
    free(type);
    free(data);
    return -1;
  }
  free(type);

  /*
   * Parse tree entries: "<mode> <name>\0<20-byte SHA-1>"
   */
  size_t off = 0;
  while (off < len) {
    /* mode */
    uint8_t *sp = memchr(data + off, ' ', len - off);
    if (!sp) break;
    *sp = '\0';
    uint32_t mode = (uint32_t)strtoul((char *)data + off, NULL, 8);
    off = (size_t)(sp - data) + 1;

    /* name */
    uint8_t *nul = memchr(data + off, 0, len - off);
    if (!nul) break;
    char *name = (char *)(data + off);
    off = (size_t)(nul - data) + 1;

    /* 20-byte SHA-1 */
    if (off + SHA1_BIN_LEN > len) break;

    if (out->count >= out->cap) {
      size_t new_cap = out->cap * 2;
      struct index_entry *tmp = realloc(out->entries,
                                        new_cap * sizeof(*out->entries));
      if (!tmp) {
        free(data);
        return -1;
      }
      out->entries = tmp;
      out->cap     = new_cap;
    }

    struct index_entry *e = &out->entries[out->count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->path, name, MAX_PATH - 1);
    e->mode = mode;
    memcpy(e->sha.bytes, data + off, SHA1_BIN_LEN);
    for (int i = 0; i < SHA1_BIN_LEN; i++)
      snprintf(e->sha.hex + i*2, 3, "%02x", e->sha.bytes[i]);
    e->sha.hex[SHA1_HEX_LEN] = '\0';

    off += SHA1_BIN_LEN;
  }

  free(data);
  return 0;
}

int cmd_status(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }

  struct index stage_idx;
  if (index_init(&stage_idx) != 0) {
    fprintf(stderr, "aigit: out of memory\n");
    return 1;
  }
  if (index_read(&stage_idx) != 0) {
    fprintf(stderr, "aigit: failed to read index\n");
    index_free(&stage_idx);
    return 1;
  }

  /* Try to load the committed tree for HEAD */
  struct index head_idx;
  int has_head = 0;
  index_init(&head_idx);

  if (refs_head_exists()) {
    struct sha1 head_sha;
    struct commit head_commit;
    if (refs_resolve_head(&head_sha) == 0 &&
        object_read_commit(&head_sha, &head_commit) == 0) {
      tree_to_index(&head_commit.tree, &head_idx);
      has_head = 1;
    }
  }

  char branch[256] = "main";
  refs_read_head(branch, sizeof(branch));
  printf("On branch %s\n\n", branch);

  /* --- Changes staged for commit ---------------------------------------- */
  int staged_count = 0;
  for (size_t i = 0; i < stage_idx.count; i++) {
    const char *path = stage_idx.entries[i].path;
    int is_new = 1;

    if (has_head) {
      struct index_entry *he = index_find(&head_idx, path);
      if (he) {
        is_new = 0;
        if (strcmp(he->sha.hex, stage_idx.entries[i].sha.hex) != 0) {
          if (staged_count == 0)
            printf("Changes to be committed:\n");
          printf("  modified: %s\n", path);
          staged_count++;
        }
        /* else: unchanged, skip */
      }
    }

    if (is_new) {
      if (staged_count == 0)
        printf("Changes to be committed:\n");
      printf("  new file: %s\n", path);
      staged_count++;
    }
  }

  /* Detect files deleted from stage vs HEAD */
  if (has_head) {
    for (size_t i = 0; i < head_idx.count; i++) {
      const char *path = head_idx.entries[i].path;
      if (!index_find(&stage_idx, path)) {
        if (staged_count == 0)
          printf("Changes to be committed:\n");
        printf("  deleted:  %s\n", path);
        staged_count++;
      }
    }
  }

  if (staged_count == 0)
    printf("Nothing to commit, working tree clean\n");
  else
    printf("\n");

  /* --- Changes not staged for commit ------------------------------------- */
  int unstaged_count = 0;
  for (size_t i = 0; i < stage_idx.count; i++) {
    /* Skip gitlinks (submodules) */
    if ((stage_idx.entries[i].mode & 0170000) == 0160000)
      continue;
    const char *path = stage_idx.entries[i].path;
    struct stat st;
    if (stat(path, &st) != 0) {
      if (unstaged_count == 0)
        printf("Changes not staged for commit:\n");
      printf("  deleted:  %s\n", path);
      unstaged_count++;
      continue;
    }
    struct sha1 disk_sha;
    if (object_hash_file(path, &disk_sha) == 0) {
      if (strcmp(disk_sha.hex, stage_idx.entries[i].sha.hex) != 0) {
        if (unstaged_count == 0)
          printf("Changes not staged for commit:\n");
        printf("  modified: %s\n", path);
        unstaged_count++;
      }
    }
  }
  if (unstaged_count > 0)
    printf("\n");

  /* --- Untracked files --------------------------------------------------- */
  /*
   * Collect all regular files in the working tree, then emit those
   * not present in the staging index.
   */
  struct {
    char paths[MAX_ENTRIES][MAX_PATH];
    int  count;
  } *wt = calloc(1, sizeof(*wt));
  if (!wt) {
    index_free(&stage_idx);
    index_free(&head_idx);
    return 1;
  }

  void collect_file(const char *path, void *ud) {
    typeof(wt) w = ud;
    if (w->count < MAX_ENTRIES)
      strncpy(w->paths[w->count++], path, MAX_PATH - 1);
  }

  struct walk_state ws = { .cb = collect_file, .userdata = wt };
  walk_dir(".", &ws);

  int untracked_count = 0;
  for (int i = 0; i < wt->count; i++) {
    if (!index_find(&stage_idx, wt->paths[i])) {
      if (untracked_count == 0)
        printf("Untracked files:\n");
      printf("  %s\n", wt->paths[i]);
      untracked_count++;
    }
  }

  free(wt);
  index_free(&stage_idx);
  index_free(&head_idx);
  return 0;
}
