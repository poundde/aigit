#ifndef AIGIT_H
#define AIGIT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>

#define GIT_DIR        ".git"
#define OBJECTS_DIR    ".git/objects"
#define REFS_DIR       ".git/refs"
#define HEADS_DIR      ".git/refs/heads"
#define HEAD_FILE      ".git/HEAD"
#define INDEX_FILE        ".git/index"
#define LOCAL_CONFIG_FILE ".git/config"

#define SHA1_HEX_LEN   40
#define SHA1_BIN_LEN   20
#define SHA1_STR_SIZE  (SHA1_HEX_LEN + 1)

#define INDEX_MAGIC    0x44495243  /* "DIRC" */

#define CONFIG_ANY     0
#define CONFIG_GLOBAL  1
#define CONFIG_LOCAL   2
#define INDEX_VERSION  2

#define OBJ_BLOB       "blob"
#define OBJ_TREE       "tree"
#define OBJ_COMMIT     "commit"

#define MAX_PATH       4096
#define MAX_MSG        4096
#define MAX_ENTRIES    65536

/*
 * A SHA-1 digest stored as raw bytes plus a NUL-terminated hex string
 * for convenience — we keep both to avoid repeated hex encoding.
 */
struct sha1 {
  uint8_t  bytes[SHA1_BIN_LEN];
  char     hex[SHA1_STR_SIZE];
};

/*
 * One entry in the staging index.  Mirrors git's index entry format
 * closely enough that git itself can read the result.
 */
struct index_entry {
  uint32_t ctime_sec;
  uint32_t ctime_nsec;
  uint32_t mtime_sec;
  uint32_t mtime_nsec;
  uint32_t dev;
  uint32_t ino;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint32_t size;
  struct sha1 sha;
  uint16_t flags;
  char     path[MAX_PATH];
};

/*
 * The full in-memory index — a flat array of entries plus the count.
 * Entries are kept sorted by path to match git's expectations.
 */
struct index {
  struct index_entry *entries;
  size_t              count;
  size_t              cap;
};

/*
 * A parsed commit object — the fields we care about for log display.
 */
struct commit {
  struct sha1  sha;
  struct sha1  tree;
  struct sha1  parent;       /* zeroed if root commit */
  int          has_parent;
  char         author[256];
  char         committer[256];
  int64_t      author_time;
  int64_t      commit_time;
  char         message[MAX_MSG];
};

/*
 * A node in the commit graph used by `log`.
 */
struct commit_node {
  struct commit        commit;
  struct commit_node  *parent;
};

/* --- object.c ----------------------------------------------------------- */
int  object_hash_file(const char *path, struct sha1 *out);
int  object_write_blob(const char *path, struct sha1 *out);
int  object_write_tree(struct index *idx, struct sha1 *out);
int  object_write_commit(const struct sha1 *tree,
                         const struct sha1 *parent, int has_parent,
                         const char *author, const char *committer,
                         int64_t when, const char *message,
                         struct sha1 *out);
int  object_read(const struct sha1 *sha, char **type_out,
                 uint8_t **data_out, size_t *len_out);
int  object_read_commit(const struct sha1 *sha, struct commit *out);

/* --- index.c ------------------------------------------------------------ */
int  index_init(struct index *idx);
void index_free(struct index *idx);
int  index_read(struct index *idx);
int  index_write(const struct index *idx);
int  index_add(struct index *idx, const char *path);
struct index_entry *index_find(struct index *idx, const char *path);

/* --- refs.c ------------------------------------------------------------- */
int  refs_read_head(char *branch, size_t branch_len);
int  refs_read_ref(const char *refname, struct sha1 *out);
int  refs_write_ref(const char *refname, const struct sha1 *sha);
int  refs_resolve_head(struct sha1 *out);
int  refs_head_exists(void);

/* --- sha1.c ------------------------------------------------------------- */
void sha1_compute(const uint8_t *data, size_t len, struct sha1 *out);
void sha1_hex_to_bytes(const char *hex, uint8_t *bytes);
int  sha1_is_zero(const struct sha1 *sha);
void sha1_zero(struct sha1 *sha);

/* --- cmd_*.c ------------------------------------------------------------ */
int  cmd_init(int argc, char **argv);
int  cmd_add(int argc, char **argv);
int  cmd_commit(int argc, char **argv);
int  cmd_status(int argc, char **argv);
int  cmd_diff(int argc, char **argv);
int  cmd_log(int argc, char **argv);

/* --- ignore.c ----------------------------------------------------------- */

/*
 * A single compiled pattern from a .gitignore file.
 *
 * Patterns are stored as plain strings.  We support:
 *   - Leading '!' to negate (un-ignore) a pattern
 *   - Trailing '/' to match directories only
 *   - '*' and '?' glob wildcards (via fnmatch)
 *   - '**' to match across directory separators
 *   - A pattern containing '/' (other than trailing) is anchored to the
 *     directory that owns the .gitignore; otherwise it matches any component
 */
struct ignore_pattern {
  char  pattern[MAX_PATH];
  int   negate;
  int   dir_only;
  int   anchored;
  char  base_dir[MAX_PATH];
};

/*
 * A loaded set of ignore rules built by scanning .gitignore files from
 * the repo root down to the path being tested.  Rules from deeper
 * .gitignore files appear later in the array and win over shallower ones.
 */
struct ignore_list {
  struct ignore_pattern *patterns;
  size_t                 count;
  size_t                 cap;
};

int  ignore_list_init(struct ignore_list *il);
void ignore_list_free(struct ignore_list *il);
int  ignore_list_load_file(struct ignore_list *il,
                            const char *gitignore_path,
                            const char *base_dir);
int  ignore_list_load_dir(struct ignore_list *il, const char *dir);
int  ignore_is_ignored(const struct ignore_list *il,
                        const char *path, int is_dir);

/* --- config.c ----------------------------------------------------------- */
int  config_get(int scope, const char *dotkey, char *value, size_t value_len);
int  config_set(int scope, const char *dotkey, const char *value);
int  config_read_file(const char *path, const char *dotkey,
                      char *value, size_t value_len);
int  config_write_file(const char *path, const char *dotkey, const char *value);

/* --- util.c ------------------------------------------------------------- */
int   util_find_git_dir(void);
char *util_read_file(const char *path, size_t *len_out);
int   util_write_file(const char *path, const uint8_t *data, size_t len);
int   util_mkdir_p(const char *path);
void  util_die(const char *fmt, ...) __attribute__((noreturn, format(printf,1,2)));
void  util_warn(const char *fmt, ...) __attribute__((format(printf,1,2)));
int   util_is_tty(int fd);
char *util_get_identity(void);   /* "Name <email>" from env/config */

/* --- refs.c (branching additions) --------------------------------------- */
int  refs_write_head(const char *branch);
int  refs_list_branches(char ***names_out, size_t *count_out);
void refs_list_free(char **names, size_t count);
int  refs_delete_ref(const char *refname);

/* --- object.c (checkout additions) -------------------------------------- */
int  object_restore_tree(const struct sha1 *tree_sha, const char *prefix);

/* --- cmd_*.c (branching additions) -------------------------------------- */
int  cmd_branch(int argc, char **argv);
int  cmd_checkout(int argc, char **argv);
int  cmd_config(int argc, char **argv);
/* --- cmd_remote / cmd_push / cmd_pull ----------------------------------- */
int  cmd_remote(int argc, char **argv);
int  cmd_push(int argc, char **argv);
int  cmd_pull(int argc, char **argv);

/* --- packfile.c --------------------------------------------------------- */
int  packfile_read(const struct sha1 *sha, char **type_out,
                   uint8_t **data_out, size_t *len_out);

#endif /* AIGIT_H */
/* Sentinel: branching additions below — do not duplicate */
