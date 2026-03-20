#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "aigit.h"

/*
 * Very simple line-oriented data structure used for Myers diff.
 */
struct line_array {
  char  **lines;
  size_t  count;
};

static void line_array_free(struct line_array *la)
{
  for (size_t i = 0; i < la->count; i++)
    free(la->lines[i]);
  free(la->lines);
  la->lines = NULL;
  la->count = 0;
}

/*
 * Split a buffer into a line array.  Each line includes its trailing
 * newline (if present).
 */
static int split_lines(const char *buf, size_t len, struct line_array *out)
{
  out->lines = NULL;
  out->count = 0;

  if (len == 0)
    return 0;

  size_t cap = 64;
  out->lines = malloc(cap * sizeof(char *));
  if (!out->lines)
    return -1;

  size_t start = 0;
  for (size_t i = 0; i <= len; i++) {
    if (i == len || buf[i] == '\n') {
      size_t end = (i < len) ? i + 1 : len;  /* include newline */
      size_t llen = end - start;
      char *line = malloc(llen + 1);
      if (!line) {
        line_array_free(out);
        return -1;
      }
      memcpy(line, buf + start, llen);
      line[llen] = '\0';

      if (out->count >= cap) {
        cap *= 2;
        char **tmp = realloc(out->lines, cap * sizeof(char *));
        if (!tmp) {
          free(line);
          line_array_free(out);
          return -1;
        }
        out->lines = tmp;
      }
      out->lines[out->count++] = line;
      start = end;
    }
  }
  return 0;
}

/*
 * Extremely simple O(ND) unified diff — we emit hunks of context=3.
 *
 * We use the classic patience-like fallback: compute an LCS edit script
 * using a simple DP table.  For files up to ~500 lines this is fine.
 * For larger files we fall back to emitting the whole file as changed.
 */
#define MAX_DIFF_LINES  2048

static void emit_unified_diff(const char *a_label,
                               const char *b_label,
                               const struct line_array *a,
                               const struct line_array *b)
{
  size_t m = a->count;
  size_t n = b->count;

  if (m > MAX_DIFF_LINES || n > MAX_DIFF_LINES) {
    printf("--- %s\n+++ %s\n", a_label, b_label);
    printf("@@ -1,%zu +1,%zu @@\n", m, n);
    for (size_t i = 0; i < m; i++) printf("-%s", a->lines[i]);
    for (size_t i = 0; i < n; i++) printf("+%s", b->lines[i]);
    return;
  }

  /*
   * dp[i][j] = length of LCS of a[0..i-1], b[0..j-1]
   * We allocate a flat (m+1)*(n+1) table.
   */
  size_t *dp = calloc((m+1) * (n+1), sizeof(size_t));
  if (!dp) {
    fprintf(stderr, "aigit: out of memory for diff\n");
    return;
  }

  for (size_t i = 1; i <= m; i++) {
    for (size_t j = 1; j <= n; j++) {
      if (strcmp(a->lines[i-1], b->lines[j-1]) == 0)
        dp[i*(n+1)+j] = dp[(i-1)*(n+1)+(j-1)] + 1;
      else
        dp[i*(n+1)+j] = dp[(i-1)*(n+1)+j] > dp[i*(n+1)+(j-1)]
                       ? dp[(i-1)*(n+1)+j]
                       : dp[i*(n+1)+(j-1)];
    }
  }

  /*
   * Reconstruct the edit script via backtracking.
   * ops: 0 = keep, 1 = delete (from a), 2 = insert (into b)
   */
  size_t max_ops = m + n + 4;
  char   *ops   = malloc(max_ops);
  size_t *ai    = malloc(max_ops * sizeof(size_t));
  size_t *bi    = malloc(max_ops * sizeof(size_t));
  if (!ops || !ai || !bi) {
    free(dp); free(ops); free(ai); free(bi);
    return;
  }

  size_t num_ops = 0;
  size_t ci = m, cj = n;
  while (ci > 0 || cj > 0) {
    if (ci > 0 && cj > 0 &&
        strcmp(a->lines[ci-1], b->lines[cj-1]) == 0) {
      ops[num_ops] = 0;
      ai[num_ops]  = ci - 1;
      bi[num_ops]  = cj - 1;
      num_ops++;
      ci--; cj--;
    } else if (cj > 0 &&
               (ci == 0 || dp[ci*(n+1)+cj] == dp[ci*(n+1)+(cj-1)])) {
      ops[num_ops] = 2;
      ai[num_ops]  = ci;
      bi[num_ops]  = cj - 1;
      num_ops++;
      cj--;
    } else {
      ops[num_ops] = 1;
      ai[num_ops]  = ci - 1;
      bi[num_ops]  = cj;
      num_ops++;
      ci--;
    }
  }
  free(dp);

  /* Reverse the ops so they run forward */
  for (size_t i = 0; i < num_ops / 2; i++) {
    char tc = ops[i]; ops[i] = ops[num_ops-1-i]; ops[num_ops-1-i] = tc;
    size_t ta = ai[i];  ai[i] = ai[num_ops-1-i];  ai[num_ops-1-i] = ta;
    size_t tb = bi[i];  bi[i] = bi[num_ops-1-i];  bi[num_ops-1-i] = tb;
  }

  /* Find hunks (regions with changes, surrounded by up to 3 context lines) */
  int    printed_header = 0;
  size_t ctx = 3;

  for (size_t op = 0; op < num_ops; ) {
    /* Scan ahead to find the next change */
    size_t change_start = op;
    while (change_start < num_ops && ops[change_start] == 0)
      change_start++;

    if (change_start >= num_ops)
      break;

    /* Find end of this cluster of changes */
    size_t change_end = change_start;
    while (change_end < num_ops) {
      if (ops[change_end] != 0) {
        change_end++;
        continue;
      }
      /* Check if next change is within 2*ctx lines */
      size_t next_change = change_end;
      while (next_change < num_ops && ops[next_change] == 0)
        next_change++;
      if (next_change < num_ops && next_change - change_end <= 2 * ctx) {
        change_end = next_change;
      } else {
        break;
      }
    }

    /* Hunk spans [hunk_start, hunk_end) in the ops array */
    size_t hunk_start = change_start > ctx ? change_start - ctx : 0;
    size_t hunk_end   = change_end + ctx < num_ops
                       ? change_end + ctx : num_ops;

    if (!printed_header) {
      printf("--- %s\n+++ %s\n", a_label, b_label);
      printed_header = 1;
    }

    /* Count lines for the @@ header */
    size_t a_start = ai[hunk_start] + 1;
    size_t b_start = bi[hunk_start] + 1;
    size_t a_len = 0, b_len = 0;
    for (size_t k = hunk_start; k < hunk_end; k++) {
      if (ops[k] != 2) a_len++;
      if (ops[k] != 1) b_len++;
    }

    printf("@@ -%zu,%zu +%zu,%zu @@\n",
           a_start, a_len, b_start, b_len);

    for (size_t k = hunk_start; k < hunk_end; k++) {
      if (ops[k] == 0)
        printf(" %s", a->lines[ai[k]]);
      else if (ops[k] == 1)
        printf("-%s", a->lines[ai[k]]);
      else
        printf("+%s", b->lines[bi[k]]);
    }

    op = hunk_end;
  }

  free(ops);
  free(ai);
  free(bi);
}

/*
 * `aigit diff`
 *
 * Compares each staged file against the on-disk version and emits a
 * unified diff.
 */
int cmd_diff(int argc, char **argv)
{
  (void)argc;
  (void)argv;

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

  for (size_t i = 0; i < idx.count; i++) {
    const struct index_entry *e = &idx.entries[i];

    /* Skip gitlinks (submodules) — mode 0160000 */
    if ((e->mode & 0170000) == 0160000)
      continue;

    struct sha1 disk_sha;
    if (object_hash_file(e->path, &disk_sha) != 0) {
      printf("deleted: %s\n", e->path);
      continue;
    }

    if (strcmp(disk_sha.hex, e->sha.hex) == 0)
      continue;  /* not modified */

    /* Read the staged version from the object store */
    char   *type  = NULL;
    uint8_t *staged_data = NULL;
    size_t   staged_len  = 0;
    if (object_read(&e->sha, &type, &staged_data, &staged_len) != 0) {
      fprintf(stderr, "aigit: cannot read object %s\n", e->sha.hex);
      continue;
    }
    free(type);

    /* Read the disk version */
    size_t disk_len;
    char  *disk_data = util_read_file(e->path, &disk_len);
    if (!disk_data) {
      free(staged_data);
      continue;
    }

    struct line_array a_lines, b_lines;
    if (split_lines((char *)staged_data, staged_len, &a_lines) != 0 ||
        split_lines(disk_data, disk_len, &b_lines) != 0) {
      free(staged_data);
      free(disk_data);
      continue;
    }

    char a_label[MAX_PATH + 4];
    char b_label[MAX_PATH + 4];
    snprintf(a_label, sizeof(a_label), "a/%s", e->path);
    snprintf(b_label, sizeof(b_label), "b/%s", e->path);

    emit_unified_diff(a_label, b_label, &a_lines, &b_lines);

    line_array_free(&a_lines);
    line_array_free(&b_lines);
    free(staged_data);
    free(disk_data);
  }

  index_free(&idx);
  return 0;
}
