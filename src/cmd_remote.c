#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "aigit.h"

/*
 * Remotes are stored in .git/config exactly as git stores them:
 *
 *   [remote "origin"]
 *       url = git@github.com:user/repo.git
 *       fetch = +refs/heads/STAR:refs/remotes/origin/STAR
 *
 * We reuse config_read_file / config_write_file for get/set operations,
 * but remote sections have a subsection (the name), so we handle them
 * with direct file manipulation for listing and deletion.
 *
 * `aigit remote add <name> <url>`
 * `aigit remote remove <name>`
 * `aigit remote`                    — list
 * `aigit remote -v`                 — list with URLs
 */

/*
 * Build the dotted key for a remote config entry, e.g.:
 *   remote_key("origin", "url") → "remote.origin.url"
 *
 * config_read/write_file handle two-level keys (section.key) only,
 * so for subsectioned remotes we use a specialised reader/writer below.
 */

/*
 * Read a remote URL from .git/config.
 * Scans for [remote "name"] then reads the url line.
 */
static int remote_read_url(const char *name, char *url, size_t url_len)
{
  size_t flen;
  char *buf = util_read_file(LOCAL_CONFIG_FILE, &flen);
  if (!buf)
    return -1;

  char target_header[256];
  snprintf(target_header, sizeof(target_header), "[remote \"%s\"]", name);

  char *p   = buf;
  char *end = buf + flen;
  int   in_section = 0;
  int   found = 0;

  while (p < end) {
    char *nl   = memchr(p, '\n', (size_t)(end - p));
    size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
    char line[1024];
    if (llen >= sizeof(line)) llen = sizeof(line) - 1;
    memcpy(line, p, llen);
    while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == ' ')) llen--;
    line[llen] = '\0';
    p = nl ? nl + 1 : end;

    char *trim = line;
    while (*trim == ' ' || *trim == '\t') trim++;

    if (*trim == '[') {
      if (in_section)
        break;  /* left the target section */
      in_section = (strncmp(trim, target_header, strlen(target_header)) == 0);
      continue;
    }

    if (!in_section)
      continue;

    char *eq = strchr(trim, '=');
    if (!eq) continue;
    *eq = '\0';
    char *k = trim, *v = eq + 1;
    while (*k == ' ' || *k == '\t') k++;
    char *ke = k + strlen(k) - 1;
    while (ke >= k && (*ke == ' ' || *ke == '\t')) *ke-- = '\0';
    while (*v == ' ' || *v == '\t') v++;

    if (strcmp(k, "url") == 0) {
      strncpy(url, v, url_len - 1);
      url[url_len - 1] = '\0';
      found = 1;
      break;
    }
  }

  free(buf);
  return found ? 0 : -1;
}

/*
 * List all remote names by scanning [remote "..."] headers in .git/config.
 */
static int remote_list_names(char ***names_out, size_t *count_out)
{
  *names_out = NULL;
  *count_out = 0;

  size_t flen;
  char *buf = util_read_file(LOCAL_CONFIG_FILE, &flen);
  if (!buf)
    return 0;  /* no config yet */

  size_t cap   = 8;
  size_t count = 0;
  char **names = malloc(cap * sizeof(char *));
  if (!names) { free(buf); return -1; }

  char *p = buf, *end = buf + flen;
  while (p < end) {
    char *nl   = memchr(p, '\n', (size_t)(end - p));
    size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
    char line[1024];
    if (llen >= sizeof(line)) llen = sizeof(line) - 1;
    memcpy(line, p, llen);
    while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == ' ')) llen--;
    line[llen] = '\0';
    p = nl ? nl + 1 : end;

    char *trim = line;
    while (*trim == ' ' || *trim == '\t') trim++;

    if (strncmp(trim, "[remote \"", 9) != 0) continue;

    char *name_start = trim + 9;
    char *name_end   = strchr(name_start, '"');
    if (!name_end) continue;

    size_t nlen = (size_t)(name_end - name_start);
    char *name = malloc(nlen + 1);
    if (!name) { refs_list_free(names, count); free(buf); return -1; }
    memcpy(name, name_start, nlen);
    name[nlen] = '\0';

    /* Dedup */
    int dup = 0;
    for (size_t i = 0; i < count; i++)
      if (strcmp(names[i], name) == 0) { dup = 1; break; }
    if (dup) { free(name); continue; }

    if (count >= cap) {
      cap *= 2;
      char **tmp = realloc(names, cap * sizeof(char *));
      if (!tmp) { free(name); refs_list_free(names, count); free(buf); return -1; }
      names = tmp;
    }
    names[count++] = name;
  }

  free(buf);
  *names_out = names;
  *count_out = count;
  return 0;
}

/*
 * Write a [remote "name"] section to .git/config.
 * Appends; does not check for duplicates (caller does that).
 */
static int remote_write(const char *name, const char *url)
{
  /* Read existing config */
  size_t flen = 0;
  char *existing = util_read_file(LOCAL_CONFIG_FILE, &flen);

  size_t add_len = strlen(name) + strlen(url) + 128;
  size_t out_cap = flen + add_len;
  char *out = malloc(out_cap);
  if (!out) { free(existing); return -1; }

  size_t out_len = 0;
  if (existing && flen > 0) {
    memcpy(out, existing, flen);
    out_len = flen;
    /* ensure trailing newline */
    if (out[out_len - 1] != '\n')
      out[out_len++] = '\n';
    out[out_len++] = '\n';
  }
  free(existing);

  int n = snprintf(out + out_len, out_cap - out_len,
                   "[remote \"%s\"]\n\turl = %s\n"
                   "\tfetch = +refs/heads/*:refs/remotes/%s/*\n",
                   name, url, name);
  if (n < 0 || (size_t)n >= out_cap - out_len) {
    free(out);
    return -1;
  }
  out_len += (size_t)n;

  int rc = util_write_file(LOCAL_CONFIG_FILE, (uint8_t *)out, out_len);
  free(out);
  return rc;
}

/*
 * Remove a [remote "name"] section from .git/config.
 * Drops all lines from the section header to the next section header.
 */
static int remote_remove_from_config(const char *name)
{
  size_t flen;
  char *buf = util_read_file(LOCAL_CONFIG_FILE, &flen);
  if (!buf)
    return -1;

  char target_header[256];
  snprintf(target_header, sizeof(target_header), "[remote \"%s\"]", name);

  size_t out_cap = flen + 1;
  char  *out     = malloc(out_cap);
  if (!out) { free(buf); return -1; }
  size_t out_len = 0;

  char *p = buf, *end = buf + flen;
  int   skip = 0;

  while (p < end) {
    char *nl   = memchr(p, '\n', (size_t)(end - p));
    size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
    char line[1024];
    if (llen >= sizeof(line)) llen = sizeof(line) - 1;
    memcpy(line, p, llen);
    while (llen > 0 && line[llen-1] == '\r') llen--;
    line[llen] = '\0';
    p = nl ? nl + 1 : end;

    char *trim = line;
    while (*trim == ' ' || *trim == '\t') trim++;

    if (*trim == '[') {
      if (strncmp(trim, target_header, strlen(target_header)) == 0) {
        skip = 1;
        continue;
      }
      skip = 0;
    }

    if (skip) continue;

    /* Append the line */
    size_t need = llen + 2;
    if (out_len + need >= out_cap) {
      out_cap = (out_cap + need) * 2;
      char *tmp = realloc(out, out_cap);
      if (!tmp) { free(out); free(buf); return -1; }
      out = tmp;
    }
    memcpy(out + out_len, line, llen);
    out_len += llen;
    out[out_len++] = '\n';
  }

  free(buf);
  int rc = util_write_file(LOCAL_CONFIG_FILE, (uint8_t *)out, out_len);
  free(out);
  return rc;
}

int cmd_remote(int argc, char **argv)
{
  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }

  int verbose = 0;

  /* `aigit remote` or `aigit remote -v` — list */
  if (argc == 1 || (argc == 2 && strcmp(argv[1], "-v") == 0)) {
    if (argc == 2) verbose = 1;

    char **names = NULL;
    size_t count = 0;
    if (remote_list_names(&names, &count) != 0) {
      fprintf(stderr, "aigit: failed to read config\n");
      return 1;
    }
    for (size_t i = 0; i < count; i++) {
      if (verbose) {
        char url[MAX_PATH] = "(unknown)";
        remote_read_url(names[i], url, sizeof(url));
        printf("%s\t%s\n", names[i], url);
      } else {
        printf("%s\n", names[i]);
      }
    }
    refs_list_free(names, count);
    return 0;
  }

  /* `aigit remote add <name> <url>` */
  if (strcmp(argv[1], "add") == 0) {
    if (argc < 4) {
      fprintf(stderr, "usage: aigit remote add <name> <url>\n");
      return 1;
    }
    const char *name = argv[2];
    const char *url  = argv[3];

    char existing_url[MAX_PATH];
    if (remote_read_url(name, existing_url, sizeof(existing_url)) == 0) {
      fprintf(stderr, "aigit: remote '%s' already exists\n", name);
      return 1;
    }

    if (remote_write(name, url) != 0) {
      fprintf(stderr, "aigit: failed to add remote '%s'\n", name);
      return 1;
    }
    printf("Remote '%s' added (%s)\n", name, url);
    return 0;
  }

  /* `aigit remote remove <name>` */
  if (strcmp(argv[1], "remove") == 0 || strcmp(argv[1], "rm") == 0) {
    if (argc < 3) {
      fprintf(stderr, "usage: aigit remote remove <name>\n");
      return 1;
    }
    const char *name = argv[2];

    char url[MAX_PATH];
    if (remote_read_url(name, url, sizeof(url)) != 0) {
      fprintf(stderr, "aigit: remote '%s' not found\n", name);
      return 1;
    }

    if (remote_remove_from_config(name) != 0) {
      fprintf(stderr, "aigit: failed to remove remote '%s'\n", name);
      return 1;
    }
    printf("Remote '%s' removed\n", name);
    return 0;
  }

  fprintf(stderr, "aigit remote: unknown subcommand '%s'\n", argv[1]);
  fprintf(stderr, "usage: aigit remote [-v]\n");
  fprintf(stderr, "       aigit remote add <name> <url>\n");
  fprintf(stderr, "       aigit remote remove <name>\n");
  return 1;
}
