#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include "aigit.h"

/*
 * Config file format — a strict subset of git's INI dialect:
 *
 *   [section]
 *       key = value
 *
 * Blank lines and lines starting with '#' or ';' are ignored.
 * Section headers are "[section]" or "[section "subsection"]".
 * Keys are dot-separated when accessed: "user.name", "user.email".
 *
 * We store everything as flat "section.key = value" lines internally
 * but write proper INI sections on disk so git can read the file too.
 */

#define CONFIG_LINE_MAX  1024

/*
 * Return the path to the global config file (~/.aigitconfig).
 * Writes into buf[buflen].  Returns buf on success, NULL on failure.
 */
static char *global_config_path(char *buf, size_t buflen)
{
  const char *home = getenv("HOME");
  if (!home) {
    struct passwd *pw = getpwuid(getuid());
    if (pw) home = pw->pw_dir;
  }
  if (!home)
    return NULL;
  snprintf(buf, buflen, "%s/.aigitconfig", home);
  return buf;
}

/*
 * Split a dotted key like "user.name" into section="user", key="name".
 * Returns -1 if the key has no dot or is malformed.
 */
static int split_key(const char *dotkey,
                      char *section, size_t sec_len,
                      char *key,     size_t key_len)
{
  const char *dot = strchr(dotkey, '.');
  if (!dot || dot == dotkey || dot[1] == '\0')
    return -1;

  size_t slen = (size_t)(dot - dotkey);
  if (slen >= sec_len)
    return -1;
  memcpy(section, dotkey, slen);
  section[slen] = '\0';

  size_t klen = strlen(dot + 1);
  if (klen >= key_len)
    return -1;
  memcpy(key, dot + 1, klen + 1);
  return 0;
}

/*
 * Read the value for `dotkey` from the config file at `path`.
 * Writes result into value[value_len].  Returns 0 on success, -1 if not found.
 */
int config_read_file(const char *path, const char *dotkey,
                     char *value, size_t value_len)
{
  char section[128], key[128];
  if (split_key(dotkey, section, sizeof(section), key, sizeof(key)) != 0)
    return -1;

  size_t flen;
  char *buf = util_read_file(path, &flen);
  if (!buf)
    return -1;

  char cur_section[128] = "";
  int  found = 0;
  char *p = buf, *end = buf + flen;

  while (p < end) {
    char *nl = memchr(p, '\n', (size_t)(end - p));
    size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);

    char line[CONFIG_LINE_MAX];
    if (llen >= CONFIG_LINE_MAX) llen = CONFIG_LINE_MAX - 1;
    memcpy(line, p, llen);
    /* strip trailing CR */
    while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == ' '))
      llen--;
    line[llen] = '\0';

    p = nl ? nl + 1 : end;

    /* skip blank lines and comments */
    char *trim = line;
    while (*trim == ' ' || *trim == '\t') trim++;
    if (*trim == '\0' || *trim == '#' || *trim == ';')
      continue;

    /* section header: [section] or [section "subsection"] */
    if (*trim == '[') {
      char *close = strchr(trim, ']');
      if (!close) continue;
      *close = '\0';
      trim++;  /* skip '[' */
      /* strip subsection for simplicity */
      char *space = strchr(trim, ' ');
      if (space) *space = '\0';
      /* lowercase the section name */
      for (char *q = trim; *q; q++)
        if (*q >= 'A' && *q <= 'Z') *q |= 0x20;
      strncpy(cur_section, trim, sizeof(cur_section) - 1);
      continue;
    }

    /* key = value */
    char *eq = strchr(trim, '=');
    if (!eq) continue;
    *eq = '\0';
    char *k = trim;
    char *v = eq + 1;

    /* strip trailing whitespace from key */
    char *ke = k + strlen(k) - 1;
    while (ke >= k && (*ke == ' ' || *ke == '\t')) *ke-- = '\0';

    /* strip leading whitespace from value */
    while (*v == ' ' || *v == '\t') v++;

    /* lowercase the key name */
    for (char *q = k; *q; q++)
      if (*q >= 'A' && *q <= 'Z') *q |= 0x20;

    if (strcmp(cur_section, section) == 0 && strcmp(k, key) == 0) {
      strncpy(value, v, value_len - 1);
      value[value_len - 1] = '\0';
      found = 1;
      /* don't break — last matching entry wins */
    }
  }

  free(buf);
  return found ? 0 : -1;
}

/*
 * Write (or overwrite) `dotkey = value` in the config file at `path`.
 *
 * Strategy: read the whole file, find the right section and key, replace
 * or append.  We rewrite the entire file atomically.
 */
int config_write_file(const char *path, const char *dotkey, const char *value)
{
  char section[128], key[128];
  if (split_key(dotkey, section, sizeof(section), key, sizeof(key)) != 0)
    return -1;

  /* Read existing content (may not exist yet) */
  size_t flen = 0;
  char *existing = util_read_file(path, &flen);
  /* existing == NULL is fine — new file */

  /*
   * Rebuild the file content, inserting or updating the key.
   *
   * We do a line-by-line pass, tracking whether we are inside the target
   * section and whether we have already written the key.
   */
  size_t out_cap = flen + 256;
  char *out = malloc(out_cap);
  if (!out) { free(existing); return -1; }
  size_t out_len = 0;

#define EMIT(str) do { \
    size_t _l = strlen(str); \
    if (out_len + _l + 1 >= out_cap) { \
      out_cap = (out_cap + _l) * 2; \
      char *_t = realloc(out, out_cap); \
      if (!_t) { free(out); free(existing); return -1; } \
      out = _t; \
    } \
    memcpy(out + out_len, str, _l); \
    out_len += _l; \
  } while (0)

  int in_target_section = 0;
  int key_written       = 0;

  char *p   = existing ? existing : "";
  char *end = p + flen;

  while (p < end) {
    char *nl   = memchr(p, '\n', (size_t)(end - p));
    size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);

    char line[CONFIG_LINE_MAX];
    if (llen >= CONFIG_LINE_MAX) llen = CONFIG_LINE_MAX - 1;
    memcpy(line, p, llen);
    while (llen > 0 && line[llen-1] == '\r') llen--;
    line[llen] = '\0';
    p = nl ? nl + 1 : end;

    char *trim = line;
    while (*trim == ' ' || *trim == '\t') trim++;

    /* Section header */
    if (*trim == '[') {
      /*
       * If we are leaving the target section without having written the key,
       * append it now before moving to the next section.
       */
      if (in_target_section && !key_written) {
        char entry[CONFIG_LINE_MAX];
        snprintf(entry, sizeof(entry), "\t%s = %s\n", key, value);
        EMIT(entry);
        key_written = 1;
      }

      char hdr[128];
      char *close = strchr(trim, ']');
      if (close) {
        size_t hl = (size_t)(close - trim - 1);
        if (hl >= sizeof(hdr)) hl = sizeof(hdr) - 1;
        memcpy(hdr, trim + 1, hl);
        hdr[hl] = '\0';
        /* strip subsection */
        char *sp = strchr(hdr, ' '); if (sp) *sp = '\0';
        for (char *q = hdr; *q; q++) if (*q >= 'A' && *q <= 'Z') *q |= 0x20;
        in_target_section = (strcmp(hdr, section) == 0);
      }

      EMIT(line); EMIT("\n");
      continue;
    }

    /* key = value line inside target section — replace if matches */
    if (in_target_section && !key_written) {
      char *eq = strchr(trim, '=');
      if (eq) {
        char k[128];
        size_t kl = (size_t)(eq - trim);
        while (kl > 0 && (trim[kl-1] == ' ' || trim[kl-1] == '\t')) kl--;
        if (kl >= sizeof(k)) kl = sizeof(k) - 1;
        memcpy(k, trim, kl); k[kl] = '\0';
        for (char *q = k; *q; q++) if (*q >= 'A' && *q <= 'Z') *q |= 0x20;

        if (strcmp(k, key) == 0) {
          char entry[CONFIG_LINE_MAX];
          snprintf(entry, sizeof(entry), "\t%s = %s\n", key, value);
          EMIT(entry);
          key_written = 1;
          continue;
        }
      }
    }

    EMIT(line); EMIT("\n");
  }

  /* If we finished the file still in the target section */
  if (in_target_section && !key_written) {
    char entry[CONFIG_LINE_MAX];
    snprintf(entry, sizeof(entry), "\t%s = %s\n", key, value);
    EMIT(entry);
    key_written = 1;
  }

  /* If the section didn't exist at all, append it */
  if (!key_written) {
    /* Add a blank line separator if the file is non-empty */
    if (out_len > 0 && out[out_len-1] != '\n') EMIT("\n");
    if (out_len > 0) EMIT("\n");

    char hdr[256];
    snprintf(hdr, sizeof(hdr), "[%s]\n", section);
    EMIT(hdr);

    char entry[CONFIG_LINE_MAX];
    snprintf(entry, sizeof(entry), "\t%s = %s\n", key, value);
    EMIT(entry);
  }

#undef EMIT

  free(existing);

  int rc = util_write_file(path, (uint8_t *)out, out_len);
  free(out);
  return rc;
}

/*
 * Read a key from either the local repo config or the global config.
 * Local takes priority over global.
 *
 * scope: CONFIG_LOCAL, CONFIG_GLOBAL, or CONFIG_ANY
 */
int config_get(int scope, const char *dotkey, char *value, size_t value_len)
{
  if (scope == CONFIG_LOCAL || scope == CONFIG_ANY) {
    if (config_read_file(LOCAL_CONFIG_FILE, dotkey, value, value_len) == 0)
      return 0;
  }
  if (scope == CONFIG_GLOBAL || scope == CONFIG_ANY) {
    char gpath[MAX_PATH];
    if (global_config_path(gpath, sizeof(gpath)))
      if (config_read_file(gpath, dotkey, value, value_len) == 0)
        return 0;
  }
  return -1;
}

int config_set(int scope, const char *dotkey, const char *value)
{
  if (scope == CONFIG_GLOBAL) {
    char gpath[MAX_PATH];
    if (!global_config_path(gpath, sizeof(gpath)))
      return -1;
    return config_write_file(gpath, dotkey, value);
  }
  /* CONFIG_LOCAL */
  return config_write_file(LOCAL_CONFIG_FILE, dotkey, value);
}
