#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include "aigit.h"

void util_die(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "aigit: fatal: ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}

void util_warn(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "aigit: warning: ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

/*
 * Walk up from cwd until we find a .git/ directory or hit the root.
 * chdir() into the work-tree root so all relative paths work uniformly.
 *
 * Returns 0 on success, -1 if no repository is found.
 */
int util_find_git_dir(void)
{
  char buf[MAX_PATH];
  struct stat st;

  for (int depth = 0; depth < 256; depth++) {
    if (stat(GIT_DIR, &st) == 0 && S_ISDIR(st.st_mode))
      return 0;
    if (getcwd(buf, sizeof(buf)) == NULL)
      return -1;
    if (strcmp(buf, "/") == 0)
      return -1;
    if (chdir("..") != 0)
      return -1;
  }
  return -1;
}

/*
 * Read an entire file into a malloc'd buffer.  Caller frees.
 * Appends a NUL byte so the result is safe to use as a C string.
 */
char *util_read_file(const char *path, size_t *len_out)
{
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return NULL;

  struct stat st;
  if (fstat(fd, &st) < 0) {
    close(fd);
    return NULL;
  }

  char *buf = malloc((size_t)st.st_size + 1);
  if (!buf) {
    close(fd);
    return NULL;
  }

  ssize_t n = read(fd, buf, (size_t)st.st_size);
  close(fd);
  if (n < 0) {
    free(buf);
    return NULL;
  }

  buf[n] = '\0';
  if (len_out)
    *len_out = (size_t)n;
  return buf;
}

/*
 * Atomically write data to a file: write to a temp file then rename.
 * Creates the file with 0644 permissions.
 */
int util_write_file(const char *path, const uint8_t *data, size_t len)
{
  char tmp[MAX_PATH];
  snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());

  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return -1;

  size_t written = 0;
  while (written < len) {
    ssize_t n = write(fd, data + written, len - written);
    if (n < 0) {
      close(fd);
      unlink(tmp);
      return -1;
    }
    written += (size_t)n;
  }

  if (close(fd) != 0) {
    unlink(tmp);
    return -1;
  }

  if (rename(tmp, path) != 0) {
    unlink(tmp);
    return -1;
  }
  return 0;
}

/*
 * Create all components of a directory path, ignoring EEXIST at each step.
 */
int util_mkdir_p(const char *path)
{
  char buf[MAX_PATH];
  size_t len = strlen(path);
  if (len >= MAX_PATH)
    return -1;

  memcpy(buf, path, len + 1);

  for (char *p = buf + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
      return -1;
    *p = '/';
  }

  if (mkdir(buf, 0755) != 0 && errno != EEXIST)
    return -1;

  return 0;
}

int util_is_tty(int fd)
{
  return isatty(fd);
}

/*
 * Return a "Name <email>" identity string for use in commit objects.
 * Checks GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL env vars first, then
 * falls back to the Unix username and a placeholder domain.
 *
 * Returns a malloc'd string; caller frees.
 */
char *util_get_identity(void)
{
  /*
   * Identity resolution order (first match wins):
   *   1. GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL environment variables
   *   2. user.name / user.email in .git/config  (local)
   *   3. user.name / user.email in ~/.aigitconfig  (global)
   *   4. Unix gecos / pw_name fallback
   */
  char cfg_name[256]  = "";
  char cfg_email[256] = "";
  config_get(CONFIG_ANY, "user.name",  cfg_name,  sizeof(cfg_name));
  config_get(CONFIG_ANY, "user.email", cfg_email, sizeof(cfg_email));

  const char *name  = getenv("GIT_AUTHOR_NAME");
  const char *email = getenv("GIT_AUTHOR_EMAIL");

  char fallback_name[256]  = "Unknown";
  char fallback_email[256] = "unknown@localhost";

  if (!name) {
    if (cfg_name[0]) {
      name = cfg_name;
    } else {
      struct passwd *pw = getpwuid(getuid());
      if (pw && pw->pw_gecos && pw->pw_gecos[0]) {
        strncpy(fallback_name, pw->pw_gecos, sizeof(fallback_name) - 1);
        char *comma = strchr(fallback_name, ',');
        if (comma) *comma = '\0';
      } else if (pw) {
        strncpy(fallback_name, pw->pw_name, sizeof(fallback_name) - 1);
      }
      name = fallback_name;
    }
  }
  if (!email) {
    if (cfg_email[0]) {
      email = cfg_email;
    } else {
      struct passwd *pw = getpwuid(getuid());
      if (pw) {
        snprintf(fallback_email, sizeof(fallback_email),
                 "%s@localhost", pw->pw_name);
      }
      email = fallback_email;
    }
  }

  char *result = NULL;
  if (asprintf(&result, "%s <%s>", name, email) < 0)
    return NULL;
  return result;
}
