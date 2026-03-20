#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "aigit.h"
#include "transport.h"

/* -------------------------------------------------------------------------
 * URL parsing
 * ------------------------------------------------------------------------- */

int url_parse(const char *url, struct remote_url *out)
{
  memset(out, 0, sizeof(*out));
  out->port = -1;

  /*
   * SCP-style SSH:  git@github.com:user/repo.git
   * We detect this by the absence of "://" and the presence of ":".
   * The colon must come before any slash.
   */
  if (strstr(url, "://") == NULL) {
    const char *colon = strchr(url, ':');
    const char *slash = strchr(url, '/');
    if (colon && (!slash || colon < slash)) {
      /* SCP-style: [user@]host:path */
      strncpy(out->scheme, "ssh", sizeof(out->scheme) - 1);

      const char *at = strchr(url, '@');
      const char *host_start;
      if (at && at < colon) {
        size_t ulen = (size_t)(at - url);
        if (ulen >= sizeof(out->user)) ulen = sizeof(out->user) - 1;
        memcpy(out->user, url, ulen);
        out->user[ulen] = '\0';
        host_start = at + 1;
      } else {
        host_start = url;
      }

      size_t hlen = (size_t)(colon - host_start);
      if (hlen >= sizeof(out->host)) hlen = sizeof(out->host) - 1;
      memcpy(out->host, host_start, hlen);
      out->host[hlen] = '\0';

      const char *path_start = colon + 1;
      strncpy(out->path, path_start, sizeof(out->path) - 1);
      out->port = 22;
      return 0;
    }
    return -1;
  }

  /* Scheme://[user@]host[:port]/path */
  const char *scheme_end = strstr(url, "://");
  size_t slen = (size_t)(scheme_end - url);
  if (slen >= sizeof(out->scheme)) return -1;
  memcpy(out->scheme, url, slen);
  out->scheme[slen] = '\0';
  for (char *p = out->scheme; *p; p++)
    if (*p >= 'A' && *p <= 'Z') *p |= 0x20;

  const char *rest = scheme_end + 3;  /* after "://" */

  /* Default ports */
  if (strcmp(out->scheme, "https") == 0 || strcmp(out->scheme, "git+https") == 0)
    out->port = 443;
  else if (strcmp(out->scheme, "http") == 0 || strcmp(out->scheme, "git+http") == 0)
    out->port = 80;
  else if (strcmp(out->scheme, "ssh") == 0 || strcmp(out->scheme, "git+ssh") == 0 ||
           strcmp(out->scheme, "git") == 0)
    out->port = 22;

  /* Optional user@ */
  const char *at = strchr(rest, '@');
  const char *slash = strchr(rest, '/');
  if (at && (!slash || at < slash)) {
    size_t ulen = (size_t)(at - rest);
    if (ulen >= sizeof(out->user)) ulen = sizeof(out->user) - 1;
    memcpy(out->user, rest, ulen);
    out->user[ulen] = '\0';
    rest = at + 1;
  }

  /* host[:port] */
  slash = strchr(rest, '/');
  const char *host_end = slash ? slash : rest + strlen(rest);
  const char *port_colon = memchr(rest, ':', (size_t)(host_end - rest));
  if (port_colon) {
    size_t hlen = (size_t)(port_colon - rest);
    if (hlen >= sizeof(out->host)) hlen = sizeof(out->host) - 1;
    memcpy(out->host, rest, hlen);
    out->host[hlen] = '\0';
    out->port = atoi(port_colon + 1);
  } else {
    size_t hlen = (size_t)(host_end - rest);
    if (hlen >= sizeof(out->host)) hlen = sizeof(out->host) - 1;
    memcpy(out->host, rest, hlen);
    out->host[hlen] = '\0';
  }

  /* path */
  if (slash)
    strncpy(out->path, slash, sizeof(out->path) - 1);
  else
    strncpy(out->path, "/", sizeof(out->path) - 1);

  return 0;
}

/* -------------------------------------------------------------------------
 * TCP connection helper
 * ------------------------------------------------------------------------- */

static int tcp_connect(const char *host, int port) __attribute__((unused));
static int tcp_connect(const char *host, int port)
{
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  struct addrinfo hints, *res, *rp;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host, port_str, &hints, &res) != 0)
    return -1;

  int fd = -1;
  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) continue;
    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}


/*
 * Read the HTTP body from fd, decoding chunked transfer encoding if needed.
 * Returns malloc'd buffer with full body, sets *body_len.
 * Also handles non-chunked (just reads until EOF).
 */
static uint8_t *http_read_body(int fd, const char *hdrbuf, size_t *body_len)
  __attribute__((unused));
static uint8_t *http_read_body(int fd, const char *hdrbuf, size_t *body_len)
{
  int is_chunked = (strcasestr(hdrbuf, "Transfer-Encoding: chunked") != NULL);
  size_t content_len = 0;
  const char *cl = strcasestr(hdrbuf, "Content-Length:");
  if (cl) content_len = (size_t)atol(cl + 15);

  size_t cap = content_len ? content_len + 1 : (1 << 16);
  uint8_t *body = malloc(cap);
  if (!body) return NULL;
  size_t len = 0;

  if (is_chunked) {
    /* Chunked: each chunk is hex-size CRLF data CRLF */
    char line[32];
    while (1) {
      /* Read chunk size line */
      size_t li = 0;
      while (li < sizeof(line) - 1) {
        char ch;
        ssize_t r = read(fd, &ch, 1);
        if (r <= 0) goto done;
        if (ch == '\n') break;
        if (ch != '\r') line[li++] = ch;
      }
      line[li] = '\0';
      size_t chunk_sz = (size_t)strtoul(line, NULL, 16);
      if (chunk_sz == 0) break;  /* final chunk */

      if (len + chunk_sz > cap) {
        cap = (cap + chunk_sz) * 2;
        uint8_t *tmp = realloc(body, cap);
        if (!tmp) { free(body); return NULL; }
        body = tmp;
      }
      /* Read chunk data */
      size_t done2 = 0;
      while (done2 < chunk_sz) {
        ssize_t r = read(fd, body + len + done2, chunk_sz - done2);
        if (r <= 0) goto done;
        done2 += (size_t)r;
      }
      len += chunk_sz;
      /* Consume trailing CRLF */
      char crlf[2];
      ssize_t r2 = read(fd, crlf, 2); (void)r2;
    }
  } else {
    /* Read until content-length or EOF */
    size_t to_read = content_len ? content_len : SIZE_MAX;
    while (len < to_read) {
      if (len >= cap) {
        cap *= 2;
        uint8_t *tmp = realloc(body, cap);
        if (!tmp) { free(body); return NULL; }
        body = tmp;
      }
      size_t want = cap - len;
      if (want > to_read - len) want = to_read - len;
      ssize_t r = read(fd, body + len, want);
      if (r <= 0) break;
      len += (size_t)r;
    }
  }
done:
  *body_len = len;
  return body;
}

/* -------------------------------------------------------------------------
 * SSH transport
 * ------------------------------------------------------------------------- */

/*
 * Spawn `ssh [user@]host git-<service> '/path'` and set up pipes.
 * The service is "upload-pack" (for fetch) or "receive-pack" (for push).
 */
int transport_open_ssh(struct transport *t,
                        const char *user, const char *host,
                        const char *path, const char *service)
{
  int to_ssh[2], from_ssh[2];

  if (pipe(to_ssh) != 0 || pipe(from_ssh) != 0)
    return -1;

  pid_t pid = fork();
  if (pid < 0) return -1;

  if (pid == 0) {
    /* Child: wire up stdin/stdout, inherit stderr so SSH errors reach terminal */
    close(to_ssh[1]);
    close(from_ssh[0]);
    dup2(to_ssh[0],   STDIN_FILENO);
    dup2(from_ssh[1], STDOUT_FILENO);
    close(to_ssh[0]);
    close(from_ssh[1]);

    /*
     * Build the remote command.  GitHub expects the path exactly as it
     * appears in the URL — for SCP-style "git@github.com:user/repo.git"
     * url_parse gives path="user/repo.git" (no leading slash), so we
     * pass it as-is.  For ssh:// URLs with a leading slash we strip it
     * since git-receive-pack on GitHub doesn't want the slash.
     */
    const char *repo_path = path;
    if (repo_path[0] == '/') repo_path++;

    char remote_cmd[2048];
    snprintf(remote_cmd, sizeof(remote_cmd),
             "git-%s '%s'", service, repo_path);

    char host_arg[512];
    if (user[0])
      snprintf(host_arg, sizeof(host_arg), "%s@%s", user, host);
    else
      snprintf(host_arg, sizeof(host_arg), "%s", host);

    /*
     * Do NOT use BatchMode=yes — it disables passphrase prompting and
     * breaks when the key isn't loaded in ssh-agent.  The user's normal
     * SSH config and agent handle authentication.
     */
    execl("/usr/bin/ssh", "ssh", host_arg, remote_cmd, NULL);
    execlp("ssh",         "ssh", host_arg, remote_cmd, NULL);
    _exit(127);
  }

  close(to_ssh[0]);
  close(from_ssh[1]);
  t->type    = TRANSPORT_SSH;
  t->ssh_out = to_ssh[1];    /* we write here → ssh stdin */
  t->ssh_in  = from_ssh[0];  /* we read here ← ssh stdout */
  t->ssh_pid = pid;
  return 0;
}

/* -------------------------------------------------------------------------
 * HTTP/HTTPS transport — all routed through curl
 * -------------------------------------------------------------------------
 *
 * We use curl for both plain HTTP and HTTPS.  This gives us:
 *   - TLS for free
 *   - Correct handling of chunked transfer encoding
 *   - HTTP/2 support
 *   - Redirect following
 *   - Auth credential helpers (netrc, etc.)
 *
 * For GET (info/refs): curl writes response to a pipe we read from.
 * For POST (upload-pack, receive-pack): we write the request body to
 * curl's stdin via a pipe, curl POSTs it and writes the response to
 * another pipe we read from.
 */

/*
 * Run curl to GET a URL.  Returns a readable fd of the response body.
 */
static int curl_get(const char *url_str, const char *accept_header)
{
  int pipefd[2];
  if (pipe(pipefd) != 0) return -1;

  pid_t pid = fork();
  if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    /* Forward curl errors to terminal so auth failures are visible */
    execlp("curl", "curl",
           "-s", "--fail", "--location",
           "-H", accept_header,
           url_str,
           NULL);
    _exit(127);
  }

  close(pipefd[1]);
  return pipefd[0];
}

/*
 * Run curl to POST body_len bytes from body[] to url_str.
 * Returns a readable fd of the response body.
 *
 * We write the request body to curl via its stdin (--data-binary @-)
 * so we never need a temp file.
 */
static int curl_post(const char *url_str,
                      const char *content_type,
                      const char *accept_header,
                      const uint8_t *body, size_t body_len)
{
  int in_pipe[2];   /* parent writes request body → curl stdin  */
  int out_pipe[2];  /* curl writes response       → parent reads */

  if (pipe(in_pipe) != 0) return -1;
  if (pipe(out_pipe) != 0) { close(in_pipe[0]); close(in_pipe[1]); return -1; }

  char ct_hdr[256], ac_hdr[256];
  snprintf(ct_hdr, sizeof(ct_hdr), "Content-Type: %s", content_type);
  snprintf(ac_hdr, sizeof(ac_hdr), "Accept: %s", accept_header);

  pid_t pid = fork();
  if (pid < 0) {
    close(in_pipe[0]); close(in_pipe[1]);
    close(out_pipe[0]); close(out_pipe[1]);
    return -1;
  }

  if (pid == 0) {
    close(in_pipe[1]);
    close(out_pipe[0]);
    dup2(in_pipe[0],  STDIN_FILENO);
    dup2(out_pipe[1], STDOUT_FILENO);
    close(in_pipe[0]);
    close(out_pipe[1]);
    execlp("curl", "curl",
           "-s", "--fail", "--location",
           "-X", "POST",
           "-H", ct_hdr,
           "-H", ac_hdr,
           "--data-binary", "@-",
           url_str,
           NULL);
    _exit(127);
  }

  /* Parent: close unused ends */
  close(in_pipe[0]);
  close(out_pipe[1]);

  /* Write body to curl's stdin */
  size_t written = 0;
  while (written < body_len) {
    ssize_t w = write(in_pipe[1], body + written, body_len - written);
    if (w <= 0) break;
    written += (size_t)w;
  }
  close(in_pipe[1]);  /* EOF signals curl to start the POST */

  return out_pipe[0];
}

/*
 * Open HTTP(S) transport for GET /info/refs.
 * Stores transport state in t, returns readable fd in *fd_out.
 */
int transport_open_http(struct transport *t,
                         const char *url, const char *service,
                         int *fd_out)
{
  struct remote_url ru;
  if (url_parse(url, &ru) != 0) {
    fprintf(stderr, "aigit: cannot parse URL '%s'\n", url);
    return -1;
  }

  strncpy(t->http_url,  url,     sizeof(t->http_url)  - 1);
  strncpy(t->http_host, ru.host, sizeof(t->http_host) - 1);
  { size_t _pl = strnlen(ru.path, sizeof(t->http_path)-1);
    memcpy(t->http_path, ru.path, _pl);
    t->http_path[_pl] = '\0'; }
  t->http_port = ru.port;
  t->http_tls  = (strcmp(ru.scheme, "https") == 0 ||
                  strcmp(ru.scheme, "git+https") == 0) ? 1 : 0;
  t->type = TRANSPORT_HTTP;

  char info_url[8192];
  snprintf(info_url, sizeof(info_url),
           "%s/info/refs?service=git-%.32s", url, service);

  char accept_hdr[128];
  snprintf(accept_hdr, sizeof(accept_hdr),
           "Accept: application/x-git-%s-advertisement", service);

  int fd = curl_get(info_url, accept_hdr);
  if (fd < 0) return -1;
  *fd_out = fd;
  return 0;
}

/*
 * HTTP(S) POST to the service endpoint.
 * Returns a readable fd of the response body.
 */
int transport_http_post(struct transport *t,
                         const char *service,
                         const uint8_t *body, size_t body_len,
                         int *fd_out)
{
  char ct[128], accept[128], endpoint[8192];
  snprintf(ct,       sizeof(ct),       "application/x-git-%s-request",  service);
  snprintf(accept,   sizeof(accept),   "application/x-git-%s-result",   service);
  snprintf(endpoint, sizeof(endpoint), "%s/git-%.32s", t->http_url, service);

  int fd = curl_post(endpoint, ct, accept, body, body_len);
  if (fd < 0) return -1;
  *fd_out = fd;
  return 0;
}

void transport_close(struct transport *t)
{
  if (t->type == TRANSPORT_SSH) {
    if (t->ssh_in  >= 0) close(t->ssh_in);
    if (t->ssh_out >= 0) close(t->ssh_out);
    if (t->ssh_pid > 0) {
      int status;
      waitpid(t->ssh_pid, &status, 0);
    }
    t->ssh_in = t->ssh_out = -1;
    t->ssh_pid = -1;
  }
}
