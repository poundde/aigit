#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

/* write() wrapper that explicitly discards the return value */
static void write_ignore(int fd, const void *buf, size_t n)
{
  ssize_t r = write(fd, buf, n);
  (void)r;
}

#include "aigit.h"
#include "transport.h"

/* -- shared helpers -- */

#define MAX_REMOTE_REFS 1024

struct ref_list {
  char     names[MAX_REMOTE_REFS][256];
  struct sha1 shas[MAX_REMOTE_REFS];
  char     caps[4096];
  size_t   count;
};

static int read_ref_advertisements(int fd, struct ref_list *rl)
{
  rl->count   = 0;
  rl->caps[0] = '\0';

  struct pkt_reader pr;
  pr.fd = fd;

  int saw_http_service = 0;
  int saw_http_flush   = 0;

  for (int i = 0; i < MAX_REMOTE_REFS + 8; i++) {
    int n = pkt_read(&pr);
    if (n < 0) return -1;

    if (pr.is_flush) {
      if (saw_http_service && !saw_http_flush) {
        saw_http_flush = 1;
        continue;
      }
      break;
    }

    if (strncmp(pr.buf, "# service=", 10) == 0) {
      saw_http_service = 1;
      continue;
    }

    if ((size_t)n < SHA1_HEX_LEN + 1) continue;

    char hex[SHA1_STR_SIZE];
    memcpy(hex, pr.buf, SHA1_HEX_LEN);
    hex[SHA1_HEX_LEN] = '\0';

    int valid = 1;
    for (int j = 0; j < SHA1_HEX_LEN; j++)
      if (!((hex[j] >= '0' && hex[j] <= '9') ||
            (hex[j] >= 'a' && hex[j] <= 'f')))
        { valid = 0; break; }
    if (!valid || pr.buf[SHA1_HEX_LEN] != ' ') continue;

    const char *refname = pr.buf + SHA1_HEX_LEN + 1;

    /* Skip capabilities^{} pseudo-ref from empty repos */
    if (strncmp(refname, "capabilities^{}", 15) == 0) {
      const char *nul2 = memchr(refname, '\0', (size_t)n - SHA1_HEX_LEN - 1);
      if (nul2) {
        size_t cl = strnlen(nul2 + 1, sizeof(rl->caps) - 1);
        memcpy(rl->caps, nul2 + 1, cl);
        rl->caps[cl] = '\0';
      }
      continue;
    }

    const char *nul = memchr(refname, '\0', (size_t)n - SHA1_HEX_LEN - 1);

    if (nul && rl->count == 0) {
      size_t cl = strnlen(nul + 1, sizeof(rl->caps) - 1);
      memcpy(rl->caps, nul + 1, cl);
      rl->caps[cl] = '\0';
    }

    if (rl->count >= MAX_REMOTE_REFS) continue;

    size_t rlen = nul ? (size_t)(nul - refname) : strnlen(refname, 255);
    if (rlen >= 256) rlen = 255;
    memcpy(rl->names[rl->count], refname, rlen);
    rl->names[rl->count][rlen] = '\0';

    memcpy(rl->shas[rl->count].hex, hex, SHA1_HEX_LEN);
    rl->shas[rl->count].hex[SHA1_HEX_LEN] = '\0';
    sha1_hex_to_bytes(hex, rl->shas[rl->count].bytes);
    rl->count++;
  }
  return 0;
}
static int ref_list_find(const struct ref_list *rl, const char *name)
{
  for (size_t i = 0; i < rl->count; i++)
    if (strcmp(rl->names[i], name) == 0)
      return (int)i;
  return -1;
}

static int resolve_remote_url(const char *remote_name, char *url, size_t url_len)
{
  size_t flen;
  char *buf = util_read_file(LOCAL_CONFIG_FILE, &flen);
  if (!buf) return -1;

  char target[256];
  snprintf(target, sizeof(target), "[remote \"%s\"]", remote_name);

  char *p = buf, *end = buf + flen;
  int in_section = 0, found = 0;

  while (p < end) {
    char *nl = memchr(p, '\n', (size_t)(end - p));
    size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
    char line[2048];
    if (llen >= sizeof(line)) llen = sizeof(line) - 1;
    memcpy(line, p, llen);
    while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == ' ')) llen--;
    line[llen] = '\0';
    p = nl ? nl + 1 : end;

    char *trim = line;
    while (*trim == ' ' || *trim == '\t') trim++;
    if (*trim == '[') {
      if (in_section) break;
      in_section = (strncmp(trim, target, strlen(target)) == 0);
      continue;
    }
    if (!in_section) continue;
    char *eq = strchr(trim, '=');
    if (!eq) continue;
    *eq = '\0';
    char *k = trim, *v = eq + 1;
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

static void ensure_core_config(void)
{
  char value[64];
  if (config_read_file(LOCAL_CONFIG_FILE, "core.repositoryformatversion",
                       value, sizeof(value)) == 0)
    return;
  config_write_file(LOCAL_CONFIG_FILE, "core.repositoryformatversion", "0");
  config_write_file(LOCAL_CONFIG_FILE, "core.filemode",  "true");
  config_write_file(LOCAL_CONFIG_FILE, "core.bare",      "false");
}

/* Write a pkt-line into a pack_buf instead of a fd */
static int pb_pkt_write(struct pack_buf *pb, const char *data, size_t len)
{
  char hdr[5];
  snprintf(hdr, sizeof(hdr), "%04x", (unsigned)(len + 4));
  if (pack_buf_append(pb, (uint8_t *)hdr, 4) != 0) return -1;
  return pack_buf_append(pb, (uint8_t *)data, len);
}

static int pb_pkt_writef(struct pack_buf *pb, const char *fmt, ...)
  __attribute__((format(printf,2,3)));
static int pb_pkt_writef(struct pack_buf *pb, const char *fmt, ...)
{
  char buf[PKT_MAX_PAYLOAD];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0 || (size_t)n >= sizeof(buf)) return -1;
  return pb_pkt_write(pb, buf, (size_t)n);
}

static int pb_pkt_flush(struct pack_buf *pb)
{
  return pack_buf_append(pb, (uint8_t *)"0000", 4);
}

/* -- PUSH -- */

static int do_push(struct transport *t __attribute__((unused)), int rd, int wr,
                    const char *branch, const struct sha1 *local_sha,
                    int is_http, struct transport *http_t)
{
  struct ref_list rl;
  if (read_ref_advertisements(rd, &rl) != 0) {
    fprintf(stderr, "aigit: failed to read remote refs\n");
    return 1;
  }

  char refname[512];
  snprintf(refname, sizeof(refname), "refs/heads/%s", branch);
  int idx = ref_list_find(&rl, refname);

  struct sha1 remote_tip;
  int is_new = (idx < 0);
  if (idx >= 0) remote_tip = rl.shas[idx];
  else sha1_zero(&remote_tip);

  struct sha1_set have, need;
  sha1_set_init(&have);
  sha1_set_init(&need);
  for (size_t i = 0; i < rl.count; i++)
    sha1_set_add(&have, &rl.shas[i]);
  if (objects_reachable_from(local_sha, &have, &need) != 0) {
    sha1_set_free(&have); sha1_set_free(&need);
    return 1;
  }
  sha1_set_free(&have);

  struct pack_buf pack;
  pack_buf_init(&pack);
  if (pack_build(&pack, need.items, need.count) != 0) {
    pack_buf_free(&pack); sha1_set_free(&need);
    return 1;
  }
  sha1_set_free(&need);

  char zero40[SHA1_STR_SIZE];
  memset(zero40, '0', SHA1_HEX_LEN);
  zero40[SHA1_HEX_LEN] = '\0';

  if (is_http) {
    /* Build full POST body into a pack_buf */
    struct pack_buf body;
    pack_buf_init(&body);

    /* First ref-update line with capabilities (NUL-separated) */
    char update[512];
    int ulen = snprintf(update, sizeof(update), "%s %s %s",
                        is_new ? zero40 : remote_tip.hex,
                        local_sha->hex, refname);
    const char *caps = "\x00report-status side-band-64k agent=aigit/1.0";
    size_t caps_len = 1 + strlen("report-status side-band-64k agent=aigit/1.0");
    char hdr[5];
    snprintf(hdr, sizeof(hdr), "%04x", (unsigned)((size_t)ulen + caps_len + 4));
    pack_buf_append(&body, (uint8_t *)hdr, 4);
    pack_buf_append(&body, (uint8_t *)update, (size_t)ulen);
    pack_buf_append(&body, (uint8_t *)caps, caps_len);
    pb_pkt_flush(&body);
    pack_buf_append(&body, pack.data, pack.len);
    pack_buf_free(&pack);

    int resp_fd;
    if (transport_http_post(http_t, "receive-pack",
                             body.data, body.len, &resp_fd) != 0) {
      pack_buf_free(&body);
      return 1;
    }
    pack_buf_free(&body);

    struct pkt_reader pr; pr.fd = resp_fd;
    int success = 0;
    while (1) {
      int n = pkt_read(&pr);
      if (n <= 0) break;
      uint8_t band = (uint8_t)pr.buf[0];
      const char *msg = pr.buf + 1;
      int mlen = n - 1;
      if (band == 1) {
        if (strncmp(msg, "unpack ok", 9) == 0) success = 1;
        else if (strncmp(msg, "ok ", 3) == 0)
          printf("  updated %s\n", msg + 3);
        else if (strncmp(msg, "ng ", 3) == 0)
          fprintf(stderr, "aigit: rejected: %.*s\n", mlen - 3, msg + 3);
      } else if (band == 2) {
        fwrite(msg, 1, (size_t)mlen, stderr);
      } else if (band == 3) {
        fprintf(stderr, "aigit: error: %.*s\n", mlen, msg);
      } else {
        /* No sideband */
        if (strncmp(pr.buf, "unpack ok", 9) == 0) success = 1;
      }
    }
    close(resp_fd);
    return success ? 0 : 1;

  } else {
    /* SSH: write to wr fd */
    char update[512];
    int ulen = snprintf(update, sizeof(update), "%s %s %s",
                        is_new ? zero40 : remote_tip.hex,
                        local_sha->hex, refname);
    const char *caps = "\x00report-status side-band-64k agent=aigit/1.0";
    size_t caps_len = 1 + strlen("report-status side-band-64k agent=aigit/1.0");
    char hdr[5];
    snprintf(hdr, sizeof(hdr), "%04x", (unsigned)((size_t)ulen + caps_len + 4));
    write_ignore(wr, hdr, 4);
    write_ignore(wr, update, (size_t)ulen);
    write_ignore(wr, caps, caps_len);
    write_ignore(wr, "0000", 4);

    /* Send PACK */
    size_t done = 0;
    while (done < pack.len) {
      ssize_t w = write(wr, pack.data + done, pack.len - done);
      if (w <= 0) break;
      done += (size_t)w;
    }
    pack_buf_free(&pack);

    struct pkt_reader pr; pr.fd = rd;
    int success = 0;
    while (1) {
      int n = pkt_read(&pr);
      if (n <= 0) break;
      /* Response is sideband-wrapped because we negotiated side-band-64k.
       * Band 1 = report-status lines, band 2 = progress, band 3 = error. */
      const char *msg = pr.buf;
      int mlen = n;
      uint8_t band = (uint8_t)pr.buf[0];
      if (band == 1 || band == 2 || band == 3) {
        msg  = pr.buf + 1;
        mlen = n - 1;
        if (band == 2) { fwrite(msg, 1, (size_t)mlen, stderr); continue; }
        if (band == 3) { fprintf(stderr, "aigit: error: %.*s\n", mlen, msg); continue; }
      }
      if (strncmp(msg, "unpack ok", 9) == 0) success = 1;
      else if (strncmp(msg, "ok ", 3) == 0)
        printf("  updated %.*s\n", mlen - 3, msg + 3);
      else if (strncmp(msg, "ng ", 3) == 0)
        fprintf(stderr, "aigit: rejected: %.*s\n", mlen - 3, msg + 3);
    }
    return success ? 0 : 1;
  }
}

int cmd_push(int argc, char **argv)
{
  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }
  ensure_core_config();

  const char *remote_name = "origin";
  const char *branch = NULL;
  char branch_buf[256];
  if (argc >= 2) remote_name = argv[1];
  if (argc >= 3) { branch = argv[2]; }
  else {
    if (refs_read_head(branch_buf, sizeof(branch_buf)) != 0) {
      fprintf(stderr, "aigit: cannot determine current branch\n");
      return 1;
    }
    branch = branch_buf;
  }

  char url[MAX_PATH];
  if (resolve_remote_url(remote_name, url, sizeof(url)) != 0) {
    fprintf(stderr, "aigit: remote '%s' not found\n", remote_name);
    return 1;
  }

  struct sha1 local_sha;
  if (!refs_head_exists()) {
    fprintf(stderr, "aigit: no commits to push\n");
    return 1;
  }
  if (refs_resolve_head(&local_sha) != 0) {
    fprintf(stderr, "aigit: cannot resolve HEAD\n");
    return 1;
  }

  printf("Pushing '%s' to '%s' (%s)...\n", branch, remote_name, url);

  struct remote_url ru;
  if (url_parse(url, &ru) != 0) {
    fprintf(stderr, "aigit: cannot parse remote URL\n");
    return 1;
  }

  if (strcmp(ru.scheme, "ssh") == 0 || strcmp(ru.scheme, "git+ssh") == 0) {
    struct transport t;
    memset(&t, 0, sizeof(t));
    if (transport_open_ssh(&t, ru.user, ru.host, ru.path, "receive-pack") != 0)
      return 1;
    int rc = do_push(&t, t.ssh_in, t.ssh_out, branch, &local_sha, 0, NULL);
    transport_close(&t);
    return rc;
  } else if (strcmp(ru.scheme, "http") == 0 || strcmp(ru.scheme, "https") == 0 ||
             strcmp(ru.scheme, "git+http") == 0 || strcmp(ru.scheme, "git+https") == 0) {
    struct transport t;
    memset(&t, 0, sizeof(t));
    int info_fd;
    if (transport_open_http(&t, url, "receive-pack", &info_fd) != 0)
      return 1;
    int rc = do_push(NULL, info_fd, -1, branch, &local_sha, 1, &t);
    close(info_fd);
    return rc;
  }
  fprintf(stderr, "aigit: unsupported URL scheme '%s'\n", ru.scheme);
  return 1;
}

/* -- PULL -- */

static int do_pull(int rd, int wr, const char *branch,
                    int is_http, struct transport *http_t)
{
  struct ref_list rl;
  if (read_ref_advertisements(rd, &rl) != 0) {
    fprintf(stderr, "aigit: failed to read remote refs\n");
    return 1;
  }

  char refname[512];
  snprintf(refname, sizeof(refname), "refs/heads/%s", branch);
  int idx = ref_list_find(&rl, refname);
  if (idx < 0) {
    fprintf(stderr, "aigit: remote has no branch '%s'\n", branch);
    return 1;
  }
  struct sha1 want_sha = rl.shas[idx];

  struct sha1 local_sha;
  int has_local = (refs_resolve_head(&local_sha) == 0);
  if (has_local && strcmp(local_sha.hex, want_sha.hex) == 0) {
    printf("Already up to date.\n");
    return 0;
  }

  /* Fast-forward check */
  if (has_local && !sha1_is_zero(&local_sha)) {
    struct sha1 walk = want_sha;
    int is_ff = 0;
    for (int depth = 0; depth < 4096; depth++) {
      if (strcmp(walk.hex, local_sha.hex) == 0) { is_ff = 1; break; }
      struct commit c;
      if (object_read_commit(&walk, &c) != 0 || !c.has_parent) break;
      walk = c.parent;
    }
    if (!is_ff) {
      fprintf(stderr, "aigit: not a fast-forward; merge not implemented.\n");
      return 1;
    }
  }

  int pack_fd = -1;

  if (is_http) {
    struct pack_buf req;
    pack_buf_init(&req);
    pb_pkt_writef(&req, "want %s multi_ack_detailed side-band-64k ofs-delta\n",
                  want_sha.hex);
    if (has_local) {
      struct sha1 hw = local_sha;
      for (int d = 0; d < 32 && !sha1_is_zero(&hw); d++) {
        pb_pkt_writef(&req, "have %s\n", hw.hex);
        struct commit c;
        if (object_read_commit(&hw, &c) != 0 || !c.has_parent) break;
        hw = c.parent;
      }
    }
    pb_pkt_flush(&req);
    pb_pkt_writef(&req, "done\n");

    if (transport_http_post(http_t, "upload-pack",
                             req.data, req.len, &pack_fd) != 0) {
      pack_buf_free(&req);
      return 1;
    }
    pack_buf_free(&req);
  } else {
    /* SSH */
    pkt_writef(wr, "want %s multi_ack_detailed side-band-64k ofs-delta\n",
               want_sha.hex);
    if (has_local) {
      struct sha1 hw = local_sha;
      for (int d = 0; d < 32 && !sha1_is_zero(&hw); d++) {
        pkt_writef(wr, "have %s\n", hw.hex);
        struct commit c;
        if (object_read_commit(&hw, &c) != 0 || !c.has_parent) break;
        hw = c.parent;
      }
    }
    pkt_flush(wr);
    pkt_writef(wr, "done\n");
    pack_fd = rd;
  }

  fprintf(stderr, "Receiving objects...\n");
  if (pack_receive(pack_fd) != 0) {
    fprintf(stderr, "aigit: failed to receive pack\n");
    if (is_http) close(pack_fd);
    return 1;
  }
  if (is_http) close(pack_fd);

  /* Update local ref */
  char local_ref[MAX_PATH];
  snprintf(local_ref, sizeof(local_ref), "refs/heads/%s", branch);
  if (refs_write_ref(local_ref, &want_sha) != 0) {
    fprintf(stderr, "aigit: failed to update local ref\n");
    return 1;
  }

  /* Restore working tree */
  struct commit target;
  if (object_read_commit(&want_sha, &target) != 0) {
    fprintf(stderr, "aigit: failed to read commit\n");
    return 1;
  }
  if (object_restore_tree(&target.tree, "") != 0) {
    fprintf(stderr, "aigit: failed to restore working tree\n");
    return 1;
  }

  /* Rebuild index from tree */
  struct index new_idx;
  index_init(&new_idx);
  char *ttype = NULL; uint8_t *tdata = NULL; size_t tlen = 0;
  if (object_read(&target.tree, &ttype, &tdata, &tlen) == 0) {
    size_t off = 0;
    while (off < tlen) {
      uint8_t *sp = memchr(tdata + off, ' ', tlen - off);
      if (!sp) break;
      off = (size_t)(sp - tdata) + 1;
      uint8_t *nul = memchr(tdata + off, '\0', tlen - off);
      if (!nul) break;
      size_t nlen = (size_t)(nul - (tdata + off));
      if (nlen < MAX_PATH) {
        char name[MAX_PATH];
        memcpy(name, tdata + off, nlen);
        name[nlen] = '\0';
        index_add(&new_idx, name);
      }
      off = (size_t)(nul - tdata) + 1 + SHA1_BIN_LEN;
    }
    free(ttype); free(tdata);
  }
  index_write(&new_idx);
  index_free(&new_idx);

  printf("Fast-forwarded '%s' to %.7s\n", branch, want_sha.hex);
  return 0;
}

int cmd_pull(int argc, char **argv)
{
  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }
  ensure_core_config();

  const char *remote_name = "origin";
  const char *branch = NULL;
  char branch_buf[256];
  if (argc >= 2) remote_name = argv[1];
  if (argc >= 3) { branch = argv[2]; }
  else {
    if (refs_read_head(branch_buf, sizeof(branch_buf)) != 0) {
      fprintf(stderr, "aigit: cannot determine current branch\n");
      return 1;
    }
    branch = branch_buf;
  }

  char url[MAX_PATH];
  if (resolve_remote_url(remote_name, url, sizeof(url)) != 0) {
    fprintf(stderr, "aigit: remote '%s' not found\n", remote_name);
    return 1;
  }

  struct index idx; index_init(&idx); index_read(&idx);
  int dirty = 0;
  for (size_t i = 0; i < idx.count; i++) {
    struct sha1 disk;
    if (object_hash_file(idx.entries[i].path, &disk) != 0 ||
        strcmp(disk.hex, idx.entries[i].sha.hex) != 0) { dirty = 1; break; }
  }
  index_free(&idx);
  if (dirty) {
    fprintf(stderr, "aigit: uncommitted changes; commit first.\n");
    return 1;
  }

  printf("Pulling '%s' from '%s' (%s)...\n", branch, remote_name, url);

  struct remote_url ru;
  if (url_parse(url, &ru) != 0) {
    fprintf(stderr, "aigit: cannot parse remote URL\n");
    return 1;
  }

  if (strcmp(ru.scheme, "ssh") == 0 || strcmp(ru.scheme, "git+ssh") == 0) {
    struct transport t; memset(&t, 0, sizeof(t));
    if (transport_open_ssh(&t, ru.user, ru.host, ru.path, "upload-pack") != 0)
      return 1;
    int rc = do_pull(t.ssh_in, t.ssh_out, branch, 0, NULL);
    transport_close(&t);
    return rc;
  } else if (strcmp(ru.scheme, "http") == 0 || strcmp(ru.scheme, "https") == 0 ||
             strcmp(ru.scheme, "git+http") == 0 || strcmp(ru.scheme, "git+https") == 0) {
    struct transport t; memset(&t, 0, sizeof(t));
    int info_fd;
    if (transport_open_http(&t, url, "upload-pack", &info_fd) != 0)
      return 1;
    int rc = do_pull(info_fd, -1, branch, 1, &t);
    close(info_fd);
    return rc;
  }
  fprintf(stderr, "aigit: unsupported URL scheme '%s'\n", ru.scheme);
  return 1;
}
