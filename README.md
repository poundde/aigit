# aigit

A from-scratch reimplementation of Git — written entirely by [Claude Sonnet 4.6](https://anthropic.com). No human wrote a single line of code in this repository.

---

## What this is

`aigit` is a functional version control system that reimplements Git's core from the ground up in pure C (`gnu11`). It stores objects in the same SHA-1-addressed, zlib-compressed loose object format as real Git, meaning **Git can read everything aigit writes** — `git log`, `git show`, `git cat-file` all work natively on an aigit repository.

The transport layer speaks the real Git smart HTTP and SSH wire protocols, so `aigit push` and `aigit pull` work directly against GitHub, Gitea, Forgejo, or any standard Git host.

---

## Why this is notable

This entire codebase — ~7500 lines across 25 files — was designed, written, debugged, and iterated on entirely by an AI in a single conversation. That includes:

- A from-scratch SHA-1 implementation (FIPS 180-4, no OpenSSL)
- The Git index v2 binary format (with correct 8-byte alignment and trailing checksum)
- zlib object compression/decompression
- The full Git smart HTTP protocol (pkt-line framing, sideband multiplexing)
- SSH transport via `git-upload-pack` / `git-receive-pack`
- PACK format generation (for push) and reception (for pull/fetch)
- OFS_DELTA and REF_DELTA decompression with a position index
- Pack index v2 reader (for repos that have been `git gc`'d)
- `.gitignore` pattern matching (`**`, negation, directory-only patterns, per-directory files)
- An ncurses TUI for `aigit log` with a branch graph, color, keyboard navigation, and a detail pane
- Myers diff algorithm for `aigit diff`

---

## Commands

```
aigit init                          initialize a new repository
aigit add <file|dir...>             stage files (recursive, .gitignore aware)
aigit commit -m <message>           commit staged changes
aigit status                        show staged / unstaged / untracked files
aigit diff                          show unstaged changes as unified diff
aigit log                           ncurses TUI commit log (plain text if not a TTY)
aigit branch                        list branches
aigit branch <name>                 create branch at HEAD
aigit branch -d <name>              delete branch
aigit branch -m <old> <new>         rename branch
aigit checkout <branch>             switch branch
aigit checkout -b <branch>          create and switch
aigit remote add <name> <url>       add a remote
aigit remote remove <name>          remove a remote
aigit remote [-v]                   list remotes
aigit push [<remote> [<branch>]]    push to remote (SSH or HTTP/HTTPS)
aigit pull [<remote> [<branch>]]    pull from remote (fast-forward only)
aigit config --global user.name "you"
aigit config --global user.email "you@example.com"
```

---

## Building

```sh
# Dependencies
# Debian/Ubuntu:
sudo apt-get install build-essential zlib1g-dev libncurses-dev

# Arch:
sudo pacman -S base-devel zlib ncurses

# Build
sh create.sh

# Build and install to /usr/local/bin
sh create.sh install
```

Or if you already have a clone:

```sh
make -j$(nproc)
```

---

## Getting started with GitHub

```sh
# One-time identity setup
aigit config --global user.name "raute"
aigit config --global user.email "you@github.email"

# In your project
aigit init
aigit add .
aigit commit -m "initial commit"
aigit remote add origin git@github.com:raute/yourrepo.git
aigit push
```

Requires your SSH key to already be set up with GitHub. Create the GitHub repo empty (no README) so histories don't diverge.

---

## Technical notes

### Object storage

Objects are stored identically to Git's loose object format:

```
.git/objects/ab/cdef1234...   zlib( "blob 42\0<content>" )
```

SHA-1 is computed over the full `"<type> <size>\0<content>"` string, so object hashes match what Git would produce for the same content. This means any existing Git tooling (including `git push`) can operate on an aigit repository without any conversion step.

### Wire protocol

Push and pull implement the Git smart HTTP and SSH protocols from scratch:

- **pkt-line framing** — 4-hex-digit length-prefixed packets, flush packets, sideband multiplexing
- **upload-pack** (fetch/pull) — `want`/`have`/`done` negotiation, sideband-64k, receives PACK
- **receive-pack** (push) — ref update lines with capabilities, sends PACK, reads report-status
- **SSH** — forks `ssh` with `git-upload-pack`/`git-receive-pack`, communicates over stdio pipes
- **HTTP** — raw TCP for `http://`, `curl` subprocess for `https://`

### PACK format

Outgoing packs (push): non-deltified blobs, trees, and commits — always valid, never rejected.

Incoming packs (pull): full PACK v2 parser including:
- Non-delta objects (commit/tree/blob)
- `OFS_DELTA` — resolved via a position index built as the pack is parsed (bases always precede their deltas)
- `REF_DELTA` — resolved against the local object store
- Correct sideband demultiplexing (NAK/ACK pkt-lines drained before sideband begins)

### Index

The staging area uses the Git index v2 binary format exactly, including big-endian field encoding, 8-byte entry alignment, and a trailing SHA-1 checksum. `git status` and `git diff --cached` can read it directly.

---

## Limitations

- Fast-forward pulls only (no merge)
- No `--force` push
- No `git stash`, `git rebase`, or `git tag`
- Single-parent commits only (no merge commits)
- Flat tree objects only (subdirectory grouping not supported in the index — paths are stored as full relative paths)
- `http://` uses raw TCP; `https://` requires `curl` in PATH

---

## Human Footnote
I just asked Claude to write Git from scratch for fun, did not expect it to go so far. You should definitely NOT use it for real-world project version control, as this probably has a lot of bugs.
