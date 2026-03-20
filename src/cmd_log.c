#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ncurses.h>
#include "aigit.h"

/*
 * -------------------------------------------------------------------------
 * Commit graph data structures
 * -------------------------------------------------------------------------
 *
 * We walk the commit chain from HEAD back to the root, building an array
 * of commit_node structs.  For each node we record the graph column it
 * occupies so we can draw connecting lines.
 *
 * This implementation handles linear histories only — merges are noted
 * but graph columns are not split for them (out of scope for a single
 * branch VCS).
 */

struct log_entry {
  struct commit commit;
  int           col;    /* graph column (always 0 for linear history) */
};

struct log_state {
  struct log_entry *entries;
  size_t            count;
  size_t            cap;
};

static int log_state_init(struct log_state *ls)
{
  ls->cap     = 64;
  ls->count   = 0;
  ls->entries = malloc(ls->cap * sizeof(*ls->entries));
  return ls->entries ? 0 : -1;
}

static void log_state_free(struct log_state *ls)
{
  free(ls->entries);
  ls->entries = NULL;
  ls->count   = ls->cap = 0;
}

static int log_state_push(struct log_state *ls, const struct commit *c)
{
  if (ls->count >= ls->cap) {
    size_t new_cap = ls->cap * 2;
    struct log_entry *tmp = realloc(ls->entries,
                                    new_cap * sizeof(*ls->entries));
    if (!tmp)
      return -1;
    ls->entries = tmp;
    ls->cap     = new_cap;
  }
  ls->entries[ls->count].commit = *c;
  ls->entries[ls->count].col    = 0;
  ls->count++;
  return 0;
}

/*
 * Walk from HEAD backwards, collecting commits.
 */
static int collect_commits(struct log_state *ls)
{
  if (!refs_head_exists())
    return 0;

  struct sha1 sha;
  if (refs_resolve_head(&sha) != 0)
    return -1;

  while (1) {
    if (sha1_is_zero(&sha))
      break;

    struct commit c;
    if (object_read_commit(&sha, &c) != 0)
      break;

    if (log_state_push(ls, &c) != 0)
      return -1;

    if (!c.has_parent)
      break;

    memcpy(&sha, &c.parent, sizeof(sha));
  }

  return 0;
}

/*
 * -------------------------------------------------------------------------
 * Plain-text log (non-TTY fallback)
 * -------------------------------------------------------------------------
 */

static void print_commit_plain(const struct log_entry *e)
{
  char timebuf[64];
  time_t t = (time_t)e->commit.author_time;
  struct tm *tm = gmtime(&t);
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC", tm);

  printf("commit %s\n", e->commit.sha.hex);
  printf("Author: %s\n", e->commit.author);
  printf("Date:   %s\n", timebuf);
  printf("\n    %s\n\n", e->commit.message);
}

static void log_plain(const struct log_state *ls)
{
  for (size_t i = 0; i < ls->count; i++)
    print_commit_plain(&ls->entries[i]);
}

/*
 * -------------------------------------------------------------------------
 * ncurses TUI
 * -------------------------------------------------------------------------
 *
 * Layout (one commit row):
 *
 *   ● abc1234  2024-01-15  Author Name  <message first line>
 *   │
 *   ● ...
 *
 * Box-drawing characters used:
 *   ●  U+25CF  BLACK CIRCLE   (commit marker)
 *   │  U+2502  BOX DRAWINGS LIGHT VERTICAL
 *   ╰  U+2570  BOX DRAWINGS LIGHT ARC UP AND RIGHT (last commit)
 *
 * Navigation:
 *   j / ↓  — scroll down
 *   k / ↑  — scroll up
 *   q      — quit
 *   Enter  — expand selected commit to show full message
 */

#define COLOR_GRAPH   1
#define COLOR_SHA     2
#define COLOR_DATE    3
#define COLOR_AUTHOR  4
#define COLOR_MSG     5
#define COLOR_HEADER  6
#define COLOR_SELECT  7

struct tui_state {
  const struct log_state *ls;
  int                     selected;
  int                     scroll;
  int                     rows;
  int                     cols;
  int                     detail_mode;   /* show full commit detail */
};

/*
 * Render the status bar at the bottom of the screen.
 */
static void tui_draw_statusbar(const struct tui_state *ts)
{
  char buf[256];
  snprintf(buf, sizeof(buf),
           "  %zu commit%s  |  j/k: navigate  Enter: detail  q: quit  ",
           ts->ls->count,
           ts->ls->count == 1 ? "" : "s");

  attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
  mvhline(ts->rows - 1, 0, ' ', ts->cols);
  mvprintw(ts->rows - 1, 0, "%s", buf);
  attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
}

/*
 * Render one commit row in the graph view.
 *
 * Each commit occupies 2 screen rows:
 *   row 0:  ● <sha7>  <date>  <author>  <message>
 *   row 1:  │                           (connector, omitted for last)
 */
static void tui_draw_commit_row(const struct tui_state *ts,
                                 int screen_row,
                                 size_t entry_idx)
{
  const struct log_entry *e   = &ts->ls->entries[entry_idx];
  int is_selected              = ((int)entry_idx == ts->selected);
  int is_last                  = (entry_idx == ts->ls->count - 1);

  if (is_selected) {
    attron(COLOR_PAIR(COLOR_SELECT) | A_BOLD);
    mvhline(screen_row, 0, ' ', ts->cols);
  }

  /* Graph marker */
  attron(COLOR_PAIR(COLOR_GRAPH) | A_BOLD);
  mvprintw(screen_row, 0, "● ");
  if (!is_selected) attroff(COLOR_PAIR(COLOR_GRAPH) | A_BOLD);

  /* Short SHA */
  attron(COLOR_PAIR(COLOR_SHA));
  printw("%.7s  ", e->commit.sha.hex);
  attroff(COLOR_PAIR(COLOR_SHA));

  /* Date */
  char datebuf[16];
  time_t t = (time_t)e->commit.author_time;
  struct tm *tm = gmtime(&t);
  strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", tm);
  attron(COLOR_PAIR(COLOR_DATE));
  printw("%s  ", datebuf);
  attroff(COLOR_PAIR(COLOR_DATE));

  /* Author (truncated) */
  char author_short[24];
  strncpy(author_short, e->commit.author, sizeof(author_short) - 1);
  author_short[sizeof(author_short) - 1] = '\0';
  /* Strip email if present */
  char *lt = strchr(author_short, '<');
  if (lt && lt > author_short) {
    *(lt - 1) = '\0';
  }
  attron(COLOR_PAIR(COLOR_AUTHOR));
  printw("%-20.20s  ", author_short);
  attroff(COLOR_PAIR(COLOR_AUTHOR));

  /* Message (rest of row) */
  int cur_col;
  int cur_row_unused;
  getyx(stdscr, cur_row_unused, cur_col);
  (void)cur_row_unused;
  int remaining = ts->cols - cur_col - 1;
  if (remaining > 0) {
    attron(COLOR_PAIR(COLOR_MSG));
    char msg_trunc[512];
    strncpy(msg_trunc, e->commit.message, sizeof(msg_trunc) - 1);
    msg_trunc[sizeof(msg_trunc) - 1] = '\0';
    /* Only first line of message */
    char *nl = strchr(msg_trunc, '\n');
    if (nl) *nl = '\0';
    printw("%.*s", remaining, msg_trunc);
    attroff(COLOR_PAIR(COLOR_MSG));
  }

  if (is_selected)
    attroff(COLOR_PAIR(COLOR_SELECT) | A_BOLD);

  /* Graph connector on row below */
  if (!is_last && screen_row + 1 < ts->rows - 1) {
    attron(COLOR_PAIR(COLOR_GRAPH));
    mvprintw(screen_row + 1, 0, "│ ");
    attroff(COLOR_PAIR(COLOR_GRAPH));
  }
}

/*
 * Full commit detail pane — shown when Enter is pressed.
 */
static void tui_draw_detail(const struct tui_state *ts)
{
  const struct log_entry *e = &ts->ls->entries[ts->selected];

  clear();

  attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
  mvprintw(0, 0, " Commit Detail                                              (q/Esc: back)");
  attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);

  attron(COLOR_PAIR(COLOR_SHA) | A_BOLD);
  mvprintw(2, 2, "commit %s", e->commit.sha.hex);
  attroff(COLOR_PAIR(COLOR_SHA) | A_BOLD);

  char timebuf[64];
  time_t t = (time_t)e->commit.author_time;
  struct tm *tm = gmtime(&t);
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC", tm);

  mvprintw(3, 2, "Author:  %s", e->commit.author);
  mvprintw(4, 2, "Date:    %s", timebuf);
  if (e->commit.has_parent)
    mvprintw(5, 2, "Parent:  %s", e->commit.parent.hex);

  attron(A_BOLD);
  mvprintw(7, 2, "Message:");
  attroff(A_BOLD);

  /* Wrap the message to terminal width */
  int wrap_col = ts->cols - 6;
  if (wrap_col < 20) wrap_col = 20;
  int row = 9;
  const char *p = e->commit.message;
  while (*p && row < ts->rows - 2) {
    int len = (int)strlen(p);
    if (len <= wrap_col) {
      mvprintw(row++, 4, "%s", p);
      break;
    }
    /* Find last space before wrap_col */
    int brk = wrap_col;
    while (brk > 0 && p[brk] != ' ') brk--;
    if (brk == 0) brk = wrap_col;
    mvprintw(row++, 4, "%.*s", brk, p);
    p += brk;
    while (*p == ' ') p++;
  }

  attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
  mvhline(ts->rows - 1, 0, ' ', ts->cols);
  mvprintw(ts->rows - 1, 0, "  Press q or Esc to return to log");
  attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);

  refresh();
}

/*
 * Draw the full log view.
 *
 * Each commit takes 2 rows (commit line + connector).  The last commit
 * takes 1 row.
 */
static void tui_draw_log(struct tui_state *ts)
{
  clear();

  /* Header */
  attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
  mvhline(0, 0, ' ', ts->cols);
  mvprintw(0, 0, "  aigit log");
  attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);

  int usable_rows = ts->rows - 2;  /* minus header and status bar */
  size_t n = ts->ls->count;

  /*
   * Ensure the selected entry is visible.
   * Each entry occupies 2 rows except the last.
   */
  int sel_screen_top = (ts->selected - ts->scroll) * 2;
  if (sel_screen_top < 0)
    ts->scroll = ts->selected;
  if (sel_screen_top + 2 > usable_rows)
    ts->scroll = ts->selected - (usable_rows / 2 - 1);
  if (ts->scroll < 0)
    ts->scroll = 0;

  for (size_t i = (size_t)ts->scroll; i < n; i++) {
    int screen_row = 1 + (int)(i - (size_t)ts->scroll) * 2;
    if (screen_row >= ts->rows - 1)
      break;
    tui_draw_commit_row(ts, screen_row, i);
  }

  tui_draw_statusbar(ts);
  refresh();
}

static void tui_init_colors(void)
{
  if (!has_colors())
    return;
  start_color();
  use_default_colors();
  init_pair(COLOR_GRAPH,  COLOR_YELLOW,  -1);
  init_pair(COLOR_SHA,    COLOR_CYAN,    -1);
  init_pair(COLOR_DATE,   COLOR_GREEN,   -1);
  init_pair(COLOR_AUTHOR, COLOR_MAGENTA, -1);
  init_pair(COLOR_MSG,    -1,            -1);
  init_pair(COLOR_HEADER, COLOR_BLACK,   COLOR_CYAN);
  init_pair(COLOR_SELECT, COLOR_BLACK,   COLOR_YELLOW);
}

static void log_tui(const struct log_state *ls)
{
  initscr();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);
  curs_set(0);
  tui_init_colors();

  struct tui_state ts = {
    .ls          = ls,
    .selected    = 0,
    .scroll      = 0,
    .detail_mode = 0,
  };
  getmaxyx(stdscr, ts.rows, ts.cols);

  tui_draw_log(&ts);

  while (1) {
    int ch = getch();
    getmaxyx(stdscr, ts.rows, ts.cols);

    if (ts.detail_mode) {
      if (ch == 'q' || ch == 27 /* Esc */) {
        ts.detail_mode = 0;
        tui_draw_log(&ts);
      }
      continue;
    }

    switch (ch) {
    case 'q':
      goto quit;

    case 'j':
    case KEY_DOWN:
      if (ts.selected + 1 < (int)ls->count) {
        ts.selected++;
        tui_draw_log(&ts);
      }
      break;

    case 'k':
    case KEY_UP:
      if (ts.selected > 0) {
        ts.selected--;
        tui_draw_log(&ts);
      }
      break;

    case KEY_NPAGE:
      ts.selected += ts.rows / 2;
      if (ts.selected >= (int)ls->count)
        ts.selected = (int)ls->count - 1;
      tui_draw_log(&ts);
      break;

    case KEY_PPAGE:
      ts.selected -= ts.rows / 2;
      if (ts.selected < 0)
        ts.selected = 0;
      tui_draw_log(&ts);
      break;

    case KEY_HOME:
      ts.selected = 0;
      ts.scroll   = 0;
      tui_draw_log(&ts);
      break;

    case KEY_END:
      ts.selected = (int)ls->count - 1;
      tui_draw_log(&ts);
      break;

    case '\n':
    case KEY_ENTER:
      ts.detail_mode = 1;
      tui_draw_detail(&ts);
      break;

    case KEY_RESIZE:
      getmaxyx(stdscr, ts.rows, ts.cols);
      tui_draw_log(&ts);
      break;

    default:
      break;
    }
  }

quit:
  endwin();
}

/*
 * `aigit log`
 *
 * Launches the ncurses TUI when stdout is a TTY; otherwise falls back
 * to plain-text output.
 */
int cmd_log(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  if (util_find_git_dir() != 0) {
    fprintf(stderr, "aigit: not a git repository\n");
    return 1;
  }

  struct log_state ls;
  if (log_state_init(&ls) != 0) {
    fprintf(stderr, "aigit: out of memory\n");
    return 1;
  }

  if (collect_commits(&ls) != 0) {
    fprintf(stderr, "aigit: failed to read commit history\n");
    log_state_free(&ls);
    return 1;
  }

  if (ls.count == 0) {
    fprintf(stderr, "aigit: no commits yet\n");
    log_state_free(&ls);
    return 0;
  }

  if (util_is_tty(STDOUT_FILENO)) {
    log_tui(&ls);
  } else {
    log_plain(&ls);
  }

  log_state_free(&ls);
  return 0;
}
