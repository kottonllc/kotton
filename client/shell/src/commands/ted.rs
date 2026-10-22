// SPDX-License-Identifier: AGPL-3.0-or-later
//! Built-in `ted` command — in-process full-screen text editor.
//!
//! Reads a VFS file into memory, lets the user edit it with a nano-style
//! TUI, then writes the result back to the VFS on save.  Works in both the
//! native REPL and the app-level shell.
//!
//! To open the kotton-edit GUI app instead, use:
//!   app open sh.kotton.edit path=<file>
//! or define an alias in your kotton profile.

use anyhow::Result;
use async_trait::async_trait;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{
        Attribute, Color, Print, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor,
    },
    terminal::{self, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{self, Write};

use super::{Command, CommandOutput};
use crate::state::ShellState;

// ─── public command struct ────────────────────────────────────────────────────

pub struct TedCommand;

#[async_trait]
impl Command for TedCommand {
    fn help_text(&self) -> &'static str {
        "ted — in-process full-screen text editor\n\nUSAGE:\n  ted <file>\n\nNOTES:\n  Ctrl-S saves. Ctrl-X saves and exits. Ctrl-Q exits without saving.\n  Ctrl-K cuts to end of line. Ctrl-U pastes.\n  To open the GUI editor app: app open sh.kotton.edit path=<file>\n"
    }

    async fn execute(&self, args: &[String], state: &mut ShellState) -> Result<CommandOutput> {
        if args.is_empty() {
            return Ok(CommandOutput::error(1, "Usage: ted <file>".to_string()));
        }

        let path = resolve_path(&state.current_dir, &args[0]);
        let display_name = args[0].clone();

        // Read existing content (empty string for new files)
        let content = match state.host.read_file(&path).await {
            Ok(data) => String::from_utf8_lossy(&data).to_string(),
            Err(_) => String::new(),
        };

        // Run the blocking TUI loop on a dedicated thread so the tokio
        // runtime stays healthy.  block_in_place is safe here because the
        // shell runs on a multi-thread tokio runtime.
        let (saved, new_content) = tokio::task::block_in_place(|| {
            let mut editor = Editor::new(&content, display_name);
            let saved = editor.run().unwrap_or(false);
            let content = editor.content_string();
            (saved, content)
        });

        if saved {
            state
                .host
                .write_file(&path, new_content.as_bytes())
                .await
                .map_err(|e| anyhow::anyhow!("write failed: {}", e))?;
            Ok(CommandOutput::success_with_output(format!(
                "Saved {}",
                path
            )))
        } else {
            Ok(CommandOutput::success())
        }
    }
}

fn resolve_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if cwd == "/" {
        format!("/{}", path)
    } else {
        format!("{}/{}", cwd, path)
    }
}

// ─── Editor state ─────────────────────────────────────────────────────────────

struct Editor {
    /// File content represented as a vec of char-vecs so all cursor
    /// arithmetic is in characters, not bytes.
    lines: Vec<Vec<char>>,
    /// Zero-based row index into `lines`.
    cursor_row: usize,
    /// Zero-based character index within the current line.
    cursor_col: usize,
    /// First visible row (vertical scroll offset).
    scroll_row: usize,
    /// First visible column (horizontal scroll offset).
    scroll_col: usize,
    modified: bool,
    filename: String,
    /// Yanked text (Ctrl+K / Ctrl+U clipboard).
    clipboard: Option<Vec<char>>,
    /// Transient status message shown in the footer (e.g. "Saved!").
    status_msg: Option<String>,
}

impl Editor {
    fn new(content: &str, filename: String) -> Self {
        // Always have at least one (possibly empty) line.
        let mut lines: Vec<Vec<char>> = content.split('\n').map(|l| l.chars().collect()).collect();
        if lines.is_empty() {
            lines.push(vec![]);
        }
        Self {
            lines,
            cursor_row: 0,
            cursor_col: 0,
            scroll_row: 0,
            scroll_col: 0,
            modified: false,
            filename,
            clipboard: None,
            status_msg: None,
        }
    }

    /// Reconstruct a `\n`-separated string from the char vecs.
    fn content_string(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // ── cursor helpers ──────────────────────────────────────────────────────

    fn clamp_col(&mut self) {
        let max = self.lines[self.cursor_row].len();
        if self.cursor_col > max {
            self.cursor_col = max;
        }
    }

    /// Width (in chars) of the line-number gutter + separator.
    fn gutter_width(&self) -> usize {
        let digits = format!("{}", self.lines.len()).len().max(2);
        digits + 4 // " NNN │ " = 1 + digits + 1 + 1 + 1
    }

    /// Adjust scroll so the cursor stays in view.
    fn ensure_cursor_visible(&mut self, content_rows: usize, text_cols: usize) {
        // Vertical
        if self.cursor_row < self.scroll_row {
            self.scroll_row = self.cursor_row;
        }
        if self.cursor_row >= self.scroll_row + content_rows {
            self.scroll_row = self.cursor_row + 1 - content_rows;
        }
        // Horizontal
        if self.cursor_col < self.scroll_col {
            self.scroll_col = self.cursor_col;
        }
        if self.cursor_col >= self.scroll_col + text_cols {
            self.scroll_col = self.cursor_col + 1 - text_cols;
        }
    }

    // ── movement ────────────────────────────────────────────────────────────

    fn move_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.clamp_col();
        }
    }

    fn move_down(&mut self) {
        if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            self.clamp_col();
        }
    }

    fn move_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.cursor_col = self.lines[self.cursor_row].len();
        }
    }

    fn move_right(&mut self) {
        let len = self.lines[self.cursor_row].len();
        if self.cursor_col < len {
            self.cursor_col += 1;
        } else if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            self.cursor_col = 0;
        }
    }

    fn move_home(&mut self) {
        self.cursor_col = 0;
    }

    fn move_end(&mut self) {
        self.cursor_col = self.lines[self.cursor_row].len();
    }

    fn page_up(&mut self, content_rows: usize) {
        self.cursor_row = self.cursor_row.saturating_sub(content_rows);
        self.clamp_col();
    }

    fn page_down(&mut self, content_rows: usize) {
        let last = self.lines.len() - 1;
        self.cursor_row = (self.cursor_row + content_rows).min(last);
        self.clamp_col();
    }

    // ── editing ─────────────────────────────────────────────────────────────

    fn insert_char(&mut self, ch: char) {
        self.lines[self.cursor_row].insert(self.cursor_col, ch);
        self.cursor_col += 1;
        self.modified = true;
        self.status_msg = None;
    }

    fn insert_newline(&mut self) {
        let tail = self.lines[self.cursor_row].split_off(self.cursor_col);
        self.lines.insert(self.cursor_row + 1, tail);
        self.cursor_row += 1;
        self.cursor_col = 0;
        self.modified = true;
        self.status_msg = None;
    }

    fn backspace(&mut self) {
        if self.cursor_col > 0 {
            self.lines[self.cursor_row].remove(self.cursor_col - 1);
            self.cursor_col -= 1;
            self.modified = true;
        } else if self.cursor_row > 0 {
            let tail = self.lines.remove(self.cursor_row);
            self.cursor_row -= 1;
            self.cursor_col = self.lines[self.cursor_row].len();
            self.lines[self.cursor_row].extend(tail);
            self.modified = true;
        }
        self.status_msg = None;
    }

    fn delete_forward(&mut self) {
        let len = self.lines[self.cursor_row].len();
        if self.cursor_col < len {
            self.lines[self.cursor_row].remove(self.cursor_col);
            self.modified = true;
        } else if self.cursor_row + 1 < self.lines.len() {
            let next = self.lines.remove(self.cursor_row + 1);
            self.lines[self.cursor_row].extend(next);
            self.modified = true;
        }
        self.status_msg = None;
    }

    /// Cut from cursor to end of line (kill line).  Stores in clipboard.
    fn kill_line(&mut self) {
        let len = self.lines[self.cursor_row].len();
        if self.cursor_col < len {
            let yanked = self.lines[self.cursor_row].split_off(self.cursor_col);
            self.clipboard = Some(yanked);
        } else if self.cursor_row + 1 < self.lines.len() {
            // At end of line: eat the newline
            let next = self.lines.remove(self.cursor_row + 1);
            let mut yanked = vec!['\n'];
            yanked.extend(next);
            self.clipboard = Some(yanked);
        }
        self.modified = true;
        self.status_msg = None;
    }

    /// Paste clipboard contents (yank).
    fn yank_line(&mut self) {
        let Some(clip) = self.clipboard.clone() else {
            return;
        };
        if clip.first() == Some(&'\n') {
            // Insert as new line below
            let content: Vec<char> = clip.into_iter().skip(1).collect();
            self.lines.insert(self.cursor_row + 1, content);
            self.cursor_row += 1;
            self.cursor_col = 0;
        } else {
            for &ch in &clip {
                self.lines[self.cursor_row].insert(self.cursor_col, ch);
                self.cursor_col += 1;
            }
        }
        self.modified = true;
    }

    // ── rendering ───────────────────────────────────────────────────────────

    fn render(&mut self, stdout: &mut io::Stdout) -> io::Result<()> {
        let (cols, rows) = terminal::size()?;
        let cols = cols as usize;
        let rows = rows as usize;
        let content_rows = rows.saturating_sub(2); // 1 title + 1 footer
        let gutter = self.gutter_width();
        let text_cols = cols.saturating_sub(gutter);

        self.ensure_cursor_visible(content_rows, text_cols);

        queue!(stdout, cursor::Hide)?;

        // ── Title bar ──────────────────────────────────────────────────────
        let mod_flag = if self.modified { "[+] " } else { "     " };
        let left = format!("  ✎  {}  {}", self.filename, mod_flag);
        let right = format!(" Ln {}, Col {}  ", self.cursor_row + 1, self.cursor_col + 1);
        let mid_pad = cols.saturating_sub(left.chars().count() + right.chars().count());
        let title = format!("{}{}{}", left, " ".repeat(mid_pad), right);
        let title_trunc: String = title.chars().take(cols).collect();

        queue!(
            stdout,
            cursor::MoveTo(0, 0),
            SetBackgroundColor(Color::Rgb {
                r: 0,
                g: 84,
                b: 166
            }),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
            Print(format!("{:<width$}", title_trunc, width = cols)),
            SetAttribute(Attribute::Reset),
        )?;

        // ── Content area ──────────────────────────────────────────────────
        let digits = format!("{}", self.lines.len()).len().max(2);

        for screen_row in 0..content_rows {
            let file_row = self.scroll_row + screen_row;
            queue!(
                stdout,
                cursor::MoveTo(0, (screen_row + 1) as u16),
                ResetColor,
                terminal::Clear(ClearType::CurrentLine),
            )?;

            if file_row < self.lines.len() {
                let is_current = file_row == self.cursor_row;

                // Gutter: " NNN │ "
                if is_current {
                    queue!(
                        stdout,
                        SetForegroundColor(Color::Cyan),
                        SetAttribute(Attribute::Bold),
                    )?;
                } else {
                    queue!(
                        stdout,
                        SetForegroundColor(Color::Rgb {
                            r: 90,
                            g: 90,
                            b: 90
                        }),
                        SetAttribute(Attribute::Reset),
                    )?;
                }
                queue!(
                    stdout,
                    SetBackgroundColor(Color::Rgb {
                        r: 28,
                        g: 28,
                        b: 28
                    }),
                    Print(format!(" {:>width$} ", file_row + 1, width = digits)),
                    SetForegroundColor(Color::Rgb {
                        r: 60,
                        g: 60,
                        b: 60
                    }),
                    Print("│"),
                    SetAttribute(Attribute::Reset),
                    ResetColor,
                    Print(" "),
                )?;

                // Current line highlight
                if is_current {
                    queue!(
                        stdout,
                        SetBackgroundColor(Color::Rgb {
                            r: 30,
                            g: 30,
                            b: 50
                        }),
                    )?;
                }

                // Text content (scrolled)
                let line = &self.lines[file_row];
                let start = self.scroll_col.min(line.len());
                let end = (start + text_cols).min(line.len());
                let display: String = line[start..end].iter().collect();
                queue!(
                    stdout,
                    Print(format!("{:<width$}", display, width = text_cols)),
                    ResetColor,
                )?;
            } else {
                // Past end-of-file: dim tilde, like vim
                queue!(
                    stdout,
                    SetBackgroundColor(Color::Rgb {
                        r: 28,
                        g: 28,
                        b: 28
                    }),
                    SetForegroundColor(Color::Rgb {
                        r: 60,
                        g: 60,
                        b: 90
                    }),
                    Print(format!(" {:>width$} ", "~", width = digits)),
                    ResetColor,
                    Print(format!("{:<width$}", " ", width = text_cols + 2)),
                )?;
            }
        }

        // ── Footer / keybinding bar ────────────────────────────────────────
        self.render_footer(stdout, cols, rows)?;

        // ── Reposition visible cursor ──────────────────────────────────────
        let screen_col = (self.cursor_col.saturating_sub(self.scroll_col) + gutter) as u16;
        let screen_row = (self.cursor_row - self.scroll_row + 1) as u16;
        queue!(stdout, cursor::Show, cursor::MoveTo(screen_col, screen_row))?;

        stdout.flush()
    }

    fn render_footer(&self, stdout: &mut io::Stdout, cols: usize, rows: usize) -> io::Result<()> {
        let y = (rows - 1) as u16;
        queue!(stdout, cursor::MoveTo(0, y))?;

        // If there's a transient status message, show it centred.
        if let Some(msg) = &self.status_msg {
            queue!(
                stdout,
                SetBackgroundColor(Color::Rgb {
                    r: 30,
                    g: 100,
                    b: 30
                }),
                SetForegroundColor(Color::White),
                SetAttribute(Attribute::Bold),
                Print(format!("{:^width$}", msg, width = cols)),
                SetAttribute(Attribute::Reset),
                ResetColor,
            )?;
            return Ok(());
        }

        // Alternating dark-bg shortcut hints
        let shortcuts: &[(&str, &str)] = &[
            ("^S", "Save"),
            ("^X", "Save+Exit"),
            ("^Q", "Quit"),
            ("^K", "Cut"),
            ("^U", "Paste"),
            ("^E", "End"),
            ("^A", "Home"),
        ];

        queue!(
            stdout,
            SetBackgroundColor(Color::Rgb {
                r: 38,
                g: 38,
                b: 38
            }),
        )?;

        let mut x: u16 = 0;
        for (i, (key, label)) in shortcuts.iter().enumerate() {
            if x as usize >= cols {
                break;
            }
            // Alternating key bracket colour
            let key_color = if i % 2 == 0 {
                Color::Cyan
            } else {
                Color::Green
            };
            // Key badge
            queue!(
                stdout,
                cursor::MoveTo(x, y),
                SetBackgroundColor(Color::Rgb {
                    r: 60,
                    g: 60,
                    b: 60
                }),
                SetForegroundColor(key_color),
                SetAttribute(Attribute::Bold),
                Print(format!(" {} ", key)),
                SetAttribute(Attribute::Reset),
            )?;
            x += (key.len() + 2) as u16;

            // Label
            let label_str = format!(" {}  ", label);
            queue!(
                stdout,
                cursor::MoveTo(x, y),
                SetBackgroundColor(Color::Rgb {
                    r: 38,
                    g: 38,
                    b: 38
                }),
                SetForegroundColor(Color::Rgb {
                    r: 200,
                    g: 200,
                    b: 200
                }),
                Print(&label_str),
            )?;
            x += label_str.len() as u16;
        }

        // Pad the rest of the footer
        if (x as usize) < cols {
            queue!(
                stdout,
                cursor::MoveTo(x, y),
                SetBackgroundColor(Color::Rgb {
                    r: 38,
                    g: 38,
                    b: 38
                }),
                Print(format!("{:<width$}", "", width = cols - x as usize)),
            )?;
        }

        queue!(stdout, ResetColor)
    }

    // ── confirm discard ─────────────────────────────────────────────────────

    /// Write a prompt and block waiting for y/n.  Returns true if the user
    /// confirmed they want to discard changes.
    fn confirm_discard(&mut self, stdout: &mut io::Stdout) -> io::Result<bool> {
        let (cols, rows) = terminal::size()?;
        let y = rows - 1;

        let msg = "  Discard unsaved changes? [y/N]  ";
        queue!(
            stdout,
            cursor::MoveTo(0, y),
            SetBackgroundColor(Color::Rgb {
                r: 150,
                g: 60,
                b: 0
            }),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
            Print(format!("{:<width$}", msg, width = cols as usize)),
            SetAttribute(Attribute::Reset),
            ResetColor,
            cursor::Show,
            cursor::MoveTo(msg.len() as u16 - 2, y),
        )?;
        stdout.flush()?;

        loop {
            if let Event::Key(KeyEvent {
                code,
                kind: KeyEventKind::Press,
                ..
            }) = event::read()?
            {
                return match code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => Ok(true),
                    _ => Ok(false),
                };
            }
        }
    }

    // ── main entry point ────────────────────────────────────────────────────

    /// Enter alternate screen, run the event loop, restore terminal.
    /// Returns `true` if the content should be saved.
    fn run(&mut self) -> io::Result<bool> {
        let mut stdout = io::stdout();
        terminal::enable_raw_mode()?;
        execute!(stdout, EnterAlternateScreen, cursor::Hide)?;

        let result = self.event_loop(&mut stdout);

        // Always restore terminal, even on error
        let _ = execute!(stdout, LeaveAlternateScreen, cursor::Show);
        let _ = terminal::disable_raw_mode();

        result
    }

    fn event_loop(&mut self, stdout: &mut io::Stdout) -> io::Result<bool> {
        loop {
            self.render(stdout)?;

            let (_, rows) = terminal::size()?;
            let content_rows = (rows as usize).saturating_sub(2);

            match event::read()? {
                Event::Key(KeyEvent {
                    code,
                    modifiers,
                    kind: KeyEventKind::Press,
                    ..
                }) => {
                    match (code, modifiers) {
                        // ── Save & stay ──────────────────────────────────
                        (KeyCode::Char('s'), KeyModifiers::CONTROL) => {
                            self.modified = false;
                            self.status_msg = Some("  ✔  Saved!  ".to_string());
                            return Ok(true);
                        }
                        // ── Save & exit ──────────────────────────────────
                        (KeyCode::Char('x'), KeyModifiers::CONTROL) => {
                            return Ok(true);
                        }
                        // ── Quit without saving ───────────────────────────
                        (KeyCode::Char('q'), KeyModifiers::CONTROL) => {
                            if self.modified {
                                if self.confirm_discard(stdout)? {
                                    return Ok(false);
                                }
                                // Redraw after prompt
                            } else {
                                return Ok(false);
                            }
                        }
                        // ── Navigation ───────────────────────────────────
                        (KeyCode::Up, _) => self.move_up(),
                        (KeyCode::Down, _) => self.move_down(),
                        (KeyCode::Left, _) => self.move_left(),
                        (KeyCode::Right, _) => self.move_right(),
                        (KeyCode::Home, _) | (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
                            self.move_home()
                        }
                        (KeyCode::End, _) | (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
                            self.move_end()
                        }
                        (KeyCode::PageUp, _) => self.page_up(content_rows),
                        (KeyCode::PageDown, _) => self.page_down(content_rows),
                        // ── Editing ───────────────────────────────────────
                        (KeyCode::Enter, _) => self.insert_newline(),
                        (KeyCode::Backspace, _) => self.backspace(),
                        (KeyCode::Delete, _) => self.delete_forward(),
                        (KeyCode::Char('k'), KeyModifiers::CONTROL) => self.kill_line(),
                        (KeyCode::Char('u'), KeyModifiers::CONTROL) => self.yank_line(),
                        // ── Regular character ─────────────────────────────
                        (KeyCode::Char(c), m)
                            if m == KeyModifiers::NONE || m == KeyModifiers::SHIFT =>
                        {
                            self.insert_char(c)
                        }
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {
                    // next render() call will pick up new dimensions
                }
                _ => {}
            }
        }
    }
}
