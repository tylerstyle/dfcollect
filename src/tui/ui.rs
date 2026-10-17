//! Pure rendering functions for the `dfcollect` TUI (`Home`, `FilesForm`,
//! `Preview`, `Running`, `Result`, `Verify` and modal overlays).
//!
//! Uses only the standard 16 ANSI colours (`Color::Cyan`, `Green`, `Yellow`,
//! `Red`, `Magenta`, `White`, `DarkGray`, `Black`) so the interface renders
//! cleanly on Linux virtual consoles and serial terminals (`TERM=vt220`/`linux`)
//! down to 80×24.

use crate::{
    common::{human_bytes, Phase},
    files::PREVIEW_SAMPLE,
    meta::Kind,
    tui::{
        app::{
            confirm_start_lines, exit_code_meaning, format_duration, App, Modal, NoticeLevel,
            PreviewData, PreviewState, Screen, VerifyFocus, VerifyReportData, HOME_ITEMS,
        },
        command::{files_argv, shell_quote},
        form::FilesField,
        input::{str_width, truncate_to_width, visible_window, wrap_text},
    },
    VERSION,
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, Paragraph},
    Frame,
};
use std::sync::atomic::Ordering;

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn window_and_col(text: &str, cursor: usize, width: usize) -> (String, usize) {
    let (before, under, after) = visible_window(text, cursor, width);
    let col = str_width(&before);
    let mut win = before;
    if let Some(c) = under {
        win.push(c);
    }
    win.push_str(&after);
    (win, col)
}

pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < 40 || area.height < 10 {
        let msg = Paragraph::new(format!(
            "Terminal too small ({}x{}); need at least 80x24.",
            area.width, area.height
        ))
        .style(Style::default().fg(Color::Yellow));
        frame.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(area);

    render_title_bar(frame, chunks[0], app);

    match app.screen {
        Screen::Home => render_home(frame, chunks[1], app),
        Screen::FilesForm => render_files_form(frame, chunks[1], app),
        Screen::Preview => render_preview(frame, chunks[1], app),
        Screen::Running => render_running(frame, chunks[1], app),
        Screen::Result => render_result(frame, chunks[1], app),
        Screen::Verify => render_verify(frame, chunks[1], app),
    }

    render_footer(frame, chunks[2], app);

    if let Some(comp) = &app.completion {
        if !comp.candidates.is_empty() {
            render_completion_popup(frame, area, &comp.candidates, comp.index);
        }
    }

    if let Some(modal) = &app.modal {
        render_modal(frame, area, app, modal);
    }
}

fn push_wrapped_field(
    lines: &mut Vec<Line<'static>>,
    label: &'static str,
    value: &str,
    value_style: Style,
    total_width: usize,
) {
    let label_w = str_width(label);
    let avail = total_width.saturating_sub(label_w).max(16);
    let wrapped = wrap_text(value, avail);
    let indent = " ".repeat(label_w);
    for (i, part) in wrapped.into_iter().enumerate() {
        if i == 0 {
            lines.push(Line::from(vec![
                Span::styled(label, Style::default().fg(Color::Gray)),
                Span::styled(part, value_style),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::raw(indent.clone()),
                Span::styled(part, value_style),
            ]));
        }
    }
}

fn push_wrapped_bullet(
    lines: &mut Vec<Line<'static>>,
    prefix: &'static str,
    text: &str,
    style: Style,
    total_width: usize,
) {
    let prefix_w = str_width(prefix);
    let avail = total_width.saturating_sub(prefix_w).max(16);
    let wrapped = wrap_text(text, avail);
    let indent = " ".repeat(prefix_w);
    for (i, part) in wrapped.into_iter().enumerate() {
        if i == 0 {
            lines.push(Line::from(Span::styled(format!("{prefix}{part}"), style)));
        } else {
            lines.push(Line::from(Span::styled(format!("{indent}{part}"), style)));
        }
    }
}

fn render_title_bar(frame: &mut Frame, area: Rect, app: &App) {
    let screen_name = match app.screen {
        Screen::Home => "Home",
        Screen::FilesForm => "Files",
        Screen::Preview => "Preview",
        Screen::Running => "Running",
        Screen::Result => "Result",
        Screen::Verify => "Verify",
    };
    let left = format!(" dfcollect {VERSION} — logical forensic acquisition ");
    let right = format!(" [{screen_name}] ");
    let pad = (area.width as usize).saturating_sub(str_width(&left) + str_width(&right));
    let line = Line::from(vec![
        Span::styled(
            left,
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " ".repeat(pad),
            Style::default().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::styled(
            right,
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let notice_line = if let Some(n) = &app.notice {
        let (prefix, color) = match n.level {
            NoticeLevel::Info => ("INFO: ", Color::Cyan),
            NoticeLevel::Warning => ("WARN: ", Color::Yellow),
            NoticeLevel::Error => ("ERROR: ", Color::Red),
        };
        let text = truncate_to_width(
            &format!("{prefix}{}", n.text),
            area.width.saturating_sub(1) as usize,
        );
        Line::from(Span::styled(
            text,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
    } else {
        match app.screen {
            Screen::FilesForm => {
                let cmd = shell_quote(&files_argv(&app.files_form));
                let shown = truncate_to_width(
                    &format!("cmd: {cmd}"),
                    area.width.saturating_sub(1) as usize,
                );
                Line::from(Span::styled(shown, Style::default().fg(Color::DarkGray)))
            }
            Screen::Home => {
                let item = &HOME_ITEMS[app.home_idx.min(HOME_ITEMS.len() - 1)];
                let shown = truncate_to_width(item.hint, area.width.saturating_sub(1) as usize);
                Line::from(Span::styled(shown, Style::default().fg(Color::Cyan)))
            }
            _ => Line::from(""),
        }
    };

    let keys = match app.screen {
        Screen::Home => " ↑/↓ select  Enter open  f files  v verify  ? keys  q quit",
        Screen::FilesForm => {
            " Tab/↑↓ move  Enter edit/toggle  F2/p preview  F4/Tab complete  ? keys  Esc"
        }
        Screen::Preview if app.is_worker_running() => " Esc / s stop preview  ? keys",
        Screen::Preview => " Enter start  e/Esc edit  c copy cmd  r/F2 re-run  ↑/↓ scroll  ? keys",
        Screen::Running => {
            " s/Ctrl+C stop (closes as aborted)  ? keys  (quit disabled while running)"
        }
        Screen::Result => " v verify  n next acquisition  h/Esc home  ↑/↓ scroll  ? keys  q quit",
        Screen::Verify if app.is_worker_running() => " Esc / s stop verification  ? keys",
        Screen::Verify => {
            " Enter/F2 verify  Tab focus  F4/Tab complete  ↑/↓ scroll  ? keys  Esc  q quit"
        }
    };
    let keys_line = Line::from(Span::styled(
        truncate_to_width(keys, area.width as usize),
        Style::default().fg(Color::Black).bg(Color::Gray),
    ));

    frame.render_widget(Paragraph::new(vec![notice_line, keys_line]), area);
}

// ------------------------------------------------------------------
// 4.1 Home screen
// ------------------------------------------------------------------

fn render_home(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(format!(" dfcollect {VERSION} — logical acquisition "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        " Select an operation:",
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    for (i, item) in HOME_ITEMS.iter().enumerate() {
        if i == 2 {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "   ── command line only (for now) ──",
                Style::default().fg(Color::DarkGray),
            )));
        }
        let selected = i == app.home_idx;
        let marker = if selected { " ▸ " } else { "   " };
        let title_width = 44usize;
        let padded_title = format!(
            "{:<width$}",
            truncate_to_width(item.title, title_width),
            width = title_width
        );
        if item.enabled {
            let row_style = if selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let cmd_style = if selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Cyan)
            };
            lines.push(Line::from(vec![
                Span::styled(marker, row_style),
                Span::styled(padded_title, row_style),
                Span::raw("  "),
                Span::styled(item.command, cmd_style),
            ]));
        } else {
            let row_style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            lines.push(Line::from(vec![
                Span::styled(marker, row_style),
                Span::styled(padded_title, row_style),
                Span::raw("  "),
                Span::styled(item.command, row_style),
            ]));
        }
    }

    lines.push(Line::from(""));
    let selected_item = &HOME_ITEMS[app.home_idx.min(HOME_ITEMS.len() - 1)];
    if !selected_item.enabled {
        lines.push(Line::from(vec![
            Span::styled(
                " CLI usage: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                selected_item.command,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

// ------------------------------------------------------------------
// 4.2 Files form screen
// ------------------------------------------------------------------

fn render_files_form(frame: &mut Frame, area: Rect, app: &App) {
    let form = &app.files_form;
    let block = Block::default()
        .title(" Acquire files from a mounted directory (dfcollect files) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 20 || inner.height < 4 {
        return;
    }

    let label_col = 18usize;
    let val_width = (inner.width as usize).saturating_sub(label_col + 4).max(10);

    let mut lines: Vec<Line> = Vec::new();
    let mut focused_line_idx: usize = 0;
    let mut cursor_screen_offset: Option<(usize, u16)> = None;

    for field in FilesField::ALL {
        if !form.applies(field) {
            continue;
        }
        // Section headers
        match field {
            FilesField::CaseNumber => {
                push_section(&mut lines, "Case metadata (case & examiner kept on 'n')")
            }
            FilesField::SourceMount | FilesField::SourcePath
                if field == FilesField::SourceMount
                    || (field == FilesField::SourcePath && form.source_mounts.is_empty()) =>
            {
                push_section(
                    &mut lines,
                    "Source (read-only mount) & Output collection directory",
                );
            }
            FilesField::ScopeFile => push_section(
                &mut lines,
                "Scope (warrant patterns, time window or JSON file)",
            ),
            FilesField::ReferenceTime => {
                push_section(&mut lines, "Reference clock (both or neither)")
            }
            FilesField::Md5 => push_section(&mut lines, "Hashes & container options"),
            FilesField::AllowTmpfs => {
                push_section(&mut lines, "Safety overrides (require confirmation)")
            }
            FilesField::PreviewButton => lines.push(Line::from("")),
            _ => {}
        }

        let is_focused = form.field == field;
        let line_idx = lines.len();
        if is_focused {
            focused_line_idx = line_idx;
        }

        let marker = if is_focused { "▸ " } else { "  " };
        let label = format!("{:<width$}", field.label(), width = label_col);
        let label_style = if is_focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        if field == FilesField::PreviewButton {
            let btn_style = if is_focused {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            };
            lines.push(Line::from(vec![
                Span::styled(marker, label_style),
                Span::styled(form.value_text(field), btn_style),
            ]));
            continue;
        }

        if field.is_text() {
            let raw = form.text(field).map(String::as_str).unwrap_or("");
            let (shown_span, cursor_col) = if raw.is_empty() && (!is_focused || !form.editing) {
                (
                    Span::styled(
                        truncate_to_width(field.placeholder(), val_width),
                        Style::default().fg(Color::DarkGray),
                    ),
                    0,
                )
            } else {
                let cur = if is_focused { form.cursor } else { raw.len() };
                let (win, col) = window_and_col(raw, cur, val_width);
                let style = if is_focused {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                (Span::styled(win, style), col)
            };

            if is_focused {
                let x_off = (2 + label_col + cursor_col) as u16;
                cursor_screen_offset = Some((line_idx, x_off));
            }

            lines.push(Line::from(vec![
                Span::styled(marker, label_style),
                Span::styled(label, label_style),
                shown_span,
            ]));
        } else {
            let val = truncate_to_width(&form.value_text(field), val_width);
            let val_style = if field.is_safety()
                && ((field == FilesField::AllowTmpfs && form.allow_tmpfs)
                    || (field == FilesField::AllowWritableSource && form.allow_writable_source))
            {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else if is_focused {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::styled(marker, label_style),
                Span::styled(label, label_style),
                Span::styled(val, val_style),
            ]));
        }

        // Live probe info / UTC hints / validation errors under the field
        let indent = " ".repeat(2 + label_col);
        if field == FilesField::SourcePath {
            if let Some(p) = &form.source_probe {
                if p.exists && p.is_dir && p.read_only {
                    lines.push(Line::from(Span::styled(
                        format!("{indent}✓ read-only directory"),
                        Style::default().fg(Color::Green),
                    )));
                }
            }
        } else if field == FilesField::OutputPath {
            if let Some(p) = &form.output_probe {
                if let Some(free) = p.free_bytes {
                    lines.push(Line::from(Span::styled(
                        format!("{indent}Free space on target: {}", human_bytes(free)),
                        Style::default().fg(Color::Cyan),
                    )));
                }
            }
        } else if matches!(
            field,
            FilesField::NotBefore | FilesField::NotAfter | FilesField::ReferenceTime
        ) {
            if let Some(hint) = form.utc_hint(field) {
                lines.push(Line::from(Span::styled(
                    format!("{indent}{hint}"),
                    Style::default().fg(Color::Cyan),
                )));
            }
            if field == FilesField::ReferenceTime {
                if let Some(stamp) = form.reference_stamp_hint() {
                    lines.push(Line::from(Span::styled(
                        format!("{indent}{stamp}"),
                        Style::default().fg(Color::Green),
                    )));
                }
            }
        }

        if let Some(err) = form.validate_field(field) {
            let should_show = is_focused
                || !form.text(field).is_some_and(|t| t.trim().is_empty())
                || matches!(field, FilesField::SourcePath | FilesField::OutputPath);
            if should_show {
                let msg = truncate_to_width(&format!("{indent}! {err}"), inner.width as usize);
                lines.push(Line::from(Span::styled(
                    msg,
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
            }
        }
    }

    let height = inner.height as usize;
    let scroll = if focused_line_idx + 2 >= height {
        (focused_line_idx + 3).saturating_sub(height)
    } else {
        0
    };
    let visible: Vec<Line> = lines.into_iter().skip(scroll).take(height).collect();
    frame.render_widget(Paragraph::new(visible), inner);

    if app.modal.is_none() {
        if let Some((line_idx, x_off)) = cursor_screen_offset {
            if line_idx >= scroll && line_idx - scroll < height {
                let y = inner.y + (line_idx - scroll) as u16;
                let x = (inner.x + x_off).min(inner.x + inner.width.saturating_sub(1));
                frame.set_cursor_position(Position::new(x, y));
            }
        }
    }
}

fn push_section(lines: &mut Vec<Line<'static>>, title: &'static str) {
    if !lines.is_empty() {
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        format!(" ── {title} ──"),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
}

// ------------------------------------------------------------------
// 4.3 Preview screen
// ------------------------------------------------------------------

fn render_preview(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Scope Preview (Dry Run — metadata only, nothing written) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match &app.preview_state {
        None => {
            frame.render_widget(
                Paragraph::new("No preview loaded. Press Esc to return to the form."),
                inner,
            );
        }
        Some(PreviewState::Running {
            argv,
            progress,
            started,
            ..
        }) => {
            let spin = SPINNER[(app.ticks as usize) % SPINNER.len()];
            let entries = progress.entries.load(Ordering::Relaxed);
            let files = progress.files.load(Ordering::Relaxed);
            let bytes = progress.bytes.load(Ordering::Relaxed);
            let oos = progress.out_of_scope.load(Ordering::Relaxed);
            let errs = progress.errors.load(Ordering::Relaxed);
            let elapsed = format_duration(started.elapsed());

            let mut lines = vec![
                Line::from(Span::styled(
                    format!(" {spin} Walking source tree and evaluating scope ({elapsed})..."),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!("   Entries examined : {entries}")),
                Line::from(format!(
                    "   In-scope files   : {files} ({})",
                    human_bytes(bytes)
                )),
                Line::from(format!("   Out of scope     : {oos}")),
                Line::from(format!("   Errors           : {errs}")),
                Line::from(""),
                Line::from(Span::styled(
                    " Equivalent command:",
                    Style::default()
                        .fg(Color::Gray)
                        .add_modifier(Modifier::BOLD),
                )),
            ];
            let cmd = shell_quote(argv);
            for w in wrap_text(&cmd, inner.width.saturating_sub(4) as usize) {
                lines.push(Line::from(Span::styled(
                    format!("   {w}"),
                    Style::default().fg(Color::White),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " Press Esc or 's' to stop the preview early.",
                Style::default().fg(Color::Yellow),
            )));
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Some(PreviewState::Failed { argv, error, code }) => {
            let mut lines = vec![
                Line::from(Span::styled(
                    format!(
                        " Preview failed (exit {code}: {})",
                        exit_code_meaning(*code, false)
                    ),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];
            for w in wrap_text(error, inner.width.saturating_sub(4) as usize) {
                lines.push(Line::from(Span::styled(
                    format!("   {w}"),
                    Style::default().fg(Color::Red),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " Equivalent command:",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD),
            )));
            let cmd = shell_quote(argv);
            for w in wrap_text(&cmd, inner.width.saturating_sub(4) as usize) {
                lines.push(Line::from(Span::styled(
                    format!("   {w}"),
                    Style::default().fg(Color::White),
                )));
            }
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Some(PreviewState::Ready(data)) => {
            render_preview_ready(frame, inner, app, data);
        }
    }
}

fn render_preview_ready(frame: &mut Frame, area: Rect, app: &App, data: &PreviewData) {
    let pv = &data.preview;
    let stale = app.is_preview_stale();

    let cmd_str = shell_quote(&data.argv);
    let cmd_wrapped = wrap_text(&cmd_str, area.width.saturating_sub(4) as usize);
    let cmd_height = (cmd_wrapped.len() as u16 + 2).min(5);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if stale || pv.short_of_space() { 9 } else { 8 }),
            Constraint::Min(5),
            Constraint::Length(cmd_height),
        ])
        .split(area);

    // 1. Summary section
    let mut sum_lines = Vec::new();
    if let Some(reason) = &pv.stopped {
        sum_lines.push(Line::from(Span::styled(
            format!(
                " ! STOPPED EARLY ({reason}) — press F2 / 'r' to re-run preview before starting"
            ),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    } else if stale {
        sum_lines.push(Line::from(Span::styled(
            " ! STALE PREVIEW (form changed) — press F2 / 'r' to re-run preview before starting",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }

    push_wrapped_field(
        &mut sum_lines,
        " In scope  : ",
        &format!(
            "{} files ({}), {} dirs, {} symlinks, {} special ({} acquired)",
            pv.files,
            human_bytes(pv.bytes),
            pv.directories,
            pv.symlinks,
            pv.special,
            pv.acquired()
        ),
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        area.width as usize,
    );

    let space_line = match pv.target_free {
        Some(free) if pv.short_of_space() => Line::from(vec![
            Span::styled(" Target    : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "WARNING: {} free < {} in-scope bytes (short of space!)",
                    human_bytes(free),
                    human_bytes(pv.bytes)
                ),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
        Some(free) => Line::from(vec![
            Span::styled(" Target    : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "{} free vs {} in-scope bytes",
                    human_bytes(free),
                    human_bytes(pv.bytes)
                ),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        None => Line::from(vec![
            Span::styled(" Target    : ", Style::default().fg(Color::Gray)),
            Span::raw("unknown"),
        ]),
    };
    sum_lines.push(space_line);

    let oos_total: u64 = pv.out_of_scope.values().sum();
    let oos_reasons: Vec<String> = pv
        .out_of_scope
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    let oos_summary = if oos_reasons.is_empty() {
        "0 items".to_string()
    } else {
        format!("{oos_total} ({})", oos_reasons.join("; "))
    };
    sum_lines.push(Line::from(vec![
        Span::styled(" Excluded  : ", Style::default().fg(Color::Gray)),
        Span::styled(
            truncate_to_width(&oos_summary, area.width.saturating_sub(14) as usize),
            Style::default().fg(Color::Yellow),
        ),
    ]));

    sum_lines.push(Line::from(vec![
        Span::styled(" Unlisted  : ", Style::default().fg(Color::Gray)),
        Span::raw(format!(
            "{} excluded tree(s), {} tree(s) outside includes",
            pv.excluded_trees, pv.trees_outside_includes
        )),
    ]));

    let other_fs = if pv.other_filesystems.is_empty() {
        "none".to_string()
    } else {
        format!(
            "{} ({})",
            pv.other_filesystems.len(),
            pv.other_filesystems.join(", ")
        )
    };
    sum_lines.push(Line::from(vec![
        Span::styled(" Other fs  : ", Style::default().fg(Color::Gray)),
        Span::raw(truncate_to_width(
            &other_fs,
            area.width.saturating_sub(14) as usize,
        )),
    ]));

    let err_summary = if pv.errors.is_empty() {
        Span::styled("0", Style::default().fg(Color::Green))
    } else {
        let joined: Vec<String> = pv.errors.iter().map(|(p, e)| format!("{p}: {e}")).collect();
        Span::styled(
            truncate_to_width(
                &format!("{} ({})", pv.errors.len(), joined.join("; ")),
                area.width.saturating_sub(14) as usize,
            ),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    };
    sum_lines.push(Line::from(vec![
        Span::styled(" Walk errs : ", Style::default().fg(Color::Gray)),
        err_summary,
    ]));

    frame.render_widget(Paragraph::new(sum_lines), chunks[0]);

    // 2. Scrollable sample of in-scope entries (never any out-of-scope names)
    let total_in_scope = pv.acquired() + pv.special;
    let sample_title = format!(
        " In-scope sample (showing {} of {total_in_scope}, max {PREVIEW_SAMPLE}; ↑/↓/PgUp/PgDn) ",
        pv.sample.len()
    );
    let sample_block = Block::default()
        .title(sample_title)
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let sample_inner = sample_block.inner(chunks[1]);
    frame.render_widget(sample_block, chunks[1]);

    let mut sample_lines = Vec::new();
    let rows_avail = sample_inner.height as usize;
    for entry in pv.sample.iter().skip(data.scroll).take(rows_avail) {
        let (mark, mark_color, suffix) = match entry.kind {
            Kind::File => (
                "f",
                Color::Green,
                format!(" ({})", human_bytes(entry.size.unwrap_or(0))),
            ),
            Kind::Directory => ("d", Color::Cyan, "/".to_string()),
            Kind::Symlink => ("l", Color::Magenta, String::new()),
            Kind::Special(what) => ("s", Color::Yellow, format!(" [{what}]")),
        };
        let path_room = (sample_inner.width as usize)
            .saturating_sub(6 + str_width(&suffix))
            .max(8);
        let shown_path = truncate_to_width(&entry.path, path_room);
        sample_lines.push(Line::from(vec![
            Span::styled(
                format!(" [{mark}] "),
                Style::default().fg(mark_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(shown_path, Style::default().fg(Color::White)),
            Span::styled(suffix, Style::default().fg(Color::DarkGray)),
        ]));
    }
    if sample_lines.is_empty() {
        sample_lines.push(Line::from(Span::styled(
            "   (no in-scope entries matched)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(Paragraph::new(sample_lines), sample_inner);

    // 3. Wrapped command block
    let copy_tag = if data.copied_osc52 {
        " Equivalent CLI command (copied via OSC 52; 'c' to copy again) "
    } else {
        " Equivalent CLI command ('c' to copy via OSC 52) "
    };
    let cmd_block = Block::default()
        .title(copy_tag)
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let cmd_inner = cmd_block.inner(chunks[2]);
    frame.render_widget(cmd_block, chunks[2]);

    let cmd_lines: Vec<Line> = cmd_wrapped
        .into_iter()
        .take(cmd_inner.height as usize)
        .map(|l| {
            Line::from(Span::styled(
                format!(" {l}"),
                Style::default().fg(Color::Cyan),
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(cmd_lines), cmd_inner);
}

// ------------------------------------------------------------------
// 4.4 Running screen
// ------------------------------------------------------------------

fn render_running(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Acquisition in Progress (dfcollect files) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(run) = &app.run_state else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(6),
        ])
        .split(inner);

    let phase = run.progress.phase();
    let files_done = run.progress.files.load(Ordering::Relaxed);
    let bytes_done = run.progress.bytes.load(Ordering::Relaxed);
    let check_bytes = run.progress.check_bytes.load(Ordering::Relaxed);
    let oos = run.progress.out_of_scope.load(Ordering::Relaxed);
    let errs = run.progress.errors.load(Ordering::Relaxed);
    let current = run.progress.current();

    // 1. Phase indicator
    let style_active = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let style_done = Style::default().fg(Color::Green);
    let style_pending = Style::default().fg(Color::DarkGray);

    let (s_copy, s_check, s_fin) = match phase {
        Phase::Listing | Phase::Copying => (style_active, style_pending, style_pending),
        Phase::CheckingContainer => (style_done, style_active, style_pending),
        Phase::Finishing | Phase::Done => (style_done, style_done, style_active),
    };
    let phase_line = Line::from(vec![
        Span::raw(" Phase: "),
        Span::styled("1. Copying", s_copy),
        Span::raw("  →  "),
        Span::styled("2. Checking container", s_check),
        Span::raw("  →  "),
        Span::styled("3. Finishing", s_fin),
    ]);
    let target_line = Line::from(vec![
        Span::styled(" Target: ", Style::default().fg(Color::Gray)),
        Span::styled(
            truncate_to_width(
                &format!(
                    "{} → {}",
                    run.args.source.display(),
                    run.args.output.display()
                ),
                inner.width.saturating_sub(10) as usize,
            ),
            Style::default().fg(Color::White),
        ),
    ]);
    frame.render_widget(Paragraph::new(vec![phase_line, target_line]), chunks[0]);

    // 2. Progress gauge
    let (ratio, label) = match phase {
        Phase::Listing | Phase::Copying => {
            let r = if run.expected_bytes == 0 {
                0.0
            } else {
                (bytes_done as f64 / run.expected_bytes as f64).clamp(0.0, 1.0)
            };
            (
                r,
                format!(
                    "Copying: {} / ~{} ({:.0}%)",
                    human_bytes(bytes_done),
                    human_bytes(run.expected_bytes),
                    r * 100.0
                ),
            )
        }
        Phase::CheckingContainer => {
            let denom = bytes_done.max(1);
            let r = (check_bytes as f64 / denom as f64).clamp(0.0, 1.0);
            (
                r,
                format!(
                    "Verifying container: {} / {} ({:.0}%)",
                    human_bytes(check_bytes),
                    human_bytes(bytes_done),
                    r * 100.0
                ),
            )
        }
        Phase::Finishing | Phase::Done => (1.0, "Closing manifest and audit records...".into()),
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Progress (preview size is an estimate) "),
        )
        .gauge_style(
            Style::default()
                .fg(if run.stop_requested {
                    Color::Yellow
                } else {
                    Color::Cyan
                })
                .bg(Color::Black),
        )
        .ratio(ratio)
        .label(label);
    frame.render_widget(gauge, chunks[1]);

    // 3. Telemetry lines
    let rate_str = run
        .rate_bps()
        .map(|r| format!("{}/s", human_bytes(r)))
        .unwrap_or_else(|| "—".into());
    let elapsed_str = format_duration(run.started.elapsed());
    let eta_str = run
        .eta(bytes_done)
        .map(format_duration)
        .unwrap_or_else(|| "—".into());

    let shown_cur = if current.is_empty() {
        "—".to_string()
    } else {
        truncate_to_width(&current, inner.width.saturating_sub(18) as usize)
    };

    let mut details = vec![
        Line::from(format!(
            " Files acquired : {files_done} / {}",
            run.expected_files
        )),
        Line::from(format!(
            " Bytes copied   : {} (estimate: {})",
            human_bytes(bytes_done),
            human_bytes(run.expected_bytes)
        )),
        Line::from(format!(" Out of scope   : {oos}    Errors: {errs}")),
        Line::from(format!(
            " Rate (5s avg)  : {rate_str}    Elapsed: {elapsed_str}    ETA: {eta_str}"
        )),
        Line::from(vec![
            Span::styled(" Current item   : ", Style::default().fg(Color::Gray)),
            Span::styled(shown_cur, Style::default().fg(Color::White)),
        ]),
    ];
    if run.stop_requested {
        details.push(Line::from(Span::styled(
            " Stopping acquisition — closing collection as aborted...",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
    }
    frame.render_widget(Paragraph::new(details), chunks[2]);
}

// ------------------------------------------------------------------
// 4.5 Result screen
// ------------------------------------------------------------------

fn render_result(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Acquisition Result ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(res) = &app.result_data else {
        return;
    };

    let status_color = match res.code {
        0 => Color::Green,
        7 | 8 => Color::Yellow,
        _ => Color::Red,
    };

    let mut top = Vec::new();
    push_wrapped_field(
        &mut top,
        " Status      : ",
        &format!(
            "{} (exit {}: {})",
            res.status.to_uppercase(),
            res.code,
            exit_code_meaning(res.code, false)
        ),
        Style::default()
            .fg(status_color)
            .add_modifier(Modifier::BOLD),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut top,
        " Collection  : ",
        &format!(
            "{}{}",
            res.collection.display(),
            if res.left_unfinished {
                " (left unfinished)"
            } else {
                ""
            }
        ),
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut top,
        " Acquired    : ",
        &format!("{} item(s) ({})", res.acquired, human_bytes(res.bytes)),
        Style::default().fg(Color::White),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut top,
        " Out of scope: ",
        &format!(
            "{} counted, {} listed, {} excluded tree(s), {} outside includes",
            res.out_of_scope_counted,
            res.out_of_scope_listed,
            res.excluded_trees,
            res.trees_outside_includes
        ),
        Style::default().fg(Color::White),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut top,
        " Errors/Skip : ",
        &format!(
            "{} error(s), {} skipped, {} container mismatch(es)",
            res.errors,
            res.skipped,
            res.container_mismatches.len()
        ),
        Style::default().fg(Color::White),
        inner.width as usize,
    );
    top.push(Line::from(Span::styled(
        " Audit anchor:",
        Style::default().fg(Color::Gray),
    )));
    top.push(Line::from(Span::styled(
        format!(
            " {}",
            res.audit_anchor
                .as_deref()
                .unwrap_or("none (audit log unavailable)")
        ),
        Style::default().fg(Color::Cyan),
    )));
    top.push(Line::from(vec![
        Span::styled(" Command     : ", Style::default().fg(Color::Gray)),
        Span::styled(
            truncate_to_width(
                &shell_quote(&res.argv),
                inner.width.saturating_sub(16) as usize,
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    if let Some(fatal) = &res.fatal_error {
        push_wrapped_field(
            &mut top,
            " Fatal error : ",
            fatal,
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            inner.width as usize,
        );
    }

    let top_h = (top.len() as u16).min(inner.height.saturating_sub(3));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(top_h), Constraint::Min(3)])
        .split(inner);

    frame.render_widget(Paragraph::new(top), chunks[0]);

    let prob_block = Block::default()
        .title(" Problems, Warnings & Container Mismatches (↑/↓/PgUp/PgDn) ")
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let prob_inner = prob_block.inner(chunks[1]);
    frame.render_widget(prob_block, chunks[1]);

    let mut items: Vec<(Color, String)> = Vec::new();
    for m in &res.container_mismatches {
        items.push((Color::Red, format!("[MISMATCH] {m}")));
    }
    for w in &res.warnings {
        items.push((Color::Yellow, format!("[WARN] {w}")));
    }
    for p in &res.problems {
        items.push((Color::Red, format!("[PROBLEM] {p}")));
    }

    let mut all_prob_lines = Vec::new();
    if items.is_empty() {
        all_prob_lines.push(Line::from(Span::styled(
            "   No problems, warnings or container mismatches recorded.",
            Style::default().fg(Color::Green),
        )));
    } else {
        for (color, text) in items {
            push_wrapped_bullet(
                &mut all_prob_lines,
                " • ",
                &text,
                Style::default().fg(color),
                prob_inner.width as usize,
            );
        }
    }
    let max_scroll = all_prob_lines
        .len()
        .saturating_sub(prob_inner.height as usize);
    let eff_scroll = res.scroll.min(max_scroll);
    let prob_lines: Vec<Line> = all_prob_lines
        .into_iter()
        .skip(eff_scroll)
        .take(prob_inner.height as usize)
        .collect();
    frame.render_widget(Paragraph::new(prob_lines), prob_inner);
}

// ------------------------------------------------------------------
// 4.6 Verify screen
// ------------------------------------------------------------------

fn render_verify(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Verify Collection (dfcollect verify) ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let vs = &app.verify_state;
    let session_rows = if app.session_collections.is_empty() {
        0
    } else {
        (app.session_collections.len() as u16 + 1).min(4)
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3 + session_rows), Constraint::Min(6)])
        .split(inner);

    // 1. Input & session collections
    let mut top_lines = Vec::new();
    let path_focused = vs.focus == VerifyFocus::PathInput;
    let path_label = "Collection dir*: ";
    let val_width = (inner.width as usize)
        .saturating_sub(path_label.len() + 4)
        .max(10);
    let (win, col) = if vs.path.is_empty() && !path_focused {
        (
            truncate_to_width("collection directory containing manifest.json", val_width),
            0,
        )
    } else {
        window_and_col(&vs.path, vs.cursor, val_width)
    };
    top_lines.push(Line::from(vec![
        Span::styled(
            if path_focused { "▸ " } else { "  " },
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            path_label,
            if path_focused {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            },
        ),
        Span::styled(
            win,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    if !app.session_collections.is_empty() {
        let sess_focused = vs.focus == VerifyFocus::SessionList;
        top_lines.push(Line::from(Span::styled(
            "  Collections from this session (↑/↓ select, Enter verify):",
            if sess_focused {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            },
        )));
        for (i, dir) in app
            .session_collections
            .iter()
            .enumerate()
            .take(session_rows.saturating_sub(1) as usize)
        {
            let sel = sess_focused && i == vs.session_idx;
            top_lines.push(Line::from(Span::styled(
                format!("   {} {}", if sel { "▸" } else { " " }, dir.display()),
                if sel {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                },
            )));
        }
    }

    let btn_focused = vs.focus == VerifyFocus::VerifyButton;
    top_lines.push(Line::from(vec![
        Span::raw(if btn_focused { "▸ " } else { "  " }),
        Span::styled(
            "[ Verify collection (Enter / F2) ]",
            if btn_focused {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            },
        ),
    ]));

    frame.render_widget(Paragraph::new(top_lines), chunks[0]);

    if path_focused && app.modal.is_none() && !app.is_worker_running() {
        let x = (chunks[0].x + 2 + path_label.len() as u16 + col as u16)
            .min(chunks[0].x + chunks[0].width.saturating_sub(1));
        frame.set_cursor_position(Position::new(x, chunks[0].y));
    }

    // 2. Running gauge or Verification Report
    if let Some(running) = &vs.running {
        let check_bytes = running.progress.check_bytes.load(Ordering::Relaxed);
        let elapsed = format_duration(running.started.elapsed());
        let ratio = match running.container_bytes {
            Some(total) if total > 0 => (check_bytes as f64 / total as f64).clamp(0.0, 1.0),
            _ => 0.0,
        };
        let label = match running.container_bytes {
            Some(total) => format!(
                "Hashing container members: {} / {} ({:.0}%, {elapsed})",
                human_bytes(check_bytes),
                human_bytes(total),
                ratio * 100.0
            ),
            None => format!(
                "Hashing container members: {} read ({elapsed})",
                human_bytes(check_bytes)
            ),
        };
        let g_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(chunks[1]);
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Verifying {} ", running.dir.display())),
            )
            .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
            .ratio(ratio)
            .label(label);
        frame.render_widget(gauge, g_chunks[0]);
    } else if let Some(rep) = &vs.report {
        render_verify_report(frame, chunks[1], rep, vs.scroll);
    }
}

fn render_verify_report(frame: &mut Frame, area: Rect, rep: &VerifyReportData, scroll: usize) {
    let block = Block::default()
        .title(" Verification Report ")
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let (verdict, color) = if rep.ok {
        ("VERIFIED OK", Color::Green)
    } else if rep.code == 8 {
        ("STOPPED", Color::Yellow)
    } else {
        ("VERIFICATION FAILED", Color::Red)
    };

    let mut lines = Vec::new();
    push_wrapped_field(
        &mut lines,
        " Verdict        : ",
        &format!(
            "{verdict} (exit {}: {})",
            rep.code,
            exit_code_meaning(rep.code, true)
        ),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut lines,
        " Collection     : ",
        &format!("{} (manifest status: {})", rep.dir.display(), rep.status),
        Style::default().fg(Color::White),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut lines,
        " Container      : ",
        &format!(
            "{} member(s) verified OK, {} problem(s)",
            rep.members_ok,
            rep.member_problems.len()
        ),
        Style::default().fg(Color::White),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut lines,
        " Items          : ",
        &format!(
            "{} re-hashed OK, {} mismatch, {} missing",
            rep.files_ok,
            rep.files_mismatch.len(),
            rep.files_missing.len()
        ),
        Style::default().fg(Color::White),
        inner.width as usize,
    );
    push_wrapped_field(
        &mut lines,
        " Audit records  : ",
        &format!(
            "start anchor found={}, finish record found={}",
            rep.audit_anchor_found
                .map(|b| if b { "yes" } else { "no" })
                .unwrap_or("n/a"),
            rep.audit_finish_found
                .map(|b| if b { "yes" } else { "no" })
                .unwrap_or("n/a"),
        ),
        Style::default().fg(Color::White),
        inner.width as usize,
    );

    if let Some(stopped) = &rep.stopped {
        push_wrapped_field(
            &mut lines,
            " Stopped        : ",
            stopped,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            inner.width as usize,
        );
    }

    if let Some(fatal) = &rep.fatal_error {
        push_wrapped_field(
            &mut lines,
            " Error          : ",
            fatal,
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            inner.width as usize,
        );
    }

    let mut probs: Vec<String> = Vec::new();
    for m in &rep.files_mismatch {
        probs.push(format!("file hash mismatch: {m}"));
    }
    for m in &rep.files_missing {
        probs.push(format!("missing file: {m}"));
    }
    for p in &rep.member_problems {
        probs.push(p.clone());
    }
    for p in &rep.problems {
        probs.push(p.clone());
    }

    if !probs.is_empty() {
        lines.push(Line::from(Span::styled(
            " Problems:",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        for p in probs {
            push_wrapped_bullet(
                &mut lines,
                "   • ",
                &p,
                Style::default().fg(Color::Red),
                inner.width as usize,
            );
        }
    }

    let max_scroll = lines.len().saturating_sub(inner.height as usize);
    let eff_scroll = scroll.min(max_scroll);
    let visible: Vec<Line> = lines
        .into_iter()
        .skip(eff_scroll)
        .take(inner.height as usize)
        .collect();
    frame.render_widget(Paragraph::new(visible), inner);
}

// ------------------------------------------------------------------
// Modals & completion popup
// ------------------------------------------------------------------

fn render_completion_popup(
    frame: &mut Frame,
    area: Rect,
    candidates: &[String],
    selected: Option<usize>,
) {
    let h = (candidates.len() as u16 + 2).min(8);
    let w = area.width.saturating_sub(6).min(72);
    let y = area.height.saturating_sub(h + 3);
    let rect = Rect::new(area.x + 3, y, w, h);
    frame.render_widget(Clear, rect);

    let block = Block::default()
        .title(format!(
            " Path completions ({}) — Tab/F4 cycle ",
            candidates.len()
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let skip = selected
        .unwrap_or(0)
        .saturating_sub(inner.height.saturating_sub(1) as usize);
    let lines: Vec<Line> = candidates
        .iter()
        .enumerate()
        .skip(skip)
        .take(inner.height as usize)
        .map(|(i, c)| {
            let is_sel = selected == Some(i);
            let style = if is_sel {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(
                truncate_to_width(c, inner.width as usize),
                style,
            ))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_modal(frame: &mut Frame, area: Rect, app: &App, modal: &Modal) {
    match modal {
        Modal::Help => {
            let rect = centered_rect(72, 18, area);
            frame.render_widget(Clear, rect);
            let block = Block::default()
                .title(" Keybindings ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let lines = vec![
                Line::from(Span::styled(
                    " Navigation & Forms",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from("   Tab / Shift-Tab / ↑ / ↓   Move between fields or items"),
                Line::from("   Enter / Space / ← / →     Edit text, toggle option or cycle picker"),
                Line::from("   F4 (or Tab while typing)  Autocomplete directory/file path"),
                Line::from("   a / d / Enter             Add, delete or edit glob pattern in list"),
                Line::from("   F2 / p / Ctrl+P           Run scope preview (--dry-run)"),
                Line::from(""),
                Line::from(Span::styled(
                    " Preview, Run & Result",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from("   Enter (in Preview)        Open confirmation sheet to start"),
                Line::from("   c (in Preview)            Copy equivalent CLI command via OSC 52"),
                Line::from(
                    "   s / Ctrl+C (in Run)       Stop acquisition (closes as aborted, exit 8)",
                ),
                Line::from("   v / n (in Result)         Verify collection / New acquisition"),
                Line::from("   Esc / q                   Back / Quit (when not running)"),
                Line::from(""),
                Line::from(Span::styled(
                    " Press Esc, Enter or '?' to close.",
                    Style::default().fg(Color::Yellow),
                )),
            ];
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Modal::ConfirmSafety { field } => {
            let rect = centered_rect(68, 10, area);
            frame.render_widget(Clear, rect);
            let block = Block::default()
                .title(format!(" Confirm Safety Override: {} ", field.label()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let body = match field {
                FilesField::AllowTmpfs => {
                    "Allow writing the collection to RAM (tmpfs / ramfs)? Data in RAM is lost on power-off or reboot."
                }
                FilesField::AllowWritableSource => {
                    "Allow acquiring from a read-write source mount? The source is not write-protected by mount flags; reading may update access times or contend with active writes."
                }
                _ => "Enable safety override?",
            };
            let mut lines: Vec<Line> = wrap_text(body, inner.width.saturating_sub(2) as usize)
                .into_iter()
                .map(|l| Line::from(format!(" {l}")))
                .collect();
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " [y] Enable override     [n / Esc] Keep off (safe default)",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Modal::EditPattern {
            is_include,
            index,
            text,
            cursor,
            error,
        } => {
            let rect = centered_rect(68, 10, area);
            frame.render_widget(Clear, rect);
            let kind_str = if *is_include { "Include" } else { "Exclude" };
            let action = if index.is_some() { "Edit" } else { "Add" };
            let block = Block::default()
                .title(format!(" {action} {kind_str} Glob Pattern "))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let w = inner.width.saturating_sub(4) as usize;
            let (win, col) = window_and_col(text, *cursor, w);
            let mut lines = vec![
                Line::from(Span::styled(
                    " Relative glob (* and ? within a folder, ** across folders, e.g. Documents/**):",
                    Style::default().fg(Color::Gray),
                )),
                Line::from(vec![
                    Span::styled(" > ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled(win, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                ]),
            ];
            if let Some(err) = error {
                lines.push(Line::from(Span::styled(
                    format!(" ! {err}"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
            } else {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                " [Enter] Save pattern     [Esc] Cancel",
                Style::default().fg(Color::Yellow),
            )));
            frame.render_widget(Paragraph::new(lines), inner);

            let x = (inner.x + 3 + col as u16).min(inner.x + inner.width.saturating_sub(1));
            let y = inner.y + 1;
            frame.set_cursor_position(Position::new(x, y));
        }
        Modal::ConfirmStart => {
            let rect = centered_rect(72, 15, area);
            frame.render_widget(Clear, rect);
            let block = Block::default()
                .title(" Confirm Acquisition Start ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let mut lines = Vec::new();
            if let Some(PreviewState::Ready(data)) = &app.preview_state {
                for (k, v) in confirm_start_lines(&app.files_form, data) {
                    lines.push(Line::from(vec![
                        Span::styled(format!(" {:<18}: ", k), Style::default().fg(Color::Gray)),
                        Span::styled(
                            truncate_to_width(&v, inner.width.saturating_sub(22) as usize),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ]));
                }
                if data.preview.short_of_space() {
                    lines.push(Line::from(Span::styled(
                        " ! WARNING: Target free space is smaller than in-scope bytes!",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " [y] Start acquisition     [n / Esc] Cancel",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Modal::ConfirmStop => {
            let rect = centered_rect(64, 8, area);
            frame.render_widget(Clear, rect);
            let block = Block::default()
                .title(" Stop Acquisition? ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let lines = vec![
                Line::from(" Stop the acquisition? The collection is closed as aborted."),
                Line::from(" Everything acquired so far is recorded and verifiable (exit 8)."),
                Line::from(""),
                Line::from(Span::styled(
                    " [y] Stop acquisition     [n / Esc] Continue running",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ))
                .alignment(Alignment::Left),
            ];
            frame.render_widget(Paragraph::new(lines), inner);
        }
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width.saturating_sub(2));
    let h = height.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{Progress, Stop},
        files::{Preview, SampleEntry},
        tui::{
            app::{ResultData, RunState},
            command::parse_files_argv,
            form::{OutputProbe, SourceProbe},
            mounts::MountChoice,
        },
    };
    use ratatui::{backend::TestBackend, Terminal};
    use std::{
        collections::{BTreeMap, VecDeque},
        path::PathBuf,
        sync::Arc,
        time::Instant,
    };

    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        let buf = terminal.backend().buffer();
        let mut lines = Vec::with_capacity(height as usize);
        for y in 0..height {
            let mut row = String::new();
            for x in 0..width {
                row.push_str(buf[(x, y)].symbol());
            }
            lines.push(row.trim_end().to_string());
        }
        lines.join("\n")
    }

    fn invented_app(stop: &'static Stop) -> App {
        let mut app = App::with_mounts(
            stop,
            vec![MountChoice {
                mount_point: PathBuf::from("/media/evidence/sdb1"),
                source: "/dev/sdb1".into(),
                read_only: true,
                free_bytes: None,
            }],
            vec![MountChoice {
                mount_point: PathBuf::from("/media/target/sdc1"),
                source: "/dev/sdc1".into(),
                read_only: false,
                free_bytes: Some(500 << 30),
            }],
        );
        app.files_form.case = "VG 12345/26".into();
        app.files_form.evidence = "share01".into();
        app.files_form.examiner = "KHK Muster".into();
        app.files_form.legal_basis = "AG Musterstadt 12 Gs 34/26".into();
        app.files_form.include = vec!["Documents/**".into()];
        app.files_form.exclude = vec!["Documents/Private/**".into()];
        app.files_form.update_output_suggestion();
        app.files_form.source_probe = Some(SourceProbe {
            exists: true,
            is_dir: true,
            read_only: true,
            mount_source: Some("/dev/sdb1".into()),
        });
        app.files_form.output_probe = Some(OutputProbe {
            free_bytes: Some(500 << 30),
            non_empty: false,
            is_tmpfs: false,
            inside_source: false,
            check_error: None,
        });
        app
    }

    #[test]
    fn renders_all_screens_at_80x24_and_120x40_with_invented_data() {
        static STOP: Stop = Stop::new();
        let mut app = invented_app(&STOP);
        let anchor_64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        for (w, h) in [(80u16, 24u16), (120u16, 40u16)] {
            // 1. Home screen
            app.screen = Screen::Home;
            let home_out = render_to_string(&app, w, h);
            assert!(home_out.contains("[Home]"));
            assert!(home_out.contains("Acquire files from a mounted directory"));
            assert!(home_out.contains("Verify a collection"));
            assert!(home_out.contains("command line only"));
            assert!(!home_out.lines().next_back().unwrap().ends_with('…'));

            // 2. FilesForm screen
            app.screen = Screen::FilesForm;
            app.files_form.set_focus(FilesField::CaseNumber);
            let form_out = render_to_string(&app, w, h);
            assert!(form_out.contains("[Files]"));
            assert!(form_out.contains("VG 12345/26"));
            assert!(form_out.contains("/media/evidence/sdb1"));
            assert!(form_out.contains("/media/target/sdc1/VG_12345_26/share01"));
            assert!(!form_out.lines().next_back().unwrap().ends_with('…'));

            // 3. Preview screen
            let argv = files_argv(&app.files_form);
            let args = parse_files_argv(&argv).unwrap();
            let mut oos = BTreeMap::new();
            oos.insert("excluded by pattern Documents/Private/**".into(), 14);
            app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
                preview: Preview {
                    source: PathBuf::from("/media/evidence/sdb1"),
                    output: PathBuf::from("/media/target/sdc1/VG_12345_26/share01"),
                    files: 42,
                    bytes: 10 * 1024 * 1024,
                    directories: 5,
                    symlinks: 1,
                    special: 0,
                    out_of_scope: oos,
                    excluded_trees: 1,
                    trees_outside_includes: 3,
                    other_filesystems: Vec::new(),
                    errors: Vec::new(),
                    sample: vec![
                        SampleEntry {
                            kind: Kind::Directory,
                            path: "Documents".into(),
                            size: None,
                        },
                        SampleEntry {
                            kind: Kind::File,
                            path: "Documents/invoice-2026.pdf".into(),
                            size: Some(204_800),
                        },
                        SampleEntry {
                            kind: Kind::Symlink,
                            path: "Documents/latest.pdf".into(),
                            size: None,
                        },
                    ],
                    target_free: Some(500 << 30),
                    stopped: None,
                    at_ns: 1_776_000_000_000_000_000,
                },
                argv: argv.clone(),
                args: args.clone(),
                scroll: 0,
                copied_osc52: false,
            })));
            app.screen = Screen::Preview;
            let prev_out = render_to_string(&app, w, h);
            assert!(prev_out.contains("[Preview]"));
            assert!(prev_out.contains("42 files"));
            assert!(prev_out.contains("(48 acquired)"));
            assert!(prev_out.contains("Documents/invoice-2026.pdf"));
            // Out-of-scope counts appear, never out-of-scope file names
            assert!(prev_out.contains("excluded by pattern"));
            assert!(!prev_out.lines().next_back().unwrap().ends_with('…'));

            // 4. Running screen
            let progress = Arc::new(Progress::default());
            progress.files.store(21, Ordering::Relaxed);
            progress.bytes.store(5 * 1024 * 1024, Ordering::Relaxed);
            progress.set_current("Documents/report.pdf");
            app.run_state = Some(RunState {
                args: Box::new(args),
                argv: argv.clone(),
                expected_files: 42,
                expected_bytes: 10 * 1024 * 1024,
                progress,
                started: Instant::now(),
                rate_samples: VecDeque::new(),
                stop_requested: false,
                handle: None,
            });
            app.screen = Screen::Running;
            let run_out = render_to_string(&app, w, h);
            assert!(run_out.contains("[Running]"));
            assert!(run_out.contains("1. Copying"));
            assert!(run_out.contains("21 / 42"));
            assert!(run_out.contains("Documents/report.pdf"));
            assert!(!run_out.lines().next_back().unwrap().ends_with('…'));

            // 5. Result screen
            app.result_data = Some(ResultData {
                code: 0,
                status: "complete".into(),
                collection: PathBuf::from("/media/target/sdc1/VG_12345_26/share01"),
                argv,
                acquired: 48,
                bytes: 10 * 1024 * 1024,
                out_of_scope_listed: 0,
                out_of_scope_counted: 14,
                excluded_trees: 1,
                trees_outside_includes: 3,
                errors: 0,
                skipped: 0,
                audit_anchor: Some(anchor_64.into()),
                container_mismatches: Vec::new(),
                warnings: Vec::new(),
                problems: Vec::new(),
                fatal_error: None,
                left_unfinished: false,
                scroll: 0,
            });
            app.screen = Screen::Result;
            let res_out = render_to_string(&app, w, h);
            assert!(res_out.contains("[Result]"));
            assert!(res_out.contains("COMPLETE"));
            assert!(res_out.contains("container verified"));
            assert!(res_out.contains("/media/target/sdc1/VG_12345_26/share01"));
            assert!(
                res_out.lines().any(|line| line.contains(anchor_64)),
                "full 64-hex anchor must appear on a single line at {w}x{h}:\n{res_out}"
            );
            assert!(!res_out.lines().next_back().unwrap().ends_with('…'));

            // 6. Verify screen
            app.verify_state.path = "/media/target/sdc1/VG_12345_26/share01".into();
            app.verify_state.report = Some(VerifyReportData {
                dir: PathBuf::from("/media/target/sdc1/VG_12345_26/share01"),
                code: 0,
                ok: true,
                status: "complete".into(),
                stopped: None,
                members_ok: 42,
                member_problems: Vec::new(),
                files_ok: 42,
                files_mismatch: Vec::new(),
                files_missing: Vec::new(),
                audit_anchor_found: Some(true),
                audit_finish_found: Some(true),
                problems: Vec::new(),
                fatal_error: None,
            });
            app.screen = Screen::Verify;
            let ver_out = render_to_string(&app, w, h);
            assert!(ver_out.contains("[Verify]"));
            assert!(ver_out.contains("VERIFIED OK"));
            assert!(ver_out.contains("audit anchor verified"));
            assert!(ver_out.contains("42 member(s) verified OK"));
            assert!(ver_out.contains("42 re-hashed OK, 0 mismatch, 0 missing"));
            assert!(!ver_out.lines().next_back().unwrap().ends_with('…'));
        }
    }
}
