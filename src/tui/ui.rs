//! Pure rendering functions for the `dfcollect` TUI (`Home`, `FilesForm`,
//! `IngestForm`, `CloudForm`, `DbForm`, `Preview`, `Running`, `Result`,
//! `Verify` and modal overlays).
//!
//! Uses only the standard 16 ANSI colours (`Color::Cyan`, `Green`, `Yellow`,
//! `Red`, `Magenta`, `White`, `DarkGray`, `Black`) so the interface renders
//! cleanly on Linux virtual consoles and serial terminals (`TERM=vt220`/`linux`)
//! down to 80×24.

use crate::{
    common::{human_bytes, Phase},
    console::Level,
    files::PREVIEW_SAMPLE,
    meta::Kind,
    tui::{
        app::{
            confirm_start_lines, exit_code_meaning, format_duration, App, ListTarget, Modal, Mode,
            ModePreview, NoticeLevel, PreviewData, PreviewState, Screen, VerifyFocus,
            VerifyReportData, HOME_ITEMS,
        },
        command::{cloud_argv, db_argv, files_argv, ingest_argv, shell_quote},
        form::{CloudField, DbField, FilesField, IngestField},
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

    let notice_rows = if let Some(n) = &app.notice {
        let prefix = match n.level {
            NoticeLevel::Info => "INFO: ",
            NoticeLevel::Warning => "WARN: ",
            NoticeLevel::Error => "ERROR: ",
        };
        let wrapped = wrap_text(
            &format!("{prefix}{}", n.text),
            area.width.saturating_sub(1).max(20) as usize,
        );
        (wrapped.len() as u16).clamp(1, 2)
    } else {
        1
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(10),
            Constraint::Length(notice_rows + 1),
        ])
        .split(area);

    render_title_bar(frame, chunks[0], app);

    match app.screen {
        Screen::Home => render_home(frame, chunks[1], app),
        Screen::FilesForm => render_files_form(frame, chunks[1], app),
        Screen::IngestForm => render_ingest_form(frame, chunks[1], app),
        Screen::CloudForm => render_cloud_form(frame, chunks[1], app),
        Screen::DbForm => render_db_form(frame, chunks[1], app),
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

fn push_wrapped_kv(
    lines: &mut Vec<Line<'static>>,
    key: &str,
    value: &str,
    value_style: Style,
    total_width: usize,
) {
    let label = format!(" {key:<12}: ");
    let label_w = str_width(&label);
    let avail = total_width.saturating_sub(label_w).max(16);
    let wrapped = wrap_text(value, avail);
    let indent = " ".repeat(label_w);
    for (i, part) in wrapped.into_iter().enumerate() {
        if i == 0 {
            lines.push(Line::from(vec![
                Span::styled(label.clone(), Style::default().fg(Color::Gray)),
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

fn push_form_error(lines: &mut Vec<Line<'static>>, indent: &str, err: &str, total_width: usize) {
    let avail = total_width.saturating_sub(indent.len() + 2).max(16);
    for (i, part) in wrap_text(err, avail).into_iter().enumerate() {
        let pfx = if i == 0 {
            format!("{indent}! ")
        } else {
            format!("{indent}  ")
        };
        lines.push(Line::from(Span::styled(
            format!("{pfx}{part}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
}

fn render_title_bar(frame: &mut Frame, area: Rect, app: &App) {
    let screen_name = match app.screen {
        Screen::Home => "Home",
        Screen::FilesForm => "Files",
        Screen::IngestForm => "Ingest",
        Screen::CloudForm => "Cloud",
        Screen::DbForm => "Database",
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
    let mut footer_lines: Vec<Line> = Vec::new();
    let max_notice_rows = area.height.saturating_sub(1).max(1) as usize;
    if let Some(n) = &app.notice {
        let (prefix, color) = match n.level {
            NoticeLevel::Info => ("INFO: ", Color::Cyan),
            NoticeLevel::Warning => ("WARN: ", Color::Yellow),
            NoticeLevel::Error => ("ERROR: ", Color::Red),
        };
        let wrapped = wrap_text(
            &format!("{prefix}{}", n.text),
            area.width.saturating_sub(1).max(20) as usize,
        );
        for w in wrapped.into_iter().take(max_notice_rows) {
            footer_lines.push(Line::from(Span::styled(
                w,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )));
        }
    } else {
        let notice_line = match app.screen {
            Screen::FilesForm => {
                let cmd = shell_quote(&files_argv(&app.files_form));
                let shown = truncate_to_width(
                    &format!("cmd: {cmd}"),
                    area.width.saturating_sub(1) as usize,
                );
                Line::from(Span::styled(shown, Style::default().fg(Color::DarkGray)))
            }
            Screen::IngestForm => {
                let spec = app.ingest_form.field.spec();
                let tag = if spec.flag.is_empty() {
                    String::new()
                } else if spec.required {
                    format!("[{} *] ", spec.flag)
                } else {
                    format!("[{}] ", spec.flag)
                };
                let cmd = shell_quote(&ingest_argv(&app.ingest_form));
                let shown = truncate_to_width(
                    &format!("{tag}cmd: {cmd}"),
                    area.width.saturating_sub(1) as usize,
                );
                Line::from(Span::styled(shown, Style::default().fg(Color::DarkGray)))
            }
            Screen::CloudForm => {
                let spec = app.cloud_form.field.spec();
                let tag = if spec.flag.is_empty() {
                    String::new()
                } else if spec.required {
                    format!("[{} *] ", spec.flag)
                } else {
                    format!("[{}] ", spec.flag)
                };
                let cmd = shell_quote(&cloud_argv(&app.cloud_form));
                let shown = truncate_to_width(
                    &format!("{tag}cmd: {cmd}"),
                    area.width.saturating_sub(1) as usize,
                );
                Line::from(Span::styled(shown, Style::default().fg(Color::DarkGray)))
            }
            Screen::DbForm => {
                let spec = app.db_form.field.spec(app.db_form.engine);
                let tag = if spec.flag.is_empty() {
                    String::new()
                } else if spec.required {
                    format!("[{} *] ", spec.flag)
                } else {
                    format!("[{}] ", spec.flag)
                };
                let cmd = shell_quote(&db_argv(&app.db_form));
                let shown = truncate_to_width(
                    &format!("{tag}cmd: {cmd}"),
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
        };
        footer_lines.push(notice_line);
    }

    let keys = match app.screen {
        Screen::Home => " ↑/↓ select  Enter open  f/v/i/c/d mode  ? keys  q quit",
        Screen::FilesForm | Screen::IngestForm | Screen::CloudForm | Screen::DbForm => {
            " Tab/↑↓ move  Enter edit/toggle  F2/p preview  F4/Tab complete  ? keys  Esc"
        }
        Screen::Preview if app.is_worker_running() => " Esc / s stop preview  ? keys",
        Screen::Preview if !app.is_preview_stale() => {
            " Enter start  e/Esc edit  c copy cmd  r/F2 re-run  ↑/↓ scroll  ? keys"
        }
        Screen::Preview => " e/Esc edit  c copy cmd  r/F2 re-run  ↑/↓ scroll  ? keys",
        Screen::Running => {
            " s/Ctrl+C stop (aborts)  l notices  ↑/↓ scroll  ? keys  (quit disabled)"
        }
        Screen::Result => " v verify  n next acquisition  h/Esc home  ↑/↓ scroll  ? keys  q quit",
        Screen::Verify if app.is_worker_running() => " Esc / s stop verification  ? keys",
        Screen::Verify => {
            " Enter/F2 verify  Tab focus  F4/Tab complete  ↑/↓ scroll  ? keys  Esc  q quit"
        }
    };
    footer_lines.push(Line::from(Span::styled(
        truncate_to_width(keys, area.width as usize),
        Style::default().fg(Color::Black).bg(Color::Gray),
    )));

    frame.render_widget(Paragraph::new(footer_lines), area);
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
        if i > 0 && !item.enabled && HOME_ITEMS[i - 1].enabled {
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
// 4.2 Form screens (Files, Ingest, Cloud, Db)
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
                push_form_error(&mut lines, &indent, &err, inner.width as usize);
            }
        }
        if is_focused {
            focused_line_idx = lines.len().saturating_sub(1);
        }
    }

    finish_form_scroll_and_cursor(
        frame,
        inner,
        lines,
        focused_line_idx,
        cursor_screen_offset,
        app.modal.is_none(),
    );
}

fn render_ingest_form(frame: &mut Frame, area: Rect, app: &App) {
    let form = &app.ingest_form;
    let block = Block::default()
        .title(" Provider delivery package (dfcollect ingest) ")
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

    for field in IngestField::ALL {
        let spec = field.spec();
        if let Some(sec) = spec.section {
            push_section(&mut lines, sec);
        }
        if field == IngestField::PreviewButton {
            lines.push(Line::from(""));
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

        if field == IngestField::PreviewButton {
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

        if spec.kind.is_text() {
            let raw = form.text(field).map(String::as_str).unwrap_or("");
            let (shown_span, cursor_col) = if raw.is_empty() && (!is_focused || !form.editing) {
                (
                    Span::styled(
                        truncate_to_width(spec.placeholder, val_width),
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
            let val_style = if spec.kind.is_safety() && form.output.allow_tmpfs {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else if field == IngestField::AllowUnlisted && form.hashes.is_empty() {
                Style::default().fg(Color::DarkGray)
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

        let indent = " ".repeat(2 + label_col);
        if field == IngestField::Package {
            if let Some(p) = &form.package_probe {
                if p.exists && (p.is_file || p.is_dir) {
                    let kind_label = if p.is_dir {
                        "✓ directory package"
                    } else {
                        "✓ file package"
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{indent}{kind_label}"),
                        Style::default().fg(Color::Green),
                    )));
                }
            }
        } else if field == IngestField::OutputPath {
            if let Some(p) = &form.output.output_probe {
                if let Some(free) = p.free_bytes {
                    lines.push(Line::from(Span::styled(
                        format!("{indent}Free space on target: {}", human_bytes(free)),
                        Style::default().fg(Color::Cyan),
                    )));
                }
            }
        } else if matches!(field, IngestField::ReceivedAt | IngestField::ReferenceTime) {
            if let Some(hint) = form.utc_hint(field) {
                lines.push(Line::from(Span::styled(
                    format!("{indent}{hint}"),
                    Style::default().fg(Color::Cyan),
                )));
            }
            if field == IngestField::ReferenceTime {
                if let Some(stamp) = form.clock.stamp_hint() {
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
                || matches!(field, IngestField::Package | IngestField::OutputPath);
            if should_show {
                push_form_error(&mut lines, &indent, &err, inner.width as usize);
            }
        }
        if is_focused {
            focused_line_idx = lines.len().saturating_sub(1);
        }
    }

    finish_form_scroll_and_cursor(
        frame,
        inner,
        lines,
        focused_line_idx,
        cursor_screen_offset,
        app.modal.is_none(),
    );
}

fn render_cloud_form(frame: &mut Frame, area: Rect, app: &App) {
    let form = &app.cloud_form;
    let block = Block::default()
        .title(" Cloud / remote storage via rclone (dfcollect cloud) ")
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

    if form.remotes.is_empty() {
        let (hint, hint_color) = if form.rclone_missing {
            (
                "rclone not found on PATH — dfcollect cloud needs it (the dfnix package includes it)",
                Color::Red,
            )
        } else {
            (
                "Configure a remote first (e.g. rclone config create <name> <type> config_is_local=false) in a terminal or set rclone config below to an existing rclone.conf.",
                Color::Yellow,
            )
        };
        for (i, w) in wrap_text(hint, inner.width.saturating_sub(4) as usize)
            .into_iter()
            .enumerate()
        {
            let prefix = if i == 0 { " ℹ " } else { "   " };
            lines.push(Line::from(Span::styled(
                format!("{prefix}{w}"),
                Style::default().fg(hint_color),
            )));
        }
    }

    for field in CloudField::ALL {
        if !form.applies(field) {
            continue;
        }
        let spec = field.spec();
        if let Some(sec) = spec.section {
            push_section(&mut lines, sec);
        }
        if field == CloudField::PreviewButton {
            lines.push(Line::from(""));
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

        if field == CloudField::PreviewButton {
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

        if spec.kind.is_text() {
            let raw = form.text(field).map(String::as_str).unwrap_or("");
            let (shown_span, cursor_col) = if raw.is_empty() && (!is_focused || !form.editing) {
                (
                    Span::styled(
                        truncate_to_width(spec.placeholder, val_width),
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
            let val_style = if spec.kind.is_safety() && form.output.allow_tmpfs {
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

        let indent = " ".repeat(2 + label_col);
        if field == CloudField::OutputPath {
            if let Some(p) = &form.output.output_probe {
                if let Some(free) = p.free_bytes {
                    lines.push(Line::from(Span::styled(
                        format!("{indent}Free space on target: {}", human_bytes(free)),
                        Style::default().fg(Color::Cyan),
                    )));
                }
            }
        } else if matches!(
            field,
            CloudField::NotBefore | CloudField::NotAfter | CloudField::ReferenceTime
        ) {
            if let Some(hint) = form.utc_hint(field) {
                lines.push(Line::from(Span::styled(
                    format!("{indent}{hint}"),
                    Style::default().fg(Color::Cyan),
                )));
            }
            if field == CloudField::ReferenceTime {
                if let Some(stamp) = form.clock.stamp_hint() {
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
                || matches!(field, CloudField::Source | CloudField::OutputPath);
            if should_show {
                push_form_error(&mut lines, &indent, &err, inner.width as usize);
            }
        }
        if is_focused {
            focused_line_idx = lines.len().saturating_sub(1);
        }
    }

    finish_form_scroll_and_cursor(
        frame,
        inner,
        lines,
        focused_line_idx,
        cursor_screen_offset,
        app.modal.is_none(),
    );
}

fn render_db_form(frame: &mut Frame, area: Rect, app: &App) {
    let form = &app.db_form;
    let block = Block::default()
        .title(" Database dump (PostgreSQL / MariaDB) (dfcollect db) ")
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

    for field in DbField::ALL {
        if !form.applies(field) {
            continue;
        }
        let spec = field.spec(form.engine);
        if let Some(sec) = spec.section {
            push_section(&mut lines, sec);
        }
        if field == DbField::PreviewButton {
            lines.push(Line::from(""));
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

        if field == DbField::PreviewButton {
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

        if spec.kind.is_text() {
            let raw = form.text(field).map(String::as_str).unwrap_or("");
            let (shown_span, cursor_col) = if raw.is_empty() && (!is_focused || !form.editing) {
                (
                    Span::styled(
                        truncate_to_width(spec.placeholder, val_width),
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
            let val_style = if spec.kind.is_safety() && form.output.allow_tmpfs {
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

        let indent = " ".repeat(2 + label_col);
        if field == DbField::Engine {
            if let Some((eng, probes)) = &form.tool_probe {
                if *eng == form.engine {
                    let missing: Vec<&str> = probes
                        .iter()
                        .filter(|(_, v)| v.is_none())
                        .map(|(n, _)| n.as_str())
                        .collect();
                    if !missing.is_empty() {
                        lines.push(Line::from(Span::styled(
                            format!("{indent}! missing tool(s) in PATH: {}", missing.join(", ")),
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        )));
                    }
                }
            }
        } else if field == DbField::NoPassword
            && form.password_file.trim().is_empty()
            && !form.no_password
        {
            lines.push(Line::from(Span::styled(
                truncate_to_width(
                    &format!("{indent}ℹ Password prompted in masked modal on Preview/Run"),
                    inner.width as usize,
                ),
                Style::default().fg(Color::Cyan),
            )));
        } else if field == DbField::OutputPath {
            if let Some(p) = &form.output.output_probe {
                if let Some(free) = p.free_bytes {
                    lines.push(Line::from(Span::styled(
                        format!("{indent}Free space on target: {}", human_bytes(free)),
                        Style::default().fg(Color::Cyan),
                    )));
                }
            }
        } else if field == DbField::ReferenceTime {
            if let Some(hint) = form.utc_hint(field) {
                lines.push(Line::from(Span::styled(
                    format!("{indent}{hint}"),
                    Style::default().fg(Color::Cyan),
                )));
            }
            if let Some(stamp) = form.clock.stamp_hint() {
                lines.push(Line::from(Span::styled(
                    format!("{indent}{stamp}"),
                    Style::default().fg(Color::Green),
                )));
            }
        }

        if let Some(err) = form.validate_field(field) {
            let should_show = is_focused
                || !form.text(field).is_some_and(|t| t.trim().is_empty())
                || matches!(field, DbField::Host | DbField::User | DbField::OutputPath);
            if should_show {
                push_form_error(&mut lines, &indent, &err, inner.width as usize);
            }
        }
        if is_focused {
            focused_line_idx = lines.len().saturating_sub(1);
        }
    }

    finish_form_scroll_and_cursor(
        frame,
        inner,
        lines,
        focused_line_idx,
        cursor_screen_offset,
        app.modal.is_none(),
    );
}

fn finish_form_scroll_and_cursor(
    frame: &mut Frame,
    inner: Rect,
    lines: Vec<Line>,
    focused_line_idx: usize,
    cursor_screen_offset: Option<(usize, u16)>,
    allow_cursor: bool,
) {
    let height = inner.height as usize;
    let scroll = if focused_line_idx + 1 >= height {
        (focused_line_idx + 2).saturating_sub(height)
    } else {
        0
    };
    let visible: Vec<Line> = lines.into_iter().skip(scroll).take(height).collect();
    frame.render_widget(Paragraph::new(visible), inner);

    if allow_cursor {
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
            mode,
            argv,
            progress,
            console,
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
            let stage = progress.stage();
            let headline = if !stage.is_empty() {
                format!(" {spin} {stage} ({elapsed})...")
            } else {
                match mode {
                    Mode::Files => {
                        format!(" {spin} Walking source tree and evaluating scope ({elapsed})...")
                    }
                    Mode::Ingest => {
                        format!(" {spin} Inspecting provider package and hash lists ({elapsed})...")
                    }
                    Mode::Cloud => {
                        format!(" {spin} Listing cloud remote objects via rclone ({elapsed})...")
                    }
                    Mode::Db => {
                        format!(
                            " {spin} Connecting to database and estimating sizes ({elapsed})..."
                        )
                    }
                }
            };

            let mut lines = vec![
                Line::from(Span::styled(
                    headline,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!("   Entries examined : {entries}")),
                Line::from(format!(
                    "   In-scope items   : {files} ({})",
                    human_bytes(bytes)
                )),
                Line::from(format!("   Out of scope     : {oos}")),
                Line::from(format!("   Errors           : {errs}")),
            ];
            if let Some((_, msg)) = console.notices_snapshot().last() {
                lines.push(Line::from(format!("   Latest notice    : {msg}")));
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
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " Press Esc or 's' to stop the preview early.",
                Style::default().fg(Color::Yellow),
            )));
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Some(PreviewState::Failed {
            mode,
            argv,
            error,
            code,
        }) => {
            let mut lines = Vec::new();
            let wrap_w = inner.width.saturating_sub(4).max(20) as usize;
            if *code == 8 {
                let heading = if error.starts_with("Preview ") {
                    error.clone()
                } else if error == "cancelled before anything was written" {
                    "Preview cancelled before anything was written".to_string()
                } else {
                    format!("Preview stopped ({error})")
                };
                for w in wrap_text(&heading, wrap_w) {
                    lines.push(Line::from(Span::styled(
                        format!(" {w}"),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "   Press F2 / 'r' to re-run preview, or Esc to return to the form.",
                    Style::default().fg(Color::Gray),
                )));
            } else {
                let heading = format!(
                    "{} preview failed (exit {code}: {})",
                    mode.title(),
                    exit_code_meaning(*code, false)
                );
                for w in wrap_text(&heading, wrap_w) {
                    lines.push(Line::from(Span::styled(
                        format!(" {w}"),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )));
                }
                lines.push(Line::from(""));
                for w in wrap_text(error, wrap_w) {
                    lines.push(Line::from(Span::styled(
                        format!("   {w}"),
                        Style::default().fg(Color::Red),
                    )));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " Equivalent command:",
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD),
            )));
            let cmd = shell_quote(argv);
            for w in wrap_text(&cmd, wrap_w) {
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
    let stale = app.is_preview_stale();
    let sum_lines = build_preview_summary_lines(area.width as usize, stale, &data.mode_preview);

    let cmd_str = shell_quote(&data.argv);
    let cmd_wrapped = wrap_text(&cmd_str, area.width.saturating_sub(4) as usize);
    let sum_h = (sum_lines.len() as u16).min(area.height.saturating_sub(6));
    let max_cmd_h = area.height.saturating_sub(sum_h + 4).max(3);
    let cmd_height = (cmd_wrapped.len() as u16 + 1).min(max_cmd_h);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(sum_h),
            Constraint::Min(4),
            Constraint::Length(cmd_height),
        ])
        .split(area);

    frame.render_widget(Paragraph::new(sum_lines), chunks[0]);

    match &data.mode_preview {
        ModePreview::Files { preview, .. } => {
            render_files_preview_sample(frame, chunks[1], preview, data.scroll);
        }
        ModePreview::Ingest { preview, args } => {
            render_ingest_preview_sample(frame, chunks[1], preview, args, data.scroll);
        }
        ModePreview::Cloud { preview, .. } => {
            render_cloud_preview_sample(frame, chunks[1], preview, data.scroll);
        }
        ModePreview::Db { preview, .. } => {
            render_db_preview_sample(frame, chunks[1], preview, data.scroll);
        }
    }

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

    let max_cmd_lines = cmd_inner.height as usize;
    let cmd_lines: Vec<Line> = if cmd_wrapped.len() <= max_cmd_lines {
        cmd_wrapped
            .into_iter()
            .map(|l| {
                Line::from(Span::styled(
                    format!(" {l}"),
                    Style::default().fg(Color::Cyan),
                ))
            })
            .collect()
    } else if max_cmd_lines > 0 {
        let mut lines: Vec<Line> = cmd_wrapped
            .into_iter()
            .take(max_cmd_lines - 1)
            .map(|l| {
                Line::from(Span::styled(
                    format!(" {l}"),
                    Style::default().fg(Color::Cyan),
                ))
            })
            .collect();
        lines.push(Line::from(Span::styled(
            " … ('c' copies the whole command)",
            Style::default().fg(Color::Yellow),
        )));
        lines
    } else {
        Vec::new()
    };
    frame.render_widget(Paragraph::new(cmd_lines), cmd_inner);
}

fn build_preview_summary_lines(
    width: usize,
    stale: bool,
    mode_preview: &ModePreview,
) -> Vec<Line<'static>> {
    let mut sum_lines = Vec::new();
    if let Some(reason) = mode_preview.stopped() {
        push_wrapped_field(
            &mut sum_lines,
            " ! ",
            &format!("Preview stopped ({reason}) — press F2 / 'r' to re-run preview"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            width,
        );
    } else if let Some(block_reason) = mode_preview.start_block_reason() {
        push_wrapped_field(
            &mut sum_lines,
            " ! ",
            &block_reason,
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            width,
        );
    } else if stale {
        push_wrapped_field(
            &mut sum_lines,
            " ! ",
            "STALE PREVIEW (form changed) — press F2 / 'r' to re-run preview before starting",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            width,
        );
    }

    match mode_preview {
        ModePreview::Files { preview: pv, .. } => {
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
                width,
            );
            sum_lines.push(render_target_space_line(
                pv.target_free,
                pv.bytes,
                pv.short_of_space(),
            ));

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
            push_wrapped_field(
                &mut sum_lines,
                " Excluded  : ",
                &oos_summary,
                Style::default().fg(Color::Yellow),
                width,
            );

            push_wrapped_field(
                &mut sum_lines,
                " Unlisted  : ",
                &format!(
                    "{} excluded tree(s), {} tree(s) outside includes",
                    pv.excluded_trees, pv.trees_outside_includes
                ),
                Style::default().fg(Color::White),
                width,
            );

            let other_fs = if pv.other_filesystems.is_empty() {
                "none".to_string()
            } else {
                format!(
                    "{} ({})",
                    pv.other_filesystems.len(),
                    pv.other_filesystems.join(", ")
                )
            };
            push_wrapped_field(
                &mut sum_lines,
                " Other fs  : ",
                &other_fs,
                Style::default().fg(Color::White),
                width,
            );

            if pv.errors.is_empty() {
                sum_lines.push(Line::from(vec![
                    Span::styled(" Walk errs : ", Style::default().fg(Color::Gray)),
                    Span::styled("0", Style::default().fg(Color::Green)),
                ]));
            } else {
                let joined: Vec<String> =
                    pv.errors.iter().map(|(p, e)| format!("{p}: {e}")).collect();
                push_wrapped_field(
                    &mut sum_lines,
                    " Walk errs : ",
                    &format!("{} ({})", pv.errors.len(), joined.join("; ")),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    width,
                );
            }
        }
        ModePreview::Ingest { preview: pv, args } => {
            push_wrapped_field(
                &mut sum_lines,
                " Package   : ",
                &args.package.display().to_string(),
                Style::default().fg(Color::White),
                width,
            );

            let prov_desc = format!(
                "{} (received {}, via {}{})",
                args.provider,
                args.received_at,
                args.channel,
                args.reference
                    .as_deref()
                    .map(|r| format!(", ref {r}"))
                    .unwrap_or_default()
            );
            push_wrapped_field(
                &mut sum_lines,
                " Provider  : ",
                &prov_desc,
                Style::default().fg(Color::Cyan),
                width,
            );

            push_wrapped_field(
                &mut sum_lines,
                " In scope  : ",
                &format!(
                    "{} files ({}), {} symlinks, {} special",
                    pv.files,
                    human_bytes(pv.bytes),
                    pv.symlinks,
                    pv.special
                ),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                width,
            );

            sum_lines.push(render_target_space_line(
                pv.target_free,
                pv.bytes,
                pv.short_of_space(),
            ));

            if pv.lists.is_empty() {
                sum_lines.push(Line::from(vec![
                    Span::styled(" Hash list : ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        "none provided (all package files accepted)",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
            } else {
                let bad = pv.missing_count > 0 || (pv.unlisted_count > 0 && !args.allow_unlisted);
                push_wrapped_field(
                    &mut sum_lines,
                    " Hash list : ",
                    &format!(
                        "{} list(s): {} listed present, {} missing, {} unlisted",
                        pv.lists.len(),
                        pv.listed_present,
                        pv.missing_count,
                        pv.unlisted_count
                    ),
                    Style::default().fg(if bad { Color::Red } else { Color::Green }),
                    width,
                );
            }
        }
        ModePreview::Cloud { preview: pv, args } => {
            let hashes_str = if pv.hash_types.is_empty() {
                "none reported by remote".into()
            } else {
                pv.hash_types.join(", ")
            };
            push_wrapped_field(
                &mut sum_lines,
                " Remote    : ",
                &format!("{} (provider hashes: {hashes_str})", args.source),
                Style::default().fg(Color::White),
                width,
            );

            push_wrapped_field(
                &mut sum_lines,
                " In scope  : ",
                &format!(
                    "{} object(s) ({}) of {} listed",
                    pv.files,
                    human_bytes(pv.bytes),
                    pv.listed
                ),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                width,
            );

            sum_lines.push(render_target_space_line(
                pv.target_free,
                pv.bytes,
                pv.short_of_space(),
            ));

            let oos_total: u64 = pv.out_of_scope.values().sum();
            let oos_reasons: Vec<String> = pv
                .out_of_scope
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect();
            let oos_summary = if oos_reasons.is_empty() {
                "0 objects".to_string()
            } else {
                format!("{oos_total} ({})", oos_reasons.join("; "))
            };
            push_wrapped_field(
                &mut sum_lines,
                " Excluded  : ",
                &oos_summary,
                Style::default().fg(Color::Yellow),
                width,
            );

            sum_lines.push(Line::from(vec![
                Span::styled(" Time basis: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    "Cloud object modification time (ModTime)",
                    Style::default().fg(Color::Cyan),
                ),
            ]));
        }
        ModePreview::Db { preview: pv, args } => {
            let port = args.port.unwrap_or(match args.engine {
                crate::db::Engine::Postgres => 5432,
                crate::db::Engine::Mariadb => 3306,
            });
            push_wrapped_field(
                &mut sum_lines,
                " Server    : ",
                &format!(
                    "{}://{}:{} (user: {}) — {}",
                    args.engine.as_cli_str(),
                    args.host,
                    port,
                    args.user,
                    pv.server
                ),
                Style::default().fg(Color::White),
                width,
            );

            let tools_summary: Vec<String> =
                pv.tools.iter().map(|(t, v)| format!("{t}: {v}")).collect();
            push_wrapped_field(
                &mut sum_lines,
                " Tools/Time: ",
                &format!(
                    "server clock {} | {}",
                    pv.server_time,
                    tools_summary.join(", ")
                ),
                Style::default().fg(Color::Cyan),
                width,
            );

            let in_scope_count = pv.databases.iter().filter(|(_, _, s)| *s).count();
            let in_scope_bytes = pv.in_scope_bytes();
            push_wrapped_field(
                &mut sum_lines,
                " In scope  : ",
                &format!(
                    "{in_scope_count} of {} database(s), ~{}",
                    pv.databases.len(),
                    human_bytes(in_scope_bytes)
                ),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                width,
            );

            sum_lines.push(render_target_space_line(
                pv.target_free,
                in_scope_bytes,
                pv.short_of_space(),
            ));

            if !pv.missing.is_empty() {
                push_wrapped_field(
                    &mut sum_lines,
                    " Missing   : ",
                    &pv.missing.join(", "),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    width,
                );
            }
        }
    }

    sum_lines
}

fn render_target_space_line(
    target_free: Option<u64>,
    expected_bytes: u64,
    short: bool,
) -> Line<'static> {
    match target_free {
        Some(free) if short => Line::from(vec![
            Span::styled(" Target    : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "WARNING: {} free < {} in-scope bytes (short of space!)",
                    human_bytes(free),
                    human_bytes(expected_bytes)
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
                    human_bytes(expected_bytes)
                ),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        None => Line::from(vec![
            Span::styled(" Target    : ", Style::default().fg(Color::Gray)),
            Span::raw("unknown"),
        ]),
    }
}

fn render_files_preview_sample(
    frame: &mut Frame,
    sample_area: Rect,
    pv: &crate::files::Preview,
    scroll: usize,
) {
    let total_in_scope = pv.acquired() + pv.special;
    let sample_title = format!(
        " In-scope sample (showing {} of {total_in_scope}, max {PREVIEW_SAMPLE}; ↑/↓/PgUp/PgDn) ",
        pv.sample.len()
    );
    let sample_block = Block::default()
        .title(sample_title)
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let sample_inner = sample_block.inner(sample_area);
    frame.render_widget(sample_block, sample_area);

    let mut sample_lines = Vec::new();
    let rows_avail = sample_inner.height as usize;
    for entry in pv.sample.iter().skip(scroll).take(rows_avail) {
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
}

fn render_ingest_preview_sample(
    frame: &mut Frame,
    sample_area: Rect,
    pv: &crate::ingest::IngestPreview,
    args: &crate::args::IngestArgs,
    scroll: usize,
) {
    let list_block = Block::default()
        .title(" Hash lists, missing & unlisted package entries (↑/↓/PgUp/PgDn) ")
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let list_inner = list_block.inner(sample_area);
    frame.render_widget(list_block, sample_area);

    let mut lines = Vec::new();
    for (name, count) in &pv.lists {
        lines.push(Line::from(vec![
            Span::styled(
                " [list] ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(name.clone(), Style::default().fg(Color::White)),
            Span::styled(
                format!(" ({count} entries)"),
                Style::default().fg(Color::Gray),
            ),
        ]));
    }
    for m in &pv.missing {
        lines.push(Line::from(Span::styled(
            truncate_to_width(&format!(" [MISSING] {m}"), list_inner.width as usize),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    for u in &pv.unlisted {
        let col = if args.allow_unlisted {
            Color::Yellow
        } else {
            Color::Red
        };
        lines.push(Line::from(Span::styled(
            truncate_to_width(&format!(" [UNLISTED] {u}"), list_inner.width as usize),
            Style::default().fg(col),
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "   ✓ Package ready for ingest (no missing or unlisted entries).",
            Style::default().fg(Color::Green),
        )));
    }
    let visible: Vec<Line> = lines
        .into_iter()
        .skip(scroll)
        .take(list_inner.height as usize)
        .collect();
    frame.render_widget(Paragraph::new(visible), list_inner);
}

fn render_cloud_preview_sample(
    frame: &mut Frame,
    sample_area: Rect,
    pv: &crate::cloud::CloudPreview,
    scroll: usize,
) {
    let sample_title = format!(
        " In-scope objects (showing {} of {}, max {PREVIEW_SAMPLE}; ↑/↓/PgUp/PgDn) ",
        pv.sample.len(),
        pv.files
    );
    let sample_block = Block::default()
        .title(sample_title)
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let sample_inner = sample_block.inner(sample_area);
    frame.render_widget(sample_block, sample_area);

    let mut sample_lines = Vec::new();
    let rows_avail = sample_inner.height as usize;
    for (path, size) in pv.sample.iter().skip(scroll).take(rows_avail) {
        let suffix = format!(" ({})", human_bytes(*size));
        let path_room = (sample_inner.width as usize)
            .saturating_sub(6 + str_width(&suffix))
            .max(8);
        let shown_path = truncate_to_width(path, path_room);
        sample_lines.push(Line::from(vec![
            Span::styled(
                " [f] ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(shown_path, Style::default().fg(Color::White)),
            Span::styled(suffix, Style::default().fg(Color::DarkGray)),
        ]));
    }
    if sample_lines.is_empty() {
        sample_lines.push(Line::from(Span::styled(
            "   (no in-scope objects matched)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(Paragraph::new(sample_lines), sample_inner);
}

fn render_db_preview_sample(
    frame: &mut Frame,
    sample_area: Rect,
    pv: &crate::db::DbPreview,
    scroll: usize,
) {
    let db_block = Block::default()
        .title(format!(
            " Server databases ({}) (↑/↓/PgUp/PgDn) ",
            pv.databases.len()
        ))
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let db_inner = db_block.inner(sample_area);
    frame.render_widget(db_block, sample_area);

    let mut lines = Vec::new();
    for (name, bytes, in_scope) in &pv.databases {
        let (tag, col) = if *in_scope {
            (" [in scope] ", Color::Green)
        } else {
            (" [skip]     ", Color::DarkGray)
        };
        let size_str = bytes
            .map(|b| format!(" (~{})", human_bytes(b)))
            .unwrap_or_else(|| " (size unknown)".into());
        lines.push(Line::from(vec![
            Span::styled(tag, Style::default().fg(col).add_modifier(Modifier::BOLD)),
            Span::styled(
                name.clone(),
                Style::default().fg(if *in_scope {
                    Color::White
                } else {
                    Color::DarkGray
                }),
            ),
            Span::styled(size_str, Style::default().fg(Color::Gray)),
        ]));
    }
    let visible: Vec<Line> = lines
        .into_iter()
        .skip(scroll)
        .take(db_inner.height as usize)
        .collect();
    frame.render_widget(Paragraph::new(visible), db_inner);
}

// ------------------------------------------------------------------
// 4.4 Running screen
// ------------------------------------------------------------------

fn render_running(frame: &mut Frame, area: Rect, app: &App) {
    let Some(run) = &app.run_state else {
        return;
    };

    let block = Block::default()
        .title(format!(
            " Acquisition in Progress (dfcollect {}) ",
            run.mode.cli_name()
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let notices = run.console.notices_snapshot();
    let notice_pane_height = if run.notices_expanded {
        inner.height.saturating_sub(11).max(4)
    } else if notices.is_empty() {
        2
    } else {
        (notices.len() as u16 + 1).min(6)
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(notice_pane_height),
        ])
        .split(inner);

    let phase = run.progress.phase();
    let files_done = run.progress.files.load(Ordering::Relaxed);
    let items_total = run.progress.items_total.load(Ordering::Relaxed);
    let bytes_done = run.progress.bytes.load(Ordering::Relaxed);
    let check_bytes = run.progress.check_bytes.load(Ordering::Relaxed);
    let oos = run.progress.out_of_scope.load(Ordering::Relaxed);
    let errs = run.progress.errors.load(Ordering::Relaxed);
    let current = run.progress.current();
    let stage = run.progress.stage();

    // 1. Phase indicator
    let style_active = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let style_done = Style::default().fg(Color::Green);
    let style_pending = Style::default().fg(Color::DarkGray);

    let (s_copy, s_check, s_fin) = match phase {
        Phase::Listing | Phase::Copying | Phase::SigningIn | Phase::Waiting => {
            (style_active, style_pending, style_pending)
        }
        Phase::CheckingContainer => (style_done, style_active, style_pending),
        Phase::Finishing | Phase::Done => (style_done, style_done, style_active),
    };
    let copy_label = if !stage.is_empty() {
        format!("1. Copying ({stage})")
    } else {
        "1. Copying".to_string()
    };
    let phase_line = Line::from(vec![
        Span::raw(" Phase: "),
        Span::styled(copy_label, s_copy),
        Span::raw("  →  "),
        Span::styled("2. Checking container", s_check),
        Span::raw("  →  "),
        Span::styled("3. Finishing", s_fin),
    ]);
    let target_line = Line::from(vec![
        Span::styled(" Target: ", Style::default().fg(Color::Gray)),
        Span::styled(
            truncate_to_width(
                &format!("{} → {}", run.source_display, run.output.display()),
                inner.width.saturating_sub(10) as usize,
            ),
            Style::default().fg(Color::White),
        ),
    ]);
    frame.render_widget(Paragraph::new(vec![phase_line, target_line]), chunks[0]);

    // 2. Progress gauge
    let eff_total_items = if items_total > 0 {
        items_total
    } else {
        run.expected_files
    };
    let (ratio, label) = match phase {
        Phase::Listing | Phase::Copying | Phase::SigningIn | Phase::Waiting => {
            if run.expected_bytes > 0 {
                let r = (bytes_done as f64 / run.expected_bytes as f64).clamp(0.0, 1.0);
                (
                    r,
                    format!(
                        "Copying: {} / ~{} ({:.0}%)",
                        human_bytes(bytes_done),
                        human_bytes(run.expected_bytes),
                        r * 100.0
                    ),
                )
            } else if eff_total_items > 0 {
                let r = (files_done as f64 / eff_total_items as f64).clamp(0.0, 1.0);
                (
                    r,
                    format!(
                        "Copying: {} / {} items ({})",
                        files_done,
                        eff_total_items,
                        human_bytes(bytes_done)
                    ),
                )
            } else {
                (
                    0.0,
                    format!("Copying: {} ({files_done} items)", human_bytes(bytes_done)),
                )
            }
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
            eff_total_items
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

    // 4. Notices pane (last 5 notices or expanded scrollable list on 'l')
    let notice_title = if run.notices_expanded {
        format!(" Notices ({}/50; 'l' collapse, ↑/↓ scroll) ", notices.len())
    } else {
        format!(" Notices ({} total; 'l' expand) ", notices.len())
    };
    let notice_block = Block::default()
        .title(notice_title)
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let notice_inner = notice_block.inner(chunks[3]);
    frame.render_widget(notice_block, chunks[3]);

    let avail_rows = notice_inner.height as usize;
    let slice: Vec<(Level, String)> = if run.notices_expanded {
        let max_scroll = notices.len().saturating_sub(avail_rows);
        let eff_scroll = run.notices_scroll.min(max_scroll);
        notices
            .into_iter()
            .skip(eff_scroll)
            .take(avail_rows)
            .collect()
    } else {
        let skip = notices.len().saturating_sub(avail_rows.min(5));
        notices.into_iter().skip(skip).take(avail_rows).collect()
    };

    let mut notice_lines = Vec::new();
    if slice.is_empty() {
        notice_lines.push(Line::from(Span::styled(
            "   (no notices)",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for (lvl, msg) in slice {
            let (tag, col) = match lvl {
                Level::Info => ("INFO", Color::Cyan),
                Level::Done => ("DONE", Color::Green),
                Level::Warning => ("WARN", Color::Yellow),
            };
            notice_lines.push(Line::from(vec![
                Span::styled(
                    format!(" [{tag}] "),
                    Style::default().fg(col).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    truncate_to_width(&msg, notice_inner.width.saturating_sub(8) as usize),
                    Style::default().fg(Color::White),
                ),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(notice_lines), notice_inner);
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
    let acquired_desc = match res.mode {
        Mode::Files => format!("{} item(s) ({})", res.acquired, human_bytes(res.bytes)),
        Mode::Ingest => format!(
            "{} file(s); {} total with hash lists",
            res.acquired,
            human_bytes(res.bytes)
        ),
        Mode::Cloud => format!(
            "{} file(s); {} total with rclone listings",
            res.acquired,
            human_bytes(res.bytes)
        ),
        Mode::Db => format!(
            "{} dump(s); {} total with server-info members",
            res.acquired,
            human_bytes(res.bytes)
        ),
    };
    push_wrapped_field(
        &mut top,
        " Acquired    : ",
        &acquired_desc,
        Style::default().fg(Color::White),
        inner.width as usize,
    );

    if res.mode == Mode::Files {
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
    }

    for (k, v) in &res.summary_kv {
        push_wrapped_kv(
            &mut top,
            k,
            v,
            Style::default().fg(Color::Cyan),
            inner.width as usize,
        );
    }

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
    push_wrapped_field(
        &mut top,
        " Command     : ",
        &shell_quote(&res.argv),
        Style::default().fg(Color::DarkGray),
        inner.width as usize,
    );
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
            let rect = centered_rect(72, 19, area);
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
                Line::from("   a / d / Enter             Add, delete or edit item in list field"),
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
                Line::from("   l (in Run)                Expand / collapse notices log"),
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
        Modal::ConfirmSafety { target } => {
            let rect = centered_rect(68, 10, area);
            frame.render_widget(Clear, rect);
            let block = Block::default()
                .title(format!(" Confirm Safety Override: {} ", target.label()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let body = if target.is_writable_source() {
                "Allow acquiring from a read-write source mount? The source is not write-protected by mount flags; reading may update access times or contend with active writes."
            } else {
                "Allow writing the collection to RAM (tmpfs / ramfs)? Data in RAM is lost on power-off or reboot."
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
                    Span::styled(
                        " > ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        win,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
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
        Modal::EditListItem {
            target,
            index,
            text,
            cursor,
            error,
        } => {
            let rect = centered_rect(68, 10, area);
            frame.render_widget(Clear, rect);
            let action = if index.is_some() { "Edit" } else { "Add" };
            let (title, hint) = match target {
                ListTarget::CloudInclude => (
                    format!(" {action} Include Glob Pattern "),
                    " Relative glob (* and ? within a folder, ** across folders, e.g. Documents/**):",
                ),
                ListTarget::CloudExclude => (
                    format!(" {action} Exclude Glob Pattern "),
                    " Relative glob (* and ? within a folder, ** across folders, e.g. Private/**):",
                ),
                ListTarget::IngestHashes => (
                    format!(" {action} Companion Hash List File (--hashes) "),
                    " Path to a SHA-256 / SHA-1 / MD5 hash file (e.g. /tmp/SHA256SUMS):",
                ),
                ListTarget::CloudRcloneArgs => (
                    format!(" {action} Extra rclone Flag (--rclone-arg) "),
                    " Extra flag forwarded to rclone (e.g. --drive-shared-with-me):",
                ),
                ListTarget::DbDatabases => (
                    format!(" {action} Database Name (--database) "),
                    " Database name to dump (leave list empty to dump all non-system databases):",
                ),
            };
            let block = Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let w = inner.width.saturating_sub(4) as usize;
            let (win, col) = window_and_col(text, *cursor, w);
            let mut lines = vec![
                Line::from(Span::styled(
                    truncate_to_width(hint, inner.width as usize),
                    Style::default().fg(Color::Gray),
                )),
                Line::from(vec![
                    Span::styled(
                        " > ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        win,
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
            ];
            if let Some(err) = error {
                lines.push(Line::from(Span::styled(
                    truncate_to_width(&format!(" ! {err}"), inner.width as usize),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
            } else {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                " [Enter] Save item     [Esc] Cancel",
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
                for (k, v) in confirm_start_lines(app, data) {
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
                if data.mode_preview.short_of_space() {
                    lines.push(Line::from(Span::styled(
                        " ! WARNING: Target free space is smaller than estimated bytes!",
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
        Modal::Secret(sec) => {
            let rect = centered_rect(68, 9, area);
            frame.render_widget(Clear, rect);
            let block = Block::default()
                .title(" Credential Required (masked — never echoed or written to disk) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow));
            let inner = block.inner(rect);
            frame.render_widget(block, rect);

            let w = inner.width.saturating_sub(4) as usize;
            let n_chars = sec.buffer.chars().count();
            let visible_bullets = n_chars.min(w.saturating_sub(1));
            let bullets = "•".repeat(visible_bullets);

            let mut lines = Vec::new();
            for p_line in wrap_text(&sec.ask.prompt, inner.width.saturating_sub(2) as usize)
                .into_iter()
                .take(2)
            {
                lines.push(Line::from(Span::styled(
                    format!(" {p_line}"),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )));
            }
            let input_row_idx = lines.len() as u16;
            lines.push(Line::from(vec![
                Span::styled(
                    " > ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    bullets,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                format!(" (or cancel and set {} on the form)", sec.ask.file_flag),
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(Span::styled(
                " [Enter] Submit credential     [Esc] Cancel (stops as cancelled)",
                Style::default().fg(Color::Yellow),
            )));
            frame.render_widget(Paragraph::new(lines), inner);

            let x =
                (inner.x + 3 + visible_bullets as u16).min(inner.x + inner.width.saturating_sub(1));
            let y = (inner.y + input_row_idx).min(inner.y + inner.height.saturating_sub(1));
            frame.set_cursor_position(Position::new(x, y));
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
        cloud::CloudPreview,
        common::{Progress, Stop},
        console::{Console, SecretAsk},
        db::{DbPreview, Engine},
        files::{Preview, SampleEntry},
        ingest::IngestPreview,
        tui::{
            app::{ResultData, RunState, SecretModal, TuiConsole},
            command::{parse_cloud_argv, parse_db_argv, parse_files_argv, parse_ingest_argv},
            form::{OutputProbe, PackageProbe, RcloneRemote, SourceProbe},
            mounts::MountChoice,
        },
    };
    use ratatui::{backend::TestBackend, Terminal};
    use std::{
        collections::{BTreeMap, VecDeque},
        path::PathBuf,
        sync::{atomic::Ordering, mpsc, Arc},
        time::Instant,
    };
    use zeroize::Zeroizing;

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
            assert!(home_out.contains("Provider delivery package"));
            assert!(home_out.contains("Cloud / remote storage (rclone)"));
            assert!(home_out.contains("Database dump (PostgreSQL / MariaDB)"));
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

            // 3. Preview screen (files)
            let argv = files_argv(&app.files_form);
            let args = parse_files_argv(&argv).unwrap();
            let mut oos = BTreeMap::new();
            oos.insert("excluded by pattern Documents/Private/**".into(), 14);
            app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData::from_files(
                Preview {
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
                argv.clone(),
                args.clone(),
            ))));
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
            let console = Arc::new(TuiConsole::new(&STOP, app.secret_tx.clone()));
            console.notice(Level::Info, "connected to source");
            app.run_state = Some(RunState {
                mode: Mode::Files,
                source_display: args.source.display().to_string(),
                output: args.output.clone(),
                argv: argv.clone(),
                expected_files: 42,
                expected_bytes: 10 * 1024 * 1024,
                progress,
                console,
                notices_expanded: false,
                notices_scroll: 0,
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
            assert!(run_out.contains("connected to source"));
            assert!(!run_out.lines().next_back().unwrap().ends_with('…'));

            // 5. Result screen
            app.result_data = Some(ResultData {
                mode: Mode::Files,
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
                summary_kv: Vec::new(),
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

    #[test]
    fn renders_ingest_cloud_db_forms_and_previews_and_secret_modal_at_80x24_and_120x40() {
        static STOP: Stop = Stop::new();
        let mut app = invented_app(&STOP);

        // Configure ingest form
        app.ingest_form.case.case = "VG 12345/26".into();
        app.ingest_form.case.evidence = "takeout01".into();
        app.ingest_form.case.examiner = "KHK Muster".into();
        app.ingest_form.package = "/media/evidence/sdb1/takeout.zip".into();
        app.ingest_form.provider = "Google LLC".into();
        app.ingest_form.received_at = "2026-04-17T08:00:00Z".into();
        app.ingest_form.channel = "LE portal".into();
        app.ingest_form.reference = "T-9988".into();
        app.ingest_form
            .output
            .update_suggestion(&app.ingest_form.case.case, &app.ingest_form.case.evidence);
        app.ingest_form.package_probe = Some(PackageProbe {
            exists: true,
            is_file: true,
            is_dir: false,
        });

        // Configure cloud form
        app.cloud_form.case.case = "VG 12345/26".into();
        app.cloud_form.case.evidence = "gdrive01".into();
        app.cloud_form.case.examiner = "KHK Muster".into();
        app.cloud_form.remotes = vec![RcloneRemote {
            name: "case-drive:".into(),
            kind: "drive".into(),
        }];
        app.cloud_form.selected_remote = Some(0);
        app.cloud_form.source = "case-drive:Shared/Project".into();
        app.cloud_form
            .output
            .update_suggestion(&app.cloud_form.case.case, &app.cloud_form.case.evidence);

        // Configure db form
        app.db_form.case.case = "VG 12345/26".into();
        app.db_form.case.evidence = "pg01".into();
        app.db_form.case.examiner = "KHK Muster".into();
        app.db_form.engine = Engine::Postgres;
        app.db_form.host = "10.0.0.15".into();
        app.db_form.user = "auditor".into();
        app.db_form
            .output
            .update_suggestion(&app.db_form.case.case, &app.db_form.case.evidence);

        for (w, h) in [(80u16, 24u16), (120u16, 40u16)] {
            // 1. IngestForm
            app.screen = Screen::IngestForm;
            app.ingest_form.set_focus(IngestField::Package);
            let ing_form_out = render_to_string(&app, w, h);
            assert!(ing_form_out.contains("[Ingest]"));
            assert!(ing_form_out.contains("Google LLC"));
            assert!(!ing_form_out.lines().next_back().unwrap().ends_with('…'));

            // 2. Ingest Preview
            let ing_argv = ingest_argv(&app.ingest_form);
            let ing_args = parse_ingest_argv(&ing_argv).unwrap();
            app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
                mode_preview: ModePreview::Ingest {
                    preview: IngestPreview {
                        files: 12,
                        bytes: 4096,
                        symlinks: 0,
                        special: 0,
                        listed_present: 12,
                        unlisted: Vec::new(),
                        unlisted_count: 0,
                        missing: Vec::new(),
                        missing_count: 0,
                        lists: vec![("SHA256SUMS".into(), 12)],
                        target_free: Some(500 << 30),
                        stopped: None,
                        at_ns: 1_776_000_000_000_000_000,
                    },
                    args: Box::new(ing_args),
                },
                argv: ing_argv,
                scroll: 0,
                copied_osc52: false,
            })));
            app.screen = Screen::Preview;
            let ing_prev_out = render_to_string(&app, w, h);
            assert!(ing_prev_out.contains("Google LLC"));
            assert!(ing_prev_out.contains("12 listed present"));
            assert!(ing_prev_out.contains("SHA256SUMS"));

            // 3. CloudForm
            app.screen = Screen::CloudForm;
            app.cloud_form.set_focus(CloudField::Source);
            let cl_form_out = render_to_string(&app, w, h);
            assert!(cl_form_out.contains("[Cloud]"));
            assert!(cl_form_out.contains("case-drive:Shared/Project"));
            assert!(!cl_form_out.lines().next_back().unwrap().ends_with('…'));

            // 4. Cloud Preview
            let cl_argv = cloud_argv(&app.cloud_form);
            let cl_args = parse_cloud_argv(&cl_argv).unwrap();
            let mut cl_oos = BTreeMap::new();
            cl_oos.insert("excluded by pattern Secret/**".into(), 5);
            app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
                mode_preview: ModePreview::Cloud {
                    preview: CloudPreview {
                        listed: 15,
                        files: 10,
                        bytes: 1024 * 1024,
                        out_of_scope: cl_oos,
                        hash_types: vec!["md5".into(), "sha1".into()],
                        sample: vec![("Shared/Project/budget.xlsx".into(), 51200)],
                        target_free: Some(500 << 30),
                        stopped: None,
                        at_ns: 1_776_000_000_000_000_000,
                    },
                    args: Box::new(cl_args),
                },
                argv: cl_argv,
                scroll: 0,
                copied_osc52: false,
            })));
            app.screen = Screen::Preview;
            let cl_prev_out = render_to_string(&app, w, h);
            assert!(cl_prev_out.contains("10 object(s)"));
            assert!(cl_prev_out.contains("Shared/Project/budget.xlsx"));
            assert!(cl_prev_out.contains("ModTime"));

            // 5. DbForm
            app.screen = Screen::DbForm;
            app.db_form.set_focus(DbField::Host);
            let db_form_out = render_to_string(&app, w, h);
            assert!(db_form_out.contains("[Database]"));
            assert!(db_form_out.contains("10.0.0.15"));
            assert!(db_form_out.contains("Serializable"));
            assert!(!db_form_out.contains("Binlog pos."));
            assert!(!db_form_out.lines().next_back().unwrap().ends_with('…'));

            // 6. Db Preview
            let db_argv_vec = db_argv(&app.db_form);
            let db_args = parse_db_argv(&db_argv_vec).unwrap();
            app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
                mode_preview: ModePreview::Db {
                    preview: DbPreview {
                        server: "PostgreSQL 16.4".into(),
                        server_time: "2026-10-17T10:00:00Z".into(),
                        databases: vec![("appdb".into(), Some(64 * 1024 * 1024), true)],
                        missing: Vec::new(),
                        tools: vec![
                            ("psql".into(), "psql 16.4".into()),
                            ("pg_dump".into(), "pg_dump 16.4".into()),
                        ],
                        target_free: Some(500 << 30),
                        at_ns: 1_776_000_000_000_000_000,
                    },
                    args: Box::new(db_args),
                },
                argv: db_argv_vec,
                scroll: 0,
                copied_osc52: false,
            })));
            app.screen = Screen::Preview;
            let db_prev_out = render_to_string(&app, w, h);
            assert!(db_prev_out.contains("postgres://10.0.0.15:5432"));
            assert!(db_prev_out.contains("PostgreSQL 16.4"));
            assert!(db_prev_out.contains("appdb"));

            // 7. Secret Modal — must mask secret with bullets and NEVER render raw secret
            let (tx, _rx) = mpsc::channel();
            app.modal = Some(Modal::Secret(SecretModal {
                ask: SecretAsk {
                    prompt: "Database password: ".into(),
                    file_flag: "--password-file",
                },
                buffer: Zeroizing::new("TopSecretForensicPass99!".into()),
                cursor: 24,
                reply: tx,
            }));
            let sec_out = render_to_string(&app, w, h);
            assert!(sec_out.contains("Credential Required"));
            assert!(sec_out.contains("••••••"));
            assert!(
                !sec_out.contains("TopSecretForensicPass99!"),
                "raw secret must NEVER appear in rendered buffer!"
            );
            app.modal = None;

            // 8. Stopped / cancelled preview (code == 8) — never says "preview failed"
            app.preview_state = Some(PreviewState::Failed {
                mode: Mode::Db,
                argv: db_argv(&app.db_form),
                error: "Preview cancelled before anything was written".into(),
                code: 8,
            });
            app.screen = Screen::Preview;
            let cancel_out = render_to_string(&app, w, h);
            assert!(cancel_out.contains("Preview cancelled before anything was written"));
            assert!(!cancel_out.contains("preview failed"));

            app.preview_state = Some(PreviewState::Failed {
                mode: Mode::Db,
                argv: db_argv(&app.db_form),
                error: "Preview stopped (by the examiner)".into(),
                code: 8,
            });
            let stop_out = render_to_string(&app, w, h);
            assert!(stop_out.contains("Preview stopped (by the examiner)"));
            assert!(!stop_out.contains("preview failed"));

            // 9. CloudForm with empty remotes — top hint wraps without clipping config_is_local=false)
            let saved_remotes = std::mem::take(&mut app.cloud_form.remotes);
            app.screen = Screen::CloudForm;
            app.cloud_form.set_focus(CloudField::CaseNumber);
            let cl_empty_out = render_to_string(&app, w, h);
            assert!(cl_empty_out.contains("config_is_local=false)"));

            // 9b. CloudForm with rclone missing on PATH
            app.cloud_form.rclone_missing = true;
            let cl_missing_out = render_to_string(&app, w, h);
            assert!(cl_missing_out.contains("rclone not found on PATH"));
            assert!(cl_missing_out.contains("dfnix package"));
            assert!(cl_missing_out.contains("includes it)"));
            app.cloud_form.rclone_missing = false;
            app.cloud_form.remotes = saved_remotes;
        }
    }

    #[test]
    fn round3_no_clipping_at_80x24() {
        static STOP: Stop = Stop::new();
        let mut app = invented_app(&STOP);

        // 1. Every Home item footer hint fits at 80x24 without ellipsis
        app.screen = Screen::Home;
        for idx in 0..HOME_ITEMS.len() {
            app.home_idx = idx;
            let out = render_to_string(&app, 80, 24);
            for line in out.lines() {
                assert!(
                    !line.contains('…'),
                    "Home screen with item {idx} clipped at 80x24:\n{out}"
                );
            }
        }

        // 2. Tmpfs inline error wraps on form at 80x24 so '--allow-tmpfs' is visible
        app.screen = Screen::CloudForm;
        app.cloud_form.output.output_path = "/tmp/case/out".into();
        app.cloud_form.output.output_probe = Some(crate::tui::form::OutputProbe {
            free_bytes: Some(1 << 30),
            non_empty: false,
            is_tmpfs: true,
            inside_source: false,
            check_error: None,
        });
        app.cloud_form.set_focus(CloudField::OutputPath);
        let form_out = render_to_string(&app, 80, 24);
        assert!(
            form_out.contains("enable --allow-tmpfs"),
            "tmpfs warning should wrap instead of clipping '--allow-tmpfs' at 80x24:\n{form_out}"
        );

        // 3. Long cloud preview command (5 wrapped lines) and long provider hash list at 80x24
        app.cloud_form.output.allow_tmpfs = true;
        app.cloud_form.rclone_config =
            "/tmp/very-long-forensic-case-directory/config/rclone/rclone.conf".into();
        app.cloud_form.scope.include = vec!["Documents/**".into(), "Finance/**".into()];
        app.cloud_form.scope.exclude = vec!["**/Cache/**".into()];
        app.cloud_form.case.case = "VG 12345/26".into();
        app.cloud_form.case.evidence = "cloud-sub-01".into();
        app.cloud_form.case.examiner = "KHK Muster".into();
        app.cloud_form.source = "local-test:sub".into();

        let cl_argv = cloud_argv(&app.cloud_form);
        let cl_args = parse_cloud_argv(&cl_argv).unwrap();
        app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
            mode_preview: ModePreview::Cloud {
                preview: CloudPreview {
                    listed: 2,
                    files: 2,
                    bytes: 14,
                    out_of_scope: BTreeMap::new(),
                    hash_types: vec![
                        "blake3".into(),
                        "crc32".into(),
                        "md5".into(),
                        "sha1".into(),
                        "sha256".into(),
                        "dropbox".into(),
                        "quickxorhash".into(),
                    ],
                    sample: vec![("sub/a.txt".into(), 7), ("sub/b.txt".into(), 7)],
                    target_free: Some(10 << 30),
                    stopped: None,
                    at_ns: 1_776_000_000_000_000_000,
                },
                args: Box::new(cl_args),
            },
            argv: cl_argv.clone(),
            scroll: 0,
            copied_osc52: false,
        })));
        app.screen = Screen::Preview;
        let prev_out = render_to_string(&app, 80, 24);
        assert!(
            prev_out.contains("quickxorhash)"),
            "provider hash list must wrap onto a second line and not clip at 80x24:\n{prev_out}"
        );
        assert!(
            prev_out.contains("local-test:sub"),
            "5-line wrapped CLI command must keep remote source visible at 80x24:\n{prev_out}"
        );
        assert!(
            prev_out.contains("Enter start"),
            "valid preview must show 'Enter start' in footer:\n{prev_out}"
        );

        // 4. Stale preview hides 'Enter start' and status notice does not clip
        app.cloud_form.source = "local-test:other".into();
        app.request_start_acquisition();
        let stale_out = render_to_string(&app, 80, 24);
        assert!(
            !stale_out.contains("Enter start"),
            "stale preview must hide 'Enter start' in footer:\n{stale_out}"
        );
        assert!(
            stale_out.contains("press F2 / 'r' to re-run preview."),
            "stale preview notice must not clip at 80x24:\n{stale_out}"
        );

        // 5. Cloud Result screen clarifies Acquired count vs total bytes and wraps Command
        app.notice = None;
        app.result_data = Some(ResultData {
            mode: Mode::Cloud,
            code: 0,
            status: "completed".into(),
            collection: PathBuf::from("/tmp/case/out/dfcollect-cloud-sub-01"),
            argv: cl_argv,
            acquired: 2,
            bytes: 4837,
            out_of_scope_listed: 0,
            out_of_scope_counted: 0,
            excluded_trees: 0,
            trees_outside_includes: 0,
            errors: 0,
            skipped: 0,
            summary_kv: vec![
                ("remote".into(), "local-test:sub".into()),
                ("listed".into(), "2".into()),
                ("out_of_scope".into(), "0".into()),
            ],
            audit_anchor: None,
            container_mismatches: Vec::new(),
            warnings: Vec::new(),
            problems: Vec::new(),
            fatal_error: None,
            left_unfinished: false,
            scroll: 0,
        });
        app.screen = Screen::Result;
        let res_out = render_to_string(&app, 80, 24);
        assert!(
            res_out.contains("2 file(s); 4.7 KiB total with rclone listings"),
            "cloud result must distinguish file count from total container bytes:\n{res_out}"
        );
        assert!(
            res_out.contains("-o /tmp/case/out") && res_out.contains("local-test:sub"),
            "result Command must wrap so -o and remote source are visible at 80x24:\n{res_out}"
        );
    }
}
