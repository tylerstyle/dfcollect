//! Application state, screen transitions, key handling and worker-thread
//! polling for the `dfcollect` TUI (`files` and `verify`).

use crate::{
    args::FilesArgs,
    common::{human_bytes, Progress, RunCtx, Stop},
    console::QuietConsole,
    files::{self, Preview},
    mail::client::base64,
    scope,
    tui::{
        autocomplete::{expand_tilde, find_path_completions, longest_common_prefix},
        command::{files_argv, parse_files_argv, shell_quote, verify_argv},
        form::{FilesField, FilesForm},
        input::edit_text,
        mounts::{discover_mounts, MountChoice},
    },
    verify, Usage,
};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn sanitize_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Rolling window for the transfer-rate estimate on the Run screen.
const RATE_WINDOW: Duration = Duration::from_secs(5);

/// Active screen of the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    FilesForm,
    Preview,
    Running,
    Result,
    Verify,
}

/// Items on the Home screen. The first two are interactive TUI workflows in
/// v0.2.0; the remaining modes are command-line only and show their `--help`
/// command when selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeItem {
    pub title: &'static str,
    pub command: &'static str,
    pub enabled: bool,
    pub hint: &'static str,
}

pub const HOME_ITEMS: [HomeItem; 9] = [
    HomeItem {
        title: "Acquire files from a mounted directory",
        command: "dfcollect files",
        enabled: true,
        hint: "Scoped file acquisition from a read-only mount (dfmount / dfnet) into a verifiable container",
    },
    HomeItem {
        title: "Verify a collection",
        command: "dfcollect verify",
        enabled: true,
        hint: "Verify manifest.json, items.jsonl, footprint.jsonl, items.csv, data.zip members and audit anchors",
    },
    HomeItem {
        title: "IMAP mailbox",
        command: "dfcollect imap --help",
        enabled: false,
        hint: "Command-line only: run `dfcollect imap --help` for read-only IMAP acquisition (EXAMINE / BODY.PEEK[])",
    },
    HomeItem {
        title: "Microsoft 365 mailbox (Graph)",
        command: "dfcollect graph --help",
        enabled: false,
        hint: "Command-line only: run `dfcollect graph --help` for Exchange Online acquisition via Microsoft Graph",
    },
    HomeItem {
        title: "Gmail / Google Workspace mailbox",
        command: "dfcollect gmail --help",
        enabled: false,
        hint: "Command-line only: run `dfcollect gmail --help` for Gmail API raw RFC 2822 acquisition",
    },
    HomeItem {
        title: "Cloud / remote storage (rclone)",
        command: "dfcollect cloud --help",
        enabled: false,
        hint: "Command-line only: run `dfcollect cloud --help` for OneDrive, SharePoint, Drive, Dropbox, S3, WebDAV",
    },
    HomeItem {
        title: "Database dump (PostgreSQL / MariaDB)",
        command: "dfcollect db --help",
        enabled: false,
        hint: "Command-line only: run `dfcollect db --help` for consistent logical database snapshots",
    },
    HomeItem {
        title: "Microsoft 365 tenant audit logs",
        command: "dfcollect m365-logs --help",
        enabled: false,
        hint: "Command-line only: run `dfcollect m365-logs --help` for Entra sign-in, directory and Unified Audit Logs",
    },
    HomeItem {
        title: "Provider delivery package",
        command: "dfcollect ingest --help",
        enabled: false,
        hint: "Command-line only: run `dfcollect ingest --help` to package and verify provider productions",
    },
];

/// Severity level for the status / notice banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Warning,
    Error,
}

/// One-line status banner shown at the bottom of the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: NoticeLevel,
    pub text: String,
}

/// Modal dialog overlaid on the current screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// Keybindings help (`?` or `F1`).
    Help,
    /// Confirmation before enabling `--allow-tmpfs` or `--allow-writable-source`.
    ConfirmSafety { field: FilesField },
    /// Adding or editing an `--include` or `--exclude` glob pattern.
    EditPattern {
        is_include: bool,
        index: Option<usize>,
        text: String,
        cursor: usize,
        error: Option<String>,
    },
    /// Confirmation sheet before starting the acquisition from the Preview screen.
    ConfirmStart,
    /// Confirmation sheet before stopping a running acquisition (`s` or `Ctrl+C`).
    ConfirmStop,
}

/// Which path field owns the current autocompletion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTarget {
    Files(FilesField),
    Verify,
}

/// Active path-completion candidates for `Tab` / `F4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionState {
    pub target: PathTarget,
    pub candidates: Vec<String>,
    pub index: Option<usize>,
    pub suffix: String,
}

/// Finished preview held on [`Screen::Preview`].
#[derive(Debug, Clone)]
pub struct PreviewData {
    pub preview: Preview,
    pub argv: Vec<String>,
    pub args: FilesArgs,
    pub scroll: usize,
    pub copied_osc52: bool,
}

/// State of the preview worker or its result.
pub enum PreviewState {
    Running {
        argv: Vec<String>,
        args: Box<FilesArgs>,
        progress: Arc<Progress>,
        started: Instant,
        handle: Option<JoinHandle<anyhow::Result<Preview>>>,
    },
    Ready(Box<PreviewData>),
    Failed {
        argv: Vec<String>,
        error: String,
        code: u8,
    },
}

/// Live state of an in-progress `dfcollect files` acquisition on [`Screen::Running`].
pub struct RunState {
    pub args: Box<FilesArgs>,
    pub argv: Vec<String>,
    pub expected_files: u64,
    pub expected_bytes: u64,
    pub progress: Arc<Progress>,
    pub started: Instant,
    pub rate_samples: VecDeque<(Instant, u64)>,
    pub stop_requested: bool,
    pub handle: Option<JoinHandle<anyhow::Result<files::Outcome>>>,
}

impl RunState {
    /// Current transfer rate in bytes/sec over the last [`RATE_WINDOW`].
    pub fn rate_bps(&self) -> Option<u64> {
        let (t0, b0) = self.rate_samples.front()?;
        let (t1, b1) = self.rate_samples.back()?;
        let dt = t1.checked_duration_since(*t0)?.as_secs_f64();
        if dt < 0.2 || b1 < b0 {
            return None;
        }
        Some(((b1 - b0) as f64 / dt) as u64)
    }

    /// Estimated remaining duration for the copying phase.
    pub fn eta(&self, current_bytes: u64) -> Option<Duration> {
        let rate = self.rate_bps()?;
        if rate == 0 || current_bytes >= self.expected_bytes {
            return None;
        }
        let rem = self.expected_bytes - current_bytes;
        Some(Duration::from_secs(rem / rate))
    }
}

/// Structured result of a finished (or failed/aborted) `dfcollect files` run.
#[derive(Debug, Clone)]
pub struct ResultData {
    pub code: u8,
    pub status: String,
    pub collection: PathBuf,
    pub argv: Vec<String>,
    pub acquired: u64,
    pub bytes: u64,
    pub out_of_scope_listed: u64,
    pub out_of_scope_counted: u64,
    pub excluded_trees: u64,
    pub trees_outside_includes: u64,
    pub errors: u64,
    pub skipped: u64,
    pub audit_anchor: Option<String>,
    pub container_mismatches: Vec<String>,
    pub warnings: Vec<String>,
    pub problems: Vec<String>,
    pub fatal_error: Option<String>,
    pub left_unfinished: bool,
    pub scroll: usize,
}

impl ResultData {
    pub fn from_outcome(outcome: &files::Outcome, collection: PathBuf, argv: Vec<String>) -> Self {
        let s = &outcome.summary;
        let str_vec = |key: &str| -> Vec<String> {
            s.get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            code: outcome.code,
            status: s
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            collection: s
                .get("collection")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or(collection),
            argv,
            acquired: s.get("acquired").and_then(|v| v.as_u64()).unwrap_or(0),
            bytes: s.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0),
            out_of_scope_listed: s
                .get("out_of_scope_listed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            out_of_scope_counted: s
                .get("out_of_scope_counted")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            excluded_trees: s
                .get("excluded_trees")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            trees_outside_includes: s
                .get("trees_outside_includes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            errors: s.get("errors").and_then(|v| v.as_u64()).unwrap_or(0),
            skipped: s.get("skipped").and_then(|v| v.as_u64()).unwrap_or(0),
            audit_anchor: s
                .get("audit_anchor")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            container_mismatches: str_vec("container_mismatches"),
            warnings: str_vec("warnings"),
            problems: str_vec("problems"),
            fatal_error: None,
            left_unfinished: false,
            scroll: 0,
        }
    }

    pub fn from_error(err: &anyhow::Error, collection: PathBuf, argv: Vec<String>) -> Self {
        let code = classify_error(err);
        Self {
            code,
            status: "failed".into(),
            collection,
            argv,
            acquired: 0,
            bytes: 0,
            out_of_scope_listed: 0,
            out_of_scope_counted: 0,
            excluded_trees: 0,
            trees_outside_includes: 0,
            errors: 1,
            skipped: 0,
            audit_anchor: None,
            container_mismatches: Vec::new(),
            warnings: Vec::new(),
            problems: Vec::new(),
            fatal_error: Some(format!("{err:#}")),
            left_unfinished: false,
            scroll: 0,
        }
    }

    pub fn from_panic(message: String, collection: PathBuf, argv: Vec<String>) -> Self {
        Self {
            code: 4,
            status: "failed (left unfinished)".into(),
            collection,
            argv,
            acquired: 0,
            bytes: 0,
            out_of_scope_listed: 0,
            out_of_scope_counted: 0,
            excluded_trees: 0,
            trees_outside_includes: 0,
            errors: 1,
            skipped: 0,
            audit_anchor: None,
            container_mismatches: Vec::new(),
            warnings: Vec::new(),
            problems: Vec::new(),
            fatal_error: Some(format!(
                "internal error in worker thread ({message}); collection left unfinished"
            )),
            left_unfinished: true,
            scroll: 0,
        }
    }
}

/// Focusable controls on the Verify screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyFocus {
    PathInput,
    SessionList,
    VerifyButton,
}

/// Running verification worker on [`Screen::Verify`].
pub struct VerifyRunning {
    pub dir: PathBuf,
    pub container_bytes: Option<u64>,
    pub progress: Arc<Progress>,
    pub started: Instant,
    pub handle: Option<JoinHandle<anyhow::Result<verify::Outcome>>>,
}

/// Structured report of a finished `dfcollect verify` run.
#[derive(Debug, Clone)]
pub struct VerifyReportData {
    pub dir: PathBuf,
    pub code: u8,
    pub ok: bool,
    pub status: String,
    pub stopped: Option<String>,
    pub members_ok: u64,
    pub member_problems: Vec<String>,
    pub files_ok: u64,
    pub files_mismatch: Vec<String>,
    pub files_missing: Vec<String>,
    pub audit_anchor_found: Option<bool>,
    pub audit_finish_found: Option<bool>,
    pub problems: Vec<String>,
    pub fatal_error: Option<String>,
}

impl VerifyReportData {
    pub fn from_outcome(outcome: &verify::Outcome, dir: PathBuf) -> Self {
        let s = &outcome.summary;
        let str_vec = |key: &str| -> Vec<String> {
            s.get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            dir: s
                .get("collection")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or(dir),
            code: outcome.code,
            ok: s.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
            status: s
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            stopped: s
                .get("stopped")
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            members_ok: s.get("members_ok").and_then(|v| v.as_u64()).unwrap_or(0),
            member_problems: str_vec("member_problems"),
            files_ok: s.get("files_ok").and_then(|v| v.as_u64()).unwrap_or(0),
            files_mismatch: str_vec("files_mismatch"),
            files_missing: str_vec("files_missing"),
            audit_anchor_found: s.get("audit_anchor_found").and_then(|v| v.as_bool()),
            audit_finish_found: s.get("audit_finish_found").and_then(|v| v.as_bool()),
            problems: str_vec("problems"),
            fatal_error: None,
        }
    }

    pub fn from_error(err: &anyhow::Error, dir: PathBuf) -> Self {
        Self {
            dir,
            code: classify_error(err),
            ok: false,
            status: "error".into(),
            stopped: None,
            members_ok: 0,
            member_problems: Vec::new(),
            files_ok: 0,
            files_mismatch: Vec::new(),
            files_missing: Vec::new(),
            audit_anchor_found: None,
            audit_finish_found: None,
            problems: Vec::new(),
            fatal_error: Some(format!("{err:#}")),
        }
    }

    pub fn from_panic(message: String, dir: PathBuf) -> Self {
        Self {
            dir,
            code: 4,
            ok: false,
            status: "failed (left unfinished)".into(),
            stopped: None,
            members_ok: 0,
            member_problems: Vec::new(),
            files_ok: 0,
            files_mismatch: Vec::new(),
            files_missing: Vec::new(),
            audit_anchor_found: None,
            audit_finish_found: None,
            problems: Vec::new(),
            fatal_error: Some(format!("internal error in verification worker ({message})")),
        }
    }
}

/// State of the Verify screen.
pub struct VerifyState {
    pub path: String,
    pub cursor: usize,
    pub editing: bool,
    pub focus: VerifyFocus,
    pub session_idx: usize,
    pub running: Option<VerifyRunning>,
    pub report: Option<VerifyReportData>,
    pub scroll: usize,
}

impl Default for VerifyState {
    fn default() -> Self {
        Self {
            path: String::new(),
            cursor: 0,
            editing: false,
            focus: VerifyFocus::PathInput,
            session_idx: 0,
            running: None,
            report: None,
            scroll: 0,
        }
    }
}

/// Human-readable exit-code meaning from the README table.
pub fn exit_code_meaning(code: u8, is_verify: bool) -> &'static str {
    match code {
        0 if is_verify => "Complete: every record, container member and audit anchor verified",
        0 => "Complete: every in-scope item was acquired and the container verified",
        2 => "Usage error (invalid options or scope); nothing was written",
        3 => "Refused by a safety check; nothing was written",
        4 if is_verify => "Failed to run (a check could not run, or audit anchors are missing)",
        4 => "Failed to run",
        5 => "The container or the records do not match",
        6 => "Incomplete: the container could not be written (e.g. target is full)",
        7 => "Complete with errors: some items failed (read errors, files changed while read)",
        8 => "Stopped by signal or examiner; everything acquired so far is recorded and verifiable",
        _ => "Finished with non-zero status",
    }
}

/// Classify an `anyhow::Error` into the CLI's exit code (2, 3, or 4).
pub fn classify_error(err: &anyhow::Error) -> u8 {
    if err.downcast_ref::<Usage>().is_some() {
        2
    } else if dfcore::is_refusal(err) {
        3
    } else {
        4
    }
}

/// Extract a human-readable message from a thread panic payload.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unexpected panic".to_string()
    }
}

/// Top-level TUI state machine.
pub struct App {
    pub stop: &'static Stop,
    pub screen: Screen,
    pub home_idx: usize,
    pub files_form: FilesForm,
    pub preview_state: Option<PreviewState>,
    pub run_state: Option<RunState>,
    pub result_data: Option<ResultData>,
    pub verify_state: VerifyState,
    pub session_collections: Vec<PathBuf>,
    pub modal: Option<Modal>,
    pub completion: Option<CompletionState>,
    pub notice: Option<Notice>,
    pub ticks: u64,
    pub should_quit: bool,
    pub headless: bool,
    /// Base64 payload queued for an OSC 52 clipboard write by the terminal loop.
    pub pending_osc52: Option<String>,
    /// Outcome produced when a worker ended due to an external signal (`STOP.signal`),
    /// to be printed on stdout after the alternate screen is restored.
    pub signal_outcome: Option<verify::Outcome>,
}

impl App {
    /// Create a new `App` discovering mounts from `/proc/self/mountinfo`.
    pub fn new(stop: &'static Stop) -> Self {
        let (sources, targets) = discover_mounts();
        Self::with_mounts(stop, sources, targets)
    }

    /// Create a new `App` with explicit mount lists (used by unit and render tests
    /// so no host paths or serials leak into snapshots).
    pub fn with_mounts(
        stop: &'static Stop,
        source_mounts: Vec<MountChoice>,
        target_mounts: Vec<MountChoice>,
    ) -> Self {
        Self {
            stop,
            screen: Screen::Home,
            home_idx: 0,
            files_form: FilesForm::with_mounts(source_mounts, target_mounts),
            preview_state: None,
            run_state: None,
            result_data: None,
            verify_state: VerifyState::default(),
            session_collections: Vec::new(),
            modal: None,
            completion: None,
            notice: None,
            ticks: 0,
            should_quit: false,
            headless: false,
            pending_osc52: None,
            signal_outcome: None,
        }
    }

    pub fn notify(&mut self, level: NoticeLevel, text: impl Into<String>) {
        self.notice = Some(Notice {
            level,
            text: sanitize_line(&text.into()),
        });
    }

    /// Whether a background worker thread (preview, acquisition, or verify) is active.
    pub fn is_worker_running(&self) -> bool {
        matches!(
            &self.preview_state,
            Some(PreviewState::Running {
                handle: Some(_),
                ..
            })
        ) || matches!(
            &self.run_state,
            Some(RunState {
                handle: Some(_),
                ..
            })
        ) || matches!(
            &self.verify_state.running,
            Some(VerifyRunning {
                handle: Some(_),
                ..
            })
        )
    }

    /// Whether the current preview is missing, stopped early, or no longer matches `files_form`.
    pub fn is_preview_stale(&self) -> bool {
        let Some(PreviewState::Ready(data)) = &self.preview_state else {
            return true;
        };
        if data.preview.stopped.is_some() {
            return true;
        }
        files_argv(&self.files_form) != data.argv
    }

    /// Poll running worker threads and update transfer rate / spinner state.
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);

        // 1. Poll preview worker
        let preview_done = matches!(
            &self.preview_state,
            Some(PreviewState::Running { handle: Some(h), .. }) if h.is_finished()
        );
        if preview_done {
            if let Some(PreviewState::Running {
                argv,
                args,
                mut handle,
                ..
            }) = self.preview_state.take()
            {
                if let Some(h) = handle.take() {
                    match h.join() {
                        Ok(Ok(preview)) => {
                            if self.stop.signal.load(Ordering::Relaxed) {
                                self.signal_outcome = Some(verify::Outcome {
                                    code: preview.stopped.as_ref().map_or(0, |_| 8),
                                    summary: preview.summary(),
                                });
                                self.should_quit = true;
                                return;
                            }
                            if let Some(reason) = &preview.stopped {
                                self.notify(
                                    NoticeLevel::Warning,
                                    format!(
                                        "Preview ended early ({reason}); re-run preview before starting."
                                    ),
                                );
                            } else {
                                self.notice = None;
                            }
                            self.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
                                preview,
                                argv,
                                args: *args,
                                scroll: 0,
                                copied_osc52: false,
                            })));
                        }
                        Ok(Err(e)) => {
                            let code = classify_error(&e);
                            let msg = format!("{e:#}");
                            self.notify(NoticeLevel::Error, &msg);
                            self.preview_state = Some(PreviewState::Failed {
                                argv,
                                error: msg,
                                code,
                            });
                        }
                        Err(payload) => {
                            let msg = format!(
                                "internal error in preview worker ({})",
                                panic_message(payload.as_ref())
                            );
                            self.notify(NoticeLevel::Error, &msg);
                            self.preview_state = Some(PreviewState::Failed {
                                argv,
                                error: msg,
                                code: 4,
                            });
                        }
                    }
                }
            }
        }

        // 2. Poll files acquisition worker
        if let Some(run) = &mut self.run_state {
            let now = Instant::now();
            let bytes = run.progress.bytes.load(Ordering::Relaxed);
            run.rate_samples.push_back((now, bytes));
            while let Some((t0, _)) = run.rate_samples.front() {
                if now.saturating_duration_since(*t0) > RATE_WINDOW && run.rate_samples.len() > 2 {
                    run.rate_samples.pop_front();
                } else {
                    break;
                }
            }
        }
        let run_done = matches!(
            &self.run_state,
            Some(RunState { handle: Some(h), .. }) if h.is_finished()
        );
        if run_done {
            if let Some(mut run) = self.run_state.take() {
                if matches!(self.modal, Some(Modal::ConfirmStop)) {
                    self.modal = None;
                }
                if let Some(h) = run.handle.take() {
                    let output = run.args.output.clone();
                    let argv = run.argv.clone();
                    let joined = h.join();
                    if output.join(dfcore::manifest::MANIFEST).is_file()
                        && !self.session_collections.contains(&output)
                    {
                        self.session_collections.push(output.clone());
                    }
                    match joined {
                        Ok(Ok(outcome)) => {
                            if self.stop.signal.load(Ordering::Relaxed) || self.headless {
                                self.signal_outcome = Some(verify::Outcome {
                                    code: outcome.code,
                                    summary: outcome.summary,
                                });
                                self.should_quit = true;
                                return;
                            }
                            let res = ResultData::from_outcome(&outcome, output, argv);
                            self.notice = None;
                            self.result_data = Some(res);
                            self.screen = Screen::Result;
                        }
                        Ok(Err(e)) => {
                            let res = ResultData::from_error(&e, output, argv);
                            self.notify(NoticeLevel::Error, format!("{e:#}"));
                            self.result_data = Some(res);
                            self.screen = Screen::Result;
                            if self.stop.signal.load(Ordering::Relaxed) || self.headless {
                                self.should_quit = true;
                            }
                        }
                        Err(payload) => {
                            let msg = panic_message(payload.as_ref());
                            let res = ResultData::from_panic(msg, output, argv);
                            self.notify(
                                NoticeLevel::Error,
                                res.fatal_error.clone().unwrap_or_default(),
                            );
                            self.result_data = Some(res);
                            self.screen = Screen::Result;
                            if self.stop.signal.load(Ordering::Relaxed) || self.headless {
                                self.should_quit = true;
                            }
                        }
                    }
                }
            }
        }

        // 3. Poll verify worker
        let verify_done = matches!(
            &self.verify_state.running,
            Some(VerifyRunning { handle: Some(h), .. }) if h.is_finished()
        );
        if verify_done {
            if let Some(mut running) = self.verify_state.running.take() {
                if let Some(h) = running.handle.take() {
                    let dir = running.dir.clone();
                    match h.join() {
                        Ok(Ok(outcome)) => {
                            if self.stop.signal.load(Ordering::Relaxed) || self.headless {
                                self.signal_outcome = Some(outcome);
                                self.should_quit = true;
                                return;
                            }
                            let rep = VerifyReportData::from_outcome(&outcome, dir);
                            self.verify_state.report = Some(rep);
                            self.verify_state.scroll = 0;
                            self.notice = None;
                        }
                        Ok(Err(e)) => {
                            let rep = VerifyReportData::from_error(&e, dir);
                            self.notify(NoticeLevel::Error, format!("{e:#}"));
                            self.verify_state.report = Some(rep);
                            self.verify_state.scroll = 0;
                            if self.stop.signal.load(Ordering::Relaxed) || self.headless {
                                self.should_quit = true;
                            }
                        }
                        Err(payload) => {
                            let rep =
                                VerifyReportData::from_panic(panic_message(payload.as_ref()), dir);
                            self.notify(
                                NoticeLevel::Error,
                                rep.fatal_error.clone().unwrap_or_default(),
                            );
                            self.verify_state.report = Some(rep);
                            self.verify_state.scroll = 0;
                            if self.stop.signal.load(Ordering::Relaxed) || self.headless {
                                self.should_quit = true;
                            }
                        }
                    }
                }
            }
        }

        // 4. If an external signal arrived while idle, quit immediately
        if self.stop.signal.load(Ordering::Relaxed) && !self.is_worker_running() {
            self.should_quit = true;
        }
    }

    /// Block until any running worker thread finishes (used on signal / UI teardown).
    pub fn wait_for_worker(&mut self) {
        while self.is_worker_running() {
            std::thread::sleep(Duration::from_millis(20));
            self.tick();
        }
    }

    // ------------------------------------------------------------------
    // Key handling
    // ------------------------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Modal dialogs intercept all keys
        if self.modal.is_some() {
            self.handle_modal_key(key);
            return;
        }

        // Ctrl+C on Running screen asks to stop; elsewhere exits if idle
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            match self.screen {
                Screen::Running => {
                    self.request_stop_acquisition();
                    return;
                }
                Screen::Preview if self.is_worker_running() => {
                    self.stop.examiner.store(true, Ordering::Relaxed);
                    return;
                }
                Screen::Verify if self.is_worker_running() => {
                    self.stop.examiner.store(true, Ordering::Relaxed);
                    return;
                }
                _ => {
                    self.should_quit = true;
                    return;
                }
            }
        }

        if key.code == KeyCode::F(1) {
            self.modal = Some(Modal::Help);
            return;
        }

        match self.screen {
            Screen::Home => self.handle_home_key(key),
            Screen::FilesForm => self.handle_files_form_key(key),
            Screen::Preview => self.handle_preview_key(key),
            Screen::Running => self.handle_running_key(key),
            Screen::Result => self.handle_result_key(key),
            Screen::Verify => self.handle_verify_key(key),
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let Some(modal) = self.modal.take() else {
            return;
        };
        match modal {
            Modal::Help => match key.code {
                KeyCode::Esc
                | KeyCode::Enter
                | KeyCode::Char('q')
                | KeyCode::Char('?')
                | KeyCode::F(1) => {}
                _ => self.modal = Some(Modal::Help),
            },
            Modal::ConfirmSafety { field } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    match field {
                        FilesField::AllowTmpfs => self.files_form.allow_tmpfs = true,
                        FilesField::AllowWritableSource => {
                            self.files_form.allow_writable_source = true
                        }
                        _ => {}
                    }
                    self.files_form.refresh_probes();
                    self.notify(
                        NoticeLevel::Warning,
                        format!("Safety override '{}' enabled.", field.label()),
                    );
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => self.modal = Some(Modal::ConfirmSafety { field }),
            },
            Modal::EditPattern {
                is_include,
                index,
                mut text,
                mut cursor,
                ..
            } => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    let trimmed = text.trim().to_string();
                    if trimmed.is_empty() {
                        self.modal = Some(Modal::EditPattern {
                            is_include,
                            index,
                            text,
                            cursor,
                            error: Some("pattern cannot be empty".into()),
                        });
                        return;
                    }
                    if let Err(e) = validate_single_pattern(&trimmed, is_include) {
                        self.modal = Some(Modal::EditPattern {
                            is_include,
                            index,
                            text,
                            cursor,
                            error: Some(e),
                        });
                        return;
                    }
                    let list = if is_include {
                        &mut self.files_form.include
                    } else {
                        &mut self.files_form.exclude
                    };
                    let idx_ref = if is_include {
                        &mut self.files_form.include_idx
                    } else {
                        &mut self.files_form.exclude_idx
                    };
                    if let Some(i) = index {
                        if i < list.len() {
                            list[i] = trimmed;
                            *idx_ref = i;
                        }
                    } else {
                        list.push(trimmed);
                        *idx_ref = list.len() - 1;
                    }
                }
                _ => {
                    edit_text(&mut text, &mut cursor, key);
                    let error = if text.trim().is_empty() {
                        None
                    } else {
                        validate_single_pattern(text.trim(), is_include).err()
                    };
                    self.modal = Some(Modal::EditPattern {
                        is_include,
                        index,
                        text,
                        cursor,
                        error,
                    });
                }
            },
            Modal::ConfirmStart => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.start_files_run();
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => self.modal = Some(Modal::ConfirmStart),
            },
            Modal::ConfirmStop => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.stop.examiner.store(true, Ordering::Relaxed);
                    if let Some(run) = &mut self.run_state {
                        run.stop_requested = true;
                    }
                    self.notify(
                        NoticeLevel::Warning,
                        "Stopping acquisition — closing collection as aborted...",
                    );
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => self.modal = Some(Modal::ConfirmStop),
            },
        }
    }

    fn handle_home_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Up | KeyCode::Char('k') => {
                let n = HOME_ITEMS.len();
                self.home_idx = (self.home_idx + n - 1) % n;
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                let n = HOME_ITEMS.len();
                self.home_idx = (self.home_idx + 1) % n;
            }
            KeyCode::BackTab => {
                let n = HOME_ITEMS.len();
                self.home_idx = (self.home_idx + n - 1) % n;
            }
            KeyCode::Char('f') => self.open_files_form(),
            KeyCode::Char('v') => self.open_verify(None, false),
            KeyCode::Enter | KeyCode::Char(' ') => match self.home_idx {
                0 => self.open_files_form(),
                1 => self.open_verify(None, false),
                i => {
                    let item = &HOME_ITEMS[i];
                    self.notify(
                        NoticeLevel::Info,
                        format!(
                            "Command-line only in v0.2.0 — run `{}` in a shell.",
                            item.command
                        ),
                    );
                }
            },
            _ => {}
        }
    }

    pub fn open_files_form(&mut self) {
        self.files_form.refresh_probes();
        self.completion = None;
        self.notice = None;
        self.screen = Screen::FilesForm;
    }

    pub fn open_verify(&mut self, prefill: Option<PathBuf>, run_immediately: bool) {
        self.completion = None;
        self.notice = None;
        if let Some(p) = prefill {
            self.verify_state.path = p.display().to_string();
            self.verify_state.cursor = self.verify_state.path.len();
            self.verify_state.editing = false;
        } else if self.verify_state.path.is_empty() {
            if let Some(last) = self.session_collections.last() {
                self.verify_state.path = last.display().to_string();
                self.verify_state.cursor = self.verify_state.path.len();
            }
        }
        self.screen = Screen::Verify;
        if run_immediately {
            self.start_verify();
        }
    }

    fn handle_files_form_key(&mut self, key: KeyEvent) {
        let field = self.files_form.field;
        let tab_completes = field.is_path()
            && (self.files_form.editing || self.completion.is_some())
            && key.code == KeyCode::Tab;

        if key.code != KeyCode::F(4) && !tab_completes {
            self.completion = None;
        }

        // F2 or Ctrl+P launches preview from any field
        if key.code == KeyCode::F(2)
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p'))
        {
            self.start_preview();
            return;
        }

        // F4 triggers path completion on path fields
        if key.code == KeyCode::F(4) || tab_completes {
            if field.is_path() {
                self.complete_path(PathTarget::Files(field));
            } else {
                self.notify(
                    NoticeLevel::Info,
                    "Path autocompletion (F4 / Tab) applies to path fields.",
                );
            }
            return;
        }

        match key.code {
            KeyCode::Esc => {
                if self.files_form.editing {
                    self.files_form.editing = false;
                    self.files_form.refresh_probes();
                } else {
                    self.screen = Screen::Home;
                }
            }
            KeyCode::Down | KeyCode::Tab => {
                self.files_form.refresh_probes();
                self.files_form.focus_next(true);
            }
            KeyCode::Up | KeyCode::BackTab => {
                self.files_form.refresh_probes();
                self.files_form.focus_next(false);
            }
            KeyCode::Enter => {
                if field == FilesField::PreviewButton {
                    self.start_preview();
                } else if field.is_list() {
                    self.open_pattern_modal(field == FilesField::Includes, true);
                } else if field.is_safety() {
                    self.toggle_safety(field);
                } else if field.is_text() {
                    if field == FilesField::ReferenceTime
                        && !self.files_form.reference_time.trim().is_empty()
                    {
                        self.files_form.commit_reference_time();
                        self.files_form.editing = false;
                        self.files_form.refresh_probes();
                        self.files_form.focus_next(true);
                    } else if self.files_form.editing {
                        self.files_form.editing = false;
                        self.files_form.refresh_probes();
                        self.files_form.focus_next(true);
                    } else {
                        self.files_form.editing = true;
                        self.files_form.cursor = self.files_form.text(field).map_or(0, String::len);
                    }
                } else {
                    self.files_form.toggle_regular(field, true);
                    self.files_form.refresh_probes();
                }
            }
            // Pattern list management (Includes / Excludes)
            KeyCode::Char('a') if field.is_list() => {
                self.open_pattern_modal(field == FilesField::Includes, false);
            }
            KeyCode::Char('e') if field.is_list() => {
                self.open_pattern_modal(field == FilesField::Includes, true);
            }
            KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace if field.is_list() => {
                let (list, idx) = if field == FilesField::Includes {
                    (
                        &mut self.files_form.include,
                        &mut self.files_form.include_idx,
                    )
                } else {
                    (
                        &mut self.files_form.exclude,
                        &mut self.files_form.exclude_idx,
                    )
                };
                if !list.is_empty() {
                    let remove_at = (*idx).min(list.len() - 1);
                    list.remove(remove_at);
                    if *idx >= list.len() && !list.is_empty() {
                        *idx = list.len() - 1;
                    }
                }
            }
            KeyCode::Left if field.is_list() => {
                let (list, idx) = if field == FilesField::Includes {
                    (&self.files_form.include, &mut self.files_form.include_idx)
                } else {
                    (&self.files_form.exclude, &mut self.files_form.exclude_idx)
                };
                if !list.is_empty() {
                    *idx = (*idx + list.len() - 1) % list.len();
                }
            }
            KeyCode::Right if field.is_list() => {
                let (list, idx) = if field == FilesField::Includes {
                    (&self.files_form.include, &mut self.files_form.include_idx)
                } else {
                    (&self.files_form.exclude, &mut self.files_form.exclude_idx)
                };
                if !list.is_empty() {
                    *idx = (*idx + 1) % list.len();
                }
            }
            // Non-text field shortcuts
            KeyCode::Char('p') if !field.is_text() => self.start_preview(),
            KeyCode::Char('?') if !field.is_text() => self.modal = Some(Modal::Help),
            KeyCode::Char('q') if !field.is_text() => self.screen = Screen::Home,
            KeyCode::Char(' ') if field == FilesField::PreviewButton => self.start_preview(),
            KeyCode::Char(' ') | KeyCode::Right if !field.is_text() => {
                if field.is_safety() {
                    self.toggle_safety(field);
                } else {
                    self.files_form.toggle_regular(field, true);
                    self.files_form.refresh_probes();
                }
            }
            KeyCode::Left if !field.is_text() => {
                if field.is_safety() {
                    // Left on a safety toggle turns it off without confirmation
                    match field {
                        FilesField::AllowTmpfs => self.files_form.allow_tmpfs = false,
                        FilesField::AllowWritableSource => {
                            self.files_form.allow_writable_source = false
                        }
                        _ => {}
                    }
                    self.files_form.refresh_probes();
                } else {
                    self.files_form.toggle_regular(field, false);
                    self.files_form.refresh_probes();
                }
            }
            // Text field editing
            _ if field.is_text() => {
                let mut cursor = self.files_form.cursor;
                if let Some(t) = self.files_form.text_mut(field) {
                    let before = t.clone();
                    edit_text(t, &mut cursor, key);
                    let changed = *t != before;
                    self.files_form.cursor = cursor;
                    if changed {
                        self.files_form.editing = true;
                        match field {
                            FilesField::CaseNumber | FilesField::EvidenceNumber => {
                                self.files_form.update_output_suggestion();
                                self.files_form.refresh_probes();
                            }
                            FilesField::SourcePath => {
                                self.files_form.sync_selected_mount();
                                self.files_form.refresh_probes();
                            }
                            FilesField::OutputPath => {
                                self.files_form.output_customized =
                                    !self.files_form.output_path.trim().is_empty();
                                self.files_form.refresh_probes();
                            }
                            FilesField::ReferenceTime => {
                                self.files_form.reference_entered_ns = None;
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn toggle_safety(&mut self, field: FilesField) {
        let currently_on = match field {
            FilesField::AllowTmpfs => self.files_form.allow_tmpfs,
            FilesField::AllowWritableSource => self.files_form.allow_writable_source,
            _ => false,
        };
        if currently_on {
            match field {
                FilesField::AllowTmpfs => self.files_form.allow_tmpfs = false,
                FilesField::AllowWritableSource => self.files_form.allow_writable_source = false,
                _ => {}
            }
            self.files_form.refresh_probes();
        } else {
            self.modal = Some(Modal::ConfirmSafety { field });
        }
    }

    fn open_pattern_modal(&mut self, is_include: bool, edit_existing: bool) {
        let (list, idx) = if is_include {
            (&self.files_form.include, self.files_form.include_idx)
        } else {
            (&self.files_form.exclude, self.files_form.exclude_idx)
        };
        if edit_existing && !list.is_empty() {
            let clamped = idx.min(list.len() - 1);
            let text = list[clamped].clone();
            let cursor = text.len();
            self.modal = Some(Modal::EditPattern {
                is_include,
                index: Some(clamped),
                text,
                cursor,
                error: None,
            });
        } else {
            self.modal = Some(Modal::EditPattern {
                is_include,
                index: None,
                text: String::new(),
                cursor: 0,
                error: None,
            });
        }
    }

    // ------------------------------------------------------------------
    // Path completion
    // ------------------------------------------------------------------

    pub fn complete_path(&mut self, target: PathTarget) {
        if let Some(c) = &mut self.completion {
            if c.target == target && !c.candidates.is_empty() {
                let next = c.index.map_or(0, |i| (i + 1) % c.candidates.len());
                c.index = Some(next);
                let candidate = c.candidates[next].clone();
                let suffix = c.suffix.clone();
                self.set_path_text(target, format!("{candidate}{suffix}"), candidate.len());
                return;
            }
        }

        let dirs_only = match target {
            PathTarget::Files(f) => f.is_dirs_only_path(),
            PathTarget::Verify => true,
        };
        let (text, cursor) = match target {
            PathTarget::Files(f) => {
                let Some(t) = self.files_form.text(f) else {
                    return;
                };
                (t.clone(), self.files_form.cursor)
            }
            PathTarget::Verify => (self.verify_state.path.clone(), self.verify_state.cursor),
        };
        let mut at = cursor.min(text.len());
        while at > 0 && !text.is_char_boundary(at) {
            at -= 1;
        }
        let prefix = &text[..at];
        let suffix = text[at..].to_string();
        let candidates = find_path_completions(prefix, dirs_only);
        match candidates.len() {
            0 => {
                self.completion = None;
                self.notify(NoticeLevel::Info, "No matching paths.");
            }
            1 => {
                let only = &candidates[0];
                let new_text = format!("{only}{suffix}");
                let new_cursor = only.len();
                self.completion = None;
                self.set_path_text(target, new_text, new_cursor);
            }
            _ => {
                let lcp = longest_common_prefix(&candidates);
                let new_cursor = if lcp.len() > prefix.len() {
                    let new_text = format!("{lcp}{suffix}");
                    let len = lcp.len();
                    self.set_path_text(target, new_text, len);
                    len
                } else {
                    at
                };
                let _ = new_cursor;
                self.completion = Some(CompletionState {
                    target,
                    candidates,
                    index: None,
                    suffix,
                });
            }
        }
    }

    fn set_path_text(&mut self, target: PathTarget, new_text: String, new_cursor: usize) {
        match target {
            PathTarget::Files(f) => {
                if let Some(t) = self.files_form.text_mut(f) {
                    *t = new_text;
                }
                self.files_form.cursor = new_cursor;
                self.files_form.editing = true;
                if f == FilesField::SourcePath {
                    self.files_form.sync_selected_mount();
                } else if f == FilesField::OutputPath {
                    self.files_form.output_customized = true;
                }
                self.files_form.refresh_probes();
            }
            PathTarget::Verify => {
                self.verify_state.path = new_text;
                self.verify_state.cursor = new_cursor;
                self.verify_state.editing = true;
            }
        }
    }

    // ------------------------------------------------------------------
    // Preview & Start
    // ------------------------------------------------------------------

    pub fn start_preview(&mut self) {
        if self.is_worker_running() {
            return;
        }
        self.files_form.refresh_probes();
        let errors = self.files_form.validate_all();
        if let Some((first_field, msg)) = errors.first() {
            self.files_form.set_focus(*first_field);
            self.notify(NoticeLevel::Error, msg.clone());
            return;
        }

        let argv = files_argv(&self.files_form);
        let args = match parse_files_argv(&argv) {
            Ok(a) => a,
            Err((maybe_field, msg)) => {
                if let Some(f) = maybe_field {
                    self.files_form.set_focus(f);
                }
                self.notify(NoticeLevel::Error, msg);
                return;
            }
        };

        // Validate scope rules before launching the worker
        match scope::build(&args.scope).and_then(|s| s.rules()) {
            Ok(_) => {}
            Err(e) => {
                let target_field = if !self.files_form.scope_file.trim().is_empty() {
                    FilesField::ScopeFile
                } else {
                    FilesField::Includes
                };
                self.files_form.set_focus(target_field);
                self.notify(NoticeLevel::Error, format!("{e:#}"));
                return;
            }
        }

        self.stop.clear_examiner();
        let progress = Arc::new(Progress::default());
        let progress_worker = Arc::clone(&progress);
        let args_worker = args.clone();
        let argv_worker = argv.clone();
        let stop_ref = self.stop;

        let handle = std::thread::spawn(move || {
            let ctx = RunCtx {
                stop: stop_ref,
                progress: Some(&progress_worker),
                argv: Some(argv_worker),
                interactive: true,
                preview: None,
                credential: Default::default(),
                reference_entered_ns: None,
                console: Arc::new(QuietConsole::default()),
            };
            files::preview(&args_worker, &ctx)
        });

        self.notice = None;
        self.preview_state = Some(PreviewState::Running {
            argv,
            args: Box::new(args),
            progress,
            started: Instant::now(),
            handle: Some(handle),
        });
        self.screen = Screen::Preview;
    }

    fn handle_preview_key(&mut self, key: KeyEvent) {
        if self.is_worker_running() {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('s')) {
                self.stop.examiner.store(true, Ordering::Relaxed);
                self.notify(NoticeLevel::Warning, "Stopping preview...");
            }
            return;
        }

        match key.code {
            KeyCode::Char('e') | KeyCode::Esc => {
                self.screen = Screen::FilesForm;
            }
            KeyCode::Char('r') | KeyCode::F(2) => {
                self.start_preview();
            }
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('c') => {
                if let Some(argv) = self.preview_argv() {
                    let quoted = shell_quote(&argv);
                    self.pending_osc52 = Some(base64(quoted.as_bytes()));
                    if let Some(PreviewState::Ready(data)) = &mut self.preview_state {
                        data.copied_osc52 = true;
                    }
                    self.notify(
                        NoticeLevel::Info,
                        "Equivalent command copied to clipboard (OSC 52).",
                    );
                }
            }
            KeyCode::Enter => {
                self.request_start_acquisition();
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll_preview(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_preview(1),
            KeyCode::PageUp => self.scroll_preview(-10),
            KeyCode::PageDown => self.scroll_preview(10),
            KeyCode::Home => self.scroll_preview(-10_000),
            KeyCode::End => self.scroll_preview(10_000),
            _ => {}
        }
    }

    fn preview_argv(&self) -> Option<Vec<String>> {
        match &self.preview_state {
            Some(PreviewState::Ready(d)) => Some(d.argv.clone()),
            Some(PreviewState::Failed { argv, .. }) => Some(argv.clone()),
            Some(PreviewState::Running { argv, .. }) => Some(argv.clone()),
            None => None,
        }
    }

    fn scroll_preview(&mut self, delta: isize) {
        if let Some(PreviewState::Ready(data)) = &mut self.preview_state {
            let max = data.preview.sample.len().saturating_sub(1);
            if delta < 0 {
                data.scroll = data.scroll.saturating_sub(delta.unsigned_abs());
            } else {
                data.scroll = (data.scroll + delta as usize).min(max);
            }
        }
    }

    /// Attempt to open the Start confirmation sheet (or refuse if the preview is stale).
    pub fn request_start_acquisition(&mut self) -> bool {
        if self.is_preview_stale() {
            self.notify(
                NoticeLevel::Error,
                "Preview is stale or incomplete; press F2 / 'r' to run the preview again before starting.",
            );
            return false;
        }
        self.modal = Some(Modal::ConfirmStart);
        true
    }

    /// Launch `files::run_with` on the worker thread using the previewed arguments.
    pub fn start_files_run(&mut self) -> bool {
        if self.is_worker_running() || self.is_preview_stale() {
            self.notify(
                NoticeLevel::Error,
                "Preview is stale or incomplete; run the preview again before starting.",
            );
            return false;
        }
        let Some(PreviewState::Ready(data)) = &self.preview_state else {
            return false;
        };
        let args = data.args.clone();
        let argv = data.argv.clone();
        let preview = Some(data.preview.note());
        let reference_entered_ns = self.files_form.reference_entered_ns;
        let expected_files = data.preview.files;
        let expected_bytes = data.preview.bytes;

        self.stop.clear_examiner();
        let progress = Arc::new(Progress::default());
        let progress_worker = Arc::clone(&progress);
        let args_worker = args.clone();
        let argv_worker = argv.clone();
        let stop_ref = self.stop;

        let handle = std::thread::spawn(move || {
            let ctx = RunCtx {
                stop: stop_ref,
                progress: Some(&progress_worker),
                argv: Some(argv_worker),
                interactive: true,
                preview,
                credential: Default::default(),
                reference_entered_ns,
                console: Arc::new(QuietConsole::default()),
            };
            files::run_with(&args_worker, &ctx)
        });

        let now = Instant::now();
        let mut rate_samples = VecDeque::new();
        rate_samples.push_back((now, 0));

        self.notice = None;
        self.run_state = Some(RunState {
            args: Box::new(args),
            argv,
            expected_files,
            expected_bytes,
            progress,
            started: now,
            rate_samples,
            stop_requested: false,
            handle: Some(handle),
        });
        self.screen = Screen::Running;
        true
    }

    // ------------------------------------------------------------------
    // Running & Result screens
    // ------------------------------------------------------------------

    fn request_stop_acquisition(&mut self) {
        if let Some(run) = &self.run_state {
            if run.stop_requested {
                self.notify(
                    NoticeLevel::Warning,
                    "Stop already requested; waiting for collection to close as aborted...",
                );
                return;
            }
        }
        self.modal = Some(Modal::ConfirmStop);
    }

    fn handle_running_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('s') => self.request_stop_acquisition(),
            KeyCode::Char('q') | KeyCode::Esc => {
                self.notify(
                    NoticeLevel::Warning,
                    "Cannot quit while running — press 's' to stop first.",
                );
            }
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            _ => {}
        }
    }

    fn handle_result_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('h') | KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('n') => {
                self.files_form.reset_for_next_acquisition();
                self.preview_state = None;
                self.result_data = None;
                self.notice = None;
                self.screen = Screen::FilesForm;
            }
            KeyCode::Char('v') => {
                if let Some(res) = &self.result_data {
                    let path = res.collection.clone();
                    let has_manifest = path.join(dfcore::manifest::MANIFEST).is_file();
                    self.open_verify(Some(path), has_manifest);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll_result(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_result(1),
            KeyCode::PageUp => self.scroll_result(-10),
            KeyCode::PageDown => self.scroll_result(10),
            KeyCode::Home => self.scroll_result(-10_000),
            KeyCode::End => self.scroll_result(10_000),
            _ => {}
        }
    }

    fn scroll_result(&mut self, delta: isize) {
        if let Some(res) = &mut self.result_data {
            if delta < 0 {
                res.scroll = res.scroll.saturating_sub(delta.unsigned_abs());
            } else {
                res.scroll = res.scroll.saturating_add(delta as usize);
            }
        }
    }

    // ------------------------------------------------------------------
    // Verify screen
    // ------------------------------------------------------------------

    fn handle_verify_key(&mut self, key: KeyEvent) {
        if self.is_worker_running() {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('s')) {
                self.stop.examiner.store(true, Ordering::Relaxed);
                self.notify(NoticeLevel::Warning, "Stopping verification...");
            }
            return;
        }

        let focus = self.verify_state.focus;
        let tab_completes = focus == VerifyFocus::PathInput
            && (self.verify_state.editing || self.completion.is_some())
            && key.code == KeyCode::Tab;

        if key.code != KeyCode::F(4) && !tab_completes {
            self.completion = None;
        }

        if key.code == KeyCode::F(4) || tab_completes {
            if focus == VerifyFocus::PathInput {
                self.complete_path(PathTarget::Verify);
            }
            return;
        }

        if key.code == KeyCode::F(2) {
            self.start_verify();
            return;
        }

        match key.code {
            KeyCode::Esc => {
                if self.verify_state.editing {
                    self.verify_state.editing = false;
                } else {
                    self.screen = Screen::Home;
                }
            }
            KeyCode::Tab => {
                self.verify_state.editing = false;
                self.verify_state.focus = match focus {
                    VerifyFocus::PathInput if !self.session_collections.is_empty() => {
                        VerifyFocus::SessionList
                    }
                    VerifyFocus::PathInput | VerifyFocus::SessionList => VerifyFocus::VerifyButton,
                    VerifyFocus::VerifyButton => VerifyFocus::PathInput,
                };
            }
            KeyCode::BackTab => {
                self.verify_state.editing = false;
                self.verify_state.focus = match focus {
                    VerifyFocus::PathInput => VerifyFocus::VerifyButton,
                    VerifyFocus::SessionList => VerifyFocus::PathInput,
                    VerifyFocus::VerifyButton if !self.session_collections.is_empty() => {
                        VerifyFocus::SessionList
                    }
                    VerifyFocus::VerifyButton => VerifyFocus::PathInput,
                };
            }
            KeyCode::Enter => match focus {
                VerifyFocus::PathInput | VerifyFocus::VerifyButton => {
                    self.verify_state.editing = false;
                    self.start_verify();
                }
                VerifyFocus::SessionList => {
                    if let Some(dir) = self
                        .session_collections
                        .get(self.verify_state.session_idx)
                        .cloned()
                    {
                        self.verify_state.path = dir.display().to_string();
                        self.verify_state.cursor = self.verify_state.path.len();
                        self.start_verify();
                    }
                }
            },
            KeyCode::Up if focus == VerifyFocus::SessionList => {
                let n = self.session_collections.len();
                if n > 0 {
                    self.verify_state.session_idx = (self.verify_state.session_idx + n - 1) % n;
                    if let Some(dir) = self.session_collections.get(self.verify_state.session_idx) {
                        self.verify_state.path = dir.display().to_string();
                        self.verify_state.cursor = self.verify_state.path.len();
                    }
                }
            }
            KeyCode::Down if focus == VerifyFocus::SessionList => {
                let n = self.session_collections.len();
                if n > 0 {
                    self.verify_state.session_idx = (self.verify_state.session_idx + 1) % n;
                    if let Some(dir) = self.session_collections.get(self.verify_state.session_idx) {
                        self.verify_state.path = dir.display().to_string();
                        self.verify_state.cursor = self.verify_state.path.len();
                    }
                }
            }
            KeyCode::Up if self.verify_state.report.is_some() => {
                self.verify_state.scroll = self.verify_state.scroll.saturating_sub(1);
            }
            KeyCode::Down if self.verify_state.report.is_some() => {
                self.verify_state.scroll = self.verify_state.scroll.saturating_add(1);
            }
            KeyCode::PageUp if self.verify_state.report.is_some() => {
                self.verify_state.scroll = self.verify_state.scroll.saturating_sub(10);
            }
            KeyCode::PageDown if self.verify_state.report.is_some() => {
                self.verify_state.scroll = self.verify_state.scroll.saturating_add(10);
            }
            KeyCode::Char('q') if focus != VerifyFocus::PathInput => {
                self.should_quit = true;
            }
            KeyCode::Char('?') if focus != VerifyFocus::PathInput => {
                self.modal = Some(Modal::Help);
            }
            KeyCode::Char(' ') if focus == VerifyFocus::VerifyButton => {
                self.start_verify();
            }
            _ if focus == VerifyFocus::PathInput => {
                let before = self.verify_state.path.clone();
                edit_text(
                    &mut self.verify_state.path,
                    &mut self.verify_state.cursor,
                    key,
                );
                if self.verify_state.path != before {
                    self.verify_state.editing = true;
                }
            }
            _ => {}
        }
    }

    pub fn start_verify(&mut self) {
        if self.is_worker_running() {
            return;
        }
        let raw = self.verify_state.path.trim();
        if raw.is_empty() {
            self.verify_state.focus = VerifyFocus::PathInput;
            self.notify(
                NoticeLevel::Error,
                "collection directory is required for verification",
            );
            return;
        }
        let dir = expand_tilde(Path::new(raw));
        let container_bytes = std::fs::metadata(dir.join(files::CONTAINER))
            .ok()
            .map(|m| m.len());
        let argv = verify_argv(&dir);

        self.stop.clear_examiner();
        let progress = Arc::new(Progress::default());
        let progress_worker = Arc::clone(&progress);
        let dir_worker = dir.clone();
        let stop_ref = self.stop;

        let handle = std::thread::spawn(move || {
            let ctx = RunCtx {
                stop: stop_ref,
                progress: Some(&progress_worker),
                argv: Some(argv),
                interactive: true,
                preview: None,
                credential: Default::default(),
                reference_entered_ns: None,
                console: Arc::new(QuietConsole::default()),
            };
            verify::run_with(&dir_worker, &ctx)
        });

        self.notice = None;
        self.verify_state.report = None;
        self.verify_state.scroll = 0;
        self.verify_state.running = Some(VerifyRunning {
            dir,
            container_bytes,
            progress,
            started: Instant::now(),
            handle: Some(handle),
        });
    }
}

fn validate_single_pattern(pat: &str, is_include: bool) -> Result<(), String> {
    let scope = dfcore::manifest::Scope {
        include: if is_include {
            vec![pat.to_string()]
        } else {
            Vec::new()
        },
        exclude: if is_include {
            Vec::new()
        } else {
            vec![pat.to_string()]
        },
        ..Default::default()
    };
    scope.rules().map(|_| ()).map_err(|e| format!("{e:#}"))
}

/// Format a duration as `MM:SS` or `HH:MM:SS`.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

/// Summary line for the confirmation modal before starting an acquisition.
pub fn confirm_start_lines(form: &FilesForm, preview: &PreviewData) -> Vec<(String, String)> {
    let mut lines = vec![
        (
            "Source".into(),
            preview.preview.source.display().to_string(),
        ),
        (
            "Output collection".into(),
            preview.preview.output.display().to_string(),
        ),
        (
            "Case / Evidence".into(),
            format!("{} / {}", form.case.trim(), form.evidence.trim()),
        ),
        ("Examiner".into(), form.examiner.trim().to_string()),
        (
            "In-scope items".into(),
            format!(
                "{} files ({}), {} dirs, {} symlinks",
                preview.preview.files,
                human_bytes(preview.preview.bytes),
                preview.preview.directories,
                preview.preview.symlinks
            ),
        ),
    ];
    if let Some(stamp) = form.reference_stamp_hint() {
        lines.push(("Ref. clock".into(), stamp));
    }
    if let Some(free) = preview.preview.target_free {
        lines.push(("Target free space".into(), human_bytes(free)));
    }
    if form.allow_tmpfs || form.allow_writable_source {
        let mut flags = Vec::new();
        if form.allow_tmpfs {
            flags.push("--allow-tmpfs");
        }
        if form.allow_writable_source {
            flags.push("--allow-writable-source");
        }
        lines.push(("Safety overrides".into(), flags.join(", ")));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::form::{OutputProbe, SourceProbe};
    use std::collections::BTreeMap;

    fn sample_app(stop: &'static Stop) -> App {
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
    fn stale_preview_blocks_start() {
        static TEST_STOP: Stop = Stop::new();
        let mut app = sample_app(&TEST_STOP);

        // Without any preview, Start is blocked
        assert!(app.is_preview_stale());
        assert!(!app.request_start_acquisition());
        assert!(app.modal.is_none());

        // Attach a matching, completed preview
        let argv = files_argv(&app.files_form);
        let args = parse_files_argv(&argv).unwrap();
        let preview = Preview {
            source: PathBuf::from("/media/evidence/sdb1"),
            output: PathBuf::from("/media/target/sdc1/VG_12345_26/share01"),
            files: 3,
            bytes: 4096,
            directories: 1,
            symlinks: 0,
            special: 0,
            out_of_scope: BTreeMap::new(),
            excluded_trees: 0,
            trees_outside_includes: 0,
            other_filesystems: Vec::new(),
            errors: Vec::new(),
            sample: Vec::new(),
            target_free: Some(500 << 30),
            stopped: None,
            at_ns: 1_776_000_000_000_000_000,
        };
        app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
            preview: preview.clone(),
            argv: argv.clone(),
            args: args.clone(),
            scroll: 0,
            copied_osc52: false,
        })));
        assert!(!app.is_preview_stale());
        assert!(app.request_start_acquisition());
        assert_eq!(app.modal, Some(Modal::ConfirmStart));
        app.modal = None;

        // Mutating any form field makes the preview stale and blocks Start
        app.files_form.include.push("Documents/**".into());
        assert!(app.is_preview_stale());
        assert!(!app.request_start_acquisition());
        assert!(app.modal.is_none());
        assert!(!app.start_files_run());

        // Revert form change, but mark preview as stopped early -> still blocked
        app.files_form.include.clear();
        let mut stopped_preview = preview;
        stopped_preview.stopped = Some("stopped by the examiner".into());
        app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
            preview: stopped_preview,
            argv,
            args,
            scroll: 0,
            copied_osc52: false,
        })));
        assert!(app.is_preview_stale());
        assert!(!app.request_start_acquisition());
    }

    #[test]
    fn examiner_stop_through_worker_records_aborted_and_exit_8() {
        static WORKER_STOP: Stop = Stop::new();
        WORKER_STOP.clear_examiner();
        crate::common::test_audit_log();

        let base_dir = if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        let root = base_dir.join(format!("dfcollect-tui-stop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("src");
        let out = root.join("out");
        std::fs::create_dir_all(&src).unwrap();

        // Create several 2 MiB files so the worker is mid-copy when stopped
        let chunk = vec![b'A'; 2 * 1024 * 1024];
        for i in 0..24 {
            std::fs::write(src.join(format!("file-{i:02}.bin")), &chunk).unwrap();
        }

        let mut app = App::with_mounts(&WORKER_STOP, Vec::new(), Vec::new());
        app.files_form.case = "VG 12345/26".into();
        app.files_form.evidence = "ev01".into();
        app.files_form.examiner = "KHK Muster".into();
        app.files_form.source_path = src.display().to_string();
        app.files_form.output_path = out.display().to_string();
        app.files_form.allow_tmpfs = true;
        app.files_form.allow_writable_source = true;

        // Run preview through the worker first
        app.start_preview();
        assert_eq!(app.screen, Screen::Preview);
        app.wait_for_worker();
        assert!(!app.is_preview_stale());

        // Pre-arm examiner stop right after launching the run worker, or as soon
        // as it enters Copying, to guarantee deterministic stop in fast sandboxes.
        assert!(app.start_files_run());
        assert_eq!(app.screen, Screen::Running);

        // Wait briefly for the collection directory or first bytes, then trigger examiner stop
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(2) {
            if let Some(run) = &app.run_state {
                if run.progress.bytes.load(Ordering::Relaxed) > 0 || out.exists() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // Simulate pressing 's' then 'y' in Modal::ConfirmStop
        app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        assert_eq!(app.modal, Some(Modal::ConfirmStop));
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(WORKER_STOP.examiner.load(Ordering::Relaxed));

        // If the worker happened to finish all 48 MiB before the 1 ms poll on an
        // ultra-fast host, re-run with examiner stop pre-set right after collection creation.
        app.wait_for_worker();
        let res = app.result_data.take().unwrap();
        let res = if res.code == 0 {
            let out2 = root.join("out2");
            app.files_form.output_path = out2.display().to_string();
            app.start_preview();
            app.wait_for_worker();
            WORKER_STOP.clear_examiner();
            assert!(app.start_files_run());
            WORKER_STOP.examiner.store(true, Ordering::Relaxed);
            app.wait_for_worker();
            app.result_data.take().unwrap()
        } else {
            res
        };

        assert_eq!(res.code, 8, "expected exit 8, got {:?}", res);
        assert_eq!(res.status, "aborted");

        let manifest_text = std::fs::read_to_string(res.collection.join("manifest.json")).unwrap();
        let manifest_json: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();
        assert_eq!(manifest_json["status"], "aborted");
        assert!(
            res.problems
                .iter()
                .any(|p| p.contains("stopped by the examiner")),
            "problems: {:?}",
            res.problems
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_report_from_real_collection_and_reference_clock_stamp() {
        static VERIFY_STOP: Stop = Stop::new();
        VERIFY_STOP.clear_examiner();
        crate::common::test_audit_log();

        let base_dir = if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        let root = base_dir.join(format!("dfcollect-tui-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("src");
        let out = root.join("out");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("alpha.txt"), b"alpha").unwrap();
        std::fs::write(src.join("beta.txt"), b"beta").unwrap();

        let mut app = App::with_mounts(&VERIFY_STOP, Vec::new(), Vec::new());
        app.open_files_form();
        app.files_form.case = "VG 12345/26".into();
        app.files_form.evidence = "ev01".into();
        app.files_form.examiner = "KHK Muster".into();
        app.files_form.source_path = src.display().to_string();
        app.files_form.output_path = out.display().to_string();
        app.files_form.allow_tmpfs = true;
        app.files_form.allow_writable_source = true;

        // Set reference clock and commit with a fixed stamp; verify edit clears it
        app.files_form.reference_time = "2027-01-15T08:00:05Z".into();
        app.files_form.set_focus(FilesField::ReferenceTime);
        app.files_form
            .commit_reference_time_at(1_800_000_000_000_000_000);
        assert_eq!(
            app.files_form.reference_entered_ns,
            Some(1_800_000_000_000_000_000)
        );
        // Simulate typing/editing ReferenceTime -> clears stamp
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(app.files_form.reference_entered_ns.is_none());
        app.handle_key(KeyEvent::new(KeyCode::Char('Z'), KeyModifiers::NONE));
        app.files_form
            .commit_reference_time_at(1_800_000_000_000_000_000);
        app.files_form.reference_how = "DCF77".into();

        app.start_preview();
        app.wait_for_worker();
        assert!(!app.is_preview_stale());

        assert!(app.start_files_run());
        app.wait_for_worker();
        let res = app.result_data.take().unwrap();
        assert_eq!(res.code, 0);
        assert!(app.session_collections.contains(&out));

        // Verify manifest recorded the committed reference clock stamp
        let manifest_text = std::fs::read_to_string(out.join("manifest.json")).unwrap();
        let manifest_json: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();
        assert_eq!(
            manifest_json["clocks"]["reference"]["local"],
            "2027-01-15T08:00:00.000000000Z"
        );
        assert_eq!(manifest_json["clocks"]["reference"]["offset_seconds"], 5.0);

        // Run verify::run_with and build VerifyReportData::from_outcome
        let outcome = verify::run_with(&out, &RunCtx::cli(&VERIFY_STOP, None)).unwrap();
        let rep = VerifyReportData::from_outcome(&outcome, out.clone());
        assert_eq!(rep.status, "complete");
        assert!(rep.ok);
        assert_eq!(rep.members_ok, 2);
        assert_eq!(rep.files_ok, 0);
        assert_eq!(rep.audit_anchor_found, Some(true));

        let _ = std::fs::remove_dir_all(&root);
    }
}
