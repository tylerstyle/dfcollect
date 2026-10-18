//! Application state, screen transitions, key handling, `TuiConsole` and
//! worker-thread polling for the `dfcollect` TUI (`files`, `ingest`, `cloud`,
//! `db` and `verify`).

use crate::{
    args::{CloudArgs, DbArgs, FilesArgs, IngestArgs},
    cloud::{self, CloudPreview},
    common::{human_bytes, Credential, PreviewNote, Progress, RunCtx, Stop},
    console::{Cancelled, Console, Level, QuietConsole, SecretAsk, SignIn},
    db::{self, DbPreview},
    files::{self, Preview},
    ingest::{self, IngestPreview},
    mail::client::base64,
    scope,
    tui::{
        autocomplete::{expand_tilde, find_path_completions, longest_common_prefix},
        command::{
            cloud_argv, db_argv, files_argv, ingest_argv, parse_cloud_argv, parse_db_argv,
            parse_files_argv, parse_ingest_argv, shell_quote, verify_argv,
        },
        form::{
            CloudField, CloudForm, DbConnKey, DbField, DbForm, FilesField, FilesForm, IngestField,
            IngestForm, SharedFormState,
        },
        input::edit_text,
        mounts::{discover_mounts, MountChoice},
    },
    verify, Usage,
};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        atomic::Ordering,
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn sanitize_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Rolling window for the transfer-rate estimate on the Run screen.
const RATE_WINDOW: Duration = Duration::from_secs(5);

/// Maximum number of console notices retained in the ring buffer.
pub const MAX_NOTICES: usize = 50;

/// Request sent from a worker thread (`TuiConsole::secret`) to the UI thread.
pub struct SecretRequest {
    pub ask: SecretAsk,
    pub reply: Sender<Option<Zeroizing<String>>>,
}

/// TUI implementation of [`Console`]: routes secret prompts to a masked modal
/// on the UI thread via an `mpsc` channel, and buffers notices (up to 50) for
/// the Run screen's notices pane.
pub struct TuiConsole {
    stop: &'static Stop,
    secret_tx: Sender<SecretRequest>,
    pub notices: Mutex<VecDeque<(Level, String)>>,
    pub sign_in: Mutex<Option<SignIn>>,
}

impl TuiConsole {
    pub fn new(stop: &'static Stop, secret_tx: Sender<SecretRequest>) -> Self {
        Self {
            stop,
            secret_tx,
            notices: Mutex::new(VecDeque::with_capacity(MAX_NOTICES)),
            sign_in: Mutex::new(None),
        }
    }

    pub fn notices_snapshot(&self) -> Vec<(Level, String)> {
        self.notices
            .lock()
            .map(|q| q.iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl Console for TuiConsole {
    fn secret(&self, ask: &SecretAsk) -> anyhow::Result<Option<Zeroizing<String>>> {
        if self.stop.is_set() {
            return Ok(None);
        }
        let (reply_tx, reply_rx) = mpsc::channel();
        if self
            .secret_tx
            .send(SecretRequest {
                ask: ask.clone(),
                reply: reply_tx,
            })
            .is_err()
        {
            return Ok(None);
        }
        loop {
            match reply_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(ans) => return Ok(ans),
                Err(RecvTimeoutError::Disconnected) => return Ok(None),
                Err(RecvTimeoutError::Timeout) => {
                    if self.stop.is_set() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn sign_in(&self, s: &SignIn) {
        if let Ok(mut guard) = self.sign_in.lock() {
            *guard = Some(s.clone());
        }
    }

    fn pasted(&self) -> Option<String> {
        None
    }

    fn sign_in_done(&self) {
        if let Ok(mut guard) = self.sign_in.lock() {
            *guard = None;
        }
    }

    fn notice(&self, level: Level, text: &str) {
        if let Ok(mut q) = self.notices.lock() {
            if q.len() >= MAX_NOTICES {
                q.pop_front();
            }
            q.push_back((level, sanitize_line(text)));
        }
    }
}

/// Acquisition mode active in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Files,
    Ingest,
    Cloud,
    Db,
}

impl Mode {
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Ingest => "ingest",
            Self::Cloud => "cloud",
            Self::Db => "db",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Files => "Files",
            Self::Ingest => "Ingest",
            Self::Cloud => "Cloud",
            Self::Db => "Database",
        }
    }

    pub fn form_screen(self) -> Screen {
        match self {
            Self::Files => Screen::FilesForm,
            Self::Ingest => Screen::IngestForm,
            Self::Cloud => Screen::CloudForm,
            Self::Db => Screen::DbForm,
        }
    }
}

/// Active screen of the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    FilesForm,
    IngestForm,
    CloudForm,
    DbForm,
    Preview,
    Running,
    Result,
    Verify,
}

/// Items on the Home screen. The first five are interactive TUI workflows in
/// Batch 1 (`files`, `verify`, `ingest`, `cloud`, `db`); the remaining four
/// mail/log modes are command-line only until Batch 2 and show their `--help`
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
        hint: "Scoped file acquisition from a read-only mount into a verifiable container",
    },
    HomeItem {
        title: "Verify a collection",
        command: "dfcollect verify",
        enabled: true,
        hint: "Verify manifest.json, items, footprint, data.zip members and audit anchors",
    },
    HomeItem {
        title: "Provider delivery package",
        command: "dfcollect ingest",
        enabled: true,
        hint: "Package and verify a provider delivery (e-Evidence / export) and hash lists",
    },
    HomeItem {
        title: "Cloud / remote storage (rclone)",
        command: "dfcollect cloud",
        enabled: true,
        hint: "Scoped read-only acquisition from OneDrive, Drive, Dropbox, S3 or WebDAV",
    },
    HomeItem {
        title: "Database dump (PostgreSQL / MariaDB)",
        command: "dfcollect db",
        enabled: true,
        hint: "Consistent logical database dump (pg_dump / mariadb-dump) into a container",
    },
    HomeItem {
        title: "IMAP mailbox",
        command: "dfcollect imap --help",
        enabled: false,
        hint: "CLI only: run `dfcollect imap --help` for read-only IMAP mailbox acquisition",
    },
    HomeItem {
        title: "Microsoft 365 mailbox (Graph)",
        command: "dfcollect graph --help",
        enabled: false,
        hint: "CLI only: run `dfcollect graph --help` for Microsoft 365 Graph acquisition",
    },
    HomeItem {
        title: "Gmail / Google Workspace mailbox",
        command: "dfcollect gmail --help",
        enabled: false,
        hint: "CLI only: run `dfcollect gmail --help` for Gmail API RFC 2822 acquisition",
    },
    HomeItem {
        title: "Microsoft 365 tenant audit logs",
        command: "dfcollect m365-logs --help",
        enabled: false,
        hint: "CLI only: run `dfcollect m365-logs --help` for Entra & Unified Audit Logs",
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

/// Which safety override toggle is being confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyTarget {
    Files(FilesField),
    IngestTmpfs,
    CloudTmpfs,
    DbTmpfs,
}

impl SafetyTarget {
    pub fn label(self) -> &'static str {
        match self {
            Self::Files(f) => f.label(),
            Self::IngestTmpfs | Self::CloudTmpfs | Self::DbTmpfs => "Allow tmpfs",
        }
    }

    pub fn is_writable_source(self) -> bool {
        matches!(self, Self::Files(FilesField::AllowWritableSource))
    }
}

/// Which repeatable list field is being edited in `Modal::EditListItem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListTarget {
    IngestHashes,
    CloudRcloneArgs,
    CloudInclude,
    CloudExclude,
    DbDatabases,
}

/// State of the masked secret prompt modal (`TuiConsole::secret`).
pub struct SecretModal {
    pub ask: SecretAsk,
    pub buffer: Zeroizing<String>,
    pub cursor: usize,
    pub reply: Sender<Option<Zeroizing<String>>>,
}

impl std::fmt::Debug for SecretModal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretModal")
            .field("ask", &self.ask)
            .field("len", &self.buffer.chars().count())
            .field("cursor", &self.cursor)
            .finish()
    }
}

impl Clone for SecretModal {
    fn clone(&self) -> Self {
        Self {
            ask: self.ask.clone(),
            buffer: self.buffer.clone(),
            cursor: self.cursor,
            reply: self.reply.clone(),
        }
    }
}

impl PartialEq for SecretModal {
    fn eq(&self, other: &Self) -> bool {
        self.ask == other.ask
            && self.buffer.as_str() == other.buffer.as_str()
            && self.cursor == other.cursor
    }
}

impl Eq for SecretModal {}

/// Modal dialog overlaid on the current screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// Keybindings help (`?` or `F1`).
    Help,
    /// Confirmation before enabling `--allow-tmpfs` or `--allow-writable-source`.
    ConfirmSafety { target: SafetyTarget },
    /// Adding or editing an `--include` or `--exclude` glob pattern on `FilesForm`.
    EditPattern {
        is_include: bool,
        index: Option<usize>,
        text: String,
        cursor: usize,
        error: Option<String>,
    },
    /// Adding or editing an entry in a repeatable list (`--hashes`, `--rclone-arg`,
    /// cloud `--include`/`--exclude`, `--database`).
    EditListItem {
        target: ListTarget,
        index: Option<usize>,
        text: String,
        cursor: usize,
        error: Option<String>,
    },
    /// Masked secret input requested by `TuiConsole::secret`.
    Secret(SecretModal),
    /// Confirmation sheet before starting the acquisition from the Preview screen.
    ConfirmStart,
    /// Confirmation sheet before stopping a running acquisition (`s` or `Ctrl+C`).
    ConfirmStop,
}

/// Which path field owns the current autocompletion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTarget {
    Files(FilesField),
    Ingest(IngestField),
    Cloud(CloudField),
    Db(DbField),
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

/// Mode-specific preview payload held inside [`PreviewData`].
#[derive(Debug)]
pub enum ModePreview {
    Files {
        preview: Preview,
        args: Box<FilesArgs>,
    },
    Ingest {
        preview: IngestPreview,
        args: Box<IngestArgs>,
    },
    Cloud {
        preview: CloudPreview,
        args: Box<CloudArgs>,
    },
    Db {
        preview: DbPreview,
        args: Box<DbArgs>,
    },
}

impl ModePreview {
    pub fn mode(&self) -> Mode {
        match self {
            Self::Files { .. } => Mode::Files,
            Self::Ingest { .. } => Mode::Ingest,
            Self::Cloud { .. } => Mode::Cloud,
            Self::Db { .. } => Mode::Db,
        }
    }

    pub fn note(&self) -> PreviewNote {
        match self {
            Self::Files { preview, .. } => preview.note(),
            Self::Ingest { preview, .. } => preview.note(),
            Self::Cloud { preview, .. } => preview.note(),
            Self::Db { preview, .. } => preview.note(),
        }
    }

    pub fn stopped(&self) -> Option<&str> {
        match self {
            Self::Files { preview, .. } => preview.stopped.as_deref(),
            Self::Ingest { preview, .. } => preview.stopped.as_deref(),
            Self::Cloud { preview, .. } => preview.stopped.as_deref(),
            Self::Db { .. } => None,
        }
    }

    pub fn short_of_space(&self) -> bool {
        match self {
            Self::Files { preview, .. } => preview.short_of_space(),
            Self::Ingest { preview, .. } => preview.short_of_space(),
            Self::Cloud { preview, .. } => preview.short_of_space(),
            Self::Db { preview, .. } => preview.short_of_space(),
        }
    }

    pub fn summary(&self) -> serde_json::Value {
        match self {
            Self::Files { preview, .. } => preview.summary(),
            Self::Ingest { preview, .. } => preview.summary(),
            Self::Cloud { preview, .. } => preview.summary(),
            Self::Db { preview, .. } => preview.summary(),
        }
    }

    /// Reason why `Start` must be refused even though the preview finished.
    pub fn start_block_reason(&self) -> Option<String> {
        match self {
            Self::Db { preview, .. } => {
                if !preview.missing.is_empty() {
                    return Some(format!(
                        "Cannot start: server does not have database(s): {}",
                        preview.missing.join(", ")
                    ));
                }
                let missing_tools: Vec<&str> = preview
                    .tools
                    .iter()
                    .filter(|(_, v)| v == "not found")
                    .map(|(t, _)| t.as_str())
                    .collect();
                if !missing_tools.is_empty() {
                    return Some(format!(
                        "Cannot start: dump tool(s) not found on PATH: {}",
                        missing_tools.join(", ")
                    ));
                }
                None
            }
            _ => None,
        }
    }

    pub fn scroll_max(&self) -> usize {
        match self {
            Self::Files { preview, .. } => preview.sample.len().saturating_sub(1),
            Self::Ingest { preview, .. } => {
                (preview.lists.len() + preview.missing.len() + preview.unlisted.len())
                    .saturating_sub(1)
            }
            Self::Cloud { preview, .. } => preview.sample.len().saturating_sub(1),
            Self::Db { preview, .. } => preview.databases.len().saturating_sub(1),
        }
    }
}

/// Output returned by a background preview worker thread.
pub struct PreviewWorkerOutput {
    pub mode_preview: ModePreview,
    pub db_credential: Option<(DbConnKey, Credential)>,
}

/// Finished preview held on [`Screen::Preview`].
#[derive(Debug)]
pub struct PreviewData {
    pub mode_preview: ModePreview,
    pub argv: Vec<String>,
    pub scroll: usize,
    pub copied_osc52: bool,
}

impl PreviewData {
    #[cfg(test)]
    pub fn from_files(preview: Preview, argv: Vec<String>, args: FilesArgs) -> Self {
        Self {
            mode_preview: ModePreview::Files {
                preview,
                args: Box::new(args),
            },
            argv,
            scroll: 0,
            copied_osc52: false,
        }
    }
}

/// State of the preview worker or its result.
pub enum PreviewState {
    Running {
        mode: Mode,
        argv: Vec<String>,
        progress: Arc<Progress>,
        console: Arc<TuiConsole>,
        started: Instant,
        handle: Option<JoinHandle<anyhow::Result<PreviewWorkerOutput>>>,
    },
    Ready(Box<PreviewData>),
    Failed {
        mode: Mode,
        argv: Vec<String>,
        error: String,
        code: u8,
    },
}

/// Live state of an in-progress acquisition on [`Screen::Running`].
pub struct RunState {
    pub mode: Mode,
    pub source_display: String,
    pub output: PathBuf,
    pub argv: Vec<String>,
    pub expected_files: u64,
    pub expected_bytes: u64,
    pub progress: Arc<Progress>,
    pub console: Arc<TuiConsole>,
    pub notices_expanded: bool,
    pub notices_scroll: usize,
    pub started: Instant,
    pub rate_samples: VecDeque<(Instant, u64)>,
    pub stop_requested: bool,
    pub handle: Option<JoinHandle<anyhow::Result<verify::Outcome>>>,
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
        if self.expected_bytes == 0 {
            return None;
        }
        let rate = self.rate_bps()?;
        if rate == 0 || current_bytes >= self.expected_bytes {
            return None;
        }
        let rem = self.expected_bytes - current_bytes;
        Some(Duration::from_secs(rem / rate))
    }
}

/// Format a summary JSON value for display on the Result screen.
fn format_summary_value(key: &str, val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => {
            if key == "bytes" {
                if let Some(b) = n.as_u64() {
                    return format!("{b} ({})", human_bytes(b));
                }
            }
            n.to_string()
        }
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "none".into(),
        serde_json::Value::Object(map) if key == "remote_changes" => {
            let added = map
                .get("added")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len);
            let removed = map
                .get("removed")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len);
            let changed = map
                .get("changed")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len);
            format!("{added} added, {removed} removed, {changed} changed")
        }
        other => other.to_string(),
    }
}

/// Structured result of a finished (or failed/aborted/cancelled) acquisition run.
#[derive(Debug, Clone)]
pub struct ResultData {
    pub mode: Mode,
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
    pub summary_kv: Vec<(String, String)>,
    pub audit_anchor: Option<String>,
    pub container_mismatches: Vec<String>,
    pub warnings: Vec<String>,
    pub problems: Vec<String>,
    pub fatal_error: Option<String>,
    pub left_unfinished: bool,
    pub scroll: usize,
}

impl ResultData {
    pub fn from_outcome_for_mode(
        mode: Mode,
        outcome: &verify::Outcome,
        collection: PathBuf,
        argv: Vec<String>,
    ) -> Self {
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
        let mut summary_kv = Vec::new();
        if let Some(map) = s.as_object() {
            for (k, v) in map {
                if matches!(
                    k.as_str(),
                    "collection"
                        | "status"
                        | "acquired"
                        | "files"
                        | "dumps"
                        | "bytes"
                        | "errors"
                        | "skipped"
                        | "audit_anchor"
                        | "problems"
                        | "warnings"
                        | "container_mismatches"
                ) {
                    continue;
                }
                summary_kv.push((k.clone(), format_summary_value(k, v)));
            }
        }
        let acquired = s
            .get("acquired")
            .or_else(|| s.get("files"))
            .or_else(|| s.get("dumps"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Self {
            mode,
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
            acquired,
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
            summary_kv,
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

    pub fn from_error_for_mode(
        mode: Mode,
        err: &anyhow::Error,
        collection: PathBuf,
        argv: Vec<String>,
    ) -> Self {
        let is_cancelled = err.downcast_ref::<Cancelled>().is_some();
        let code = classify_error(err);
        let status = if is_cancelled {
            "cancelled before anything was written".into()
        } else {
            "failed".into()
        };
        Self {
            mode,
            code,
            status,
            collection,
            argv,
            acquired: 0,
            bytes: 0,
            out_of_scope_listed: 0,
            out_of_scope_counted: 0,
            excluded_trees: 0,
            trees_outside_includes: 0,
            errors: u64::from(!is_cancelled),
            skipped: 0,
            summary_kv: Vec::new(),
            audit_anchor: None,
            container_mismatches: Vec::new(),
            warnings: Vec::new(),
            problems: Vec::new(),
            fatal_error: Some(format!("{err:#}")),
            left_unfinished: false,
            scroll: 0,
        }
    }

    pub fn from_panic_for_mode(
        mode: Mode,
        message: String,
        collection: PathBuf,
        argv: Vec<String>,
    ) -> Self {
        Self {
            mode,
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
            summary_kv: Vec::new(),
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
        7 => "Complete with errors: some items were not acquired as expected; see the problems and items.jsonl",
        8 => "Stopped by signal or examiner; everything acquired so far is recorded and verifiable",
        _ => "Finished with non-zero status",
    }
}

/// Classify an `anyhow::Error` into the CLI's exit code (2, 3, 4, or 8).
pub fn classify_error(err: &anyhow::Error) -> u8 {
    if err.downcast_ref::<Usage>().is_some() {
        2
    } else if dfcore::is_refusal(err) {
        3
    } else if err.downcast_ref::<Cancelled>().is_some()
        || err.downcast_ref::<crate::common::Stopped>().is_some()
    {
        8
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
    pub active_mode: Mode,
    pub home_idx: usize,
    pub shared: SharedFormState,
    pub files_form: FilesForm,
    pub ingest_form: IngestForm,
    pub cloud_form: CloudForm,
    pub db_form: DbForm,
    pub db_credential: Option<(DbConnKey, Credential)>,
    pub secret_tx: Sender<SecretRequest>,
    pub secret_rx: Receiver<SecretRequest>,
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
        let (secret_tx, secret_rx) = mpsc::channel();
        Self {
            stop,
            screen: Screen::Home,
            active_mode: Mode::Files,
            home_idx: 0,
            shared: SharedFormState::default(),
            files_form: FilesForm::with_mounts(source_mounts, target_mounts.clone()),
            ingest_form: IngestForm::with_targets(target_mounts.clone()),
            cloud_form: CloudForm::with_remotes(Vec::new(), target_mounts.clone()),
            db_form: DbForm::with_targets(target_mounts),
            db_credential: None,
            secret_tx,
            secret_rx,
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

    /// Sync shared session fields from the currently active form before switching modes.
    pub fn capture_shared_from_active(&mut self) {
        self.shared = match self.active_mode {
            Mode::Files => self.files_form.export_shared(),
            Mode::Ingest => self.ingest_form.export_shared(),
            Mode::Cloud => self.cloud_form.export_shared(),
            Mode::Db => self.db_form.export_shared(),
        };
    }

    /// Drop any cached DB preview credential if the connection fields no longer match.
    pub fn check_db_credential(&mut self) {
        if let Some((saved_key, _)) = &self.db_credential {
            if *saved_key != self.db_form.conn_key() {
                self.db_credential = None;
            }
        }
    }

    /// Current mode's equivalent CLI command vector for the footer / preview check.
    pub fn current_mode_argv(&self, mode: Mode) -> Vec<String> {
        match mode {
            Mode::Files => files_argv(&self.files_form),
            Mode::Ingest => ingest_argv(&self.ingest_form),
            Mode::Cloud => cloud_argv(&self.cloud_form),
            Mode::Db => db_argv(&self.db_form),
        }
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

    /// Whether the current preview is missing, stopped early, blocked, or no longer
    /// matches the active mode's form.
    pub fn is_preview_stale(&self) -> bool {
        let Some(PreviewState::Ready(data)) = &self.preview_state else {
            return true;
        };
        if data.mode_preview.stopped().is_some() {
            return true;
        }
        if data.mode_preview.start_block_reason().is_some() {
            return true;
        }
        let mode = data.mode_preview.mode();
        self.current_mode_argv(mode) != data.argv
    }

    /// Poll running worker threads, service `TuiConsole::secret` requests, and
    /// update transfer rate / spinner state.
    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);

        // 0. Service or cancel secret requests from TuiConsole
        if self.headless || self.stop.is_set() {
            if let Some(Modal::Secret(mut sm)) = self.modal.take() {
                sm.buffer.zeroize();
                let _ = sm.reply.send(None);
            }
            while let Ok(req) = self.secret_rx.try_recv() {
                let _ = req.reply.send(None);
            }
        } else if !matches!(self.modal, Some(Modal::Secret(_))) {
            if let Ok(req) = self.secret_rx.try_recv() {
                self.modal = Some(Modal::Secret(SecretModal {
                    ask: req.ask,
                    buffer: Zeroizing::new(String::with_capacity(256)),
                    cursor: 0,
                    reply: req.reply,
                }));
            }
        }

        // 1. Poll preview worker
        let preview_done = matches!(
            &self.preview_state,
            Some(PreviewState::Running { handle: Some(h), .. }) if h.is_finished()
        );
        if preview_done {
            if let Some(PreviewState::Running {
                mode,
                argv,
                mut handle,
                ..
            }) = self.preview_state.take()
            {
                if let Some(Modal::Secret(mut sm)) = self.modal.take() {
                    sm.buffer.zeroize();
                    let _ = sm.reply.send(None);
                }
                if let Some(h) = handle.take() {
                    match h.join() {
                        Ok(Ok(out)) => {
                            if let Some(cred) = out.db_credential {
                                self.db_credential = Some(cred);
                            }
                            let mp = out.mode_preview;
                            if self.stop.signal.load(Ordering::Relaxed) {
                                self.signal_outcome = Some(verify::Outcome {
                                    code: mp.stopped().map_or(0, |_| 8),
                                    summary: mp.summary(),
                                });
                                self.should_quit = true;
                                return;
                            }
                            if let Some(reason) = mp.stopped() {
                                self.notify(
                                    NoticeLevel::Warning,
                                    format!(
                                        "Preview stopped ({reason}); re-run preview before starting."
                                    ),
                                );
                            } else if let Some(block_err) = mp.start_block_reason() {
                                self.notify(NoticeLevel::Error, block_err);
                            } else {
                                self.notice = None;
                            }
                            self.preview_state = Some(PreviewState::Ready(Box::new(PreviewData {
                                mode_preview: mp,
                                argv,
                                scroll: 0,
                                copied_osc52: false,
                            })));
                        }
                        Ok(Err(e)) => {
                            let is_cancelled = e.downcast_ref::<Cancelled>().is_some();
                            let is_stopped = e.downcast_ref::<crate::common::Stopped>().is_some();
                            let code = classify_error(&e);
                            let msg = if is_cancelled {
                                "Preview cancelled before anything was written".to_string()
                            } else if is_stopped {
                                let reason = if self.stop.signal.load(Ordering::Relaxed) {
                                    "by a signal"
                                } else {
                                    "by the examiner"
                                };
                                format!("Preview stopped ({reason})")
                            } else {
                                format!("{e:#}")
                            };
                            self.notify(
                                if is_cancelled || is_stopped || code == 8 {
                                    NoticeLevel::Warning
                                } else {
                                    NoticeLevel::Error
                                },
                                &msg,
                            );
                            self.preview_state = Some(PreviewState::Failed {
                                mode,
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
                                mode,
                                argv,
                                error: msg,
                                code: 4,
                            });
                        }
                    }
                }
            }
        }

        // 2. Poll acquisition worker
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
                if matches!(self.modal, Some(Modal::ConfirmStop | Modal::Secret(_))) {
                    if let Some(Modal::Secret(mut sm)) = self.modal.take() {
                        sm.buffer.zeroize();
                        let _ = sm.reply.send(None);
                    }
                    self.modal = None;
                }
                // Always drop any cached DB credential after a run completes
                self.db_credential = None;
                if let Some(h) = run.handle.take() {
                    let mode = run.mode;
                    let output = run.output.clone();
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
                                self.signal_outcome = Some(outcome);
                                self.should_quit = true;
                                return;
                            }
                            let res =
                                ResultData::from_outcome_for_mode(mode, &outcome, output, argv);
                            self.notice = None;
                            self.result_data = Some(res);
                            self.screen = Screen::Result;
                        }
                        Ok(Err(e)) => {
                            let res = ResultData::from_error_for_mode(mode, &e, output, argv);
                            self.notify(
                                if e.downcast_ref::<Cancelled>().is_some() {
                                    NoticeLevel::Warning
                                } else {
                                    NoticeLevel::Error
                                },
                                res.fatal_error.clone().unwrap_or_default(),
                            );
                            self.result_data = Some(res);
                            self.screen = Screen::Result;
                            if self.stop.signal.load(Ordering::Relaxed) || self.headless {
                                self.should_quit = true;
                            }
                        }
                        Err(payload) => {
                            let msg = panic_message(payload.as_ref());
                            let res = ResultData::from_panic_for_mode(mode, msg, output, argv);
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
            self.db_credential = None;
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
                    self.db_credential = None;
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
            Screen::IngestForm => self.handle_ingest_form_key(key),
            Screen::CloudForm => self.handle_cloud_form_key(key),
            Screen::DbForm => self.handle_db_form_key(key),
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
            Modal::ConfirmSafety { target } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    match target {
                        SafetyTarget::Files(FilesField::AllowTmpfs) => {
                            self.files_form.allow_tmpfs = true;
                            self.files_form.refresh_probes();
                        }
                        SafetyTarget::Files(FilesField::AllowWritableSource) => {
                            self.files_form.allow_writable_source = true;
                            self.files_form.refresh_probes();
                        }
                        SafetyTarget::Files(_) => {}
                        SafetyTarget::IngestTmpfs => {
                            self.ingest_form.output.allow_tmpfs = true;
                            self.ingest_form.refresh_probes();
                        }
                        SafetyTarget::CloudTmpfs => {
                            self.cloud_form.output.allow_tmpfs = true;
                            self.cloud_form.refresh_probes();
                        }
                        SafetyTarget::DbTmpfs => {
                            self.db_form.output.allow_tmpfs = true;
                            self.db_form.refresh_probes();
                        }
                    }
                    self.notify(
                        NoticeLevel::Warning,
                        format!("Safety override '{}' enabled.", target.label()),
                    );
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {}
                _ => self.modal = Some(Modal::ConfirmSafety { target }),
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
            Modal::EditListItem {
                target,
                index,
                mut text,
                mut cursor,
                ..
            } => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    let trimmed = text.trim().to_string();
                    if trimmed.is_empty() {
                        self.modal = Some(Modal::EditListItem {
                            target,
                            index,
                            text,
                            cursor,
                            error: Some("value cannot be empty".into()),
                        });
                        return;
                    }
                    if let Err(e) = validate_list_item(target, &trimmed) {
                        self.modal = Some(Modal::EditListItem {
                            target,
                            index,
                            text,
                            cursor,
                            error: Some(e),
                        });
                        return;
                    }
                    let (list, idx_ref) = match target {
                        ListTarget::IngestHashes => (
                            &mut self.ingest_form.hashes,
                            &mut self.ingest_form.hashes_idx,
                        ),
                        ListTarget::CloudRcloneArgs => (
                            &mut self.cloud_form.rclone_args,
                            &mut self.cloud_form.rclone_args_idx,
                        ),
                        ListTarget::CloudInclude => (
                            &mut self.cloud_form.scope.include,
                            &mut self.cloud_form.scope.include_idx,
                        ),
                        ListTarget::CloudExclude => (
                            &mut self.cloud_form.scope.exclude,
                            &mut self.cloud_form.scope.exclude_idx,
                        ),
                        ListTarget::DbDatabases => {
                            (&mut self.db_form.databases, &mut self.db_form.databases_idx)
                        }
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
                        validate_list_item(target, text.trim()).err()
                    };
                    self.modal = Some(Modal::EditListItem {
                        target,
                        index,
                        text,
                        cursor,
                        error,
                    });
                }
            },
            Modal::Secret(mut sm) => match key.code {
                KeyCode::Esc => {
                    sm.buffer.zeroize();
                    let _ = sm.reply.send(None);
                }
                KeyCode::Enter => {
                    let secret = std::mem::take(&mut sm.buffer);
                    let _ = sm.reply.send(Some(secret));
                }
                _ if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c') =>
                {
                    sm.buffer.zeroize();
                    let _ = sm.reply.send(None);
                }
                _ => {
                    edit_text(&mut sm.buffer, &mut sm.cursor, key);
                    self.modal = Some(Modal::Secret(sm));
                }
            },
            Modal::ConfirmStart => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.start_active_run();
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
            KeyCode::Char('q') | KeyCode::Esc => {
                self.db_credential = None;
                self.should_quit = true;
            }
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
            KeyCode::Char('i') => self.open_ingest_form(),
            KeyCode::Char('c') => self.open_cloud_form(),
            KeyCode::Char('d') => self.open_db_form(),
            KeyCode::Enter | KeyCode::Char(' ') => match self.home_idx {
                0 => self.open_files_form(),
                1 => self.open_verify(None, false),
                2 => self.open_ingest_form(),
                3 => self.open_cloud_form(),
                4 => self.open_db_form(),
                i => {
                    let item = &HOME_ITEMS[i];
                    self.notify(
                        NoticeLevel::Info,
                        format!(
                            "Command-line only for now — run `{}` in a shell.",
                            item.command
                        ),
                    );
                }
            },
            _ => {}
        }
    }

    pub fn open_files_form(&mut self) {
        self.files_form.import_shared(&self.shared);
        self.files_form.refresh_probes();
        self.active_mode = Mode::Files;
        self.completion = None;
        self.notice = None;
        self.screen = Screen::FilesForm;
    }

    pub fn open_ingest_form(&mut self) {
        self.ingest_form.import_shared(&self.shared);
        self.ingest_form.refresh_probes();
        self.active_mode = Mode::Ingest;
        self.completion = None;
        self.notice = None;
        self.screen = Screen::IngestForm;
    }

    pub fn open_cloud_form(&mut self) {
        self.cloud_form.import_shared(&self.shared);
        self.cloud_form.probe_remotes_if_needed();
        self.cloud_form.refresh_probes();
        self.active_mode = Mode::Cloud;
        self.completion = None;
        self.notice = None;
        self.screen = Screen::CloudForm;
    }

    pub fn open_db_form(&mut self) {
        self.db_form.import_shared(&self.shared);
        self.db_form.probe_tools_if_needed();
        self.db_form.refresh_probes();
        self.active_mode = Mode::Db;
        self.completion = None;
        self.notice = None;
        self.screen = Screen::DbForm;
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

    // ------------------------------------------------------------------
    // FilesForm key handling
    // ------------------------------------------------------------------

    fn handle_files_form_key(&mut self, key: KeyEvent) {
        self.active_mode = Mode::Files;
        let field = self.files_form.field;
        let tab_completes = field.is_path()
            && (self.files_form.editing || self.completion.is_some())
            && key.code == KeyCode::Tab;

        if key.code != KeyCode::F(4) && !tab_completes {
            self.completion = None;
        }

        if key.code == KeyCode::F(2)
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p'))
        {
            self.start_preview();
            return;
        }

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
                    self.capture_shared_from_active();
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
                    self.toggle_files_safety(field);
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
                remove_selected(list, idx);
            }
            KeyCode::Left if field.is_list() => {
                let (list, idx) = if field == FilesField::Includes {
                    (&self.files_form.include, &mut self.files_form.include_idx)
                } else {
                    (&self.files_form.exclude, &mut self.files_form.exclude_idx)
                };
                cycle_selected(list.len(), idx, false);
            }
            KeyCode::Right if field.is_list() => {
                let (list, idx) = if field == FilesField::Includes {
                    (&self.files_form.include, &mut self.files_form.include_idx)
                } else {
                    (&self.files_form.exclude, &mut self.files_form.exclude_idx)
                };
                cycle_selected(list.len(), idx, true);
            }
            KeyCode::Char('p') if !field.is_text() => self.start_preview(),
            KeyCode::Char('?') if !field.is_text() => self.modal = Some(Modal::Help),
            KeyCode::Char('q') if !field.is_text() => {
                self.capture_shared_from_active();
                self.screen = Screen::Home;
            }
            KeyCode::Char(' ') if field == FilesField::PreviewButton => self.start_preview(),
            KeyCode::Char(' ') | KeyCode::Right if !field.is_text() => {
                if field.is_safety() {
                    self.toggle_files_safety(field);
                } else {
                    self.files_form.toggle_regular(field, true);
                    self.files_form.refresh_probes();
                }
            }
            KeyCode::Left if !field.is_text() => {
                if field.is_safety() {
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
                        if self.files_form.validate_field(field).is_none()
                            && matches!(&self.notice, Some(n) if n.level == NoticeLevel::Error)
                        {
                            self.notice = None;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn toggle_files_safety(&mut self, field: FilesField) {
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
            self.modal = Some(Modal::ConfirmSafety {
                target: SafetyTarget::Files(field),
            });
        }
    }

    // ------------------------------------------------------------------
    // IngestForm key handling
    // ------------------------------------------------------------------

    fn handle_ingest_form_key(&mut self, key: KeyEvent) {
        self.active_mode = Mode::Ingest;
        let field = self.ingest_form.field;
        let spec = field.spec();
        let tab_completes = spec.kind.is_path()
            && (self.ingest_form.editing || self.completion.is_some())
            && key.code == KeyCode::Tab;

        if key.code != KeyCode::F(4) && !tab_completes {
            self.completion = None;
        }

        if key.code == KeyCode::F(2)
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p'))
        {
            self.start_preview();
            return;
        }

        if key.code == KeyCode::F(4) || tab_completes {
            if spec.kind.is_path() {
                self.complete_path(PathTarget::Ingest(field));
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
                if self.ingest_form.editing {
                    self.ingest_form.editing = false;
                    self.ingest_form.refresh_probes();
                } else {
                    self.capture_shared_from_active();
                    self.screen = Screen::Home;
                }
            }
            KeyCode::Down | KeyCode::Tab => {
                self.ingest_form.refresh_probes();
                self.ingest_form.focus_next(true);
            }
            KeyCode::Up | KeyCode::BackTab => {
                self.ingest_form.refresh_probes();
                self.ingest_form.focus_next(false);
            }
            KeyCode::Enter => {
                if field == IngestField::PreviewButton {
                    self.start_preview();
                } else if spec.kind.is_list() {
                    self.open_list_modal(ListTarget::IngestHashes, true);
                } else if spec.kind.is_safety() {
                    if self.ingest_form.output.allow_tmpfs {
                        self.ingest_form.output.allow_tmpfs = false;
                        self.ingest_form.refresh_probes();
                    } else {
                        self.modal = Some(Modal::ConfirmSafety {
                            target: SafetyTarget::IngestTmpfs,
                        });
                    }
                } else if spec.kind.is_text() {
                    if field == IngestField::ReferenceTime
                        && !self.ingest_form.clock.reference_time.trim().is_empty()
                    {
                        self.ingest_form.clock.commit_now();
                        self.ingest_form.editing = false;
                        self.ingest_form.refresh_probes();
                        self.ingest_form.focus_next(true);
                    } else if self.ingest_form.editing {
                        self.ingest_form.editing = false;
                        self.ingest_form.refresh_probes();
                        self.ingest_form.focus_next(true);
                    } else {
                        self.ingest_form.editing = true;
                        self.ingest_form.cursor =
                            self.ingest_form.text(field).map_or(0, String::len);
                    }
                } else {
                    self.ingest_form.toggle_regular(field);
                    self.ingest_form.refresh_probes();
                }
            }
            KeyCode::Char('a') if spec.kind.is_list() => {
                self.open_list_modal(ListTarget::IngestHashes, false);
            }
            KeyCode::Char('e') if spec.kind.is_list() => {
                self.open_list_modal(ListTarget::IngestHashes, true);
            }
            KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace if spec.kind.is_list() => {
                remove_selected(
                    &mut self.ingest_form.hashes,
                    &mut self.ingest_form.hashes_idx,
                );
            }
            KeyCode::Left if spec.kind.is_list() => {
                cycle_selected(
                    self.ingest_form.hashes.len(),
                    &mut self.ingest_form.hashes_idx,
                    false,
                );
            }
            KeyCode::Right if spec.kind.is_list() => {
                cycle_selected(
                    self.ingest_form.hashes.len(),
                    &mut self.ingest_form.hashes_idx,
                    true,
                );
            }
            KeyCode::Char('p') if !spec.kind.is_text() => self.start_preview(),
            KeyCode::Char('?') if !spec.kind.is_text() => self.modal = Some(Modal::Help),
            KeyCode::Char('q') if !spec.kind.is_text() => {
                self.capture_shared_from_active();
                self.screen = Screen::Home;
            }
            KeyCode::Char(' ') if field == IngestField::PreviewButton => self.start_preview(),
            KeyCode::Char(' ') | KeyCode::Right if !spec.kind.is_text() => {
                if spec.kind.is_safety() {
                    if self.ingest_form.output.allow_tmpfs {
                        self.ingest_form.output.allow_tmpfs = false;
                        self.ingest_form.refresh_probes();
                    } else {
                        self.modal = Some(Modal::ConfirmSafety {
                            target: SafetyTarget::IngestTmpfs,
                        });
                    }
                } else {
                    self.ingest_form.toggle_regular(field);
                    self.ingest_form.refresh_probes();
                }
            }
            KeyCode::Left if !spec.kind.is_text() => {
                if spec.kind.is_safety() {
                    self.ingest_form.output.allow_tmpfs = false;
                    self.ingest_form.refresh_probes();
                } else {
                    self.ingest_form.toggle_regular(field);
                    self.ingest_form.refresh_probes();
                }
            }
            _ if spec.kind.is_text() => {
                let mut cursor = self.ingest_form.cursor;
                if let Some(t) = self.ingest_form.text_mut(field) {
                    let before = t.clone();
                    edit_text(t, &mut cursor, key);
                    let changed = *t != before;
                    self.ingest_form.cursor = cursor;
                    if changed {
                        self.ingest_form.editing = true;
                        match field {
                            IngestField::CaseNumber | IngestField::EvidenceNumber => {
                                self.ingest_form.output.update_suggestion(
                                    &self.ingest_form.case.case,
                                    &self.ingest_form.case.evidence,
                                );
                                self.ingest_form.refresh_probes();
                            }
                            IngestField::Package => {
                                self.ingest_form.refresh_probes();
                            }
                            IngestField::OutputPath => {
                                self.ingest_form.output.output_customized =
                                    !self.ingest_form.output.output_path.trim().is_empty();
                                self.ingest_form.refresh_probes();
                            }
                            IngestField::ReferenceTime => {
                                self.ingest_form.clock.reference_entered_ns = None;
                            }
                            _ => {}
                        }
                        if self.ingest_form.validate_field(field).is_none()
                            && matches!(&self.notice, Some(n) if n.level == NoticeLevel::Error)
                        {
                            self.notice = None;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // CloudForm key handling
    // ------------------------------------------------------------------

    fn handle_cloud_form_key(&mut self, key: KeyEvent) {
        self.active_mode = Mode::Cloud;
        let field = self.cloud_form.field;
        let spec = field.spec();
        let tab_completes = spec.kind.is_path()
            && (self.cloud_form.editing || self.completion.is_some())
            && key.code == KeyCode::Tab;

        if key.code != KeyCode::F(4) && !tab_completes {
            self.completion = None;
        }

        if key.code == KeyCode::F(2)
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p'))
        {
            self.start_preview();
            return;
        }

        if key.code == KeyCode::F(4) || tab_completes {
            if spec.kind.is_path() {
                self.complete_path(PathTarget::Cloud(field));
            } else {
                self.notify(
                    NoticeLevel::Info,
                    "Path autocompletion (F4 / Tab) applies to path fields.",
                );
            }
            return;
        }

        let list_target = match field {
            CloudField::RcloneArgs => Some(ListTarget::CloudRcloneArgs),
            CloudField::Includes => Some(ListTarget::CloudInclude),
            CloudField::Excludes => Some(ListTarget::CloudExclude),
            _ => None,
        };

        match key.code {
            KeyCode::Esc => {
                if self.cloud_form.editing {
                    self.cloud_form.editing = false;
                    if field == CloudField::RcloneConfig {
                        self.cloud_form.probe_remotes_if_needed();
                    }
                    self.cloud_form.refresh_probes();
                } else {
                    self.capture_shared_from_active();
                    self.screen = Screen::Home;
                }
            }
            KeyCode::Down | KeyCode::Tab => {
                if field == CloudField::RcloneConfig {
                    self.cloud_form.probe_remotes_if_needed();
                }
                self.cloud_form.refresh_probes();
                self.cloud_form.focus_next(true);
            }
            KeyCode::Up | KeyCode::BackTab => {
                if field == CloudField::RcloneConfig {
                    self.cloud_form.probe_remotes_if_needed();
                }
                self.cloud_form.refresh_probes();
                self.cloud_form.focus_next(false);
            }
            KeyCode::Enter => {
                if field == CloudField::PreviewButton {
                    self.start_preview();
                } else if let Some(lt) = list_target {
                    self.open_list_modal(lt, true);
                } else if spec.kind.is_safety() {
                    if self.cloud_form.output.allow_tmpfs {
                        self.cloud_form.output.allow_tmpfs = false;
                        self.cloud_form.refresh_probes();
                    } else {
                        self.modal = Some(Modal::ConfirmSafety {
                            target: SafetyTarget::CloudTmpfs,
                        });
                    }
                } else if spec.kind.is_text() {
                    if field == CloudField::ReferenceTime
                        && !self.cloud_form.clock.reference_time.trim().is_empty()
                    {
                        self.cloud_form.clock.commit_now();
                        self.cloud_form.editing = false;
                        self.cloud_form.refresh_probes();
                        self.cloud_form.focus_next(true);
                    } else if self.cloud_form.editing {
                        self.cloud_form.editing = false;
                        if field == CloudField::RcloneConfig {
                            self.cloud_form.probe_remotes_if_needed();
                        }
                        self.cloud_form.refresh_probes();
                        self.cloud_form.focus_next(true);
                    } else {
                        self.cloud_form.editing = true;
                        self.cloud_form.cursor = self.cloud_form.text(field).map_or(0, String::len);
                    }
                } else {
                    self.cloud_form.toggle_regular(field, true);
                    self.cloud_form.refresh_probes();
                }
            }
            KeyCode::Char('a') if list_target.is_some() => {
                self.open_list_modal(list_target.unwrap(), false);
            }
            KeyCode::Char('e') if list_target.is_some() => {
                self.open_list_modal(list_target.unwrap(), true);
            }
            KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace if list_target.is_some() => {
                match list_target.unwrap() {
                    ListTarget::CloudRcloneArgs => remove_selected(
                        &mut self.cloud_form.rclone_args,
                        &mut self.cloud_form.rclone_args_idx,
                    ),
                    ListTarget::CloudInclude => remove_selected(
                        &mut self.cloud_form.scope.include,
                        &mut self.cloud_form.scope.include_idx,
                    ),
                    ListTarget::CloudExclude => remove_selected(
                        &mut self.cloud_form.scope.exclude,
                        &mut self.cloud_form.scope.exclude_idx,
                    ),
                    _ => {}
                }
            }
            KeyCode::Left if list_target.is_some() => match list_target.unwrap() {
                ListTarget::CloudRcloneArgs => cycle_selected(
                    self.cloud_form.rclone_args.len(),
                    &mut self.cloud_form.rclone_args_idx,
                    false,
                ),
                ListTarget::CloudInclude => cycle_selected(
                    self.cloud_form.scope.include.len(),
                    &mut self.cloud_form.scope.include_idx,
                    false,
                ),
                ListTarget::CloudExclude => cycle_selected(
                    self.cloud_form.scope.exclude.len(),
                    &mut self.cloud_form.scope.exclude_idx,
                    false,
                ),
                _ => {}
            },
            KeyCode::Right if list_target.is_some() => match list_target.unwrap() {
                ListTarget::CloudRcloneArgs => cycle_selected(
                    self.cloud_form.rclone_args.len(),
                    &mut self.cloud_form.rclone_args_idx,
                    true,
                ),
                ListTarget::CloudInclude => cycle_selected(
                    self.cloud_form.scope.include.len(),
                    &mut self.cloud_form.scope.include_idx,
                    true,
                ),
                ListTarget::CloudExclude => cycle_selected(
                    self.cloud_form.scope.exclude.len(),
                    &mut self.cloud_form.scope.exclude_idx,
                    true,
                ),
                _ => {}
            },
            KeyCode::Char('p') if !spec.kind.is_text() => self.start_preview(),
            KeyCode::Char('?') if !spec.kind.is_text() => self.modal = Some(Modal::Help),
            KeyCode::Char('q') if !spec.kind.is_text() => {
                self.capture_shared_from_active();
                self.screen = Screen::Home;
            }
            KeyCode::Char(' ') if field == CloudField::PreviewButton => self.start_preview(),
            KeyCode::Char(' ') | KeyCode::Right if !spec.kind.is_text() => {
                if spec.kind.is_safety() {
                    if self.cloud_form.output.allow_tmpfs {
                        self.cloud_form.output.allow_tmpfs = false;
                        self.cloud_form.refresh_probes();
                    } else {
                        self.modal = Some(Modal::ConfirmSafety {
                            target: SafetyTarget::CloudTmpfs,
                        });
                    }
                } else {
                    self.cloud_form.toggle_regular(field, true);
                    self.cloud_form.refresh_probes();
                }
            }
            KeyCode::Left if !spec.kind.is_text() => {
                if spec.kind.is_safety() {
                    self.cloud_form.output.allow_tmpfs = false;
                    self.cloud_form.refresh_probes();
                } else {
                    self.cloud_form.toggle_regular(field, false);
                    self.cloud_form.refresh_probes();
                }
            }
            _ if spec.kind.is_text() => {
                let mut cursor = self.cloud_form.cursor;
                if let Some(t) = self.cloud_form.text_mut(field) {
                    let before = t.clone();
                    edit_text(t, &mut cursor, key);
                    let changed = *t != before;
                    self.cloud_form.cursor = cursor;
                    if changed {
                        self.cloud_form.editing = true;
                        match field {
                            CloudField::CaseNumber | CloudField::EvidenceNumber => {
                                self.cloud_form.output.update_suggestion(
                                    &self.cloud_form.case.case,
                                    &self.cloud_form.case.evidence,
                                );
                                self.cloud_form.refresh_probes();
                            }
                            CloudField::RcloneConfig => {
                                self.cloud_form.remotes_probed_for = None;
                                self.cloud_form.probe_remotes_if_needed();
                            }
                            CloudField::Source => {
                                self.cloud_form.sync_selected_remote();
                            }
                            CloudField::OutputPath => {
                                self.cloud_form.output.output_customized =
                                    !self.cloud_form.output.output_path.trim().is_empty();
                                self.cloud_form.refresh_probes();
                            }
                            CloudField::ReferenceTime => {
                                self.cloud_form.clock.reference_entered_ns = None;
                            }
                            _ => {}
                        }
                        if self.cloud_form.validate_field(field).is_none()
                            && matches!(&self.notice, Some(n) if n.level == NoticeLevel::Error)
                        {
                            self.notice = None;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // DbForm key handling
    // ------------------------------------------------------------------

    fn handle_db_form_key(&mut self, key: KeyEvent) {
        self.active_mode = Mode::Db;
        let field = self.db_form.field;
        let spec = field.spec(self.db_form.engine);
        let tab_completes = spec.kind.is_path()
            && (self.db_form.editing || self.completion.is_some())
            && key.code == KeyCode::Tab;

        if key.code != KeyCode::F(4) && !tab_completes {
            self.completion = None;
        }

        if key.code == KeyCode::F(2)
            || (key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('p'))
        {
            self.start_preview();
            return;
        }

        if key.code == KeyCode::F(4) || tab_completes {
            if spec.kind.is_path() {
                self.complete_path(PathTarget::Db(field));
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
                if self.db_form.editing {
                    self.db_form.editing = false;
                    self.db_form.refresh_probes();
                } else {
                    self.capture_shared_from_active();
                    self.screen = Screen::Home;
                }
            }
            KeyCode::Down | KeyCode::Tab => {
                self.db_form.refresh_probes();
                self.db_form.focus_next(true);
            }
            KeyCode::Up | KeyCode::BackTab => {
                self.db_form.refresh_probes();
                self.db_form.focus_next(false);
            }
            KeyCode::Enter => {
                if field == DbField::PreviewButton {
                    self.start_preview();
                } else if spec.kind.is_list() {
                    self.open_list_modal(ListTarget::DbDatabases, true);
                } else if spec.kind.is_safety() {
                    if self.db_form.output.allow_tmpfs {
                        self.db_form.output.allow_tmpfs = false;
                        self.db_form.refresh_probes();
                    } else {
                        self.modal = Some(Modal::ConfirmSafety {
                            target: SafetyTarget::DbTmpfs,
                        });
                    }
                } else if spec.kind.is_text() {
                    if field == DbField::ReferenceTime
                        && !self.db_form.clock.reference_time.trim().is_empty()
                    {
                        self.db_form.clock.commit_now();
                        self.db_form.editing = false;
                        self.db_form.refresh_probes();
                        self.db_form.focus_next(true);
                    } else if self.db_form.editing {
                        self.db_form.editing = false;
                        self.db_form.refresh_probes();
                        self.db_form.focus_next(true);
                    } else {
                        self.db_form.editing = true;
                        self.db_form.cursor = self.db_form.text(field).map_or(0, String::len);
                    }
                } else {
                    self.db_form.toggle_regular(field, true);
                    if field == DbField::Engine {
                        self.db_form.probe_tools_if_needed();
                    }
                    self.check_db_credential();
                    self.db_form.refresh_probes();
                }
            }
            KeyCode::Char('a') if spec.kind.is_list() => {
                self.open_list_modal(ListTarget::DbDatabases, false);
            }
            KeyCode::Char('e') if spec.kind.is_list() => {
                self.open_list_modal(ListTarget::DbDatabases, true);
            }
            KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace if spec.kind.is_list() => {
                remove_selected(&mut self.db_form.databases, &mut self.db_form.databases_idx);
            }
            KeyCode::Left if spec.kind.is_list() => {
                cycle_selected(
                    self.db_form.databases.len(),
                    &mut self.db_form.databases_idx,
                    false,
                );
            }
            KeyCode::Right if spec.kind.is_list() => {
                cycle_selected(
                    self.db_form.databases.len(),
                    &mut self.db_form.databases_idx,
                    true,
                );
            }
            KeyCode::Char('p') if !spec.kind.is_text() => self.start_preview(),
            KeyCode::Char('?') if !spec.kind.is_text() => self.modal = Some(Modal::Help),
            KeyCode::Char('q') if !spec.kind.is_text() => {
                self.capture_shared_from_active();
                self.screen = Screen::Home;
            }
            KeyCode::Char(' ') if field == DbField::PreviewButton => self.start_preview(),
            KeyCode::Char(' ') | KeyCode::Right if !spec.kind.is_text() => {
                if spec.kind.is_safety() {
                    if self.db_form.output.allow_tmpfs {
                        self.db_form.output.allow_tmpfs = false;
                        self.db_form.refresh_probes();
                    } else {
                        self.modal = Some(Modal::ConfirmSafety {
                            target: SafetyTarget::DbTmpfs,
                        });
                    }
                } else {
                    self.db_form.toggle_regular(field, true);
                    if field == DbField::Engine {
                        self.db_form.probe_tools_if_needed();
                    }
                    self.check_db_credential();
                    self.db_form.refresh_probes();
                }
            }
            KeyCode::Left if !spec.kind.is_text() => {
                if spec.kind.is_safety() {
                    self.db_form.output.allow_tmpfs = false;
                    self.db_form.refresh_probes();
                } else {
                    self.db_form.toggle_regular(field, false);
                    if field == DbField::Engine {
                        self.db_form.probe_tools_if_needed();
                    }
                    self.check_db_credential();
                    self.db_form.refresh_probes();
                }
            }
            _ if spec.kind.is_text() => {
                let mut cursor = self.db_form.cursor;
                if let Some(t) = self.db_form.text_mut(field) {
                    let before = t.clone();
                    edit_text(t, &mut cursor, key);
                    let changed = *t != before;
                    self.db_form.cursor = cursor;
                    if changed {
                        self.db_form.editing = true;
                        match field {
                            DbField::CaseNumber | DbField::EvidenceNumber => {
                                self.db_form.output.update_suggestion(
                                    &self.db_form.case.case,
                                    &self.db_form.case.evidence,
                                );
                                self.db_form.refresh_probes();
                            }
                            DbField::Host
                            | DbField::Port
                            | DbField::User
                            | DbField::PasswordFile => {
                                self.check_db_credential();
                            }
                            DbField::OutputPath => {
                                self.db_form.output.output_customized =
                                    !self.db_form.output.output_path.trim().is_empty();
                                self.db_form.refresh_probes();
                            }
                            DbField::ReferenceTime => {
                                self.db_form.clock.reference_entered_ns = None;
                            }
                            _ => {}
                        }
                        if self.db_form.validate_field(field).is_none()
                            && matches!(&self.notice, Some(n) if n.level == NoticeLevel::Error)
                        {
                            self.notice = None;
                        }
                    }
                }
            }
            _ => {}
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

    fn open_list_modal(&mut self, target: ListTarget, edit_existing: bool) {
        let (list, idx) = match target {
            ListTarget::IngestHashes => (&self.ingest_form.hashes, self.ingest_form.hashes_idx),
            ListTarget::CloudRcloneArgs => (
                &self.cloud_form.rclone_args,
                self.cloud_form.rclone_args_idx,
            ),
            ListTarget::CloudInclude => (
                &self.cloud_form.scope.include,
                self.cloud_form.scope.include_idx,
            ),
            ListTarget::CloudExclude => (
                &self.cloud_form.scope.exclude,
                self.cloud_form.scope.exclude_idx,
            ),
            ListTarget::DbDatabases => (&self.db_form.databases, self.db_form.databases_idx),
        };
        if edit_existing && !list.is_empty() {
            let clamped = idx.min(list.len() - 1);
            let text = list[clamped].clone();
            let cursor = text.len();
            self.modal = Some(Modal::EditListItem {
                target,
                index: Some(clamped),
                text,
                cursor,
                error: None,
            });
        } else {
            self.modal = Some(Modal::EditListItem {
                target,
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
            PathTarget::Ingest(f) => f.spec().kind.is_dirs_only_path(),
            PathTarget::Cloud(f) => f.spec().kind.is_dirs_only_path(),
            PathTarget::Db(f) => f.spec(self.db_form.engine).kind.is_dirs_only_path(),
            PathTarget::Verify => true,
        };
        let (text, cursor) = match target {
            PathTarget::Files(f) => {
                let Some(t) = self.files_form.text(f) else {
                    return;
                };
                (t.clone(), self.files_form.cursor)
            }
            PathTarget::Ingest(f) => {
                let Some(t) = self.ingest_form.text(f) else {
                    return;
                };
                (t.clone(), self.ingest_form.cursor)
            }
            PathTarget::Cloud(f) => {
                let Some(t) = self.cloud_form.text(f) else {
                    return;
                };
                (t.clone(), self.cloud_form.cursor)
            }
            PathTarget::Db(f) => {
                let Some(t) = self.db_form.text(f) else {
                    return;
                };
                (t.clone(), self.db_form.cursor)
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
                if lcp.len() > prefix.len() {
                    let new_text = format!("{lcp}{suffix}");
                    let len = lcp.len();
                    self.set_path_text(target, new_text, len);
                }
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
            PathTarget::Ingest(f) => {
                if let Some(t) = self.ingest_form.text_mut(f) {
                    *t = new_text;
                }
                self.ingest_form.cursor = new_cursor;
                self.ingest_form.editing = true;
                if f == IngestField::OutputPath {
                    self.ingest_form.output.output_customized = true;
                }
                self.ingest_form.refresh_probes();
            }
            PathTarget::Cloud(f) => {
                if let Some(t) = self.cloud_form.text_mut(f) {
                    *t = new_text;
                }
                self.cloud_form.cursor = new_cursor;
                self.cloud_form.editing = true;
                if f == CloudField::OutputPath {
                    self.cloud_form.output.output_customized = true;
                } else if f == CloudField::RcloneConfig {
                    self.cloud_form.remotes_probed_for = None;
                    self.cloud_form.probe_remotes_if_needed();
                }
                self.cloud_form.refresh_probes();
            }
            PathTarget::Db(f) => {
                if let Some(t) = self.db_form.text_mut(f) {
                    *t = new_text;
                }
                self.db_form.cursor = new_cursor;
                self.db_form.editing = true;
                if f == DbField::OutputPath {
                    self.db_form.output.output_customized = true;
                } else if f == DbField::PasswordFile {
                    self.check_db_credential();
                }
                self.db_form.refresh_probes();
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
        match self.active_mode {
            Mode::Files => self.start_files_preview(),
            Mode::Ingest => self.start_ingest_preview(),
            Mode::Cloud => self.start_cloud_preview(),
            Mode::Db => self.start_db_preview(),
        }
    }

    fn start_files_preview(&mut self) {
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
        let console = Arc::new(TuiConsole::new(self.stop, self.secret_tx.clone()));
        let console_worker: Arc<dyn Console> = Arc::clone(&console) as Arc<dyn Console>;
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
                console: console_worker,
            };
            let pv = files::preview(&args_worker, &ctx)?;
            Ok(PreviewWorkerOutput {
                mode_preview: ModePreview::Files {
                    preview: pv,
                    args: Box::new(args_worker),
                },
                db_credential: None,
            })
        });

        self.notice = None;
        self.preview_state = Some(PreviewState::Running {
            mode: Mode::Files,
            argv,
            progress,
            console,
            started: Instant::now(),
            handle: Some(handle),
        });
        self.screen = Screen::Preview;
    }

    fn start_ingest_preview(&mut self) {
        self.ingest_form.refresh_probes();
        let errors = self.ingest_form.validate_all();
        if let Some((first_field, msg)) = errors.first() {
            self.ingest_form.set_focus(*first_field);
            self.notify(NoticeLevel::Error, msg.clone());
            return;
        }

        let argv = ingest_argv(&self.ingest_form);
        let args = match parse_ingest_argv(&argv) {
            Ok(a) => a,
            Err((maybe_field, msg)) => {
                if let Some(f) = maybe_field {
                    self.ingest_form.set_focus(f);
                }
                self.notify(NoticeLevel::Error, msg);
                return;
            }
        };

        self.stop.clear_examiner();
        let progress = Arc::new(Progress::default());
        let progress_worker = Arc::clone(&progress);
        let console = Arc::new(TuiConsole::new(self.stop, self.secret_tx.clone()));
        let console_worker: Arc<dyn Console> = Arc::clone(&console) as Arc<dyn Console>;
        let args_worker = args;
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
                console: console_worker,
            };
            let pv = ingest::preview(&args_worker, &ctx)?;
            Ok(PreviewWorkerOutput {
                mode_preview: ModePreview::Ingest {
                    preview: pv,
                    args: Box::new(args_worker),
                },
                db_credential: None,
            })
        });

        self.notice = None;
        self.preview_state = Some(PreviewState::Running {
            mode: Mode::Ingest,
            argv,
            progress,
            console,
            started: Instant::now(),
            handle: Some(handle),
        });
        self.screen = Screen::Preview;
    }

    fn start_cloud_preview(&mut self) {
        self.cloud_form.refresh_probes();
        let errors = self.cloud_form.validate_all();
        if let Some((first_field, msg)) = errors.first() {
            self.cloud_form.set_focus(*first_field);
            self.notify(NoticeLevel::Error, msg.clone());
            return;
        }

        let argv = cloud_argv(&self.cloud_form);
        let args = match parse_cloud_argv(&argv) {
            Ok(a) => a,
            Err((maybe_field, msg)) => {
                if let Some(f) = maybe_field {
                    self.cloud_form.set_focus(f);
                }
                self.notify(NoticeLevel::Error, msg);
                return;
            }
        };

        match scope::build(&args.scope).and_then(|s| s.rules()) {
            Ok(_) => {}
            Err(e) => {
                let target_field = if !self.cloud_form.scope.scope_file.trim().is_empty() {
                    CloudField::ScopeFile
                } else {
                    CloudField::Includes
                };
                self.cloud_form.set_focus(target_field);
                self.notify(NoticeLevel::Error, format!("{e:#}"));
                return;
            }
        }

        self.stop.clear_examiner();
        let progress = Arc::new(Progress::default());
        let progress_worker = Arc::clone(&progress);
        let console = Arc::new(TuiConsole::new(self.stop, self.secret_tx.clone()));
        let console_worker: Arc<dyn Console> = Arc::clone(&console) as Arc<dyn Console>;
        let args_worker = args;
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
                console: console_worker,
            };
            let pv = cloud::preview(&args_worker, &ctx)?;
            Ok(PreviewWorkerOutput {
                mode_preview: ModePreview::Cloud {
                    preview: pv,
                    args: Box::new(args_worker),
                },
                db_credential: None,
            })
        });

        self.notice = None;
        self.preview_state = Some(PreviewState::Running {
            mode: Mode::Cloud,
            argv,
            progress,
            console,
            started: Instant::now(),
            handle: Some(handle),
        });
        self.screen = Screen::Preview;
    }

    fn start_db_preview(&mut self) {
        self.db_form.refresh_probes();
        let errors = self.db_form.validate_all();
        if let Some((first_field, msg)) = errors.first() {
            self.db_form.set_focus(*first_field);
            self.notify(NoticeLevel::Error, msg.clone());
            return;
        }

        let argv = db_argv(&self.db_form);
        let args = match parse_db_argv(&argv) {
            Ok(a) => a,
            Err((maybe_field, msg)) => {
                if let Some(f) = maybe_field {
                    self.db_form.set_focus(f);
                }
                self.notify(NoticeLevel::Error, msg);
                return;
            }
        };

        self.check_db_credential();
        let conn_key = self.db_form.conn_key();
        let reused_cred = self
            .db_credential
            .take()
            .filter(|(k, _)| *k == conn_key)
            .map(|(_, c)| c);

        self.stop.clear_examiner();
        let progress = Arc::new(Progress::default());
        let progress_worker = Arc::clone(&progress);
        let console = Arc::new(TuiConsole::new(self.stop, self.secret_tx.clone()));
        let console_worker: Arc<dyn Console> = Arc::clone(&console) as Arc<dyn Console>;
        let args_worker = args;
        let argv_worker = argv.clone();
        let stop_ref = self.stop;

        let handle = std::thread::spawn(move || {
            let ctx = RunCtx {
                stop: stop_ref,
                progress: Some(&progress_worker),
                argv: Some(argv_worker),
                interactive: true,
                preview: None,
                credential: Mutex::new(reused_cred),
                reference_entered_ns: None,
                console: console_worker,
            };
            let (pv, cred) = db::preview(&args_worker, &ctx)?;
            Ok(PreviewWorkerOutput {
                mode_preview: ModePreview::Db {
                    preview: pv,
                    args: Box::new(args_worker),
                },
                db_credential: cred.map(|c| (conn_key, c)),
            })
        });

        self.notice = None;
        self.preview_state = Some(PreviewState::Running {
            mode: Mode::Db,
            argv,
            progress,
            console,
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
                self.screen = self.active_mode.form_screen();
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
            let max = data.mode_preview.scroll_max();
            if delta < 0 {
                data.scroll = data.scroll.saturating_sub(delta.unsigned_abs());
            } else {
                data.scroll = (data.scroll + delta as usize).min(max);
            }
        }
    }

    /// Attempt to open the Start confirmation sheet (or refuse if the preview is stale or blocked).
    pub fn request_start_acquisition(&mut self) -> bool {
        if let Some(PreviewState::Ready(data)) = &self.preview_state {
            if let Some(reason) = data.mode_preview.start_block_reason() {
                self.notify(NoticeLevel::Error, reason);
                return false;
            }
        }
        if self.is_preview_stale() {
            self.notify(
                NoticeLevel::Error,
                "Preview is stale or incomplete; press F2 / 'r' to re-run preview.",
            );
            return false;
        }
        self.modal = Some(Modal::ConfirmStart);
        true
    }

    /// Launch `files::run_with` on the worker thread using the previewed arguments.
    #[cfg(test)]
    pub fn start_files_run(&mut self) -> bool {
        self.active_mode = Mode::Files;
        self.start_active_run()
    }

    /// Launch the active mode's `run_with` on the worker thread using the previewed arguments.
    pub fn start_active_run(&mut self) -> bool {
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
        let mode = data.mode_preview.mode();
        let argv = data.argv.clone();
        let preview_note = Some(data.mode_preview.note());

        self.stop.clear_examiner();
        let progress = Arc::new(Progress::default());
        let progress_worker = Arc::clone(&progress);
        let console = Arc::new(TuiConsole::new(self.stop, self.secret_tx.clone()));
        let console_worker: Arc<dyn Console> = Arc::clone(&console) as Arc<dyn Console>;
        let stop_ref = self.stop;

        let (source_display, output, expected_files, expected_bytes, handle) = match &data
            .mode_preview
        {
            ModePreview::Files { preview, args } => {
                let args_w = (**args).clone();
                let argv_w = argv.clone();
                let src = args_w.source.display().to_string();
                let out = args_w.output.clone();
                let exp_f = preview.files;
                let exp_b = preview.bytes;
                let ref_ns = self.files_form.reference_entered_ns;
                let h = std::thread::spawn(move || {
                    let ctx = RunCtx {
                        stop: stop_ref,
                        progress: Some(&progress_worker),
                        argv: Some(argv_w),
                        interactive: true,
                        preview: preview_note,
                        credential: Default::default(),
                        reference_entered_ns: ref_ns,
                        console: console_worker,
                    };
                    let o = files::run_with(&args_w, &ctx)?;
                    Ok(verify::Outcome {
                        code: o.code,
                        summary: o.summary,
                    })
                });
                (src, out, exp_f, exp_b, h)
            }
            ModePreview::Ingest { preview, args } => {
                let args_w = IngestArgs {
                    package: args.package.clone(),
                    provider: args.provider.clone(),
                    received_at: args.received_at.clone(),
                    channel: args.channel.clone(),
                    reference: args.reference.clone(),
                    hashes: args.hashes.clone(),
                    allow_unlisted: args.allow_unlisted,
                    legal_basis: args.legal_basis.clone(),
                    output: args.output.clone(),
                    case: args.case.clone(),
                    clock: args.clock.clone(),
                    md5: args.md5,
                    sha1: args.sha1,
                    compress: args.compress,
                    allow_tmpfs: args.allow_tmpfs,
                    dry_run: false,
                    json: false,
                };
                let argv_w = argv.clone();
                let src = args_w.package.display().to_string();
                let out = args_w.output.clone();
                let exp_f = preview.files;
                let exp_b = preview.bytes;
                let ref_ns = self.ingest_form.clock.reference_entered_ns;
                let h = std::thread::spawn(move || {
                    let ctx = RunCtx {
                        stop: stop_ref,
                        progress: Some(&progress_worker),
                        argv: Some(argv_w),
                        interactive: true,
                        preview: preview_note,
                        credential: Default::default(),
                        reference_entered_ns: ref_ns,
                        console: console_worker,
                    };
                    let o = ingest::run_with(&args_w, &ctx)?;
                    Ok(verify::Outcome {
                        code: o.code,
                        summary: o.summary,
                    })
                });
                (src, out, exp_f, exp_b, h)
            }
            ModePreview::Cloud { preview, args } => {
                let args_w = CloudArgs {
                    source: args.source.clone(),
                    rclone_config: args.rclone_config.clone(),
                    rclone_args: args.rclone_args.clone(),
                    output: args.output.clone(),
                    case: args.case.clone(),
                    scope: args.scope.clone(),
                    clock: args.clock.clone(),
                    md5: args.md5,
                    sha1: args.sha1,
                    compress: args.compress,
                    allow_tmpfs: args.allow_tmpfs,
                    dry_run: false,
                    json: false,
                };
                let argv_w = argv.clone();
                let src = args_w.source.clone();
                let out = args_w.output.clone();
                let exp_f = preview.files;
                let exp_b = preview.bytes;
                let ref_ns = self.cloud_form.clock.reference_entered_ns;
                let h = std::thread::spawn(move || {
                    let ctx = RunCtx {
                        stop: stop_ref,
                        progress: Some(&progress_worker),
                        argv: Some(argv_w),
                        interactive: true,
                        preview: preview_note,
                        credential: Default::default(),
                        reference_entered_ns: ref_ns,
                        console: console_worker,
                    };
                    let o = cloud::run_with(&args_w, &ctx)?;
                    Ok(verify::Outcome {
                        code: o.code,
                        summary: o.summary,
                    })
                });
                (src, out, exp_f, exp_b, h)
            }
            ModePreview::Db { preview, args } => {
                let args_w = DbArgs {
                    engine: args.engine,
                    host: args.host.clone(),
                    port: args.port,
                    user: args.user.clone(),
                    password_file: args.password_file.clone(),
                    no_password: args.no_password,
                    tls: args.tls,
                    databases: args.databases.clone(),
                    legal_basis: args.legal_basis.clone(),
                    serializable: args.serializable,
                    binlog_position: args.binlog_position,
                    output: args.output.clone(),
                    case: args.case.clone(),
                    clock: args.clock.clone(),
                    md5: args.md5,
                    sha1: args.sha1,
                    compress: args.compress,
                    allow_tmpfs: args.allow_tmpfs,
                    dry_run: false,
                    json: false,
                };
                let argv_w = argv.clone();
                let src = format!(
                    "{}://{}@{}",
                    args_w.engine.as_cli_str(),
                    args_w.user,
                    args_w.host
                );
                let out = args_w.output.clone();
                let in_scope_dbs = preview.databases.iter().filter(|(_, _, s)| *s).count() as u64;
                let exp_f = in_scope_dbs + u64::from(args_w.engine == crate::db::Engine::Postgres);
                let exp_b = preview.in_scope_bytes();
                let ref_ns = self.db_form.clock.reference_entered_ns;
                let conn_key = self.db_form.conn_key();
                let reused_cred = self
                    .db_credential
                    .take()
                    .filter(|(k, _)| *k == conn_key)
                    .map(|(_, c)| c);
                let h = std::thread::spawn(move || {
                    let ctx = RunCtx {
                        stop: stop_ref,
                        progress: Some(&progress_worker),
                        argv: Some(argv_w),
                        interactive: true,
                        preview: preview_note,
                        credential: Mutex::new(reused_cred),
                        reference_entered_ns: ref_ns,
                        console: console_worker,
                    };
                    let o = db::run_with(&args_w, &ctx)?;
                    Ok(verify::Outcome {
                        code: o.code,
                        summary: o.summary,
                    })
                });
                (src, out, exp_f, exp_b, h)
            }
        };

        let now = Instant::now();
        let mut rate_samples = VecDeque::new();
        rate_samples.push_back((now, 0));

        self.notice = None;
        self.run_state = Some(RunState {
            mode,
            source_display,
            output,
            argv,
            expected_files,
            expected_bytes,
            progress,
            console,
            notices_expanded: false,
            notices_scroll: 0,
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
            KeyCode::Char('l') => {
                if let Some(run) = &mut self.run_state {
                    run.notices_expanded = !run.notices_expanded;
                    run.notices_scroll = 0;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(run) = &mut self.run_state {
                    if run.notices_expanded {
                        run.notices_scroll = run.notices_scroll.saturating_sub(1);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(run) = &mut self.run_state {
                    if run.notices_expanded {
                        run.notices_scroll = run.notices_scroll.saturating_add(1);
                    }
                }
            }
            KeyCode::PageUp => {
                if let Some(run) = &mut self.run_state {
                    if run.notices_expanded {
                        run.notices_scroll = run.notices_scroll.saturating_sub(5);
                    }
                }
            }
            KeyCode::PageDown => {
                if let Some(run) = &mut self.run_state {
                    if run.notices_expanded {
                        run.notices_scroll = run.notices_scroll.saturating_add(5);
                    }
                }
            }
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
            KeyCode::Char('q') => {
                self.db_credential = None;
                self.should_quit = true;
            }
            KeyCode::Char('h') | KeyCode::Esc => {
                self.capture_shared_from_active();
                self.db_credential = None;
                self.screen = Screen::Home;
            }
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('n') => {
                let mode = self
                    .result_data
                    .as_ref()
                    .map(|r| r.mode)
                    .unwrap_or(self.active_mode);
                self.active_mode = mode;
                self.db_credential = None;
                match mode {
                    Mode::Files => self.files_form.reset_for_next_acquisition(),
                    Mode::Ingest => self.ingest_form.reset_for_next_acquisition(),
                    Mode::Cloud => self.cloud_form.reset_for_next_acquisition(),
                    Mode::Db => self.db_form.reset_for_next_acquisition(),
                }
                self.capture_shared_from_active();
                self.preview_state = None;
                self.result_data = None;
                self.notice = None;
                self.screen = mode.form_screen();
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
                self.db_credential = None;
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

fn remove_selected(list: &mut Vec<String>, idx: &mut usize) {
    if !list.is_empty() {
        let remove_at = (*idx).min(list.len() - 1);
        list.remove(remove_at);
        if *idx >= list.len() && !list.is_empty() {
            *idx = list.len() - 1;
        }
    }
}

fn cycle_selected(len: usize, idx: &mut usize, forward: bool) {
    if len > 0 {
        *idx = if forward {
            (*idx + 1) % len
        } else {
            (*idx + len - 1) % len
        };
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

fn validate_list_item(target: ListTarget, val: &str) -> Result<(), String> {
    match target {
        ListTarget::CloudInclude => validate_single_pattern(val, true),
        ListTarget::CloudExclude => validate_single_pattern(val, false),
        ListTarget::IngestHashes => {
            let p = expand_tilde(Path::new(val));
            let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "hashes".into());
            ingest::parse_list(&text, &name)
                .map(|_| ())
                .map_err(|e| format!("{e:#}"))
        }
        ListTarget::CloudRcloneArgs | ListTarget::DbDatabases => Ok(()),
    }
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

/// Summary lines for the confirmation modal before starting an acquisition.
pub fn confirm_start_lines(app: &App, preview: &PreviewData) -> Vec<(String, String)> {
    match &preview.mode_preview {
        ModePreview::Files { preview: pv, .. } => {
            let form = &app.files_form;
            let mut lines = vec![
                ("Source".into(), pv.source.display().to_string()),
                ("Output collection".into(), pv.output.display().to_string()),
                (
                    "Case / Evidence".into(),
                    format!("{} / {}", form.case.trim(), form.evidence.trim()),
                ),
                ("Examiner".into(), form.examiner.trim().to_string()),
                (
                    "In-scope items".into(),
                    format!(
                        "{} files ({}), {} dirs, {} symlinks",
                        pv.files,
                        human_bytes(pv.bytes),
                        pv.directories,
                        pv.symlinks
                    ),
                ),
            ];
            if let Some(stamp) = form.reference_stamp_hint() {
                lines.push(("Ref. clock".into(), stamp));
            }
            if let Some(free) = pv.target_free {
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
        ModePreview::Ingest { preview: pv, args } => {
            let form = &app.ingest_form;
            let mut lines = vec![
                ("Package".into(), args.package.display().to_string()),
                ("Provider".into(), args.provider.clone()),
                (
                    "Output collection".into(),
                    args.output.display().to_string(),
                ),
                (
                    "Case / Evidence".into(),
                    format!("{} / {}", form.case.case.trim(), form.case.evidence.trim()),
                ),
                ("Examiner".into(), form.case.examiner.trim().to_string()),
                (
                    "Package items".into(),
                    format!(
                        "{} files ({}), {} listed, {} unlisted, {} missing",
                        pv.files,
                        human_bytes(pv.bytes),
                        pv.listed_present,
                        pv.unlisted_count,
                        pv.missing_count
                    ),
                ),
            ];
            if let Some(stamp) = form.clock.stamp_hint() {
                lines.push(("Ref. clock".into(), stamp));
            }
            if let Some(free) = pv.target_free {
                lines.push(("Target free space".into(), human_bytes(free)));
            }
            if form.output.allow_tmpfs {
                lines.push(("Safety overrides".into(), "--allow-tmpfs".into()));
            }
            lines
        }
        ModePreview::Cloud { preview: pv, args } => {
            let form = &app.cloud_form;
            let mut lines = vec![
                ("Remote source".into(), args.source.clone()),
                (
                    "Output collection".into(),
                    args.output.display().to_string(),
                ),
                (
                    "Case / Evidence".into(),
                    format!("{} / {}", form.case.case.trim(), form.case.evidence.trim()),
                ),
                ("Examiner".into(), form.case.examiner.trim().to_string()),
                (
                    "In-scope items".into(),
                    format!(
                        "{} of {} listed files ({})",
                        pv.files,
                        pv.listed,
                        human_bytes(pv.bytes)
                    ),
                ),
            ];
            if let Some(stamp) = form.clock.stamp_hint() {
                lines.push(("Ref. clock".into(), stamp));
            }
            if let Some(free) = pv.target_free {
                lines.push(("Target free space".into(), human_bytes(free)));
            }
            if form.output.allow_tmpfs {
                lines.push(("Safety overrides".into(), "--allow-tmpfs".into()));
            }
            lines
        }
        ModePreview::Db { preview: pv, args } => {
            let form = &app.db_form;
            let in_scope = pv.databases.iter().filter(|(_, _, s)| *s).count();
            let mut lines = vec![
                (
                    "Database server".into(),
                    format!("{}://{}@{}", args.engine.as_cli_str(), args.user, args.host),
                ),
                (
                    "Output collection".into(),
                    args.output.display().to_string(),
                ),
                (
                    "Case / Evidence".into(),
                    format!("{} / {}", form.case.case.trim(), form.case.evidence.trim()),
                ),
                ("Examiner".into(), form.case.examiner.trim().to_string()),
                (
                    "In-scope databases".into(),
                    format!(
                        "{} of {} (~{})",
                        in_scope,
                        pv.databases.len(),
                        human_bytes(pv.in_scope_bytes())
                    ),
                ),
            ];
            if let Some(stamp) = form.clock.stamp_hint() {
                lines.push(("Ref. clock".into(), stamp));
            }
            if let Some(free) = pv.target_free {
                lines.push(("Target free space".into(), human_bytes(free)));
            }
            if form.output.allow_tmpfs {
                lines.push(("Safety overrides".into(), "--allow-tmpfs".into()));
            }
            lines
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::form::{OutputProbe, RcloneRemote, SourceProbe};
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
        app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData::from_files(
            preview.clone(),
            argv.clone(),
            args.clone(),
        ))));
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
        app.preview_state = Some(PreviewState::Ready(Box::new(PreviewData::from_files(
            stopped_preview,
            argv,
            args,
        ))));
        assert!(app.is_preview_stale());
        assert!(!app.request_start_acquisition());
    }

    #[test]
    fn tui_console_secret_modal_round_trip_and_cancel() {
        static SECRET_STOP: Stop = Stop::new();
        SECRET_STOP.clear_examiner();
        let mut app = App::with_mounts(&SECRET_STOP, Vec::new(), Vec::new());
        let console = Arc::new(TuiConsole::new(&SECRET_STOP, app.secret_tx.clone()));

        // 1. Worker requests a secret; UI opens Modal::Secret, types "s3cret", presses Enter
        let c1 = Arc::clone(&console);
        let h1 = std::thread::spawn(move || {
            c1.secret(&SecretAsk {
                prompt: "Database password: ".into(),
                file_flag: "--password-file",
            })
        });
        while app.modal.is_none() {
            app.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(app.modal, Some(Modal::Secret(_))));
        for ch in "s3cret".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.modal.is_none());
        let res1 = h1.join().unwrap().unwrap();
        assert_eq!(res1.as_deref().map(String::as_str), Some("s3cret"));

        // 2. Worker requests a secret; UI presses Esc -> Ok(None) -> Cancelled
        let c2 = Arc::clone(&console);
        let h2 = std::thread::spawn(move || {
            crate::console::need_secret(
                c2.as_ref(),
                SecretAsk {
                    prompt: "Database password: ".into(),
                    file_flag: "--password-file",
                },
            )
        });
        while app.modal.is_none() {
            app.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        let err = h2.join().unwrap().unwrap_err();
        assert!(err.downcast_ref::<Cancelled>().is_some());
        let rd = ResultData::from_error_for_mode(Mode::Db, &err, PathBuf::from("/tmp/out"), vec![]);
        assert_eq!(rd.code, 8);
        assert_eq!(rd.status, "cancelled before anything was written");

        // 3. Notices ring buffer caps at MAX_NOTICES (50)
        for i in 0..65 {
            console.notice(Level::Info, &format!("notice {i}"));
        }
        let snap = console.notices_snapshot();
        assert_eq!(snap.len(), MAX_NOTICES);
        assert_eq!(snap.first().unwrap().1, "notice 15");
        assert_eq!(snap.last().unwrap().1, "notice 64");
    }

    #[test]
    fn db_credential_dropped_when_connection_field_changes() {
        static CRED_STOP: Stop = Stop::new();
        let mut app = App::with_mounts(&CRED_STOP, Vec::new(), Vec::new());
        app.open_db_form();
        app.db_form.host = "db.example.org".into();
        app.db_form.user = "postgres".into();
        let key = app.db_form.conn_key();
        app.db_credential = Some((
            key,
            Credential(crate::common::CredentialKind::Password(Zeroizing::new(
                "pw".into(),
            ))),
        ));
        assert!(app.db_credential.is_some());

        // Changing host drops the cached credential
        app.db_form.set_focus(DbField::Host);
        app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        assert!(app.db_credential.is_none());
    }

    struct TempDirGuard(PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cloud_form_rclone_config_down_focuses_remote_picker() {
        use crate::tui::form::RcloneProbe;
        static CLOUD_STOP: Stop = Stop::new();
        let root =
            std::env::temp_dir().join(format!("dfcollect-tui-rclone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let _guard = TempDirGuard(root.clone());

        let conf = root.join("rclone.conf");
        std::fs::write(&conf, "[local]\ntype = local\n[s3ev]\ntype = s3\n").unwrap();

        fn fake_rclone_probe(cfg: Option<&Path>) -> RcloneProbe {
            match cfg {
                Some(p) if p.is_file() => RcloneProbe::Remotes(vec![
                    RcloneRemote {
                        name: "local:".into(),
                        kind: "local".into(),
                    },
                    RcloneRemote {
                        name: "s3ev:".into(),
                        kind: "s3".into(),
                    },
                ]),
                _ => RcloneProbe::Remotes(Vec::new()),
            }
        }

        let mut app = App::with_mounts(&CLOUD_STOP, Vec::new(), Vec::new());
        app.cloud_form.rclone_probe = fake_rclone_probe;
        app.open_cloud_form();
        assert!(!app.cloud_form.rclone_missing);
        assert!(app.cloud_form.remotes.is_empty());
        assert!(!app.cloud_form.applies(CloudField::RemotePicker));

        app.cloud_form.set_focus(CloudField::RcloneConfig);
        for ch in conf.display().to_string().chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }

        // Pressing Down from rclone config probes remotes, makes RemotePicker
        // visible and focused, and pre-fills source with the first remote.
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.cloud_form.remotes.len(), 2);
        assert_eq!(app.cloud_form.remotes[0].name, "local:");
        assert_eq!(app.cloud_form.remotes[0].kind, "local");
        assert!(app.cloud_form.applies(CloudField::RemotePicker));
        assert_eq!(app.cloud_form.field, CloudField::RemotePicker);
        assert_eq!(app.cloud_form.source, "local:");

        // Pressing Right on RemotePicker cycles to the second remote.
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.cloud_form.selected_remote, Some(1));
        assert_eq!(app.cloud_form.source, "s3ev:");

        // When rclone is not on PATH, rclone_missing is set and remotes is empty.
        fn missing_probe(_: Option<&Path>) -> RcloneProbe {
            RcloneProbe::NotFound
        }
        app.cloud_form.rclone_probe = missing_probe;
        app.cloud_form.remotes.clear();
        app.cloud_form.remotes_probed_for = None;
        app.cloud_form.probe_remotes_if_needed();
        assert!(app.cloud_form.rclone_missing);
        assert!(app.cloud_form.remotes.is_empty());
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
        let _guard = TempDirGuard(root.clone());
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
        let _guard = TempDirGuard(root.clone());
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
    }
}
