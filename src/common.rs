//! What every acquisition shares: case fields, the reference time, checks of
//! the collection directory, reading the container back and the exit code.

use crate::{
    args::{CaseArgs, ClockArgs},
    console::{Console, Level, TermConsole},
    container,
    files::CONTAINER,
    Usage,
};
use anyhow::{Context, Result};
use dfcore::{
    host,
    manifest::{Case, Collection, Completion, Finished, ItemStatus, ReferenceTime, Status},
    sysfs, Refusal,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

/// Who asked a run to stop. A signal (the CLI's Ctrl-C, SIGTERM, a closed
/// terminal) and the examiner in the TUI are recorded differently.
#[derive(Debug, Default)]
pub struct Stop {
    pub signal: AtomicBool,
    pub examiner: AtomicBool,
}

impl Stop {
    pub const fn new() -> Self {
        Self {
            signal: AtomicBool::new(false),
            examiner: AtomicBool::new(false),
        }
    }

    /// Before the TUI starts another run; a signal stays latched
    pub fn clear_examiner(&self) {
        self.examiner.store(false, Ordering::Relaxed);
    }

    pub fn is_set(&self) -> bool {
        self.signal.load(Ordering::Relaxed) || self.examiner.load(Ordering::Relaxed)
    }

    /// The reason recorded in the manifest and the exit code; a signal wins
    pub fn reason(&self) -> Option<(String, u8)> {
        if self.signal.load(Ordering::Relaxed) {
            Some(("stopped by a signal".into(), 8))
        } else if self.examiner.load(Ordering::Relaxed) {
            Some(("stopped by the examiner".into(), 8))
        } else {
            None
        }
    }
}

/// What a run is doing, for [`Progress::phase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// A preview walks the source (metadata only)
    Listing = 0,
    /// A run walks the source and copies
    Copying = 1,
    /// The container is read back and every member hashed again
    CheckingContainer = 2,
    /// The records are closed
    Finishing = 3,
    Done = 4,
    /// Waiting for the examiner to sign in
    SigningIn = 5,
    /// Waiting for the remote side (a query that runs there)
    Waiting = 6,
}

/// Counters a run updates as it goes, read by the TUI and the CLI's progress
/// line. Only counts and the current path: nothing here is a record.
#[derive(Debug, Default)]
pub struct Progress {
    phase: AtomicU8,
    /// Entries decided, whatever the outcome
    pub entries: AtomicU64,
    /// Files acquired (a preview: files in scope)
    pub files: AtomicU64,
    /// Bytes copied (a preview: bytes in scope)
    pub bytes: AtomicU64,
    pub out_of_scope: AtomicU64,
    pub errors: AtomicU64,
    /// Bytes read back while checking the container
    pub check_bytes: AtomicU64,
    /// Items the run will handle, once known (0: not known)
    pub items_total: AtomicU64,
    current: Mutex<String>,
    /// What the run is doing, in words ("folder INBOX 3/12")
    stage: Mutex<String>,
}

impl Progress {
    pub fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Relaxed) {
            0 => Phase::Listing,
            1 => Phase::Copying,
            2 => Phase::CheckingContainer,
            3 => Phase::Finishing,
            5 => Phase::SigningIn,
            6 => Phase::Waiting,
            _ => Phase::Done,
        }
    }

    pub fn set_phase(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    pub fn current(&self) -> String {
        self.current.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn stage(&self) -> String {
        self.stage.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn set_stage(&self, text: &str) {
        if let Ok(mut c) = self.stage.lock() {
            c.clear();
            c.push_str(text);
        }
    }

    pub fn set_current(&self, path: &str) {
        if let Ok(mut c) = self.current.lock() {
            c.clear();
            c.push_str(path);
        }
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}

/// A preview that went before a run: when, and what it did to the source
/// (recorded in the run's footprint)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewNote {
    pub at_ns: i128,
    pub what: String,
}

/// What a preview signed in or connected with, handed to the run so the
/// examiner is not asked again (and the account holder not notified twice).
/// Opaque outside the library.
pub struct Credential(pub(crate) CredentialKind);

pub(crate) enum CredentialKind {
    /// A password the examiner typed for the preview
    Password(zeroize::Zeroizing<String>),
}

/// How a run is started: by the CLI or by the TUI.
pub struct RunCtx<'a> {
    pub stop: &'static Stop,
    pub progress: Option<&'a Progress>,
    /// Secrets, sign-in and notices: the terminal (CLI) or the TUI
    pub console: Arc<dyn Console>,
    /// The command line recorded as `method.argv`. None: this process's own
    /// arguments (the CLI).
    pub argv: Option<Vec<String>>,
    /// Started from the TUI (recorded in the footprint)
    pub interactive: bool,
    /// A preview that went before this run
    pub preview: Option<PreviewNote>,
    /// A credential from that preview, taken by the run (None: ask)
    pub credential: Mutex<Option<Credential>>,
    /// When the examiner entered the reference time (Unix ns). None: when
    /// the run starts, as on the command line.
    pub reference_entered_ns: Option<i128>,
}

impl<'a> RunCtx<'a> {
    pub fn cli(stop: &'static Stop, progress: Option<&'a Progress>) -> Self {
        Self {
            stop,
            progress,
            console: Arc::new(TermConsole::default()),
            argv: None,
            interactive: false,
            preview: None,
            credential: Mutex::new(None),
            reference_entered_ns: None,
        }
    }

    pub fn argv(&self) -> Vec<String> {
        self.argv
            .clone()
            .unwrap_or_else(|| std::env::args().collect())
    }

    /// Footprint entries that say how the run was started
    pub fn footprint(&self) -> Vec<dfcore::manifest::FootprintEntry> {
        let mut out = Vec::new();
        if self.interactive {
            out.push(dfcore::manifest::FootprintEntry::new(
                "info",
                serde_json::json!({
                    "what": "started from the dfcollect TUI; method.argv is the equivalent command line"
                }),
            ));
        }
        if let Some(p) = &self.preview {
            out.push(dfcore::manifest::FootprintEntry::new(
                "info",
                serde_json::json!({
                    "what": p.what,
                    "at": host::rfc3339_utc_ns(p.at_ns),
                }),
            ));
        }
        out
    }
}

impl RunCtx<'_> {
    /// The preview's credential, once
    pub(crate) fn take_credential(&self) -> Option<Credential> {
        self.credential.lock().ok()?.take()
    }

    pub fn set_phase(&self, phase: Phase) {
        if let Some(p) = self.progress {
            p.set_phase(phase);
        }
    }

    pub fn set_stage(&self, text: &str) {
        if let Some(p) = self.progress {
            p.set_stage(text);
        }
    }

    pub fn set_current(&self, text: &str) {
        if let Some(p) = self.progress {
            p.set_current(text);
        }
    }

    /// Add `n` to one of the progress counters
    pub fn count(&self, counter: impl Fn(&Progress) -> &AtomicU64, n: u64) {
        if let Some(p) = self.progress {
            Progress::add(counter(p), n);
        }
    }

    pub fn set_total(&self, n: u64) {
        if let Some(p) = self.progress {
            p.items_total.store(n, Ordering::Relaxed);
        }
    }
}

/// `Err(Stopped)` once a stop was asked for
pub fn check_stop(stop: &Stop) -> Result<()> {
    if stop.is_set() {
        Err(Stopped.into())
    } else {
        Ok(())
    }
}

/// Sleep for `d` unless a stop is asked for in the meantime (checked every
/// 200 ms; then `Err(Stopped)`)
pub fn sleep_unless_stopped(stop: &Stop, d: Duration) -> Result<()> {
    let end = Instant::now() + d;
    loop {
        check_stop(stop)?;
        let now = Instant::now();
        if now >= end {
            return Ok(());
        }
        std::thread::sleep((end - now).min(Duration::from_millis(200)));
    }
}

/// How a run's acquisition part ended: `None` when it went through,
/// `(reason, 8)` when it was stopped (a stop wins over the error it caused,
/// such as a killed tool's broken pipe), else `(error, 6)`
pub fn ended(result: Result<()>, stop: &Stop) -> Option<(String, u8)> {
    match result {
        Ok(()) => None,
        Err(_) if stop.is_set() => Some(stop.reason().unwrap_or_else(|| ("stopped".into(), 8))),
        Err(e) => Some((format!("{e:#}"), 6)),
    }
}

/// [`std::process::Command::output`], but a stop asked for in the meantime
/// kills the tool (checked every 100 ms; then `Err(Stopped)`)
pub fn output_unless_stopped(
    mut cmd: std::process::Command,
    stop: &Stop,
) -> Result<std::process::Output> {
    use std::{io::Read, process::Stdio};
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let read = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = read(
        child
            .stdout
            .take()
            .map(|o| Box::new(o) as Box<dyn Read + Send>),
    );
    let err = read(
        child
            .stderr
            .take()
            .map(|e| Box::new(e) as Box<dyn Read + Send>),
    );
    let status = loop {
        if stop.is_set() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Stopped.into());
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    Ok(std::process::Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// Why a run that could not get going (no connection, no sign-in) closes:
/// the stop's reason and 8 when it was stopped (also during a sign-in), else
/// the error and 4
pub fn not_started(e: &anyhow::Error, stop: &Stop) -> (String, u8) {
    if stop.is_set() {
        stop.reason().unwrap_or_else(|| ("stopped".into(), 8))
    } else {
        (format!("{e:#}"), 4)
    }
}

/// Record `item` and count it in the run's progress: acquired (and its
/// bytes), error or out of scope
pub fn record(
    collection: &mut Collection,
    item: dfcore::manifest::Item,
    ctx: &RunCtx,
) -> Result<u64> {
    match item.status {
        ItemStatus::Acquired => {
            ctx.count(|p| &p.files, 1);
            ctx.count(|p| &p.bytes, item.size.unwrap_or(0));
        }
        ItemStatus::Error => ctx.count(|p| &p.errors, 1),
        ItemStatus::OutOfScope => ctx.count(|p| &p.out_of_scope, 1),
        _ => {}
    }
    collection.add(item)
}

/// A read-back ended because [`Stop`] was set.
#[derive(Debug)]
pub struct Stopped;

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stopped")
    }
}

impl std::error::Error for Stopped {}

/// A reader that adds what it reads to a progress counter and fails once
/// `stop` is set, so a large file does not hold up a stop.
pub struct Counting<'a, R> {
    pub inner: R,
    pub counter: Option<&'a AtomicU64>,
    pub stop: Option<&'a Stop>,
}

impl<R: std::io::Read> std::io::Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.stop.is_some_and(Stop::is_set) {
            return Err(std::io::Error::other(Stopped));
        }
        let n = self.inner.read(buf)?;
        if let Some(c) = self.counter {
            c.fetch_add(n as u64, Ordering::Relaxed);
        }
        Ok(n)
    }
}

pub const TMPFS_MAGIC: u64 = 0x0102_1994;
pub const RAMFS_MAGIC: u64 = 0x8584_58f6;

pub struct FsInfo {
    pub magic: u64,
    pub read_only: bool,
}

/// `statfs` type and the read-only flag of the filesystem holding `path`.
pub fn fs_info(path: &Path) -> Result<FsInfo> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: zeroed structs are valid out-parameters for statfs/statvfs
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    let mut svfs: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid C string and out-pointers
    if unsafe { libc::statfs(c.as_ptr(), &mut sfs) } != 0
        || unsafe { libc::statvfs(c.as_ptr(), &mut svfs) } != 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Cannot stat the filesystem of {}", path.display()));
    }
    Ok(FsInfo {
        magic: sfs.f_type as u64,
        read_only: svfs.f_flag & libc::ST_RDONLY != 0,
    })
}

/// Bytes in binary units with one decimal: "512 B", "1.5 KiB", "3.0 GiB".
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

/// Free bytes for an unprivileged writer on the filesystem holding `path`.
pub fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: a zeroed struct is a valid out-parameter for statvfs
    let mut svfs: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid C string and out-pointer
    if unsafe { libc::statvfs(c.as_ptr(), &mut svfs) } != 0 {
        return None;
    }
    Some((svfs.f_bavail as u64).saturating_mul(svfs.f_frsize as u64))
}

pub fn case(args: &CaseArgs) -> Case {
    Case {
        case_number: args.case.clone(),
        evidence_number: args.evidence.clone(),
        examiner: args.examiner.clone(),
        description: args.description.clone(),
        notes: args.notes.clone(),
    }
}

/// The reference time, entered at `entered_ns` (None: now)
pub fn reference_at(args: &ClockArgs, entered_ns: Option<i128>) -> Result<Option<ReferenceTime>> {
    match (&args.reference_time, &args.reference_how) {
        (Some(value), Some(how)) => Ok(Some(
            ReferenceTime::new(value, how, entered_ns.unwrap_or_else(host::unix_now_ns))
                .map_err(|e| Usage(format!("{e:#}")))?,
        )),
        _ => Ok(None),
    }
}

/// The collection directory must be new or empty and not in RAM. Returns it
/// as an absolute path and the existing directory it will be created in.
pub fn check_output(output: &Path, allow_tmpfs: bool) -> Result<(PathBuf, PathBuf)> {
    let output = std::path::absolute(output)?;
    if output.exists() && std::fs::read_dir(&output)?.next().is_some() {
        return Err(Refusal(format!(
            "{} is not empty; choose a new collection directory",
            output.display()
        ))
        .into());
    }
    let ancestor = sysfs::existing_ancestor(&output);
    let ancestor = std::fs::canonicalize(&ancestor).unwrap_or(ancestor);
    let fs = fs_info(&ancestor)?;
    if matches!(fs.magic, TMPFS_MAGIC | RAMFS_MAGIC) && !allow_tmpfs {
        return Err(Refusal(format!(
            "{} is in RAM (tmpfs) and is lost at power-off; choose a target drive or pass --allow-tmpfs",
            output.display()
        ))
        .into());
    }
    Ok((output, ancestor))
}

/// Read the finished container back and compare every acquired member with
/// its item. Returns the members that do not match.
pub fn container_mismatches(
    output: &Path,
    progress: Option<&Progress>,
    stop: Option<&Stop>,
) -> Result<Vec<String>> {
    let read = progress.map(|p| &p.check_bytes);
    let members = match container::hash_members(&output.join(CONTAINER), read, stop) {
        Ok(m) => m,
        Err(e) if e.downcast_ref::<Stopped>().is_some() => return Err(e),
        Err(e) => return Ok(vec![format!("container not readable: {e:#}")]),
    };
    let mut mismatches = Vec::new();
    dfcore::manifest::for_each_item(output, |item| {
        if let (ItemStatus::Acquired, Some(member)) = (item.status, &item.member) {
            let want = (
                item.size.unwrap_or(0),
                item.hashes.sha256.clone().unwrap_or_default(),
            );
            if members.get(member) != Some(&want) {
                mismatches.push(member.clone());
            }
        }
        Ok(())
    })?;
    Ok(mismatches)
}

/// Close a run: check the container unless the run stopped, finish the
/// collection and pick the exit code (see README). The check is counted in
/// the run's progress; a stop ends it early and the collection is closed as
/// aborted.
pub fn conclude(
    mut collection: Collection,
    output: &Path,
    mut stopped: Option<(String, u8)>,
    ctx: &RunCtx,
) -> Result<(u8, Finished, Vec<String>)> {
    let (progress, stop) = (ctx.progress, Some(ctx.stop));
    let mismatches = if stopped.is_none() {
        if let Some(p) = progress {
            p.set_phase(Phase::CheckingContainer);
        }
        match container_mismatches(output, progress, stop) {
            Ok(m) => m,
            Err(e) if e.downcast_ref::<Stopped>().is_some() => {
                let reason = stop
                    .and_then(Stop::reason)
                    .unwrap_or_else(|| ("stopped".into(), 8));
                stopped = Some((
                    format!("{} while the container was checked", reason.0),
                    reason.1,
                ));
                Vec::new()
            }
            Err(e) => return Err(e),
        }
    } else {
        Vec::new()
    };
    if let Some(p) = progress {
        p.set_phase(Phase::Finishing);
    }
    for m in &mismatches {
        collection.error(format!("container check failed: {m}"));
    }
    let completion = match &stopped {
        Some((reason, _)) => Completion::Aborted {
            reason: reason.clone(),
        },
        None => Completion::Done { errors: vec![] },
    };
    let finished = collection.finish(completion)?;
    for w in &finished.warnings {
        ctx.console.notice(Level::Warning, &format!("WARNING: {w}"));
    }
    let code = match (&stopped, finished.manifest.status) {
        (Some((_, code)), _) => *code,
        (None, _) if !mismatches.is_empty() => 5,
        (None, Status::CompleteWithErrors) => 7,
        _ => 0,
    };
    Ok((code, finished, mismatches))
}

/// Set `DFNIX_AUDIT_LOG` once per test process to a per-process path so
/// parallel tests do not race on the environment variable or delete another
/// test's audit log while it is still writing.
#[cfg(test)]
pub(crate) fn test_audit_log() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let base = if Path::new("/dev/shm").is_dir() {
            PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        let path = base.join(format!("dfcollect_test_audit_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::env::set_var("DFNIX_AUDIT_LOG", path);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_kills_a_running_tool_and_ends_a_wait() {
        static STOP: Stop = Stop::new();
        STOP.clear_examiner();
        let out = output_unless_stopped(
            {
                let mut c = std::process::Command::new("sh");
                c.args(["-c", "printf ok"]);
                c
            },
            &STOP,
        )
        .unwrap();
        assert_eq!(out.stdout, b"ok");
        assert!(out.status.success());

        let t = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(300));
            STOP.examiner.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let mut c = std::process::Command::new("sleep");
        c.arg("30");
        let e = output_unless_stopped(c, &STOP).unwrap_err();
        assert!(e.downcast_ref::<Stopped>().is_some(), "{e:#}");
        assert!(started.elapsed() < Duration::from_secs(5));
        t.join().unwrap();

        let started = Instant::now();
        let e = sleep_unless_stopped(&STOP, Duration::from_secs(30)).unwrap_err();
        assert!(e.downcast_ref::<Stopped>().is_some());
        assert!(started.elapsed() < Duration::from_secs(1));
        STOP.clear_examiner();
        sleep_unless_stopped(&STOP, Duration::from_millis(10)).unwrap();
    }

    #[test]
    fn how_a_run_ended() {
        static STOP: Stop = Stop::new();
        assert_eq!(ended(Ok(()), &STOP), None);
        let e = || anyhow::anyhow!("broken pipe");
        assert_eq!(ended(Err(e()), &STOP), Some(("broken pipe".into(), 6)));
        assert_eq!(not_started(&e(), &STOP), ("broken pipe".into(), 4));
        STOP.examiner.store(true, Ordering::Relaxed);
        // A stop wins over the error it caused
        assert_eq!(
            ended(Err(e()), &STOP),
            Some(("stopped by the examiner".into(), 8))
        );
        assert_eq!(
            not_started(&e(), &STOP),
            ("stopped by the examiner".into(), 8)
        );
    }

    #[test]
    fn human_bytes_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(3 << 30), "3.0 GiB");
        assert_eq!(human_bytes(u64::MAX), "16.0 EiB");
    }

    #[test]
    fn a_signal_wins_over_the_examiner() {
        let stop: &'static Stop = Box::leak(Box::new(Stop::new()));
        assert!(!stop.is_set() && stop.reason().is_none());
        stop.examiner.store(true, Ordering::Relaxed);
        assert_eq!(stop.reason().unwrap().0, "stopped by the examiner");
        stop.signal.store(true, Ordering::Relaxed);
        assert_eq!(stop.reason(), Some(("stopped by a signal".into(), 8)));
    }
}
