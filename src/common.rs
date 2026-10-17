//! What every acquisition shares: case fields, the reference time, checks of
//! the collection directory, reading the container back and the exit code.

use crate::{
    args::{CaseArgs, ClockArgs},
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
        Mutex,
    },
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
    current: Mutex<String>,
}

impl Progress {
    pub fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Relaxed) {
            0 => Phase::Listing,
            1 => Phase::Copying,
            2 => Phase::CheckingContainer,
            3 => Phase::Finishing,
            _ => Phase::Done,
        }
    }

    pub fn set_phase(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    pub fn current(&self) -> String {
        self.current.lock().map(|c| c.clone()).unwrap_or_default()
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

/// How a run is started: by the CLI or by the TUI.
pub struct RunCtx<'a> {
    pub stop: &'a Stop,
    pub progress: Option<&'a Progress>,
    /// The command line recorded as `method.argv`. None: this process's own
    /// arguments (the CLI).
    pub argv: Option<Vec<String>>,
    /// Started from the TUI (recorded in the footprint)
    pub interactive: bool,
    /// When a preview listed the source before this run (Unix ns)
    pub preview_at_ns: Option<i128>,
}

impl<'a> RunCtx<'a> {
    pub fn cli(stop: &'a Stop, progress: Option<&'a Progress>) -> Self {
        Self {
            stop,
            progress,
            argv: None,
            interactive: false,
            preview_at_ns: None,
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
        if let Some(ns) = self.preview_at_ns {
            out.push(dfcore::manifest::FootprintEntry::new(
                "info",
                serde_json::json!({
                    "what": "a preview listed the source before the acquisition (directory listings and lstat, no file opened)",
                    "at": host::rfc3339_utc_ns(ns),
                }),
            ));
        }
        out
    }
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

pub fn reference(args: &ClockArgs) -> Result<Option<ReferenceTime>> {
    match (&args.reference_time, &args.reference_how) {
        (Some(value), Some(how)) => Ok(Some(
            ReferenceTime::new(value, how, host::unix_now_ns())
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
/// collection and pick the exit code (see README).
pub fn conclude(
    collection: Collection,
    output: &Path,
    stopped: Option<(String, u8)>,
) -> Result<(u8, Finished, Vec<String>)> {
    conclude_with(collection, output, stopped, None, None)
}

/// [`conclude`], with the container check counted in `progress`. A set
/// `stop` ends the check early and the collection is closed as aborted.
pub fn conclude_with(
    mut collection: Collection,
    output: &Path,
    mut stopped: Option<(String, u8)>,
    progress: Option<&Progress>,
    stop: Option<&Stop>,
) -> Result<(u8, Finished, Vec<String>)> {
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
        eprintln!("[!] WARNING: {w}");
    }
    let code = match (&stopped, finished.manifest.status) {
        (Some((_, code)), _) => *code,
        (None, _) if !mismatches.is_empty() => 5,
        (None, Status::CompleteWithErrors) => 7,
        _ => 0,
    };
    Ok((code, finished, mismatches))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let stop = Stop::new();
        assert!(!stop.is_set() && stop.reason().is_none());
        stop.examiner.store(true, Ordering::Relaxed);
        assert_eq!(stop.reason().unwrap().0, "stopped by the examiner");
        stop.signal.store(true, Ordering::Relaxed);
        assert_eq!(stop.reason(), Some(("stopped by a signal".into(), 8)));
    }
}
