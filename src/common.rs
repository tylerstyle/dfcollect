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
use std::path::{Path, PathBuf};

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
pub fn container_mismatches(output: &Path) -> Result<Vec<String>> {
    let members = match container::hash_members(&output.join(CONTAINER)) {
        Ok(m) => m,
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
    mut collection: Collection,
    output: &Path,
    stopped: Option<(String, u8)>,
) -> Result<(u8, Finished, Vec<String>)> {
    let mismatches = if stopped.is_none() {
        container_mismatches(output)?
    } else {
        Vec::new()
    };
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
