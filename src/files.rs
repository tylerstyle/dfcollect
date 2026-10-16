//! `dfcollect files`: a directory tree on a read-only mount into a ZIP64
//! container, with every entry decided by the scope before anything of it is
//! read.

use crate::{
    args::{FilesArgs, TimeBasis},
    common::{self, fs_info, FsInfo, RAMFS_MAGIC, TMPFS_MAGIC},
    container::{Container, CopyError, Hasher},
    meta::{self, Kind, Stamps},
    scope, Usage, TOOL, VERSION,
};
use anyhow::Result;
use dfcore::{
    host,
    manifest::{
        Candidate, Collection, Completion, Decision, FootprintEntry, Header, Item, ItemStatus,
        Method, ScopeRules, Source,
    },
    sysfs, Refusal,
};
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    fs::{File, Metadata, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

pub const CONTAINER: &str = "data.zip";
const AUDIT_ACTION: &str = "logical_collection";
/// Files whose access time is watched to learn whether the source updates it
const ATIME_PROBES: u32 = 16;

/// What the source filesystem is, from `statfs`.
fn fs_kind(magic: u64) -> &'static str {
    match magic {
        0x6969 => "nfs",
        0xFF53_4D42 | 0xFE53_4D42 | 0x517B => "smb",
        0x6573_5546 => "fuse",
        TMPFS_MAGIC | RAMFS_MAGIC => "tmpfs",
        _ => "filesystem",
    }
}

/// Open a file for reading without following a symlink and, where the kernel
/// allows it, without updating its access time.
fn open_source(path: &Path) -> std::io::Result<(File, bool)> {
    let open = |flags| OpenOptions::new().read(true).custom_flags(flags).open(path);
    match open(libc::O_NOFOLLOW | libc::O_NOATIME) {
        Ok(f) => Ok((f, true)),
        // O_NOATIME needs file ownership or CAP_FOWNER
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
            open(libc::O_NOFOLLOW).map(|f| (f, false))
        }
        Err(e) => Err(e),
    }
}

fn time_of(stamps: &Stamps, basis: TimeBasis) -> Option<i128> {
    match basis {
        TimeBasis::Modified => Some(stamps.modified),
        TimeBasis::Accessed => Some(stamps.accessed),
        TimeBasis::Changed => Some(stamps.changed),
        TimeBasis::Birth => stamps.birth,
    }
}

/// The checks before anything is created: a readable directory as source, on
/// a read-only mount, and a new collection directory that is neither inside
/// the source nor on its disk nor in RAM.
struct Plan {
    source: PathBuf,
    source_fs: FsInfo,
    mount: Option<sysfs::MountEntry>,
}

fn preflight(args: &FilesArgs) -> Result<Plan> {
    let source = std::fs::canonicalize(&args.source)
        .map_err(|e| Usage(format!("source {}: {e}", args.source.display())))?;
    if !source.is_dir() {
        return Err(Usage(format!("source {} is not a directory", source.display())).into());
    }
    let source_fs = fs_info(&source)?;
    if !source_fs.read_only && !args.allow_writable_source {
        return Err(Refusal(format!(
            "{} is on a read-write mount; mount it read-only (dfmount evidence, dfnet smb/nfs) or pass --allow-writable-source",
            source.display()
        ))
        .into());
    }

    let (output, ancestor) = common::check_output(&args.output, args.allow_tmpfs)?;
    if ancestor.starts_with(&source) {
        return Err(Refusal(format!(
            "the collection directory {} is inside the source {}",
            output.display(),
            source.display()
        ))
        .into());
    }
    if let Some(src_dev) = sysfs::backing_device_of_path(&source) {
        sysfs::check_disjoint(
            &sysfs::BlockTopology::default(),
            src_dev,
            &source.display().to_string(),
            sysfs::backing_device_of_path(&ancestor),
            &output.display().to_string(),
        )?;
    }
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map(|c| sysfs::parse_mountinfo(&c))
        .unwrap_or_default();
    let mount = sysfs::mount_containing(&mounts, &source).cloned();
    Ok(Plan {
        source,
        source_fs,
        mount,
    })
}

fn header(args: &FilesArgs, plan: &Plan, scope: dfcore::manifest::Scope) -> Result<Header> {
    let kind = fs_kind(plan.source_fs.magic);
    let (mount_source, mount_point) = plan
        .mount
        .as_ref()
        .map(|m| (m.source.clone(), m.mount_point.display().to_string()))
        .unwrap_or_default();
    let mut primitives = vec![
        "files opened read-only (O_RDONLY, O_NOFOLLOW, O_NOATIME where permitted)".to_string(),
    ];
    if plan.source_fs.read_only {
        primitives.insert(0, "read-only mount".into());
    }
    let reference = common::reference(&args.clock)?;
    Ok(Header {
        action: AUDIT_ACTION.into(),
        case: common::case(&args.case),
        source: Source {
            kind: kind.into(),
            locator: plan.source.display().to_string(),
            identity: json!({
                "mount_source": mount_source,
                "mount_point": mount_point,
                "device": plan.mount.as_ref().map(|m| format!("{}:{}", m.dev.0, m.dev.1)),
                "statfs_type": format!("{:#x}", plan.source_fs.magic),
            }),
            details: json!({ "read_only_mount": plan.source_fs.read_only }),
        },
        method: Method {
            tool: TOOL.into(),
            tool_version: VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: std::env::args().collect(),
            read_only_primitives: primitives,
            description: Some(format!(
                "Directory tree walked without following symlinks and without leaving its filesystem; \
                 files stored in {CONTAINER} (ZIP64, {}); the container is read back and every member hashed again",
                if args.compress { "deflated" } else { "stored" }
            )),
        },
        scope,
        clocks: dfcore::manifest::Clocks {
            reference,
            ..Default::default()
        },
    })
}

/// How the run ended, for the exit code.
pub struct Outcome {
    pub code: u8,
    pub summary: Value,
}

struct Walk<'a> {
    args: &'a FilesArgs,
    rules: ScopeRules,
    collection: Collection,
    container: Container,
    root_dev: u64,
    atime_probes: u32,
    atime_noted: bool,
    noatime_denied: u64,
    pruned: u64,
}

enum Step {
    Continue,
    /// The container cannot be written: stop
    Fatal(String),
}

impl Walk<'_> {
    fn decide(&self, rel: &str, time_ns: Option<i128>) -> Decision {
        self.rules.decide(&Candidate {
            path: rel,
            account: None,
            time_ns,
        })
    }

    fn out_of_scope(
        &mut self,
        rel: &str,
        reason: String,
        kind: Kind,
        md: Option<&Metadata>,
    ) -> Result<()> {
        if self.args.scope.list_out_of_scope {
            let mut item = Item::out_of_scope(rel, reason);
            item.kind = kind.item_kind();
            if let Some(md) = md {
                item.times = Stamps::of(md).times();
                if kind == Kind::File {
                    item.size = Some(md.len());
                }
            }
            self.collection.add(item)?;
        } else {
            self.collection.count_out_of_scope(&reason);
        }
        Ok(())
    }

    /// An excluded directory tree (`<pattern>/**` matching the directory) is not
    /// walked at all.
    fn pruned_by(&self, rel: &str) -> Option<String> {
        self.rules
            .scope()
            .exclude
            .iter()
            .find(|p| {
                p.strip_suffix("/**")
                    .is_some_and(|q| dfcore::manifest::glob_match(q, rel))
            })
            .cloned()
    }

    fn error_item(&mut self, rel: &str, kind: Kind, reason: String) -> Result<()> {
        let mut item = Item::new(ItemStatus::Error, rel);
        item.kind = kind.item_kind();
        item.reason = Some(reason);
        self.collection.add(item)?;
        Ok(())
    }

    fn entry(&mut self, abs: &Path, rel: &str, dirs: &mut Vec<(PathBuf, String)>) -> Result<Step> {
        let md = match std::fs::symlink_metadata(abs) {
            Ok(md) => md,
            Err(e) => {
                // Without metadata only the path can be decided
                return match self.decide(rel, None) {
                    Decision::OutOfScope(reason) => {
                        self.out_of_scope(rel, reason, Kind::File, None)?;
                        Ok(Step::Continue)
                    }
                    Decision::InScope => {
                        self.error_item(rel, Kind::File, format!("cannot read metadata: {e}"))?;
                        Ok(Step::Continue)
                    }
                };
            }
        };
        let kind = Kind::of(&md);
        let stamps = Stamps::of(&md);
        if kind == Kind::Directory {
            return self.directory(abs, rel, &md, &stamps, dirs);
        }
        let decision = self.decide(rel, time_of(&stamps, self.args.scope.time_basis));
        if let Decision::OutOfScope(reason) = decision {
            self.out_of_scope(rel, reason, kind, Some(&md))?;
            return Ok(Step::Continue);
        }
        match kind {
            Kind::File => self.file(abs, rel, &md, &stamps),
            Kind::Symlink => {
                let mut item = Item::new(ItemStatus::Acquired, rel);
                item.kind = kind.item_kind();
                item.times = stamps.times();
                item.metadata = meta::metadata(abs, &md, kind);
                self.collection.add(item)?;
                Ok(Step::Continue)
            }
            Kind::Special(what) => {
                let mut item = Item::new(ItemStatus::Skipped, rel);
                item.kind = kind.item_kind();
                item.times = stamps.times();
                item.metadata = meta::metadata(abs, &md, kind);
                item.reason = Some(format!("a {what} has no content to acquire"));
                self.collection.add(item)?;
                Ok(Step::Continue)
            }
            Kind::Directory => unreachable!("handled above"),
        }
    }

    fn directory(
        &mut self,
        abs: &Path,
        rel: &str,
        md: &Metadata,
        stamps: &Stamps,
        dirs: &mut Vec<(PathBuf, String)>,
    ) -> Result<Step> {
        if let Some(pattern) = self.pruned_by(rel) {
            self.pruned += 1;
            self.collection
                .count_out_of_scope(&format!("directory tree excluded by {pattern}"));
            return Ok(Step::Continue);
        }
        if md.dev() != self.root_dev {
            let mut item = Item::new(ItemStatus::Skipped, rel);
            item.kind = Kind::Directory.item_kind();
            item.reason = Some("another filesystem is mounted here; acquire it separately".into());
            self.collection.add(item)?;
            return Ok(Step::Continue);
        }
        // Descend in any case: include patterns can match below an
        // out-of-scope directory
        dirs.push((abs.to_path_buf(), rel.to_string()));
        // A directory outside the scope is structure, not an item: neither
        // recorded nor counted
        match self.decide(rel, time_of(stamps, self.args.scope.time_basis)) {
            Decision::OutOfScope(_) => {}
            Decision::InScope => {
                match self
                    .container
                    .add_directory(&format!("{rel}/"), md.mode(), stamps)
                {
                    Ok(()) => {}
                    Err(CopyError::Container(e)) => return Ok(Step::Fatal(format!("{e:#}"))),
                    Err(CopyError::Duplicate(name)) => {
                        self.error_item(rel, Kind::Directory, duplicate_reason(&name))?;
                        return Ok(Step::Continue);
                    }
                    Err(CopyError::Source(e)) => {
                        self.error_item(rel, Kind::Directory, format!("{e}"))?;
                        return Ok(Step::Continue);
                    }
                }
                let mut item = Item::new(ItemStatus::Acquired, rel);
                item.kind = Kind::Directory.item_kind();
                item.times = stamps.times();
                item.metadata = meta::metadata(abs, md, Kind::Directory);
                self.collection.add(item)?;
            }
        }
        Ok(Step::Continue)
    }

    fn file(&mut self, abs: &Path, rel: &str, md: &Metadata, stamps: &Stamps) -> Result<Step> {
        let (mut file, noatime) = match open_source(abs) {
            Ok(f) => f,
            Err(e) => {
                self.error_item(rel, Kind::File, format!("cannot open: {e}"))?;
                return Ok(Step::Continue);
            }
        };
        if !noatime {
            self.noatime_denied += 1;
        }
        let opened = file.metadata()?;
        if (opened.dev(), opened.ino()) != (md.dev(), md.ino()) {
            self.error_item(
                rel,
                Kind::File,
                "replaced between listing and opening (different inode)".into(),
            )?;
            return Ok(Step::Continue);
        }
        let mut hasher = Hasher::new(self.args.md5, self.args.sha1);
        let size = match self
            .container
            .add_file(rel, md.mode(), stamps, &mut file, &mut hasher)
        {
            Ok(n) => n,
            Err(CopyError::Source(e)) => {
                self.error_item(rel, Kind::File, format!("read error: {e}"))?;
                return Ok(Step::Continue);
            }
            Err(CopyError::Duplicate(name)) => {
                self.error_item(rel, Kind::File, duplicate_reason(&name))?;
                return Ok(Step::Continue);
            }
            Err(CopyError::Container(e)) => return Ok(Step::Fatal(format!("{e:#}"))),
        };
        let mut item = Item::new(ItemStatus::Acquired, rel);
        item.stored_as = Some(CONTAINER.into());
        item.member = Some(rel.to_string());
        item.size = Some(size);
        item.hashes = hasher.finish();
        item.times = stamps.times();
        item.metadata = meta::metadata(abs, md, Kind::File);

        // The file must be the same after reading as when it was listed
        let after = file.metadata()?;
        let changed = after.len() != md.len()
            || after.mtime() != md.mtime()
            || after.mtime_nsec() != md.mtime_nsec()
            || after.ctime() != md.ctime()
            || after.ctime_nsec() != md.ctime_nsec()
            || size != md.len();
        if changed {
            item.reason =
                Some("the file changed while it was read; the hash is of the bytes read".into());
            self.collection
                .error(format!("{rel}: changed while it was read"));
        }
        // Does reading change the access time on the source (e.g. an SMB or
        // NFS server)? Watch the first files and record it once.
        if self.atime_probes < ATIME_PROBES && !self.atime_noted {
            self.atime_probes += 1;
            if let Ok(now) = std::fs::symlink_metadata(abs) {
                if (now.atime(), now.atime_nsec()) != (md.atime(), md.atime_nsec()) {
                    self.atime_noted = true;
                    self.collection.footprint(FootprintEntry::new(
                        "write",
                        json!({
                            "what": "the source updated the access time of a file that was read",
                            "path": rel,
                            "before": host::rfc3339_utc_ns(Stamps::of(md).accessed),
                            "after": host::rfc3339_utc_ns(Stamps::of(&now).accessed),
                        }),
                    ))?;
                }
            }
        }
        self.collection.add(item)?;
        Ok(Step::Continue)
    }
}

/// Two source names can map to one container name when one of them is not
/// UTF-8 and the other spells its `%XX` escape literally.
fn duplicate_reason(name: &str) -> String {
    format!(
        "another entry already has the container name {name} (names that are not UTF-8 are stored with %XX escapes)"
    )
}

/// Entries of a directory, sorted by their bytes so every run walks in the
/// same order.
fn sorted_entries(dir: &Path) -> std::io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        names.push(entry?.file_name());
    }
    use std::os::unix::ffi::OsStrExt;
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

pub fn run(args: &FilesArgs, stop: &AtomicBool) -> Result<Outcome> {
    let scope = scope::build(&args.scope)?;
    let rules = scope.rules().map_err(|e| Usage(format!("{e:#}")))?;
    let plan = preflight(args)?;
    let header = header(args, &plan, scope)?;
    let output = std::path::absolute(&args.output)?;
    let mut collection = Collection::create(&output, header)?;
    if !plan.source_fs.read_only {
        collection.footprint(FootprintEntry::new(
            "warning",
            json!({ "what": "the source was mounted read-write (--allow-writable-source)" }),
        ))?;
    }
    let container = match Container::create(&output.join(CONTAINER), args.compress) {
        Ok(c) => c,
        Err(e) => {
            collection.finish(Completion::Aborted {
                reason: format!("{e:#}"),
            })?;
            return Err(e);
        }
    };
    let root_dev = std::fs::metadata(&plan.source)?.dev();
    let mut walk = Walk {
        args,
        rules,
        collection,
        container,
        root_dev,
        atime_probes: 0,
        atime_noted: false,
        noatime_denied: 0,
        pruned: 0,
    };

    let mut dirs = vec![(plan.source.clone(), String::new())];
    let mut stopped: Option<(String, u8)> = None;
    'walk: while let Some((dir, rel_dir)) = dirs.pop() {
        let names = match sorted_entries(&dir) {
            Ok(n) => n,
            Err(e) => {
                let rel = if rel_dir.is_empty() {
                    ".".to_string()
                } else {
                    rel_dir.clone()
                };
                walk.error_item(&rel, Kind::Directory, format!("cannot list: {e}"))?;
                continue;
            }
        };
        // Depth-first in name order: push subdirectories in reverse
        let mut subdirs = Vec::new();
        for name in names {
            if stop.load(Ordering::Relaxed) {
                stopped = Some(("stopped by a signal".into(), 8));
                break 'walk;
            }
            let display = meta::display_bytes(&name);
            let rel = if rel_dir.is_empty() {
                display
            } else {
                format!("{rel_dir}/{display}")
            };
            match walk.entry(&dir.join(&name), &rel, &mut subdirs)? {
                Step::Continue => {}
                Step::Fatal(reason) => {
                    stopped = Some((format!("the container could not be written: {reason}"), 6));
                    break 'walk;
                }
            }
        }
        dirs.extend(subdirs.into_iter().rev());
    }

    let Walk {
        mut collection,
        container,
        noatime_denied,
        pruned,
        ..
    } = walk;
    if noatime_denied > 0 {
        collection.footprint(FootprintEntry::new(
            "info",
            json!({ "what": "files opened without O_NOATIME (not permitted for them)", "count": noatime_denied }),
        ))?;
    }
    if let Err(e) = container.finish() {
        stopped.get_or_insert((format!("{e:#}"), 6));
    }

    let (code, finished, mismatches) = common::conclude(collection, &output, stopped)?;
    let m = &finished.manifest;
    let unlisted: u64 = m.totals.unlisted_out_of_scope.values().sum();
    Ok(Outcome {
        code,
        summary: json!({
            "collection": output,
            "status": m.status,
            "acquired": m.totals.acquired,
            "bytes": m.totals.bytes,
            "out_of_scope_listed": m.totals.out_of_scope,
            "out_of_scope_counted": unlisted,
            "excluded_trees": pruned,
            "errors": m.totals.errors,
            "skipped": m.totals.skipped,
            "container_mismatches": mismatches,
            "problems": m.errors,
            "audit_anchor": m.audit_anchor,
            "warnings": finished.warnings,
        }),
    })
}
