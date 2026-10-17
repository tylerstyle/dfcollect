//! `dfcollect files`: a directory tree on a read-only mount into a ZIP64
//! container, with every entry decided by the scope before anything of it is
//! read.

use crate::{
    args::{FilesArgs, TimeBasis},
    common::{
        self, fs_info, Counting, FsInfo, Phase, Progress, RunCtx, Stop, RAMFS_MAGIC, TMPFS_MAGIC,
    },
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
    output: PathBuf,
    /// The existing directory the collection directory will be created in
    ancestor: PathBuf,
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
        output,
        ancestor,
    })
}

fn header(
    args: &FilesArgs,
    plan: &Plan,
    scope: dfcore::manifest::Scope,
    ctx: &RunCtx,
) -> Result<Header> {
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
    let reference = common::reference_at(&args.clock, ctx.reference_entered_ns)?;
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
            argv: ctx.argv(),
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

/// What the walk does with one entry. A run and a preview both decide through
/// [`classify`], so the preview shows what the run acquires.
enum Class {
    /// `lstat` failed: only the path could be decided
    NoMetadata {
        error: std::io::Error,
        decision: Decision,
    },
    /// A directory under an exclude pattern `<p>/**`: not walked at all
    Pruned { pattern: String },
    /// A directory no include pattern can match or reach below: not walked,
    /// so nothing outside the scope is listed
    OutsideIncludes,
    /// A directory where another filesystem is mounted: not walked
    OtherFilesystem,
    /// A directory of the source's filesystem: walked, and recorded when in
    /// scope
    Directory {
        decision: Decision,
        md: Metadata,
        stamps: Stamps,
    },
    /// A file, symlink or special file
    Leaf {
        kind: Kind,
        decision: Decision,
        md: Metadata,
        stamps: Stamps,
    },
}

/// The scope's rules and what the walk needs to apply them.
struct Decider<'a> {
    rules: &'a ScopeRules,
    basis: TimeBasis,
    root_dev: u64,
}

impl Decider<'_> {
    fn decide(&self, rel: &str, time_ns: Option<i128>) -> Decision {
        self.rules.decide(&Candidate {
            path: rel,
            account: None,
            time_ns,
        })
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

    /// Can the directory `rel` or anything below it be in scope by path?
    fn reachable(&self, rel: &str) -> bool {
        let include = &self.rules.scope().include;
        include.is_empty()
            || include
                .iter()
                .any(|p| dfcore::manifest::glob_match(p, rel) || could_match_below(p, rel))
    }

    /// Decide an entry from its metadata (`lstat`, never its content).
    fn classify(&self, abs: &Path, rel: &str) -> Class {
        let md = match std::fs::symlink_metadata(abs) {
            Ok(md) => md,
            Err(error) => {
                return Class::NoMetadata {
                    error,
                    decision: self.decide(rel, None),
                }
            }
        };
        let kind = Kind::of(&md);
        let stamps = Stamps::of(&md);
        if kind == Kind::Directory {
            if let Some(pattern) = self.pruned_by(rel) {
                return Class::Pruned { pattern };
            }
            // Before the mount check, so an out-of-scope mount point is not
            // named either
            if !self.reachable(rel) {
                return Class::OutsideIncludes;
            }
            if md.dev() != self.root_dev {
                return Class::OtherFilesystem;
            }
            return Class::Directory {
                decision: self.decide(rel, time_of(&stamps, self.basis)),
                md,
                stamps,
            };
        }
        Class::Leaf {
            kind,
            decision: self.decide(rel, time_of(&stamps, self.basis)),
            md,
            stamps,
        }
    }
}

fn pruned_reason(pattern: &str) -> String {
    format!("directory tree excluded by {pattern}")
}

const OUTSIDE_INCLUDES: &str = "directory tree matches no include pattern";

/// Could `pattern` (dfcore glob syntax) match a path below the directory
/// `dir`, i.e. `dir/<something>`? Patterns run against `dir/` as a prefix:
/// `**` can take the rest, `*` and `?` stay within a segment.
fn could_match_below(pattern: &str, dir: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = dir.chars().chain(std::iter::once('/')).collect();
    let (n, m) = (p.len(), s.len());
    // can[i][j]: p[i..] matches s[j..] followed by some non-empty rest
    let mut can = vec![vec![false; m + 1]; n + 1];
    for i in (0..n).rev() {
        // All of `dir/` consumed: any pattern left can match a name below
        can[i][m] = true;
        let double = p[i] == '*' && p.get(i + 1) == Some(&'*');
        for j in (0..m).rev() {
            can[i][j] = match p[i] {
                '*' if double => true,
                '*' => can[i + 1][j] || (s[j] != '/' && can[i][j + 1]),
                '?' => s[j] != '/' && can[i + 1][j + 1],
                c => s[j] == c && can[i + 1][j + 1],
            };
        }
    }
    n > 0 && can[0][0]
}

const OTHER_FILESYSTEM: &str = "another filesystem is mounted here; acquire it separately";

enum Step {
    Continue,
    /// The container cannot be written: stop
    Fatal(String),
    /// [`Stop`] was set while a file was copied
    Stopped,
}

/// One pass over the source: a run or a preview.
trait Visitor {
    /// One entry; a directory to descend into goes to `dirs`.
    fn entry(&mut self, abs: &Path, rel: &str, dirs: &mut Vec<(PathBuf, String)>) -> Result<Step>;
    /// A directory whose entries cannot be listed.
    fn unlistable(&mut self, rel: &str, error: std::io::Error) -> Result<()>;
}

/// Walk the source depth-first in name order, without following symlinks.
/// Returns why it stopped early, if it did.
fn traverse(
    source: &Path,
    stop: &Stop,
    visitor: &mut impl Visitor,
) -> Result<Option<(String, u8)>> {
    let mut dirs = vec![(source.to_path_buf(), String::new())];
    while let Some((dir, rel_dir)) = dirs.pop() {
        let names = match sorted_entries(&dir) {
            Ok(n) => n,
            Err(e) => {
                let rel = if rel_dir.is_empty() {
                    ".".to_string()
                } else {
                    rel_dir.clone()
                };
                visitor.unlistable(&rel, e)?;
                continue;
            }
        };
        // Depth-first in name order: push subdirectories in reverse
        let mut subdirs = Vec::new();
        for name in names {
            if let Some(stopped) = stop.reason() {
                return Ok(Some(stopped));
            }
            let display = meta::display_bytes(&name);
            let rel = if rel_dir.is_empty() {
                display
            } else {
                format!("{rel_dir}/{display}")
            };
            match visitor.entry(&dir.join(&name), &rel, &mut subdirs)? {
                Step::Continue => {}
                Step::Stopped => {
                    return Ok(Some(stop.reason().unwrap_or_else(|| ("stopped".into(), 8))))
                }
                Step::Fatal(reason) => {
                    return Ok(Some((
                        format!("the container could not be written: {reason}"),
                        6,
                    )));
                }
            }
        }
        dirs.extend(subdirs.into_iter().rev());
    }
    Ok(None)
}

struct Walk<'a> {
    args: &'a FilesArgs,
    rules: ScopeRules,
    collection: Collection,
    container: Container,
    root_dev: u64,
    progress: Option<&'a Progress>,
    stop: &'a Stop,
    atime_probes: u32,
    atime_noted: bool,
    noatime_denied: u64,
    pruned: u64,
    outside_includes: u64,
}

impl Visitor for Walk<'_> {
    fn entry(&mut self, abs: &Path, rel: &str, dirs: &mut Vec<(PathBuf, String)>) -> Result<Step> {
        let class = Decider {
            rules: &self.rules,
            basis: self.args.scope.time_basis,
            root_dev: self.root_dev,
        }
        .classify(abs, rel);
        if let Some(p) = self.progress {
            Progress::add(&p.entries, 1);
        }
        match class {
            // Without metadata only the path can be decided
            Class::NoMetadata { error, decision } => match decision {
                Decision::OutOfScope(reason) => self.out_of_scope(rel, reason, Kind::File, None)?,
                Decision::InScope => {
                    self.error_item(rel, Kind::File, format!("cannot read metadata: {error}"))?
                }
            },
            Class::Pruned { pattern } => {
                self.pruned += 1;
                self.count_out_of_scope(&pruned_reason(&pattern));
            }
            Class::OutsideIncludes => {
                self.outside_includes += 1;
                self.count_out_of_scope(OUTSIDE_INCLUDES);
            }
            Class::OtherFilesystem => {
                let mut item = Item::new(ItemStatus::Skipped, rel);
                item.kind = Kind::Directory.item_kind();
                item.reason = Some(OTHER_FILESYSTEM.into());
                self.collection.add(item)?;
            }
            Class::Directory {
                decision,
                md,
                stamps,
            } => return self.directory(abs, rel, decision, &md, &stamps, dirs),
            Class::Leaf {
                kind,
                decision: Decision::OutOfScope(reason),
                md,
                ..
            } => self.out_of_scope(rel, reason, kind, Some(&md))?,
            Class::Leaf {
                kind: Kind::File,
                md,
                stamps,
                ..
            } => return self.file(abs, rel, &md, &stamps),
            Class::Leaf {
                kind: Kind::Symlink,
                md,
                stamps,
                ..
            } => {
                let mut item = Item::new(ItemStatus::Acquired, rel);
                item.kind = Kind::Symlink.item_kind();
                item.times = stamps.times();
                item.metadata = meta::metadata(abs, &md, Kind::Symlink);
                self.collection.add(item)?;
            }
            Class::Leaf {
                kind: kind @ Kind::Special(what),
                md,
                stamps,
                ..
            } => {
                let mut item = Item::new(ItemStatus::Skipped, rel);
                item.kind = kind.item_kind();
                item.times = stamps.times();
                item.metadata = meta::metadata(abs, &md, kind);
                item.reason = Some(format!("a {what} has no content to acquire"));
                self.collection.add(item)?;
            }
            Class::Leaf {
                kind: Kind::Directory,
                ..
            } => unreachable!("classify returns directories as Class::Directory"),
        }
        Ok(Step::Continue)
    }

    fn unlistable(&mut self, rel: &str, error: std::io::Error) -> Result<()> {
        self.error_item(rel, Kind::Directory, format!("cannot list: {error}"))
    }
}

impl Walk<'_> {
    fn count_out_of_scope(&mut self, reason: &str) {
        if let Some(p) = self.progress {
            Progress::add(&p.out_of_scope, 1);
        }
        self.collection.count_out_of_scope(reason);
    }

    fn out_of_scope(
        &mut self,
        rel: &str,
        reason: String,
        kind: Kind,
        md: Option<&Metadata>,
    ) -> Result<()> {
        if self.args.scope.list_out_of_scope {
            if let Some(p) = self.progress {
                Progress::add(&p.out_of_scope, 1);
            }
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
            self.count_out_of_scope(&reason);
        }
        Ok(())
    }

    fn error_item(&mut self, rel: &str, kind: Kind, reason: String) -> Result<()> {
        if let Some(p) = self.progress {
            Progress::add(&p.errors, 1);
        }
        let mut item = Item::new(ItemStatus::Error, rel);
        item.kind = kind.item_kind();
        item.reason = Some(reason);
        self.collection.add(item)?;
        Ok(())
    }

    fn directory(
        &mut self,
        abs: &Path,
        rel: &str,
        decision: Decision,
        md: &Metadata,
        stamps: &Stamps,
        dirs: &mut Vec<(PathBuf, String)>,
    ) -> Result<Step> {
        // Descend even when the directory itself is out of scope: an include
        // pattern reaches below it (classify checked)
        dirs.push((abs.to_path_buf(), rel.to_string()));
        // A directory outside the scope is structure, not an item: neither
        // recorded nor counted
        match decision {
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
        if let Some(p) = self.progress {
            p.set_current(rel);
        }
        let (file, noatime) = match open_source(abs) {
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
        let mut source = Counting {
            inner: file,
            counter: self.progress.map(|p| &p.bytes),
            stop: Some(self.stop),
        };
        let size = match self
            .container
            .add_file(rel, md.mode(), stamps, &mut source, &mut hasher)
        {
            Ok(n) => n,
            // The partial member is gone; an aborted collection does not
            // list the file it was copying
            Err(CopyError::Source(_)) if self.stop.is_set() => return Ok(Step::Stopped),
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
        let file = source.inner;
        if let Some(p) = self.progress {
            Progress::add(&p.files, 1);
        }
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

/// The scope's rules, checked once for the whole run
fn rules(args: &FilesArgs) -> Result<(dfcore::manifest::Scope, ScopeRules)> {
    let scope = scope::build(&args.scope)?;
    let rules = scope.rules().map_err(|e| Usage(format!("{e:#}")))?;
    Ok((scope, rules))
}

pub fn run_with(args: &FilesArgs, ctx: &RunCtx) -> Result<Outcome> {
    let (scope, rules) = rules(args)?;
    let plan = preflight(args)?;
    let header = header(args, &plan, scope, ctx)?;
    let output = plan.output.clone();
    let mut collection = Collection::create(&output, header)?;
    for entry in ctx.footprint() {
        collection.footprint(entry)?;
    }
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
    if let Some(p) = ctx.progress {
        p.set_phase(Phase::Copying);
    }
    let root_dev = std::fs::metadata(&plan.source)?.dev();
    let mut walk = Walk {
        args,
        rules,
        collection,
        container,
        root_dev,
        progress: ctx.progress,
        stop: ctx.stop,
        atime_probes: 0,
        atime_noted: false,
        noatime_denied: 0,
        pruned: 0,
        outside_includes: 0,
    };
    let mut stopped = traverse(&plan.source, ctx.stop, &mut walk)?;

    let Walk {
        mut collection,
        container,
        noatime_denied,
        pruned,
        outside_includes,
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

    let (code, finished, mismatches) = common::conclude(collection, &output, stopped, ctx)?;
    if let Some(p) = ctx.progress {
        p.set_phase(Phase::Done);
    }
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
            "trees_outside_includes": outside_includes,
            "errors": m.totals.errors,
            "skipped": m.totals.skipped,
            "container_mismatches": mismatches,
            "problems": m.errors,
            "audit_anchor": m.audit_anchor,
            "warnings": finished.warnings,
        }),
    })
}

/// How many in-scope paths a preview keeps for display.
pub const PREVIEW_SAMPLE: usize = 1000;

/// One in-scope entry of a preview's sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleEntry {
    pub kind: Kind,
    pub path: String,
    /// Files only
    pub size: Option<u64>,
}

/// What a run with these arguments would do, from a walk that reads only
/// directory listings and `lstat`. Names outside the scope are never kept:
/// they are counted by reason, whatever `--list-out-of-scope` says.
#[derive(Debug, Clone, Default)]
pub struct Preview {
    pub source: PathBuf,
    pub output: PathBuf,
    /// In scope: files and their bytes, directories, symlinks
    pub files: u64,
    pub bytes: u64,
    pub directories: u64,
    pub symlinks: u64,
    /// Special files in scope (recorded as skipped: no content)
    pub special: u64,
    /// Out of scope, by the reason the manifest gives
    pub out_of_scope: std::collections::BTreeMap<String, u64>,
    pub excluded_trees: u64,
    /// Directory trees no include pattern reaches (not listed)
    pub trees_outside_includes: u64,
    /// Directories where another filesystem is mounted (recorded as skipped)
    pub other_filesystems: Vec<String>,
    /// Entries a run records as errors: unlistable directories, unreadable
    /// metadata in scope
    pub errors: Vec<(String, String)>,
    /// The first [`PREVIEW_SAMPLE`] in-scope entries, in walk order
    pub sample: Vec<SampleEntry>,
    /// Free bytes for an unprivileged writer where the collection goes
    pub target_free: Option<u64>,
    /// Why the preview ended early
    pub stopped: Option<String>,
    /// When the preview started listing (Unix ns), for [`Preview::note`]
    pub at_ns: i128,
}

impl Preview {
    /// For the run's footprint
    pub fn note(&self) -> crate::common::PreviewNote {
        crate::common::PreviewNote {
            at_ns: self.at_ns,
            what: "a preview listed the source before the acquisition (directory listings and lstat, no file opened)".into(),
        }
    }

    /// The run's `acquired` total: files, directories and symlinks
    pub fn acquired(&self) -> u64 {
        self.files + self.directories + self.symlinks
    }

    /// Free space is known and smaller than the in-scope bytes. The container
    /// adds headers to that.
    pub fn short_of_space(&self) -> bool {
        self.target_free.is_some_and(|free| free < self.bytes)
    }

    pub fn summary(&self) -> Value {
        json!({
            "dry_run": true,
            "source": self.source,
            "collection": self.output,
            "acquired": self.acquired(),
            "in_scope_files": self.files,
            "in_scope_bytes": self.bytes,
            "in_scope_directories": self.directories,
            "in_scope_symlinks": self.symlinks,
            "in_scope_special": self.special,
            "out_of_scope": self.out_of_scope,
            "excluded_trees": self.excluded_trees,
            "trees_outside_includes": self.trees_outside_includes,
            "other_filesystems": self.other_filesystems,
            "errors": self.errors.iter().map(|(p, e)| format!("{p}: {e}")).collect::<Vec<_>>(),
            "target_free_bytes": self.target_free,
            "short_of_space": self.short_of_space(),
            "stopped": self.stopped,
        })
    }
}

struct PreviewWalk<'a> {
    decider: Decider<'a>,
    preview: Preview,
    progress: Option<&'a Progress>,
}

impl PreviewWalk<'_> {
    fn sample(&mut self, kind: Kind, path: &str, size: Option<u64>) {
        if self.preview.sample.len() < PREVIEW_SAMPLE {
            self.preview.sample.push(SampleEntry {
                kind,
                path: path.to_string(),
                size,
            });
        }
    }

    fn out_of_scope(&mut self, reason: String) {
        if let Some(p) = self.progress {
            Progress::add(&p.out_of_scope, 1);
        }
        *self.preview.out_of_scope.entry(reason).or_default() += 1;
    }

    fn error(&mut self, path: &str, message: String) {
        if let Some(p) = self.progress {
            Progress::add(&p.errors, 1);
        }
        self.preview.errors.push((path.to_string(), message));
    }
}

impl Visitor for PreviewWalk<'_> {
    fn entry(&mut self, abs: &Path, rel: &str, dirs: &mut Vec<(PathBuf, String)>) -> Result<Step> {
        if let Some(p) = self.progress {
            Progress::add(&p.entries, 1);
        }
        match self.decider.classify(abs, rel) {
            Class::NoMetadata { error, decision } => match decision {
                Decision::OutOfScope(reason) => self.out_of_scope(reason),
                Decision::InScope => self.error(rel, format!("cannot read metadata: {error}")),
            },
            Class::Pruned { pattern } => {
                self.preview.excluded_trees += 1;
                self.out_of_scope(pruned_reason(&pattern));
            }
            Class::OutsideIncludes => {
                self.preview.trees_outside_includes += 1;
                self.out_of_scope(OUTSIDE_INCLUDES.into());
            }
            Class::OtherFilesystem => self.preview.other_filesystems.push(rel.to_string()),
            Class::Directory { decision, .. } => {
                dirs.push((abs.to_path_buf(), rel.to_string()));
                if decision == Decision::InScope {
                    self.preview.directories += 1;
                    self.sample(Kind::Directory, rel, None);
                }
            }
            Class::Leaf {
                decision: Decision::OutOfScope(reason),
                ..
            } => self.out_of_scope(reason),
            Class::Leaf { kind, md, .. } => {
                let size = (kind == Kind::File).then_some(md.len());
                match kind {
                    Kind::File => {
                        self.preview.files += 1;
                        self.preview.bytes += md.len();
                        if let Some(p) = self.progress {
                            Progress::add(&p.files, 1);
                            Progress::add(&p.bytes, md.len());
                        }
                    }
                    Kind::Symlink => self.preview.symlinks += 1,
                    _ => self.preview.special += 1,
                }
                self.sample(kind, rel, size);
            }
        }
        Ok(Step::Continue)
    }

    fn unlistable(&mut self, rel: &str, error: std::io::Error) -> Result<()> {
        self.error(rel, format!("cannot list: {error}"));
        Ok(())
    }
}

/// `dfcollect files --dry-run` and the TUI's preview: the preflight with all
/// its refusals, then a walk with the run's own decisions that opens no file
/// and writes nothing.
pub fn preview(args: &FilesArgs, ctx: &RunCtx) -> Result<Preview> {
    let (_, rules) = rules(args)?;
    let plan = preflight(args)?;
    if let Some(p) = ctx.progress {
        p.set_phase(Phase::Listing);
    }
    let root_dev = std::fs::metadata(&plan.source)?.dev();
    let mut walk = PreviewWalk {
        decider: Decider {
            rules: &rules,
            basis: args.scope.time_basis,
            root_dev,
        },
        preview: Preview {
            source: plan.source.clone(),
            output: plan.output.clone(),
            target_free: common::free_bytes(&plan.ancestor),
            at_ns: host::unix_now_ns(),
            ..Default::default()
        },
        progress: ctx.progress,
    };
    let stopped = traverse(&plan.source, ctx.stop, &mut walk)?;
    if let Some(p) = ctx.progress {
        p.set_phase(Phase::Done);
    }
    let mut preview = walk.preview;
    preview.stopped = stopped.map(|(reason, _)| reason);
    Ok(preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command};
    use clap::Parser;
    use std::sync::atomic::Ordering;

    #[test]
    fn patterns_reach_below_a_directory() {
        assert!(could_match_below("docs/**", "docs"));
        assert!(could_match_below("docs/**", "docs/sub"));
        assert!(could_match_below("**/*.txt", "any/where"));
        assert!(could_match_below("d*/x", "docs"));
        assert!(could_match_below("docs/?/x", "docs/a"));
        assert!(could_match_below("*/*.txt", "a"));
        assert!(!could_match_below("docs/**", "other"));
        assert!(!could_match_below("*.txt", "sub"));
        assert!(!could_match_below("docs", "docs"));
        assert!(!could_match_below("docs/a", "docs/a"));
        assert!(!could_match_below("d*/x", "do/cs"));
        assert!(!could_match_below("docs/?/x", "docs/ab"));
        assert!(!could_match_below("", "docs"));
    }

    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> Self {
            let root = PathBuf::from("/dev/shm")
                .join(format!("dfcollect_files_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("src/d")).unwrap();
            std::fs::write(root.join("src/a.txt"), b"alpha").unwrap();
            std::fs::write(root.join("src/d/b.txt"), vec![0u8; 3 << 20]).unwrap();
            common::test_audit_log();
            Self(root)
        }

        fn args(&self, extra: &[&str]) -> FilesArgs {
            let src = self.0.join("src");
            let out = self.0.join("out");
            let mut argv = vec![
                "dfcollect",
                "files",
                src.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
                "-C",
                "C",
                "-E",
                "E",
                "-e",
                "x",
                "--allow-writable-source",
                "--allow-tmpfs",
            ];
            argv.extend_from_slice(extra);
            match Cli::try_parse_from(argv).unwrap().command {
                Some(Command::Files(a)) => *a,
                other => panic!("{other:?}"),
            }
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(dir: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap()
    }

    fn footprint(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("footprint.jsonl")).unwrap_or_default()
    }

    #[test]
    fn the_tui_records_its_command_line_and_the_preview() {
        let t = Tree::new("tui");
        let args = t.args(&[
            "--reference-time",
            "2027-01-15T08:00:05Z",
            "--reference-how",
            "radio clock",
        ]);
        let stop: &'static Stop = Box::leak(Box::new(Stop::new()));
        let progress = Progress::default();
        let pv = preview(&args, &RunCtx::cli(stop, Some(&progress))).unwrap();
        assert_eq!((pv.files, pv.bytes), (2, 5 + (3 << 20)));
        assert_eq!(progress.phase(), Phase::Done);
        let argv: Vec<String> = ["dfcollect", "files", "(equivalent)"]
            .map(String::from)
            .to_vec();
        let ctx = RunCtx {
            stop,
            progress: Some(&progress),
            argv: Some(argv.clone()),
            interactive: true,
            preview: Some(pv.note()),
            credential: Default::default(),
            reference_entered_ns: Some(1_800_000_000_000_000_000),
            console: std::sync::Arc::new(crate::console::QuietConsole::default()),
        };
        let progress_before = progress.bytes.load(Ordering::Relaxed);
        let out = run_with(&args, &ctx).unwrap();
        assert_eq!(out.code, 0, "{}", out.summary);
        let m = manifest(&t.0.join("out"));
        assert_eq!(m["method"]["argv"], json!(argv));
        let fp = footprint(&t.0.join("out"));
        assert!(fp.contains("started from the dfcollect TUI"), "{fp}");
        assert!(fp.contains("a preview listed the source"), "{fp}");
        // The reference time counts from when it was entered, not the start
        let r = &m["clocks"]["reference"];
        assert_eq!(r["local"], "2027-01-15T08:00:00.000000000Z", "{m}");
        assert_eq!(r["offset_seconds"], 5.0, "{m}");
        // The run counted its bytes on top of the preview's
        assert_eq!(
            progress.bytes.load(Ordering::Relaxed) - progress_before,
            5 + (3 << 20)
        );
        assert!(progress.check_bytes.load(Ordering::Relaxed) >= 5 + (3 << 20));
    }

    #[test]
    fn a_stop_by_the_examiner_is_recorded_as_such() {
        let t = Tree::new("stop");
        let args = t.args(&[]);
        let stop: &'static Stop = Box::leak(Box::new(Stop::new()));
        stop.examiner.store(true, Ordering::Relaxed);
        let out = run_with(&args, &RunCtx::cli(stop, None)).unwrap();
        assert_eq!(out.code, 8, "{}", out.summary);
        let m = manifest(&t.0.join("out"));
        assert_eq!(m["status"], "aborted", "{m}");
        assert!(m.to_string().contains("stopped by the examiner"), "{m}");
        stop.clear_examiner();
        assert!(!stop.is_set());
    }

    #[test]
    fn a_stop_ends_a_large_file_and_leaves_it_out() {
        // A reader that sets the stop after its first block
        let stop: &'static Stop = Box::leak(Box::new(Stop::new()));
        let data = vec![0u8; 3 << 20];
        let mut counting = Counting {
            inner: &data[..],
            counter: None,
            stop: Some(stop),
        };
        let mut buf = vec![0u8; 1 << 20];
        use std::io::Read;
        assert_eq!(counting.read(&mut buf).unwrap(), 1 << 20);
        stop.examiner.store(true, Ordering::Relaxed);
        let e = counting.read(&mut buf).unwrap_err();
        assert!(e.to_string().contains("stopped"));
    }
}
