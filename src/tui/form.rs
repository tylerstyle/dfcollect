//! The `dfcollect files` setup form and `dfcollect verify` directory form:
//! field focus order, placeholders, live validation (required fields, RFC 3339
//! with UTC hints, clock both-or-neither, scope file vs inline scope fields,
//! read-only source check, output directory check) and session reset.

use crate::{
    args::{TimeBasis, UnknownTimeArg},
    common::{self, RAMFS_MAGIC, TMPFS_MAGIC},
    tui::{
        autocomplete::expand_tilde,
        mounts::{suggest_output_dir, MountChoice},
    },
};
use dfcore::{host, sysfs};
use std::path::Path;

/// Every focusable item on the `dfcollect files` setup form, in focus order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilesField {
    CaseNumber,
    EvidenceNumber,
    Examiner,
    Description,
    Notes,
    SourceMount,
    SourcePath,
    OutputPath,
    ScopeFile,
    LegalBasis,
    Includes,
    Excludes,
    NotBefore,
    NotAfter,
    TimeBasis,
    UnknownTime,
    ListOutOfScope,
    ReferenceTime,
    ReferenceHow,
    Md5,
    Sha1,
    Compress,
    AllowTmpfs,
    AllowWritableSource,
    PreviewButton,
}

impl FilesField {
    pub const ALL: [FilesField; 25] = [
        FilesField::CaseNumber,
        FilesField::EvidenceNumber,
        FilesField::Examiner,
        FilesField::Description,
        FilesField::Notes,
        FilesField::SourceMount,
        FilesField::SourcePath,
        FilesField::OutputPath,
        FilesField::ScopeFile,
        FilesField::LegalBasis,
        FilesField::Includes,
        FilesField::Excludes,
        FilesField::NotBefore,
        FilesField::NotAfter,
        FilesField::TimeBasis,
        FilesField::UnknownTime,
        FilesField::ListOutOfScope,
        FilesField::ReferenceTime,
        FilesField::ReferenceHow,
        FilesField::Md5,
        FilesField::Sha1,
        FilesField::Compress,
        FilesField::AllowTmpfs,
        FilesField::AllowWritableSource,
        FilesField::PreviewButton,
    ];

    pub const INLINE_SCOPE: [FilesField; 8] = [
        FilesField::LegalBasis,
        FilesField::Includes,
        FilesField::Excludes,
        FilesField::NotBefore,
        FilesField::NotAfter,
        FilesField::TimeBasis,
        FilesField::UnknownTime,
        FilesField::ListOutOfScope,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FilesField::CaseNumber => "Case number*",
            FilesField::EvidenceNumber => "Evidence no.*",
            FilesField::Examiner => "Examiner*",
            FilesField::Description => "Description",
            FilesField::Notes => "Notes",
            FilesField::SourceMount => "Source mount",
            FilesField::SourcePath => "Source path*",
            FilesField::OutputPath => "Output dir*",
            FilesField::ScopeFile => "Scope JSON",
            FilesField::LegalBasis => "Legal basis",
            FilesField::Includes => "Include globs",
            FilesField::Excludes => "Exclude globs",
            FilesField::NotBefore => "Not before",
            FilesField::NotAfter => "Not after",
            FilesField::TimeBasis => "Time basis",
            FilesField::UnknownTime => "Unknown time",
            FilesField::ListOutOfScope => "List excluded",
            FilesField::ReferenceTime => "Ref. clock",
            FilesField::ReferenceHow => "Ref. source",
            FilesField::Md5 => "Compute MD5",
            FilesField::Sha1 => "Compute SHA-1",
            FilesField::Compress => "Deflate ZIP",
            FilesField::AllowTmpfs => "Allow tmpfs",
            FilesField::AllowWritableSource => "Writable src",
            FilesField::PreviewButton => "Preview scope",
        }
    }

    pub fn placeholder(self) -> &'static str {
        match self {
            FilesField::CaseNumber => "required, e.g. VG 12345/26",
            FilesField::EvidenceNumber => "required, e.g. share01",
            FilesField::Examiner => "required, name or badge",
            FilesField::Description => "optional",
            FilesField::Notes => "optional",
            FilesField::SourcePath => "read-only directory, e.g. /media/evidence/sdb1",
            FilesField::OutputPath => {
                "new collection dir, e.g. /media/target/sdc1/VG_12345_26/share01"
            }
            FilesField::ScopeFile => "optional ScopeSpec JSON file (replaces inline scope fields)",
            FilesField::LegalBasis => "optional order / warrant reference",
            FilesField::NotBefore => "optional RFC 3339, e.g. 2026-01-01T00:00:00+01:00",
            FilesField::NotAfter => "optional RFC 3339, e.g. 2026-07-01T00:00:00+02:00",
            FilesField::ReferenceTime => {
                "type the trusted clock's time a few seconds ahead, press Enter when the clock shows it"
            }
            FilesField::ReferenceHow => "where ref. clock came from (e.g. radio clock, phone)",
            _ => "",
        }
    }

    pub fn is_text(self) -> bool {
        matches!(
            self,
            FilesField::CaseNumber
                | FilesField::EvidenceNumber
                | FilesField::Examiner
                | FilesField::Description
                | FilesField::Notes
                | FilesField::SourcePath
                | FilesField::OutputPath
                | FilesField::ScopeFile
                | FilesField::LegalBasis
                | FilesField::NotBefore
                | FilesField::NotAfter
                | FilesField::ReferenceTime
                | FilesField::ReferenceHow
        )
    }

    pub fn is_path(self) -> bool {
        matches!(
            self,
            FilesField::SourcePath | FilesField::OutputPath | FilesField::ScopeFile
        )
    }

    pub fn is_dirs_only_path(self) -> bool {
        matches!(self, FilesField::SourcePath | FilesField::OutputPath)
    }

    pub fn is_list(self) -> bool {
        matches!(self, FilesField::Includes | FilesField::Excludes)
    }

    pub fn is_safety(self) -> bool {
        matches!(
            self,
            FilesField::AllowTmpfs | FilesField::AllowWritableSource
        )
    }
}

/// Live filesystem facts about the chosen source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceProbe {
    pub exists: bool,
    pub is_dir: bool,
    pub read_only: bool,
    pub mount_source: Option<String>,
}

/// Live filesystem facts about the chosen output collection path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputProbe {
    pub free_bytes: Option<u64>,
    pub non_empty: bool,
    pub is_tmpfs: bool,
    pub inside_source: bool,
    pub check_error: Option<String>,
}

/// State of the `dfcollect files` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesForm {
    pub case: String,
    pub evidence: String,
    pub examiner: String,
    pub description: String,
    pub notes: String,

    pub source_mounts: Vec<MountChoice>,
    pub target_mounts: Vec<MountChoice>,
    /// Selected index in `source_mounts`, or `None` when using a custom path
    pub selected_source_mount: Option<usize>,
    pub source_path: String,
    pub output_path: String,
    /// True once the examiner manually edited `output_path`
    pub output_customized: bool,

    pub scope_file: String,
    pub legal_basis: String,
    pub include: Vec<String>,
    pub include_idx: usize,
    pub exclude: Vec<String>,
    pub exclude_idx: usize,
    pub not_before: String,
    pub not_after: String,
    pub time_basis: TimeBasis,
    pub unknown_time: UnknownTimeArg,
    pub list_out_of_scope: bool,

    pub reference_time: String,
    pub reference_how: String,
    /// Local host clock (`unix_now_ns`) recorded when the examiner committed `reference_time`
    pub reference_entered_ns: Option<i128>,

    pub md5: bool,
    pub sha1: bool,
    pub compress: bool,

    pub allow_tmpfs: bool,
    pub allow_writable_source: bool,

    pub field: FilesField,
    pub cursor: usize,
    /// True when actively typing inside a text field (so `p`/`q`/`Tab` act on the text/path)
    pub editing: bool,

    pub source_probe: Option<SourceProbe>,
    pub output_probe: Option<OutputProbe>,
}

impl Default for FilesForm {
    fn default() -> Self {
        Self {
            case: String::new(),
            evidence: String::new(),
            examiner: String::new(),
            description: String::new(),
            notes: String::new(),
            source_mounts: Vec::new(),
            target_mounts: Vec::new(),
            selected_source_mount: None,
            source_path: String::new(),
            output_path: String::new(),
            output_customized: false,
            scope_file: String::new(),
            legal_basis: String::new(),
            include: Vec::new(),
            include_idx: 0,
            exclude: Vec::new(),
            exclude_idx: 0,
            not_before: String::new(),
            not_after: String::new(),
            time_basis: TimeBasis::Modified,
            unknown_time: UnknownTimeArg::Exclude,
            list_out_of_scope: false,
            reference_time: String::new(),
            reference_how: String::new(),
            reference_entered_ns: None,
            md5: false,
            sha1: false,
            compress: false,
            allow_tmpfs: false,
            allow_writable_source: false,
            field: FilesField::CaseNumber,
            cursor: 0,
            editing: false,
            source_probe: None,
            output_probe: None,
        }
    }
}

pub fn cycle<T: Copy + PartialEq>(values: &[T], current: T, forward: bool) -> T {
    let i = values.iter().position(|v| *v == current).unwrap_or(0);
    let n = values.len();
    if forward {
        values[(i + 1) % n]
    } else {
        values[(i + n - 1) % n]
    }
}

impl FilesForm {
    pub fn with_mounts(source_mounts: Vec<MountChoice>, target_mounts: Vec<MountChoice>) -> Self {
        let mut form = Self {
            source_mounts,
            target_mounts,
            ..Self::default()
        };
        if let Some(first) = form.source_mounts.first() {
            form.selected_source_mount = Some(0);
            form.source_path = first.mount_point.display().to_string();
            form.source_probe = Some(SourceProbe {
                exists: true,
                is_dir: true,
                read_only: first.read_only,
                mount_source: Some(first.source.clone()),
            });
        }
        form
    }

    /// Whether a field is active in the focus order. When a scope JSON file is
    /// given, the inline scope fields are disabled unless one of them already
    /// carries a conflicting value that the examiner needs to clear.
    pub fn applies(&self, field: FilesField) -> bool {
        if field == FilesField::SourceMount && self.source_mounts.is_empty() {
            return false;
        }
        if FilesField::INLINE_SCOPE.contains(&field)
            && !self.scope_file.trim().is_empty()
            && !self.has_inline_scope_values()
        {
            return false;
        }
        true
    }

    pub fn focus_order(&self) -> Vec<FilesField> {
        FilesField::ALL
            .into_iter()
            .filter(|f| self.applies(*f))
            .collect()
    }

    pub fn focus_next(&mut self, forward: bool) {
        let order = self.focus_order();
        if order.is_empty() {
            return;
        }
        let next = cycle(&order, self.field, forward);
        self.set_focus(next);
    }

    pub fn set_focus(&mut self, field: FilesField) {
        if self.field == FilesField::ReferenceTime
            && field != FilesField::ReferenceTime
            && self.editing
            && self.reference_entered_ns.is_none()
        {
            self.commit_reference_time();
        }
        self.field = field;
        self.editing = false;
        self.cursor = self.text(field).map_or(0, String::len);
    }

    /// Record the host's local clock (`unix_now_ns`) for `reference_time` when
    /// the examiner commits a valid RFC 3339 reading.
    pub fn commit_reference_time(&mut self) {
        self.commit_reference_time_at(host::unix_now_ns());
    }

    pub fn commit_reference_time_at(&mut self, now_ns: i128) {
        let rt = self.reference_time.trim();
        if !rt.is_empty() && host::parse_rfc3339(rt).is_ok() {
            self.reference_entered_ns = Some(now_ns);
        } else {
            self.reference_entered_ns = None;
        }
    }

    pub fn text(&self, field: FilesField) -> Option<&String> {
        Some(match field {
            FilesField::CaseNumber => &self.case,
            FilesField::EvidenceNumber => &self.evidence,
            FilesField::Examiner => &self.examiner,
            FilesField::Description => &self.description,
            FilesField::Notes => &self.notes,
            FilesField::SourcePath => &self.source_path,
            FilesField::OutputPath => &self.output_path,
            FilesField::ScopeFile => &self.scope_file,
            FilesField::LegalBasis => &self.legal_basis,
            FilesField::NotBefore => &self.not_before,
            FilesField::NotAfter => &self.not_after,
            FilesField::ReferenceTime => &self.reference_time,
            FilesField::ReferenceHow => &self.reference_how,
            _ => return None,
        })
    }

    pub fn text_mut(&mut self, field: FilesField) -> Option<&mut String> {
        Some(match field {
            FilesField::CaseNumber => &mut self.case,
            FilesField::EvidenceNumber => &mut self.evidence,
            FilesField::Examiner => &mut self.examiner,
            FilesField::Description => &mut self.description,
            FilesField::Notes => &mut self.notes,
            FilesField::SourcePath => &mut self.source_path,
            FilesField::OutputPath => &mut self.output_path,
            FilesField::ScopeFile => &mut self.scope_file,
            FilesField::LegalBasis => &mut self.legal_basis,
            FilesField::NotBefore => &mut self.not_before,
            FilesField::NotAfter => &mut self.not_after,
            FilesField::ReferenceTime => &mut self.reference_time,
            FilesField::ReferenceHow => &mut self.reference_how,
            _ => return None,
        })
    }

    /// Update the auto-suggested output directory when `case` or `evidence`
    /// changes and the examiner has not manually overridden `output_path`.
    pub fn update_output_suggestion(&mut self) {
        if self.output_customized {
            return;
        }
        let Some(target) = self.target_mounts.first() else {
            return;
        };
        if let Some(suggested) = suggest_output_dir(&target.mount_point, &self.case, &self.evidence)
        {
            self.output_path = suggested.display().to_string();
        } else {
            self.output_path.clear();
        }
    }

    /// Sync `selected_source_mount` when `source_path` is edited manually.
    pub fn sync_selected_mount(&mut self) {
        let trimmed = self.source_path.trim().trim_end_matches('/');
        self.selected_source_mount = self
            .source_mounts
            .iter()
            .position(|m| m.mount_point.to_string_lossy().trim_end_matches('/') == trimmed);
    }

    /// Cycle through discovered read-only mounts in `source_mounts`.
    pub fn cycle_source_mount(&mut self, forward: bool) {
        if self.source_mounts.is_empty() {
            return;
        }
        let n = self.source_mounts.len();
        let next = match self.selected_source_mount {
            Some(i) if forward => (i + 1) % n,
            Some(i) => (i + n - 1) % n,
            None => 0,
        };
        self.selected_source_mount = Some(next);
        let choice = &self.source_mounts[next];
        self.source_path = choice.mount_point.display().to_string();
        self.source_probe = Some(SourceProbe {
            exists: true,
            is_dir: true,
            read_only: choice.read_only,
            mount_source: Some(choice.source.clone()),
        });
    }

    /// Toggle or cycle a non-safety option field.
    pub fn toggle_regular(&mut self, field: FilesField, forward: bool) {
        match field {
            FilesField::SourceMount => self.cycle_source_mount(forward),
            FilesField::TimeBasis => {
                self.time_basis = cycle(
                    &[
                        TimeBasis::Modified,
                        TimeBasis::Accessed,
                        TimeBasis::Changed,
                        TimeBasis::Birth,
                    ],
                    self.time_basis,
                    forward,
                );
            }
            FilesField::UnknownTime => {
                self.unknown_time = cycle(
                    &[UnknownTimeArg::Exclude, UnknownTimeArg::Include],
                    self.unknown_time,
                    forward,
                );
            }
            FilesField::ListOutOfScope => self.list_out_of_scope = !self.list_out_of_scope,
            FilesField::Md5 => self.md5 = !self.md5,
            FilesField::Sha1 => self.sha1 = !self.sha1,
            FilesField::Compress => self.compress = !self.compress,
            _ => {}
        }
    }

    pub fn value_text(&self, field: FilesField) -> String {
        let check = |on: bool| if on { "[x] on" } else { "[ ] off" }.to_string();
        match field {
            FilesField::SourceMount => match self
                .selected_source_mount
                .and_then(|i| self.source_mounts.get(i))
            {
                Some(m) => format!(
                    "{} ({}, read-only)",
                    m.mount_point.display(),
                    if m.source.is_empty() {
                        "mount"
                    } else {
                        &m.source
                    }
                ),
                None if self.source_mounts.is_empty() => "no read-only mounts found".into(),
                None => format!(
                    "custom path ({} read-only mount(s) available: ←/→)",
                    self.source_mounts.len()
                ),
            },
            FilesField::Includes => {
                format_pattern_list(&self.include, self.include_idx, "everything")
            }
            FilesField::Excludes => format_pattern_list(&self.exclude, self.exclude_idx, "none"),
            FilesField::TimeBasis => match self.time_basis {
                TimeBasis::Modified => "modified (mtime)".into(),
                TimeBasis::Accessed => "accessed (atime)".into(),
                TimeBasis::Changed => "changed (ctime)".into(),
                TimeBasis::Birth => "birth (btime)".into(),
            },
            FilesField::UnknownTime => match self.unknown_time {
                UnknownTimeArg::Exclude => "exclude (safe default)".into(),
                UnknownTimeArg::Include => "include".into(),
            },
            FilesField::ListOutOfScope => {
                if self.list_out_of_scope {
                    "[x] list out-of-scope names in items.jsonl".into()
                } else {
                    "[ ] count by reason only (no out-of-scope names)".into()
                }
            }
            FilesField::Md5 => check(self.md5),
            FilesField::Sha1 => check(self.sha1),
            FilesField::Compress => {
                if self.compress {
                    "[x] deflate".into()
                } else {
                    "[ ] store uncompressed".into()
                }
            }
            FilesField::AllowTmpfs => {
                if self.allow_tmpfs {
                    "[x] ON (RAM / tmpfs destination allowed)".into()
                } else {
                    "[ ] off".into()
                }
            }
            FilesField::AllowWritableSource => {
                if self.allow_writable_source {
                    "[x] ON (read-write source mount allowed)".into()
                } else {
                    "[ ] off".into()
                }
            }
            FilesField::PreviewButton => "[ Preview scope (F2 / p) ]".into(),
            _ => String::new(),
        }
    }

    pub fn has_inline_scope_values(&self) -> bool {
        !self.legal_basis.trim().is_empty()
            || !self.include.is_empty()
            || !self.exclude.is_empty()
            || !self.not_before.trim().is_empty()
            || !self.not_after.trim().is_empty()
            || self.time_basis != TimeBasis::Modified
            || self.unknown_time != UnknownTimeArg::Exclude
            || self.list_out_of_scope
    }

    /// Refresh `source_probe` and `output_probe` from the host filesystem.
    pub fn refresh_probes(&mut self) {
        let src_trimmed = self.source_path.trim();
        self.source_probe = if src_trimmed.is_empty() {
            None
        } else {
            let src = expand_tilde(Path::new(src_trimmed));
            match std::fs::metadata(&src) {
                Ok(md) => {
                    let is_dir = md.is_dir();
                    let read_only = common::fs_info(&src).map(|i| i.read_only).unwrap_or(false);
                    Some(SourceProbe {
                        exists: true,
                        is_dir,
                        read_only,
                        mount_source: None,
                    })
                }
                Err(_) => Some(SourceProbe {
                    exists: false,
                    is_dir: false,
                    read_only: false,
                    mount_source: None,
                }),
            }
        };

        let out_trimmed = self.output_path.trim();
        self.output_probe = if out_trimmed.is_empty() {
            None
        } else {
            let out = expand_tilde(Path::new(out_trimmed));
            let abs_out = std::path::absolute(&out).unwrap_or_else(|_| out.clone());
            let non_empty = abs_out.exists()
                && std::fs::read_dir(&abs_out)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false);
            let ancestor = sysfs::existing_ancestor(&abs_out);
            let canon_anc = std::fs::canonicalize(&ancestor).unwrap_or(ancestor);
            let fs = common::fs_info(&canon_anc).ok();
            let is_tmpfs = fs
                .as_ref()
                .is_some_and(|i| matches!(i.magic, TMPFS_MAGIC | RAMFS_MAGIC));
            let free_bytes = common::free_bytes(&canon_anc);
            let inside_source = if !src_trimmed.is_empty() {
                let src = expand_tilde(Path::new(src_trimmed));
                std::fs::canonicalize(&src)
                    .ok()
                    .is_some_and(|csrc| canon_anc.starts_with(&csrc))
            } else {
                false
            };
            let check_error = common::check_output(&abs_out, self.allow_tmpfs)
                .err()
                .map(|e| format!("{e:#}"));
            Some(OutputProbe {
                free_bytes,
                non_empty,
                is_tmpfs,
                inside_source,
                check_error,
            })
        };
    }

    /// Parsed UTC hint for an RFC 3339 timestamp field (`NotBefore`, `NotAfter`,
    /// `ReferenceTime`), when valid.
    pub fn utc_hint(&self, field: FilesField) -> Option<String> {
        let raw = self.text(field)?.trim();
        if raw.is_empty() {
            return None;
        }
        let ns = host::parse_rfc3339(raw).ok()?;
        Some(format!("UTC: {}", host::rfc3339_utc_ns(ns)))
    }

    /// Formatted stamp + offset line (`"entered at <UTC> (offset +5.0 s)"`) when
    /// `reference_time` is valid and has been committed.
    pub fn reference_stamp_hint(&self) -> Option<String> {
        let rt = self.reference_time.trim();
        if rt.is_empty() {
            return None;
        }
        let entered_ns = self.reference_entered_ns?;
        let r = dfcore::manifest::ReferenceTime::new(rt, "_", entered_ns).ok()?;
        Some(format!(
            "entered at {} (offset {:+.1} s)",
            r.local, r.offset_seconds
        ))
    }

    /// Validate a single field; returns `Some(error_message)` when invalid.
    pub fn validate_field(&self, field: FilesField) -> Option<String> {
        match field {
            FilesField::CaseNumber if self.case.trim().is_empty() => {
                Some("case number is required".into())
            }
            FilesField::EvidenceNumber if self.evidence.trim().is_empty() => {
                Some("evidence number is required".into())
            }
            FilesField::Examiner if self.examiner.trim().is_empty() => {
                Some("examiner name or ID is required".into())
            }
            FilesField::SourcePath => {
                if self.source_path.trim().is_empty() {
                    return Some("source directory is required".into());
                }
                if let Some(p) = &self.source_probe {
                    if !p.exists {
                        return Some("source directory does not exist".into());
                    }
                    if !p.is_dir {
                        return Some("source path is not a directory".into());
                    }
                    if !p.read_only && !self.allow_writable_source {
                        return Some(
                            "read-write mount; mount it read-only or enable 'allow writable source'"
                                .into(),
                        );
                    }
                }
                None
            }
            FilesField::OutputPath => {
                if self.output_path.trim().is_empty() {
                    return Some("output collection directory is required".into());
                }
                if let Some(p) = &self.output_probe {
                    if p.non_empty {
                        return Some(
                            "output directory is not empty; choose a new collection directory"
                                .into(),
                        );
                    }
                    if p.inside_source {
                        return Some("output directory is inside the source directory".into());
                    }
                    if p.is_tmpfs && !self.allow_tmpfs {
                        return Some(
                            "output is in RAM (tmpfs); choose a target drive or enable 'allow tmpfs'"
                                .into(),
                        );
                    }
                    if let Some(err) = &p.check_error {
                        return Some(err.clone());
                    }
                }
                None
            }
            FilesField::ScopeFile => {
                let sf = self.scope_file.trim();
                if !sf.is_empty() && self.has_inline_scope_values() {
                    return Some(
                        "--scope file cannot be combined with inline scope fields; clear one or the other"
                            .into(),
                    );
                }
                None
            }
            FilesField::Includes => {
                if self.include.iter().any(|p| p.trim().is_empty()) {
                    return Some("include pattern cannot be empty".into());
                }
                None
            }
            FilesField::Excludes => {
                if self.exclude.iter().any(|p| p.trim().is_empty()) {
                    return Some("exclude pattern cannot be empty".into());
                }
                None
            }
            FilesField::NotBefore => {
                let nb = self.not_before.trim();
                if nb.is_empty() {
                    return None;
                }
                let nb_ns = match host::parse_rfc3339(nb) {
                    Ok(ns) => ns,
                    Err(e) => return Some(format!("invalid RFC 3339 timestamp: {e:#}")),
                };
                let na = self.not_after.trim();
                if !na.is_empty() {
                    if let Ok(na_ns) = host::parse_rfc3339(na) {
                        if nb_ns >= na_ns {
                            return Some("not-before must be earlier than not-after".into());
                        }
                    }
                }
                None
            }
            FilesField::NotAfter => {
                let na = self.not_after.trim();
                if na.is_empty() {
                    return None;
                }
                let na_ns = match host::parse_rfc3339(na) {
                    Ok(ns) => ns,
                    Err(e) => return Some(format!("invalid RFC 3339 timestamp: {e:#}")),
                };
                let nb = self.not_before.trim();
                if !nb.is_empty() {
                    if let Ok(nb_ns) = host::parse_rfc3339(nb) {
                        if nb_ns >= na_ns {
                            return Some("not-after must be later than not-before".into());
                        }
                    }
                }
                None
            }
            FilesField::ReferenceTime => {
                let rt = self.reference_time.trim();
                let rh = self.reference_how.trim();
                if rt.is_empty() && !rh.is_empty() {
                    return Some(
                        "reference time is required when reference source is given".into(),
                    );
                }
                if !rt.is_empty() {
                    if let Err(e) = host::parse_rfc3339(rt) {
                        return Some(format!("invalid RFC 3339 reference time: {e:#}"));
                    }
                    if self.reference_entered_ns.is_none() {
                        return Some(
                            "press Enter on it when the trusted clock shows that time".into(),
                        );
                    }
                }
                None
            }
            FilesField::ReferenceHow => {
                let rt = self.reference_time.trim();
                let rh = self.reference_how.trim();
                if !rt.is_empty() && rh.is_empty() {
                    return Some(
                        "reference source (--reference-how) is required when reference time is given"
                            .into(),
                    );
                }
                None
            }
            _ => None,
        }
    }

    /// All current validation errors in field order.
    pub fn validate_all(&self) -> Vec<(FilesField, String)> {
        FilesField::ALL
            .into_iter()
            .filter_map(|f| self.validate_field(f).map(|msg| (f, msg)))
            .collect()
    }

    /// Keep case, examiner, source, scope and options for the next acquisition
    /// in this session; clear per-evidence fields (evidence, description, notes,
    /// reference clock) and safety overrides.
    pub fn reset_for_next_acquisition(&mut self) {
        self.evidence.clear();
        self.description.clear();
        self.notes.clear();
        self.reference_time.clear();
        self.reference_how.clear();
        self.reference_entered_ns = None;
        self.output_customized = false;
        self.output_path.clear();
        self.allow_tmpfs = false;
        self.allow_writable_source = false;
        self.output_probe = None;
        self.set_focus(FilesField::EvidenceNumber);
    }
}

fn format_pattern_list(items: &[String], idx: usize, empty_label: &str) -> String {
    if items.is_empty() {
        return format!("({empty_label}; 'a' to add)");
    }
    let clamped = idx.min(items.len() - 1);
    let parts: Vec<String> = items
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i == clamped {
                format!("[{s}]")
            } else {
                s.clone()
            }
        })
        .collect();
    format!(
        "{} ({}/{}; a add, d del, Enter edit, ←/→ select)",
        parts.join(", "),
        clamped + 1,
        items.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn valid_form() -> FilesForm {
        let mut f = FilesForm::with_mounts(
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
        f.case = "VG 12345/26".into();
        f.evidence = "share01".into();
        f.examiner = "KHK Muster".into();
        f.update_output_suggestion();
        f.output_probe = Some(OutputProbe {
            free_bytes: Some(500 << 30),
            non_empty: false,
            is_tmpfs: false,
            inside_source: false,
            check_error: None,
        });
        f
    }

    #[test]
    fn validates_required_fields_and_sanitised_output_default() {
        let f = valid_form();
        assert_eq!(f.output_path, "/media/target/sdc1/VG_12345_26/share01");
        assert!(f.validate_all().is_empty(), "{:?}", f.validate_all());

        let mut empty = FilesForm::default();
        let errs = empty.validate_all();
        let fields: Vec<FilesField> = errs.iter().map(|(k, _)| *k).collect();
        assert!(fields.contains(&FilesField::CaseNumber));
        assert!(fields.contains(&FilesField::EvidenceNumber));
        assert!(fields.contains(&FilesField::Examiner));
        assert!(fields.contains(&FilesField::SourcePath));
        assert!(fields.contains(&FilesField::OutputPath));

        empty.case = "C".into();
        assert!(empty.validate_field(FilesField::CaseNumber).is_none());
    }

    #[test]
    fn validates_rfc3339_window_and_utc_hint() {
        let mut f = valid_form();
        f.not_before = "not-a-timestamp".into();
        assert!(f.validate_field(FilesField::NotBefore).is_some());
        assert!(f.utc_hint(FilesField::NotBefore).is_none());

        f.not_before = "2026-03-01T12:00:00+02:00".into();
        assert!(f.validate_field(FilesField::NotBefore).is_none());
        assert_eq!(
            f.utc_hint(FilesField::NotBefore).as_deref(),
            Some("UTC: 2026-03-01T10:00:00.000000000Z")
        );

        // not-after earlier than not-before
        f.not_after = "2026-01-01T00:00:00Z".into();
        assert!(f
            .validate_field(FilesField::NotBefore)
            .unwrap()
            .contains("earlier"));
        assert!(f
            .validate_field(FilesField::NotAfter)
            .unwrap()
            .contains("later"));

        f.not_after = "2026-07-01T00:00:00Z".into();
        assert!(f.validate_all().is_empty());
    }

    #[test]
    fn validates_clock_both_or_neither_and_requires_commit_stamp() {
        let mut f = valid_form();
        f.reference_time = "2027-01-15T08:00:05Z".into();
        // Valid RFC 3339 but not yet committed -> error asking examiner to press Enter
        assert_eq!(
            f.validate_field(FilesField::ReferenceTime).as_deref(),
            Some("press Enter on it when the trusted clock shows that time")
        );
        assert!(f.validate_field(FilesField::ReferenceHow).is_some());
        assert!(f.reference_stamp_hint().is_none());

        // Committing sets the stamp and satisfies ReferenceTime validation
        f.commit_reference_time_at(1_800_000_000_000_000_000);
        assert_eq!(f.reference_entered_ns, Some(1_800_000_000_000_000_000));
        assert!(f.validate_field(FilesField::ReferenceTime).is_none());
        assert_eq!(
            f.reference_stamp_hint().as_deref(),
            Some("entered at 2027-01-15T08:00:00.000000000Z (offset +5.0 s)")
        );

        f.reference_time.clear();
        f.reference_entered_ns = None;
        f.reference_how = "radio clock".into();
        assert!(f.validate_field(FilesField::ReferenceTime).is_some());
        assert!(f.validate_field(FilesField::ReferenceHow).is_none());

        // Leaving ReferenceTime after an edit also commits the stamp
        f.set_focus(FilesField::ReferenceTime);
        f.editing = true;
        f.reference_time = "2027-01-15T08:00:05Z".into();
        f.focus_next(true);
        assert!(f.reference_entered_ns.is_some());
        assert!(f.validate_all().is_empty());
    }

    #[test]
    fn validates_scope_file_exclusivity() {
        let mut f = valid_form();
        f.scope_file = "/media/target/sdc1/scope.json".into();
        assert!(f.validate_all().is_empty());
        // Inline scope fields are skipped in focus order when empty
        assert!(!f.focus_order().contains(&FilesField::Includes));

        // Setting an inline scope field alongside scope_file is an error
        f.include.push("docs/**".into());
        assert!(f
            .validate_field(FilesField::ScopeFile)
            .unwrap()
            .contains("cannot be combined"));
        assert!(f.focus_order().contains(&FilesField::Includes));
    }

    #[test]
    fn validates_writable_source_and_tmpfs_output() {
        let mut f = valid_form();
        f.source_probe = Some(SourceProbe {
            exists: true,
            is_dir: true,
            read_only: false,
            mount_source: None,
        });
        assert!(f
            .validate_field(FilesField::SourcePath)
            .unwrap()
            .contains("read-write mount"));
        f.allow_writable_source = true;
        assert!(f.validate_field(FilesField::SourcePath).is_none());

        f.output_probe = Some(OutputProbe {
            free_bytes: Some(1 << 30),
            non_empty: false,
            is_tmpfs: true,
            inside_source: false,
            check_error: None,
        });
        assert!(f
            .validate_field(FilesField::OutputPath)
            .unwrap()
            .contains("RAM (tmpfs)"));
        f.allow_tmpfs = true;
        assert!(f.validate_field(FilesField::OutputPath).is_none());
    }

    #[test]
    fn reset_for_next_acquisition_keeps_case_and_clears_evidence_description_notes_clock() {
        let mut f = valid_form();
        f.description = "share01 docs".into();
        f.notes = "sealed bag #4".into();
        f.reference_time = "2027-01-15T08:00:05Z".into();
        f.reference_how = "DCF77".into();
        f.reference_entered_ns = Some(1_800_000_000_000_000_000);
        f.include = vec!["docs/**".into()];
        f.md5 = true;
        f.allow_tmpfs = true;
        f.allow_writable_source = true;

        f.reset_for_next_acquisition();

        assert_eq!(f.case, "VG 12345/26");
        assert_eq!(f.examiner, "KHK Muster");
        assert_eq!(f.source_path, "/media/evidence/sdb1");
        assert_eq!(f.include, vec!["docs/**".to_string()]);
        assert!(f.md5);

        assert!(f.evidence.is_empty());
        assert!(f.description.is_empty());
        assert!(f.notes.is_empty());
        assert!(f.reference_time.is_empty());
        assert!(f.reference_how.is_empty());
        assert!(f.reference_entered_ns.is_none());
        assert!(f.output_path.is_empty());
        assert!(!f.allow_tmpfs);
        assert!(!f.allow_writable_source);
        assert_eq!(f.field, FilesField::EvidenceNumber);
    }
}
