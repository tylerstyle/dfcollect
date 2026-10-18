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
    /// Export shared session fields (case, examiner, clock, scope, hash/compress)
    /// so switching modes on the Home screen keeps them.
    pub fn export_shared(&self) -> SharedFormState {
        SharedFormState {
            case: self.case.clone(),
            examiner: self.examiner.clone(),
            clock: ClockFields {
                reference_time: self.reference_time.clone(),
                reference_how: self.reference_how.clone(),
                reference_entered_ns: self.reference_entered_ns,
            },
            scope: ScopeFields {
                legal_basis: self.legal_basis.clone(),
                include: self.include.clone(),
                include_idx: self.include_idx,
                exclude: self.exclude.clone(),
                exclude_idx: self.exclude_idx,
                not_before: self.not_before.clone(),
                not_after: self.not_after.clone(),
                time_basis: self.time_basis,
                list_out_of_scope: self.list_out_of_scope,
                scope_file: self.scope_file.clone(),
            },
            md5: self.md5,
            sha1: self.sha1,
            compress: self.compress,
        }
    }

    /// Import shared session fields from another mode's form.
    pub fn import_shared(&mut self, shared: &SharedFormState) {
        if !shared.case.is_empty() {
            self.case = shared.case.clone();
        }
        if !shared.examiner.is_empty() {
            self.examiner = shared.examiner.clone();
        }
        if !shared.clock.reference_time.is_empty() || !shared.clock.reference_how.is_empty() {
            self.reference_time = shared.clock.reference_time.clone();
            self.reference_how = shared.clock.reference_how.clone();
            self.reference_entered_ns = shared.clock.reference_entered_ns;
        }
        if !shared.scope.legal_basis.is_empty() {
            self.legal_basis = shared.scope.legal_basis.clone();
        }
        if !shared.scope.include.is_empty()
            || !shared.scope.exclude.is_empty()
            || !shared.scope.not_before.is_empty()
            || !shared.scope.not_after.is_empty()
            || !shared.scope.scope_file.is_empty()
        {
            self.include = shared.scope.include.clone();
            self.include_idx = shared.scope.include_idx;
            self.exclude = shared.scope.exclude.clone();
            self.exclude_idx = shared.scope.exclude_idx;
            self.not_before = shared.scope.not_before.clone();
            self.not_after = shared.scope.not_after.clone();
            self.list_out_of_scope = shared.scope.list_out_of_scope;
            self.scope_file = shared.scope.scope_file.clone();
        }
        self.md5 = shared.md5;
        self.sha1 = shared.sha1;
        self.compress = shared.compress;
        self.update_output_suggestion();
    }
}

pub fn format_pattern_list(items: &[String], idx: usize, empty_label: &str) -> String {
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

// ==================================================================
// Declarative FieldSpec & Shared Field Groups
// ==================================================================

/// Kind of a form field for declarative rendering, focus, and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Path { dirs_only: bool },
    Enum,
    Bool { safety: bool },
    List { paths: bool },
    Time,
    Action,
}

impl FieldKind {
    pub fn is_text(self) -> bool {
        matches!(self, Self::Text | Self::Path { .. } | Self::Time)
    }

    pub fn is_path(self) -> bool {
        matches!(self, Self::Path { .. })
    }

    pub fn is_dirs_only_path(self) -> bool {
        matches!(self, Self::Path { dirs_only: true })
    }

    pub fn is_list(self) -> bool {
        matches!(self, Self::List { .. })
    }

    pub fn is_safety(self) -> bool {
        matches!(self, Self::Bool { safety: true })
    }
}

/// Declarative specification of a single form field.
#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub section: Option<&'static str>,
    pub label: &'static str,
    pub flag: &'static str,
    pub placeholder: &'static str,
    pub kind: FieldKind,
    pub required: bool,
}

/// Shared case metadata fields across all acquisition modes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseFields {
    pub case: String,
    pub evidence: String,
    pub examiner: String,
    pub description: String,
    pub notes: String,
}

impl CaseFields {
    pub fn validate_case(&self) -> Option<String> {
        self.case
            .trim()
            .is_empty()
            .then(|| "case number (-C) is required".into())
    }

    pub fn validate_evidence(&self) -> Option<String> {
        self.evidence
            .trim()
            .is_empty()
            .then(|| "evidence number (-E) is required".into())
    }

    pub fn validate_examiner(&self) -> Option<String> {
        self.examiner
            .trim()
            .is_empty()
            .then(|| "examiner (-e) is required".into())
    }

    pub fn reset_per_run(&mut self) {
        self.evidence.clear();
        self.description.clear();
        self.notes.clear();
    }
}

/// Shared output collection directory, hash, compression, and `--allow-tmpfs` fields.
#[derive(Debug, Clone, Default)]
pub struct OutputFields {
    pub output_path: String,
    pub output_customized: bool,
    pub allow_tmpfs: bool,
    pub md5: bool,
    pub sha1: bool,
    pub compress: bool,
    pub target_mounts: Vec<MountChoice>,
    pub output_probe: Option<OutputProbe>,
}

impl OutputFields {
    pub fn with_targets(target_mounts: Vec<MountChoice>) -> Self {
        Self {
            target_mounts,
            ..Self::default()
        }
    }

    pub fn update_suggestion(&mut self, case: &str, evidence: &str) {
        if self.output_customized {
            return;
        }
        if let Some(target) = self.target_mounts.first() {
            if let Some(suggested) = suggest_output_dir(&target.mount_point, case, evidence) {
                self.output_path = suggested.display().to_string();
            }
        }
    }

    pub fn refresh_probe(&mut self, source_dir: Option<&Path>) {
        if self.output_path.trim().is_empty() {
            self.output_probe = None;
        } else {
            let out_p = expand_tilde(Path::new(self.output_path.trim()));
            self.output_probe = Some(probe_output(&out_p, source_dir, self.allow_tmpfs));
        }
    }

    pub fn validate_output(&self) -> Option<String> {
        let s = self.output_path.trim();
        if s.is_empty() {
            return Some("output collection directory (-o) is required".into());
        }
        if let Some(p) = &self.output_probe {
            if p.inside_source {
                return Some("output directory must not be inside the source".into());
            }
            if p.non_empty {
                return Some("output directory already exists and is not empty".into());
            }
            if p.is_tmpfs && !self.allow_tmpfs {
                return Some(
                    "output is in RAM (tmpfs); pick a disk under /media/target or enable --allow-tmpfs"
                        .into(),
                );
            }
            if let Some(err) = &p.check_error {
                return Some(err.clone());
            }
        }
        None
    }

    pub fn reset_per_run(&mut self) {
        self.output_customized = false;
        self.output_path.clear();
        self.allow_tmpfs = false;
        self.output_probe = None;
    }
}

fn probe_output(out_p: &Path, source_dir: Option<&Path>, allow_tmpfs: bool) -> OutputProbe {
    let abs_out = std::path::absolute(out_p).unwrap_or_else(|_| out_p.to_path_buf());
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
    let inside_source = source_dir
        .and_then(|src| std::fs::canonicalize(src).ok())
        .is_some_and(|csrc| canon_anc.starts_with(&csrc));
    let check_error = common::check_output(&abs_out, allow_tmpfs)
        .err()
        .map(|e| format!("{e:#}"));
    OutputProbe {
        free_bytes,
        non_empty,
        is_tmpfs,
        inside_source,
        check_error,
    }
}

/// Shared reference clock fields (`--reference-time`, `--reference-how`, and commit timestamp).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClockFields {
    pub reference_time: String,
    pub reference_how: String,
    pub reference_entered_ns: Option<i128>,
}

impl ClockFields {
    pub fn commit_at(&mut self, local_ns: i128) {
        let rt = self.reference_time.trim();
        if !rt.is_empty() && host::parse_rfc3339(rt).is_ok() {
            self.reference_entered_ns = Some(local_ns);
        } else {
            self.reference_entered_ns = None;
        }
    }

    pub fn commit_now(&mut self) {
        self.commit_at(host::unix_now_ns());
    }

    pub fn stamp_hint(&self) -> Option<String> {
        let entered = self.reference_entered_ns?;
        let ref_ns = host::parse_rfc3339(self.reference_time.trim()).ok()?;
        let offset_s = (ref_ns - entered) as f64 / 1_000_000_000.0;
        Some(format!(
            "entered at {} (offset {:+.1} s)",
            host::rfc3339_utc_ns(entered),
            offset_s
        ))
    }

    pub fn utc_hint(&self) -> Option<String> {
        let trimmed = self.reference_time.trim();
        if trimmed.is_empty() {
            return None;
        }
        let ns = host::parse_rfc3339(trimmed).ok()?;
        Some(format!("UTC: {}", host::rfc3339_utc_ns(ns)))
    }

    pub fn validate_time(&self) -> Option<String> {
        let rt = self.reference_time.trim();
        let rh = self.reference_how.trim();
        if rt.is_empty() && !rh.is_empty() {
            return Some("reference time is required when reference source is given".into());
        }
        if !rt.is_empty() {
            if let Err(e) = host::parse_rfc3339(rt) {
                return Some(format!("invalid RFC 3339 reference time: {e:#}"));
            }
            if self.reference_entered_ns.is_none() {
                return Some("press Enter on it when the trusted clock shows that time".into());
            }
        }
        None
    }

    pub fn validate_how(&self) -> Option<String> {
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

    pub fn reset_per_run(&mut self) {
        self.reference_time.clear();
        self.reference_how.clear();
        self.reference_entered_ns = None;
    }
}

/// Shared warrant scope fields (`--scope`, `--legal-basis`, `--include`, `--exclude`,
/// `--not-before`, `--not-after`, `--time-basis`, `--list-out-of-scope`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeFields {
    pub legal_basis: String,
    pub include: Vec<String>,
    pub include_idx: usize,
    pub exclude: Vec<String>,
    pub exclude_idx: usize,
    pub not_before: String,
    pub not_after: String,
    pub time_basis: TimeBasis,
    pub list_out_of_scope: bool,
    pub scope_file: String,
}

impl Default for ScopeFields {
    fn default() -> Self {
        Self {
            legal_basis: String::new(),
            include: Vec::new(),
            include_idx: 0,
            exclude: Vec::new(),
            exclude_idx: 0,
            not_before: String::new(),
            not_after: String::new(),
            time_basis: TimeBasis::Modified,
            list_out_of_scope: false,
            scope_file: String::new(),
        }
    }
}

impl ScopeFields {
    pub fn has_inline_scope(&self, check_time_basis: bool) -> bool {
        !self.legal_basis.trim().is_empty()
            || !self.include.is_empty()
            || !self.exclude.is_empty()
            || !self.not_before.trim().is_empty()
            || !self.not_after.trim().is_empty()
            || (check_time_basis && self.time_basis != TimeBasis::Modified)
    }

    pub fn utc_hint(&self, is_not_before: bool) -> Option<String> {
        let raw = if is_not_before {
            self.not_before.trim()
        } else {
            self.not_after.trim()
        };
        if raw.is_empty() {
            return None;
        }
        let ns = host::parse_rfc3339(raw).ok()?;
        Some(format!("UTC: {}", host::rfc3339_utc_ns(ns)))
    }

    pub fn validate_scope_file(&self, check_time_basis: bool) -> Option<String> {
        let sf = self.scope_file.trim();
        if sf.is_empty() {
            return None;
        }
        if self.has_inline_scope(check_time_basis) {
            return Some(
                "--scope cannot be combined with inline scope fields (legal basis, include/exclude, time window)"
                    .into(),
            );
        }
        None
    }

    pub fn validate_not_before(&self) -> Option<String> {
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

    pub fn validate_not_after(&self) -> Option<String> {
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
}

/// Session-level fields kept across mode switches (`case`, `examiner`, `clock`, `scope`, hashes/compression).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedFormState {
    pub case: String,
    pub examiner: String,
    pub clock: ClockFields,
    pub scope: ScopeFields,
    pub md5: bool,
    pub sha1: bool,
    pub compress: bool,
}

// ==================================================================
// Mode 1: IngestForm (`dfcollect ingest`)
// ==================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestField {
    CaseNumber,
    EvidenceNumber,
    Examiner,
    Description,
    Notes,
    Package,
    Provider,
    ReceivedAt,
    Channel,
    Reference,
    Hashes,
    AllowUnlisted,
    LegalBasis,
    OutputPath,
    ReferenceTime,
    ReferenceHow,
    Md5,
    Sha1,
    Compress,
    AllowTmpfs,
    PreviewButton,
}

impl IngestField {
    pub const ALL: [IngestField; 21] = [
        Self::CaseNumber,
        Self::EvidenceNumber,
        Self::Examiner,
        Self::Description,
        Self::Notes,
        Self::Package,
        Self::Provider,
        Self::ReceivedAt,
        Self::Channel,
        Self::Reference,
        Self::Hashes,
        Self::AllowUnlisted,
        Self::LegalBasis,
        Self::OutputPath,
        Self::ReferenceTime,
        Self::ReferenceHow,
        Self::Md5,
        Self::Sha1,
        Self::Compress,
        Self::AllowTmpfs,
        Self::PreviewButton,
    ];

    pub fn spec(self) -> FieldSpec {
        match self {
            Self::CaseNumber => FieldSpec {
                section: Some("Case metadata (case & examiner kept on 'n')"),
                label: "Case number*",
                flag: "-C",
                placeholder: "e.g. VG 12345/26",
                kind: FieldKind::Text,
                required: true,
            },
            Self::EvidenceNumber => FieldSpec {
                section: None,
                label: "Evidence number*",
                flag: "-E",
                placeholder: "e.g. prod01",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Examiner => FieldSpec {
                section: None,
                label: "Examiner*",
                flag: "-e",
                placeholder: "name or ID",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Description => FieldSpec {
                section: None,
                label: "Description",
                flag: "--description",
                placeholder: "optional evidence description",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Notes => FieldSpec {
                section: None,
                label: "Notes",
                flag: "--notes",
                placeholder: "optional case notes",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Package => FieldSpec {
                section: Some("Provider delivery package & receipt"),
                label: "Package path*",
                flag: "PACKAGE",
                placeholder: "delivered directory or file (Tab / F4 to complete)",
                kind: FieldKind::Path { dirs_only: false },
                required: true,
            },
            Self::Provider => FieldSpec {
                section: None,
                label: "Provider*",
                flag: "--provider",
                placeholder: "company or service that delivered the package",
                kind: FieldKind::Text,
                required: true,
            },
            Self::ReceivedAt => FieldSpec {
                section: None,
                label: "Received at*",
                flag: "--received-at",
                placeholder: "RFC 3339 with zone, e.g. 2026-10-17T10:00:00Z",
                kind: FieldKind::Time,
                required: true,
            },
            Self::Channel => FieldSpec {
                section: None,
                label: "Channel*",
                flag: "--channel",
                placeholder: "e.g. e-CODEX, SFTP, provider portal, sealed USB",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Reference => FieldSpec {
                section: None,
                label: "Order ref.",
                flag: "--reference",
                placeholder: "provider ticket or EPOC reference (optional)",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Hashes => FieldSpec {
                section: None,
                label: "Hash lists",
                flag: "--hashes",
                placeholder: "sha256sum / md5sum / BSD hash list files",
                kind: FieldKind::List { paths: true },
                required: false,
            },
            Self::AllowUnlisted => FieldSpec {
                section: None,
                label: "Allow unlisted",
                flag: "--allow-unlisted",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::LegalBasis => FieldSpec {
                section: None,
                label: "Legal basis",
                flag: "--legal-basis",
                placeholder: "production order / warrant reference (optional)",
                kind: FieldKind::Text,
                required: false,
            },
            Self::OutputPath => FieldSpec {
                section: Some("Output collection directory"),
                label: "Output dir*",
                flag: "-o",
                placeholder: "/media/target/<mount>/<case>/<evidence>",
                kind: FieldKind::Path { dirs_only: true },
                required: true,
            },
            Self::ReferenceTime => FieldSpec {
                section: Some("Reference clock (both or neither)"),
                label: "Ref. time",
                flag: "--reference-time",
                placeholder: "RFC 3339 from radio/GPS/phone clock (press Enter to stamp)",
                kind: FieldKind::Time,
                required: false,
            },
            Self::ReferenceHow => FieldSpec {
                section: None,
                label: "Ref. source",
                flag: "--reference-how",
                placeholder: "e.g. DCF77 radio clock",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Md5 => FieldSpec {
                section: Some("Hashes & container options"),
                label: "Compute MD5",
                flag: "--md5",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::Sha1 => FieldSpec {
                section: None,
                label: "Compute SHA-1",
                flag: "--sha1",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::Compress => FieldSpec {
                section: None,
                label: "Deflate ZIP",
                flag: "--compress",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::AllowTmpfs => FieldSpec {
                section: Some("Safety overrides (require confirmation)"),
                label: "Allow tmpfs",
                flag: "--allow-tmpfs",
                placeholder: "",
                kind: FieldKind::Bool { safety: true },
                required: false,
            },
            Self::PreviewButton => FieldSpec {
                section: None,
                label: "Preview",
                flag: "--dry-run",
                placeholder: "",
                kind: FieldKind::Action,
                required: false,
            },
        }
    }

    pub fn label(self) -> &'static str {
        self.spec().label
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageProbe {
    pub exists: bool,
    pub is_dir: bool,
    pub is_file: bool,
}

#[derive(Debug, Clone)]
pub struct IngestForm {
    pub case: CaseFields,
    pub package: String,
    pub provider: String,
    pub received_at: String,
    pub channel: String,
    pub reference: String,
    pub hashes: Vec<String>,
    pub hashes_idx: usize,
    pub allow_unlisted: bool,
    pub legal_basis: String,
    pub output: OutputFields,
    pub clock: ClockFields,
    pub package_probe: Option<PackageProbe>,
    pub field: IngestField,
    pub cursor: usize,
    pub editing: bool,
}

impl Default for IngestForm {
    fn default() -> Self {
        Self::with_targets(Vec::new())
    }
}

impl IngestForm {
    pub fn with_targets(target_mounts: Vec<MountChoice>) -> Self {
        Self {
            case: CaseFields::default(),
            package: String::new(),
            provider: String::new(),
            received_at: String::new(),
            channel: String::new(),
            reference: String::new(),
            hashes: Vec::new(),
            hashes_idx: 0,
            allow_unlisted: false,
            legal_basis: String::new(),
            output: OutputFields::with_targets(target_mounts),
            clock: ClockFields::default(),
            package_probe: None,
            field: IngestField::CaseNumber,
            cursor: 0,
            editing: false,
        }
    }

    pub fn export_shared(&self) -> SharedFormState {
        let mut s = SharedFormState {
            case: self.case.case.clone(),
            examiner: self.case.examiner.clone(),
            clock: self.clock.clone(),
            scope: ScopeFields::default(),
            md5: self.output.md5,
            sha1: self.output.sha1,
            compress: self.output.compress,
        };
        s.scope.legal_basis = self.legal_basis.clone();
        s
    }

    pub fn import_shared(&mut self, shared: &SharedFormState) {
        if !shared.case.is_empty() {
            self.case.case = shared.case.clone();
        }
        if !shared.examiner.is_empty() {
            self.case.examiner = shared.examiner.clone();
        }
        if !shared.clock.reference_time.is_empty() || !shared.clock.reference_how.is_empty() {
            self.clock = shared.clock.clone();
        }
        if !shared.scope.legal_basis.is_empty() && self.legal_basis.is_empty() {
            self.legal_basis = shared.scope.legal_basis.clone();
        }
        self.output.md5 = shared.md5;
        self.output.sha1 = shared.sha1;
        self.output.compress = shared.compress;
        self.output
            .update_suggestion(&self.case.case, &self.case.evidence);
    }

    pub fn refresh_probes(&mut self) {
        let pkg = self.package.trim();
        let pkg_dir = if pkg.is_empty() {
            self.package_probe = None;
            None
        } else {
            let p = expand_tilde(Path::new(pkg));
            match std::fs::symlink_metadata(&p) {
                Ok(md) => {
                    self.package_probe = Some(PackageProbe {
                        exists: true,
                        is_dir: md.is_dir(),
                        is_file: md.is_file(),
                    });
                }
                Err(_) => {
                    self.package_probe = Some(PackageProbe {
                        exists: false,
                        is_dir: false,
                        is_file: false,
                    });
                }
            }
            Some(p)
        };
        self.output.refresh_probe(pkg_dir.as_deref());
    }

    pub fn text(&self, f: IngestField) -> Option<&String> {
        match f {
            IngestField::CaseNumber => Some(&self.case.case),
            IngestField::EvidenceNumber => Some(&self.case.evidence),
            IngestField::Examiner => Some(&self.case.examiner),
            IngestField::Description => Some(&self.case.description),
            IngestField::Notes => Some(&self.case.notes),
            IngestField::Package => Some(&self.package),
            IngestField::Provider => Some(&self.provider),
            IngestField::ReceivedAt => Some(&self.received_at),
            IngestField::Channel => Some(&self.channel),
            IngestField::Reference => Some(&self.reference),
            IngestField::LegalBasis => Some(&self.legal_basis),
            IngestField::OutputPath => Some(&self.output.output_path),
            IngestField::ReferenceTime => Some(&self.clock.reference_time),
            IngestField::ReferenceHow => Some(&self.clock.reference_how),
            _ => None,
        }
    }

    pub fn text_mut(&mut self, f: IngestField) -> Option<&mut String> {
        match f {
            IngestField::CaseNumber => Some(&mut self.case.case),
            IngestField::EvidenceNumber => Some(&mut self.case.evidence),
            IngestField::Examiner => Some(&mut self.case.examiner),
            IngestField::Description => Some(&mut self.case.description),
            IngestField::Notes => Some(&mut self.case.notes),
            IngestField::Package => Some(&mut self.package),
            IngestField::Provider => Some(&mut self.provider),
            IngestField::ReceivedAt => Some(&mut self.received_at),
            IngestField::Channel => Some(&mut self.channel),
            IngestField::Reference => Some(&mut self.reference),
            IngestField::LegalBasis => Some(&mut self.legal_basis),
            IngestField::OutputPath => Some(&mut self.output.output_path),
            IngestField::ReferenceTime => Some(&mut self.clock.reference_time),
            IngestField::ReferenceHow => Some(&mut self.clock.reference_how),
            _ => None,
        }
    }

    pub fn set_focus(&mut self, next: IngestField) {
        if self.field == IngestField::ReferenceTime
            && next != IngestField::ReferenceTime
            && self.clock.reference_entered_ns.is_none()
            && !self.clock.reference_time.trim().is_empty()
        {
            self.clock.commit_now();
        }
        self.field = next;
        self.editing = false;
        self.cursor = self.text(next).map_or(0, String::len);
    }

    pub fn focus_next(&mut self, forward: bool) {
        let order = IngestField::ALL;
        let idx = order.iter().position(|f| *f == self.field).unwrap_or(0);
        let next_idx = if forward {
            (idx + 1) % order.len()
        } else {
            (idx + order.len() - 1) % order.len()
        };
        self.set_focus(order[next_idx]);
    }

    pub fn toggle_regular(&mut self, f: IngestField) {
        match f {
            IngestField::AllowUnlisted => self.allow_unlisted = !self.allow_unlisted,
            IngestField::Md5 => self.output.md5 = !self.output.md5,
            IngestField::Sha1 => self.output.sha1 = !self.output.sha1,
            IngestField::Compress => self.output.compress = !self.output.compress,
            _ => {}
        }
    }

    pub fn value_text(&self, f: IngestField) -> String {
        match f {
            IngestField::Hashes => {
                format_pattern_list(&self.hashes, self.hashes_idx, "none — optional")
            }
            IngestField::AllowUnlisted => {
                if self.allow_unlisted {
                    "[x] yes (--allow-unlisted)".into()
                } else {
                    "[ ] no (unlisted files are errors)".into()
                }
            }
            IngestField::Md5 => {
                if self.output.md5 {
                    "[x] yes (--md5)".into()
                } else {
                    "[ ] no (SHA-256 always computed)".into()
                }
            }
            IngestField::Sha1 => {
                if self.output.sha1 {
                    "[x] yes (--sha1)".into()
                } else {
                    "[ ] no".into()
                }
            }
            IngestField::Compress => {
                if self.output.compress {
                    "[x] deflate (--compress)".into()
                } else {
                    "[ ] store uncompressed (default)".into()
                }
            }
            IngestField::AllowTmpfs => {
                if self.output.allow_tmpfs {
                    "[!] ENABLED (--allow-tmpfs)".into()
                } else {
                    "[ ] disabled (refuse RAM output)".into()
                }
            }
            IngestField::PreviewButton => "[ Preview package & hash lists (F2) ]".into(),
            _ => self.text(f).cloned().unwrap_or_default(),
        }
    }

    pub fn utc_hint(&self, f: IngestField) -> Option<String> {
        match f {
            IngestField::ReceivedAt => {
                let raw = self.received_at.trim();
                if raw.is_empty() {
                    return None;
                }
                let ns = host::parse_rfc3339(raw).ok()?;
                Some(format!("UTC: {}", host::rfc3339_utc_ns(ns)))
            }
            IngestField::ReferenceTime => self.clock.utc_hint(),
            _ => None,
        }
    }

    pub fn validate_field(&self, f: IngestField) -> Option<String> {
        match f {
            IngestField::CaseNumber => self.case.validate_case(),
            IngestField::EvidenceNumber => self.case.validate_evidence(),
            IngestField::Examiner => self.case.validate_examiner(),
            IngestField::Package => {
                let s = self.package.trim();
                if s.is_empty() {
                    return Some("package path (PACKAGE) is required".into());
                }
                if let Some(p) = &self.package_probe {
                    if !p.exists {
                        return Some("package path does not exist".into());
                    }
                    if !p.is_dir && !p.is_file {
                        return Some("package path must be a directory or a regular file".into());
                    }
                }
                None
            }
            IngestField::Provider => self
                .provider
                .trim()
                .is_empty()
                .then(|| "provider (--provider) is required".into()),
            IngestField::ReceivedAt => {
                let r = self.received_at.trim();
                if r.is_empty() {
                    return Some("receipt timestamp (--received-at) is required".into());
                }
                if let Err(e) = host::parse_rfc3339(r) {
                    return Some(format!("invalid RFC 3339 timestamp: {e:#}"));
                }
                None
            }
            IngestField::Channel => self
                .channel
                .trim()
                .is_empty()
                .then(|| "delivery channel (--channel) is required".into()),
            IngestField::Hashes => {
                for h in &self.hashes {
                    let trimmed = h.trim();
                    if trimmed.is_empty() {
                        return Some("hash list path cannot be empty".into());
                    }
                }
                None
            }
            IngestField::OutputPath => self.output.validate_output(),
            IngestField::ReferenceTime => self.clock.validate_time(),
            IngestField::ReferenceHow => self.clock.validate_how(),
            _ => None,
        }
    }

    pub fn validate_all(&self) -> Vec<(IngestField, String)> {
        IngestField::ALL
            .into_iter()
            .filter_map(|f| self.validate_field(f).map(|msg| (f, msg)))
            .collect()
    }

    pub fn reset_for_next_acquisition(&mut self) {
        self.case.reset_per_run();
        self.clock.reset_per_run();
        self.output.reset_per_run();
        self.set_focus(IngestField::EvidenceNumber);
    }
}

// ==================================================================
// Mode 2: CloudForm (`dfcollect cloud`)
// ==================================================================

/// A remote discovered via `rclone listremotes --long` (name with `:`, type only; never secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcloneRemote {
    pub name: String,
    pub kind: String,
}

/// Parse stdout of `rclone listremotes --long` into `(name, kind)` entries.
pub fn parse_rclone_listremotes(text: &str) -> Vec<RcloneRemote> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((name, kind)) = trimmed.split_once(':') {
            let name = name.trim();
            let kind = kind.trim();
            if !name.is_empty() {
                out.push(RcloneRemote {
                    name: format!("{name}:"),
                    kind: if kind.is_empty() {
                        "remote".into()
                    } else {
                        kind.to_string()
                    },
                });
            }
        }
    }
    out
}

/// Outcome of probing `rclone listremotes --long`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RcloneProbe {
    Remotes(Vec<RcloneRemote>),
    NotFound,
}

/// Probe `rclone listremotes --long` (with `--config` if given) with a 2 s timeout.
/// Never invokes `rclone config show` or reads `rclone.conf` directly.
pub fn probe_rclone_remotes(rclone_config: Option<&Path>) -> RcloneProbe {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if let Some(cfg) = rclone_config {
        if !cfg.as_os_str().is_empty() && !cfg.is_file() {
            return RcloneProbe::Remotes(Vec::new());
        }
    }

    let mut cmd = Command::new("rclone");
    if let Some(cfg) = rclone_config {
        if !cfg.as_os_str().is_empty() {
            cmd.arg("--config").arg(cfg);
        }
    }
    cmd.args(["listremotes", "--long"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RcloneProbe::NotFound,
        Err(_) => return RcloneProbe::Remotes(Vec::new()),
    };
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut out) = stdout.take() {
            let _ = out.read_to_string(&mut s);
        }
        s
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return RcloneProbe::Remotes(Vec::new());
                }
                let out = reader.join().unwrap_or_default();
                return RcloneProbe::Remotes(parse_rclone_listremotes(&out));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return RcloneProbe::Remotes(Vec::new());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return RcloneProbe::Remotes(Vec::new()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudField {
    CaseNumber,
    EvidenceNumber,
    Examiner,
    Description,
    Notes,
    RcloneConfig,
    RemotePicker,
    Source,
    RcloneArgs,
    OutputPath,
    ScopeFile,
    LegalBasis,
    Includes,
    Excludes,
    NotBefore,
    NotAfter,
    ListOutOfScope,
    ReferenceTime,
    ReferenceHow,
    Md5,
    Sha1,
    Compress,
    AllowTmpfs,
    PreviewButton,
}

impl CloudField {
    pub const ALL: [CloudField; 24] = [
        Self::CaseNumber,
        Self::EvidenceNumber,
        Self::Examiner,
        Self::Description,
        Self::Notes,
        Self::RcloneConfig,
        Self::RemotePicker,
        Self::Source,
        Self::RcloneArgs,
        Self::OutputPath,
        Self::ScopeFile,
        Self::LegalBasis,
        Self::Includes,
        Self::Excludes,
        Self::NotBefore,
        Self::NotAfter,
        Self::ListOutOfScope,
        Self::ReferenceTime,
        Self::ReferenceHow,
        Self::Md5,
        Self::Sha1,
        Self::Compress,
        Self::AllowTmpfs,
        Self::PreviewButton,
    ];

    pub fn spec(self) -> FieldSpec {
        match self {
            Self::CaseNumber => FieldSpec {
                section: Some("Case metadata (case & examiner kept on 'n')"),
                label: "Case number*",
                flag: "-C",
                placeholder: "e.g. VG 12345/26",
                kind: FieldKind::Text,
                required: true,
            },
            Self::EvidenceNumber => FieldSpec {
                section: None,
                label: "Evidence number*",
                flag: "-E",
                placeholder: "e.g. cloud01",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Examiner => FieldSpec {
                section: None,
                label: "Examiner*",
                flag: "-e",
                placeholder: "name or ID",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Description => FieldSpec {
                section: None,
                label: "Description",
                flag: "--description",
                placeholder: "optional evidence description",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Notes => FieldSpec {
                section: None,
                label: "Notes",
                flag: "--notes",
                placeholder: "optional case notes",
                kind: FieldKind::Text,
                required: false,
            },
            Self::RcloneConfig => FieldSpec {
                section: Some("Cloud remote (rclone read-only: lsjson & cat) & Output"),
                label: "rclone config",
                flag: "--rclone-config",
                placeholder: "default rclone config (or path, Tab / F4)",
                kind: FieldKind::Path { dirs_only: false },
                required: false,
            },
            Self::RemotePicker => FieldSpec {
                section: None,
                label: "Remote picker",
                flag: "",
                placeholder: "",
                kind: FieldKind::Enum,
                required: false,
            },
            Self::Source => FieldSpec {
                section: None,
                label: "Remote source*",
                flag: "REMOTE:PATH",
                placeholder: "e.g. onedrive:Documents/2026 or drive:",
                kind: FieldKind::Text,
                required: true,
            },
            Self::RcloneArgs => FieldSpec {
                section: None,
                label: "rclone args",
                flag: "--rclone-arg",
                placeholder: "extra rclone flags (e.g. --drive-shared-with-me)",
                kind: FieldKind::List { paths: false },
                required: false,
            },
            Self::OutputPath => FieldSpec {
                section: None,
                label: "Output dir*",
                flag: "-o",
                placeholder: "/media/target/<mount>/<case>/<evidence>",
                kind: FieldKind::Path { dirs_only: true },
                required: true,
            },
            Self::ScopeFile => FieldSpec {
                section: Some("Scope (warrant patterns, modification-time window or JSON file)"),
                label: "Scope JSON",
                flag: "--scope",
                placeholder: "leave blank for inline scope fields below",
                kind: FieldKind::Path { dirs_only: false },
                required: false,
            },
            Self::LegalBasis => FieldSpec {
                section: None,
                label: "Legal basis",
                flag: "--legal-basis",
                placeholder: "warrant or order reference",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Includes => FieldSpec {
                section: None,
                label: "Include globs",
                flag: "--include",
                placeholder: "",
                kind: FieldKind::List { paths: false },
                required: false,
            },
            Self::Excludes => FieldSpec {
                section: None,
                label: "Exclude globs",
                flag: "--exclude",
                placeholder: "",
                kind: FieldKind::List { paths: false },
                required: false,
            },
            Self::NotBefore => FieldSpec {
                section: None,
                label: "Not before",
                flag: "--not-before",
                placeholder: "RFC 3339 with zone, e.g. 2026-01-01T00:00:00+01:00",
                kind: FieldKind::Time,
                required: false,
            },
            Self::NotAfter => FieldSpec {
                section: None,
                label: "Not after",
                flag: "--not-after",
                placeholder: "RFC 3339 with zone, e.g. 2026-07-01T00:00:00+02:00",
                kind: FieldKind::Time,
                required: false,
            },
            Self::ListOutOfScope => FieldSpec {
                section: None,
                label: "List excluded",
                flag: "--list-out-of-scope",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::ReferenceTime => FieldSpec {
                section: Some("Reference clock (both or neither)"),
                label: "Ref. time",
                flag: "--reference-time",
                placeholder: "RFC 3339 from radio/GPS/phone clock (press Enter to stamp)",
                kind: FieldKind::Time,
                required: false,
            },
            Self::ReferenceHow => FieldSpec {
                section: None,
                label: "Ref. source",
                flag: "--reference-how",
                placeholder: "e.g. DCF77 radio clock",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Md5 => FieldSpec {
                section: Some("Hashes & container options"),
                label: "Compute MD5",
                flag: "--md5",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::Sha1 => FieldSpec {
                section: None,
                label: "Compute SHA-1",
                flag: "--sha1",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::Compress => FieldSpec {
                section: None,
                label: "Deflate ZIP",
                flag: "--compress",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::AllowTmpfs => FieldSpec {
                section: Some("Safety overrides (require confirmation)"),
                label: "Allow tmpfs",
                flag: "--allow-tmpfs",
                placeholder: "",
                kind: FieldKind::Bool { safety: true },
                required: false,
            },
            Self::PreviewButton => FieldSpec {
                section: None,
                label: "Preview",
                flag: "--dry-run",
                placeholder: "",
                kind: FieldKind::Action,
                required: false,
            },
        }
    }

    pub fn label(self) -> &'static str {
        self.spec().label
    }
}

#[derive(Debug, Clone)]
pub struct CloudForm {
    pub case: CaseFields,
    pub rclone_config: String,
    pub remotes: Vec<RcloneRemote>,
    pub rclone_missing: bool,
    pub rclone_probe: fn(Option<&Path>) -> RcloneProbe,
    pub selected_remote: Option<usize>,
    pub remotes_probed_for: Option<String>,
    pub source: String,
    pub rclone_args: Vec<String>,
    pub rclone_args_idx: usize,
    pub scope: ScopeFields,
    pub output: OutputFields,
    pub clock: ClockFields,
    pub field: CloudField,
    pub cursor: usize,
    pub editing: bool,
}

impl Default for CloudForm {
    fn default() -> Self {
        Self::with_remotes(Vec::new(), Vec::new())
    }
}

impl CloudForm {
    pub fn with_remotes(remotes: Vec<RcloneRemote>, target_mounts: Vec<MountChoice>) -> Self {
        let mut form = Self {
            case: CaseFields::default(),
            rclone_config: String::new(),
            remotes,
            rclone_missing: false,
            rclone_probe: probe_rclone_remotes,
            selected_remote: None,
            remotes_probed_for: None,
            source: String::new(),
            rclone_args: Vec::new(),
            rclone_args_idx: 0,
            scope: ScopeFields::default(),
            output: OutputFields::with_targets(target_mounts),
            clock: ClockFields::default(),
            field: CloudField::CaseNumber,
            cursor: 0,
            editing: false,
        };
        if let Some(first) = form.remotes.first() {
            form.selected_remote = Some(0);
            form.source = first.name.clone();
        }
        form
    }

    pub fn export_shared(&self) -> SharedFormState {
        SharedFormState {
            case: self.case.case.clone(),
            examiner: self.case.examiner.clone(),
            clock: self.clock.clone(),
            scope: self.scope.clone(),
            md5: self.output.md5,
            sha1: self.output.sha1,
            compress: self.output.compress,
        }
    }

    pub fn import_shared(&mut self, shared: &SharedFormState) {
        if !shared.case.is_empty() {
            self.case.case = shared.case.clone();
        }
        if !shared.examiner.is_empty() {
            self.case.examiner = shared.examiner.clone();
        }
        if !shared.clock.reference_time.is_empty() || !shared.clock.reference_how.is_empty() {
            self.clock = shared.clock.clone();
        }
        if !shared.scope.legal_basis.is_empty()
            || !shared.scope.include.is_empty()
            || !shared.scope.exclude.is_empty()
            || !shared.scope.not_before.is_empty()
            || !shared.scope.not_after.is_empty()
            || !shared.scope.scope_file.is_empty()
        {
            self.scope = shared.scope.clone();
            self.scope.time_basis = TimeBasis::Modified;
        }
        self.output.md5 = shared.md5;
        self.output.sha1 = shared.sha1;
        self.output.compress = shared.compress;
        self.output
            .update_suggestion(&self.case.case, &self.case.evidence);
    }

    pub fn probe_remotes_if_needed(&mut self) {
        let cfg_key = self.rclone_config.trim().to_string();
        if !self.remotes.is_empty() && self.remotes_probed_for.as_deref() == Some(cfg_key.as_str())
        {
            return;
        }
        let cfg_path = (!cfg_key.is_empty()).then(|| expand_tilde(Path::new(&cfg_key)));
        match (self.rclone_probe)(cfg_path.as_deref()) {
            RcloneProbe::Remotes(remotes) => {
                self.rclone_missing = false;
                self.remotes = remotes;
            }
            RcloneProbe::NotFound => {
                self.rclone_missing = true;
                self.remotes.clear();
            }
        }
        self.remotes_probed_for = Some(cfg_key);
        self.sync_selected_remote();
        let src_trimmed = self.source.trim();
        if self.selected_remote.is_none() && (src_trimmed.is_empty() || src_trimmed.ends_with(':'))
        {
            if let Some(first) = self.remotes.first() {
                self.selected_remote = Some(0);
                self.source = first.name.clone();
            }
        }
    }

    pub fn sync_selected_remote(&mut self) {
        let prefix = self
            .source
            .trim()
            .split_once(':')
            .map(|(r, _)| format!("{r}:"))
            .unwrap_or_default();
        self.selected_remote = self.remotes.iter().position(|r| r.name == prefix);
    }

    pub fn refresh_probes(&mut self) {
        self.output.refresh_probe(None);
    }

    pub fn applies(&self, f: CloudField) -> bool {
        match f {
            CloudField::RemotePicker => !self.remotes.is_empty(),
            CloudField::LegalBasis => {
                self.scope.scope_file.trim().is_empty() || !self.scope.legal_basis.trim().is_empty()
            }
            CloudField::Includes => {
                self.scope.scope_file.trim().is_empty() || !self.scope.include.is_empty()
            }
            CloudField::Excludes => {
                self.scope.scope_file.trim().is_empty() || !self.scope.exclude.is_empty()
            }
            CloudField::NotBefore => {
                self.scope.scope_file.trim().is_empty() || !self.scope.not_before.trim().is_empty()
            }
            CloudField::NotAfter => {
                self.scope.scope_file.trim().is_empty() || !self.scope.not_after.trim().is_empty()
            }
            _ => true,
        }
    }

    pub fn focus_order(&self) -> Vec<CloudField> {
        CloudField::ALL
            .into_iter()
            .filter(|f| self.applies(*f))
            .collect()
    }

    pub fn text(&self, f: CloudField) -> Option<&String> {
        match f {
            CloudField::CaseNumber => Some(&self.case.case),
            CloudField::EvidenceNumber => Some(&self.case.evidence),
            CloudField::Examiner => Some(&self.case.examiner),
            CloudField::Description => Some(&self.case.description),
            CloudField::Notes => Some(&self.case.notes),
            CloudField::RcloneConfig => Some(&self.rclone_config),
            CloudField::Source => Some(&self.source),
            CloudField::OutputPath => Some(&self.output.output_path),
            CloudField::ScopeFile => Some(&self.scope.scope_file),
            CloudField::LegalBasis => Some(&self.scope.legal_basis),
            CloudField::NotBefore => Some(&self.scope.not_before),
            CloudField::NotAfter => Some(&self.scope.not_after),
            CloudField::ReferenceTime => Some(&self.clock.reference_time),
            CloudField::ReferenceHow => Some(&self.clock.reference_how),
            _ => None,
        }
    }

    pub fn text_mut(&mut self, f: CloudField) -> Option<&mut String> {
        match f {
            CloudField::CaseNumber => Some(&mut self.case.case),
            CloudField::EvidenceNumber => Some(&mut self.case.evidence),
            CloudField::Examiner => Some(&mut self.case.examiner),
            CloudField::Description => Some(&mut self.case.description),
            CloudField::Notes => Some(&mut self.case.notes),
            CloudField::RcloneConfig => Some(&mut self.rclone_config),
            CloudField::Source => Some(&mut self.source),
            CloudField::OutputPath => Some(&mut self.output.output_path),
            CloudField::ScopeFile => Some(&mut self.scope.scope_file),
            CloudField::LegalBasis => Some(&mut self.scope.legal_basis),
            CloudField::NotBefore => Some(&mut self.scope.not_before),
            CloudField::NotAfter => Some(&mut self.scope.not_after),
            CloudField::ReferenceTime => Some(&mut self.clock.reference_time),
            CloudField::ReferenceHow => Some(&mut self.clock.reference_how),
            _ => None,
        }
    }

    pub fn set_focus(&mut self, next: CloudField) {
        if self.field == CloudField::ReferenceTime
            && next != CloudField::ReferenceTime
            && self.clock.reference_entered_ns.is_none()
            && !self.clock.reference_time.trim().is_empty()
        {
            self.clock.commit_now();
        }
        self.field = next;
        self.editing = false;
        self.cursor = self.text(next).map_or(0, String::len);
    }

    pub fn focus_next(&mut self, forward: bool) {
        let order = self.focus_order();
        if order.is_empty() {
            return;
        }
        let idx = order.iter().position(|f| *f == self.field).unwrap_or(0);
        let next_idx = if forward {
            (idx + 1) % order.len()
        } else {
            (idx + order.len() - 1) % order.len()
        };
        self.set_focus(order[next_idx]);
    }

    pub fn toggle_regular(&mut self, f: CloudField, forward: bool) {
        match f {
            CloudField::RemotePicker if !self.remotes.is_empty() => {
                let n = self.remotes.len();
                let next = match self.selected_remote {
                    Some(i) if forward => (i + 1) % n,
                    Some(i) => (i + n - 1) % n,
                    None => 0,
                };
                self.selected_remote = Some(next);
                let suffix = self
                    .source
                    .split_once(':')
                    .map(|(_, path)| path)
                    .unwrap_or("");
                self.source = format!("{}{suffix}", self.remotes[next].name);
            }
            CloudField::ListOutOfScope => {
                self.scope.list_out_of_scope = !self.scope.list_out_of_scope
            }
            CloudField::Md5 => self.output.md5 = !self.output.md5,
            CloudField::Sha1 => self.output.sha1 = !self.output.sha1,
            CloudField::Compress => self.output.compress = !self.output.compress,
            _ => {}
        }
    }

    pub fn value_text(&self, f: CloudField) -> String {
        match f {
            CloudField::RemotePicker => match self.selected_remote {
                Some(i) if i < self.remotes.len() => {
                    let r = &self.remotes[i];
                    format!(
                        "◀ {} [{}] ({}/{}) ▶",
                        r.name,
                        r.kind,
                        i + 1,
                        self.remotes.len()
                    )
                }
                _ => format!(
                    "◀ custom ({} rclone remote(s) available) ▶",
                    self.remotes.len()
                ),
            },
            CloudField::RcloneArgs => format_pattern_list(
                &self.rclone_args,
                self.rclone_args_idx,
                "none — optional extra rclone flags",
            ),
            CloudField::Includes => {
                format_pattern_list(&self.scope.include, self.scope.include_idx, "all files")
            }
            CloudField::Excludes => {
                format_pattern_list(&self.scope.exclude, self.scope.exclude_idx, "none")
            }
            CloudField::ListOutOfScope => {
                if self.scope.list_out_of_scope {
                    "[x] list names in items.jsonl (--list-out-of-scope)".into()
                } else {
                    "[ ] count by reason only (recommended)".into()
                }
            }
            CloudField::Md5 => {
                if self.output.md5 {
                    "[x] yes (--md5)".into()
                } else {
                    "[ ] no (SHA-256 + provider hashes)".into()
                }
            }
            CloudField::Sha1 => {
                if self.output.sha1 {
                    "[x] yes (--sha1)".into()
                } else {
                    "[ ] no".into()
                }
            }
            CloudField::Compress => {
                if self.output.compress {
                    "[x] deflate (--compress)".into()
                } else {
                    "[ ] store uncompressed (default)".into()
                }
            }
            CloudField::AllowTmpfs => {
                if self.output.allow_tmpfs {
                    "[!] ENABLED (--allow-tmpfs)".into()
                } else {
                    "[ ] disabled (refuse RAM output)".into()
                }
            }
            CloudField::PreviewButton => "[ Preview remote listing (F2) ]".into(),
            _ => self.text(f).cloned().unwrap_or_default(),
        }
    }

    pub fn utc_hint(&self, f: CloudField) -> Option<String> {
        match f {
            CloudField::NotBefore => self.scope.utc_hint(true),
            CloudField::NotAfter => self.scope.utc_hint(false),
            CloudField::ReferenceTime => self.clock.utc_hint(),
            _ => None,
        }
    }

    pub fn validate_field(&self, f: CloudField) -> Option<String> {
        match f {
            CloudField::CaseNumber => self.case.validate_case(),
            CloudField::EvidenceNumber => self.case.validate_evidence(),
            CloudField::Examiner => self.case.validate_examiner(),
            CloudField::RcloneConfig => {
                let s = self.rclone_config.trim();
                if s.is_empty() {
                    return None;
                }
                let p = expand_tilde(Path::new(s));
                if !p.is_file() {
                    return Some("rclone config file does not exist".into());
                }
                None
            }
            CloudField::Source => {
                let s = self.source.trim();
                if s.is_empty() {
                    return Some("remote source (REMOTE: or REMOTE:PATH) is required".into());
                }
                if let Err(e) = crate::cloud::split_source(s) {
                    return Some(format!("{e:#}"));
                }
                None
            }
            CloudField::OutputPath => self.output.validate_output(),
            CloudField::ScopeFile => self.scope.validate_scope_file(false),
            CloudField::NotBefore => self.scope.validate_not_before(),
            CloudField::NotAfter => self.scope.validate_not_after(),
            CloudField::ReferenceTime => self.clock.validate_time(),
            CloudField::ReferenceHow => self.clock.validate_how(),
            _ => None,
        }
    }

    pub fn validate_all(&self) -> Vec<(CloudField, String)> {
        CloudField::ALL
            .into_iter()
            .filter_map(|f| self.validate_field(f).map(|msg| (f, msg)))
            .collect()
    }

    pub fn reset_for_next_acquisition(&mut self) {
        self.case.reset_per_run();
        self.clock.reset_per_run();
        self.output.reset_per_run();
        self.set_focus(CloudField::EvidenceNumber);
    }
}

// ==================================================================
// Mode 3: DbForm (`dfcollect db`)
// ==================================================================

impl crate::db::Engine {
    pub fn as_cli_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mariadb => "mariadb",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Postgres => "postgres (PostgreSQL: psql + pg_dump + pg_dumpall)",
            Self::Mariadb => "mariadb (MariaDB / MySQL: mariadb + mariadb-dump)",
        }
    }

    pub fn default_port_placeholder(self) -> &'static str {
        match self {
            Self::Postgres => "5432 (PostgreSQL default)",
            Self::Mariadb => "3306 (MariaDB default)",
        }
    }
}

impl crate::db::Tls {
    pub const ALL: [Self; 4] = [Self::Prefer, Self::Off, Self::Require, Self::Verify];

    pub fn as_cli_str(self) -> &'static str {
        match self {
            Self::Prefer => "prefer",
            Self::Off => "off",
            Self::Require => "require",
            Self::Verify => "verify",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Prefer => "prefer (use TLS if offered; default)",
            Self::Off => "off (no TLS; test setups only)",
            Self::Require => "require (TLS required, certificate not verified)",
            Self::Verify => "verify (TLS required, certificate verified against system CAs)",
        }
    }

    pub fn cycle(self, forward: bool) -> Self {
        let idx = Self::ALL.iter().position(|x| *x == self).unwrap_or(0);
        if forward {
            Self::ALL[(idx + 1) % Self::ALL.len()]
        } else {
            Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
        }
    }
}

/// Fingerprint of the database connection fields; if any of these change,
/// a cached preview `Credential` is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbConnKey {
    pub engine: crate::db::Engine,
    pub host: String,
    pub port: String,
    pub user: String,
    pub tls: crate::db::Tls,
    pub password_file: String,
    pub no_password: bool,
}

/// Probe the client and dump tools for `engine` on `PATH` (`--version`, 2 s timeout).
pub fn probe_db_tools(engine: crate::db::Engine) -> Vec<(String, Option<String>)> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let names: &[&str] = match engine {
        crate::db::Engine::Postgres => &["psql", "pg_dump", "pg_dumpall"],
        crate::db::Engine::Mariadb => &["mariadb", "mariadb-dump"],
    };
    names
        .iter()
        .map(|&prog| {
            let Ok(mut child) = Command::new(prog)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            else {
                return (prog.to_string(), None);
            };
            let mut stdout = child.stdout.take();
            let reader = std::thread::spawn(move || {
                let mut s = String::new();
                if let Some(mut out) = stdout.take() {
                    let _ = out.read_to_string(&mut s);
                }
                s
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) if status.success() => {
                        let out = reader.join().unwrap_or_default();
                        let line = out.lines().next().unwrap_or("").trim().to_string();
                        return (prog.to_string(), (!line.is_empty()).then_some(line));
                    }
                    Ok(Some(_)) | Err(_) => return (prog.to_string(), None),
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            return (prog.to_string(), None);
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbField {
    CaseNumber,
    EvidenceNumber,
    Examiner,
    Description,
    Notes,
    Engine,
    Host,
    Port,
    User,
    PasswordFile,
    NoPassword,
    Tls,
    Databases,
    LegalBasis,
    Serializable,
    BinlogPosition,
    OutputPath,
    ReferenceTime,
    ReferenceHow,
    Md5,
    Sha1,
    Compress,
    AllowTmpfs,
    PreviewButton,
}

impl DbField {
    pub const ALL: [DbField; 24] = [
        Self::CaseNumber,
        Self::EvidenceNumber,
        Self::Examiner,
        Self::Description,
        Self::Notes,
        Self::Engine,
        Self::Host,
        Self::Port,
        Self::User,
        Self::PasswordFile,
        Self::NoPassword,
        Self::Tls,
        Self::Databases,
        Self::LegalBasis,
        Self::Serializable,
        Self::BinlogPosition,
        Self::OutputPath,
        Self::ReferenceTime,
        Self::ReferenceHow,
        Self::Md5,
        Self::Sha1,
        Self::Compress,
        Self::AllowTmpfs,
        Self::PreviewButton,
    ];

    pub fn spec(self, engine: crate::db::Engine) -> FieldSpec {
        match self {
            Self::CaseNumber => FieldSpec {
                section: Some("Case metadata (case & examiner kept on 'n')"),
                label: "Case number*",
                flag: "-C",
                placeholder: "e.g. VG 12345/26",
                kind: FieldKind::Text,
                required: true,
            },
            Self::EvidenceNumber => FieldSpec {
                section: None,
                label: "Evidence number*",
                flag: "-E",
                placeholder: "e.g. db01",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Examiner => FieldSpec {
                section: None,
                label: "Examiner*",
                flag: "-e",
                placeholder: "name or ID",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Description => FieldSpec {
                section: None,
                label: "Description",
                flag: "--description",
                placeholder: "optional evidence description",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Notes => FieldSpec {
                section: None,
                label: "Notes",
                flag: "--notes",
                placeholder: "optional case notes",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Engine => FieldSpec {
                section: Some("Database connection & scope"),
                label: "Engine*",
                flag: "ENGINE",
                placeholder: "",
                kind: FieldKind::Enum,
                required: true,
            },
            Self::Host => FieldSpec {
                section: None,
                label: "Host*",
                flag: "--host",
                placeholder: "db.example.org or 10.0.0.5",
                kind: FieldKind::Text,
                required: true,
            },
            Self::Port => FieldSpec {
                section: None,
                label: "Port",
                flag: "--port",
                placeholder: engine.default_port_placeholder(),
                kind: FieldKind::Text,
                required: false,
            },
            Self::User => FieldSpec {
                section: None,
                label: "User*",
                flag: "-u",
                placeholder: "database account, e.g. postgres or root",
                kind: FieldKind::Text,
                required: true,
            },
            Self::PasswordFile => FieldSpec {
                section: None,
                label: "Password file",
                flag: "--password-file",
                placeholder: "leave blank to enter password interactively (never in argv)",
                kind: FieldKind::Path { dirs_only: false },
                required: false,
            },
            Self::NoPassword => FieldSpec {
                section: None,
                label: "No password",
                flag: "--no-password",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::Tls => FieldSpec {
                section: None,
                label: "TLS mode",
                flag: "--tls",
                placeholder: "",
                kind: FieldKind::Enum,
                required: false,
            },
            Self::Databases => FieldSpec {
                section: None,
                label: "Databases",
                flag: "--database",
                placeholder: "",
                kind: FieldKind::List { paths: false },
                required: false,
            },
            Self::LegalBasis => FieldSpec {
                section: None,
                label: "Legal basis",
                flag: "--legal-basis",
                placeholder: "warrant or order reference",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Serializable => FieldSpec {
                section: None,
                label: "Serializable",
                flag: "--serializable",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::BinlogPosition => FieldSpec {
                section: None,
                label: "Binlog pos.",
                flag: "--binlog-position",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::OutputPath => FieldSpec {
                section: Some("Output collection directory"),
                label: "Output dir*",
                flag: "-o",
                placeholder: "/media/target/<mount>/<case>/<evidence>",
                kind: FieldKind::Path { dirs_only: true },
                required: true,
            },
            Self::ReferenceTime => FieldSpec {
                section: Some("Reference clock (both or neither)"),
                label: "Ref. time",
                flag: "--reference-time",
                placeholder: "RFC 3339 from radio/GPS/phone clock (press Enter to stamp)",
                kind: FieldKind::Time,
                required: false,
            },
            Self::ReferenceHow => FieldSpec {
                section: None,
                label: "Ref. source",
                flag: "--reference-how",
                placeholder: "e.g. DCF77 radio clock",
                kind: FieldKind::Text,
                required: false,
            },
            Self::Md5 => FieldSpec {
                section: Some("Hashes & container options"),
                label: "Compute MD5",
                flag: "--md5",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::Sha1 => FieldSpec {
                section: None,
                label: "Compute SHA-1",
                flag: "--sha1",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::Compress => FieldSpec {
                section: None,
                label: "Deflate ZIP",
                flag: "--compress",
                placeholder: "",
                kind: FieldKind::Bool { safety: false },
                required: false,
            },
            Self::AllowTmpfs => FieldSpec {
                section: Some("Safety overrides (require confirmation)"),
                label: "Allow tmpfs",
                flag: "--allow-tmpfs",
                placeholder: "",
                kind: FieldKind::Bool { safety: true },
                required: false,
            },
            Self::PreviewButton => FieldSpec {
                section: None,
                label: "Preview",
                flag: "--dry-run",
                placeholder: "",
                kind: FieldKind::Action,
                required: false,
            },
        }
    }

    pub fn label(self) -> &'static str {
        self.spec(crate::db::Engine::Postgres).label
    }
}

/// Cached result of probing the PATH for the selected database engine's client tools.
pub type DbToolProbe = (crate::db::Engine, Vec<(String, Option<String>)>);

#[derive(Debug, Clone)]
pub struct DbForm {
    pub case: CaseFields,
    pub engine: crate::db::Engine,
    pub host: String,
    pub port: String,
    pub user: String,
    pub password_file: String,
    pub no_password: bool,
    pub tls: crate::db::Tls,
    pub databases: Vec<String>,
    pub databases_idx: usize,
    pub legal_basis: String,
    pub serializable: bool,
    pub binlog_position: bool,
    pub output: OutputFields,
    pub clock: ClockFields,
    pub tool_probe: Option<DbToolProbe>,
    pub field: DbField,
    pub cursor: usize,
    pub editing: bool,
}

impl Default for DbForm {
    fn default() -> Self {
        Self::with_targets(Vec::new())
    }
}

impl DbForm {
    pub fn with_targets(target_mounts: Vec<MountChoice>) -> Self {
        Self {
            case: CaseFields::default(),
            engine: crate::db::Engine::Postgres,
            host: String::new(),
            port: String::new(),
            user: String::new(),
            password_file: String::new(),
            no_password: false,
            tls: crate::db::Tls::Prefer,
            databases: Vec::new(),
            databases_idx: 0,
            legal_basis: String::new(),
            serializable: false,
            binlog_position: false,
            output: OutputFields::with_targets(target_mounts),
            clock: ClockFields::default(),
            tool_probe: None,
            field: DbField::CaseNumber,
            cursor: 0,
            editing: false,
        }
    }

    pub fn conn_key(&self) -> DbConnKey {
        DbConnKey {
            engine: self.engine,
            host: self.host.trim().to_string(),
            port: self.port.trim().to_string(),
            user: self.user.trim().to_string(),
            tls: self.tls,
            password_file: self.password_file.trim().to_string(),
            no_password: self.no_password,
        }
    }

    pub fn export_shared(&self) -> SharedFormState {
        let mut s = SharedFormState {
            case: self.case.case.clone(),
            examiner: self.case.examiner.clone(),
            clock: self.clock.clone(),
            scope: ScopeFields::default(),
            md5: self.output.md5,
            sha1: self.output.sha1,
            compress: self.output.compress,
        };
        s.scope.legal_basis = self.legal_basis.clone();
        s
    }

    pub fn import_shared(&mut self, shared: &SharedFormState) {
        if !shared.case.is_empty() {
            self.case.case = shared.case.clone();
        }
        if !shared.examiner.is_empty() {
            self.case.examiner = shared.examiner.clone();
        }
        if !shared.clock.reference_time.is_empty() || !shared.clock.reference_how.is_empty() {
            self.clock = shared.clock.clone();
        }
        if !shared.scope.legal_basis.is_empty() && self.legal_basis.is_empty() {
            self.legal_basis = shared.scope.legal_basis.clone();
        }
        self.output.md5 = shared.md5;
        self.output.sha1 = shared.sha1;
        self.output.compress = shared.compress;
        self.output
            .update_suggestion(&self.case.case, &self.case.evidence);
    }

    pub fn probe_tools_if_needed(&mut self) {
        if self
            .tool_probe
            .as_ref()
            .is_some_and(|(eng, _)| *eng == self.engine)
        {
            return;
        }
        self.tool_probe = Some((self.engine, probe_db_tools(self.engine)));
    }

    pub fn refresh_probes(&mut self) {
        self.output.refresh_probe(None);
    }

    pub fn applies(&self, f: DbField) -> bool {
        match f {
            DbField::Serializable => self.engine == crate::db::Engine::Postgres,
            DbField::BinlogPosition => self.engine == crate::db::Engine::Mariadb,
            _ => true,
        }
    }

    pub fn focus_order(&self) -> Vec<DbField> {
        DbField::ALL
            .into_iter()
            .filter(|f| self.applies(*f))
            .collect()
    }

    pub fn text(&self, f: DbField) -> Option<&String> {
        match f {
            DbField::CaseNumber => Some(&self.case.case),
            DbField::EvidenceNumber => Some(&self.case.evidence),
            DbField::Examiner => Some(&self.case.examiner),
            DbField::Description => Some(&self.case.description),
            DbField::Notes => Some(&self.case.notes),
            DbField::Host => Some(&self.host),
            DbField::Port => Some(&self.port),
            DbField::User => Some(&self.user),
            DbField::PasswordFile => Some(&self.password_file),
            DbField::LegalBasis => Some(&self.legal_basis),
            DbField::OutputPath => Some(&self.output.output_path),
            DbField::ReferenceTime => Some(&self.clock.reference_time),
            DbField::ReferenceHow => Some(&self.clock.reference_how),
            _ => None,
        }
    }

    pub fn text_mut(&mut self, f: DbField) -> Option<&mut String> {
        match f {
            DbField::CaseNumber => Some(&mut self.case.case),
            DbField::EvidenceNumber => Some(&mut self.case.evidence),
            DbField::Examiner => Some(&mut self.case.examiner),
            DbField::Description => Some(&mut self.case.description),
            DbField::Notes => Some(&mut self.case.notes),
            DbField::Host => Some(&mut self.host),
            DbField::Port => Some(&mut self.port),
            DbField::User => Some(&mut self.user),
            DbField::PasswordFile => Some(&mut self.password_file),
            DbField::LegalBasis => Some(&mut self.legal_basis),
            DbField::OutputPath => Some(&mut self.output.output_path),
            DbField::ReferenceTime => Some(&mut self.clock.reference_time),
            DbField::ReferenceHow => Some(&mut self.clock.reference_how),
            _ => None,
        }
    }

    pub fn set_focus(&mut self, next: DbField) {
        if self.field == DbField::ReferenceTime
            && next != DbField::ReferenceTime
            && self.clock.reference_entered_ns.is_none()
            && !self.clock.reference_time.trim().is_empty()
        {
            self.clock.commit_now();
        }
        self.field = next;
        self.editing = false;
        self.cursor = self.text(next).map_or(0, String::len);
    }

    pub fn focus_next(&mut self, forward: bool) {
        let order = self.focus_order();
        if order.is_empty() {
            return;
        }
        let idx = order.iter().position(|f| *f == self.field).unwrap_or(0);
        let next_idx = if forward {
            (idx + 1) % order.len()
        } else {
            (idx + order.len() - 1) % order.len()
        };
        self.set_focus(order[next_idx]);
    }

    pub fn toggle_regular(&mut self, f: DbField, forward: bool) {
        match f {
            DbField::Engine => {
                self.engine = match self.engine {
                    crate::db::Engine::Postgres => crate::db::Engine::Mariadb,
                    crate::db::Engine::Mariadb => crate::db::Engine::Postgres,
                };
            }
            DbField::NoPassword => self.no_password = !self.no_password,
            DbField::Tls => self.tls = self.tls.cycle(forward),
            DbField::Serializable => self.serializable = !self.serializable,
            DbField::BinlogPosition => self.binlog_position = !self.binlog_position,
            DbField::Md5 => self.output.md5 = !self.output.md5,
            DbField::Sha1 => self.output.sha1 = !self.output.sha1,
            DbField::Compress => self.output.compress = !self.output.compress,
            _ => {}
        }
    }

    pub fn value_text(&self, f: DbField) -> String {
        match f {
            DbField::Engine => format!("◀ {} ▶", self.engine.label()),
            DbField::NoPassword => {
                if self.no_password {
                    "[x] yes (--no-password)".into()
                } else {
                    "[ ] no (use --password-file or interactive prompt)".into()
                }
            }
            DbField::Tls => format!("◀ {} ▶", self.tls.label()),
            DbField::Databases => format_pattern_list(
                &self.databases,
                self.databases_idx,
                "all non-system databases",
            ),
            DbField::Serializable => {
                if self.serializable {
                    "[x] yes (--serializable)".into()
                } else {
                    "[ ] no (default REPEATABLE READ)".into()
                }
            }
            DbField::BinlogPosition => {
                if self.binlog_position {
                    "[x] yes (--binlog-position; brief global read lock)".into()
                } else {
                    "[ ] no (lockless InnoDB snapshot)".into()
                }
            }
            DbField::Md5 => {
                if self.output.md5 {
                    "[x] yes (--md5)".into()
                } else {
                    "[ ] no (SHA-256 always computed)".into()
                }
            }
            DbField::Sha1 => {
                if self.output.sha1 {
                    "[x] yes (--sha1)".into()
                } else {
                    "[ ] no".into()
                }
            }
            DbField::Compress => {
                if self.output.compress {
                    "[x] deflate (--compress)".into()
                } else {
                    "[ ] store uncompressed (default)".into()
                }
            }
            DbField::AllowTmpfs => {
                if self.output.allow_tmpfs {
                    "[!] ENABLED (--allow-tmpfs)".into()
                } else {
                    "[ ] disabled (refuse RAM output)".into()
                }
            }
            DbField::PreviewButton => "[ Preview server & databases (F2) ]".into(),
            _ => self.text(f).cloned().unwrap_or_default(),
        }
    }

    pub fn utc_hint(&self, f: DbField) -> Option<String> {
        match f {
            DbField::ReferenceTime => self.clock.utc_hint(),
            _ => None,
        }
    }

    pub fn validate_field(&self, f: DbField) -> Option<String> {
        match f {
            DbField::CaseNumber => self.case.validate_case(),
            DbField::EvidenceNumber => self.case.validate_evidence(),
            DbField::Examiner => self.case.validate_examiner(),
            DbField::Host => self
                .host
                .trim()
                .is_empty()
                .then(|| "database host (--host) is required".into()),
            DbField::Port => {
                let p = self.port.trim();
                if p.is_empty() {
                    return None;
                }
                match p.parse::<u16>() {
                    Ok(n) if n > 0 => None,
                    _ => Some("port (--port) must be a number in 1..=65535".into()),
                }
            }
            DbField::User => self
                .user
                .trim()
                .is_empty()
                .then(|| "database user (-u / --user) is required".into()),
            DbField::PasswordFile => {
                let pf = self.password_file.trim();
                if pf.is_empty() {
                    return None;
                }
                if self.no_password {
                    return Some("--password-file cannot be combined with --no-password".into());
                }
                let p = expand_tilde(Path::new(pf));
                if !p.is_file() {
                    return Some("password file does not exist".into());
                }
                None
            }
            DbField::NoPassword => {
                if self.no_password && !self.password_file.trim().is_empty() {
                    return Some("--no-password cannot be combined with --password-file".into());
                }
                None
            }
            DbField::OutputPath => self.output.validate_output(),
            DbField::ReferenceTime => self.clock.validate_time(),
            DbField::ReferenceHow => self.clock.validate_how(),
            _ => None,
        }
    }

    pub fn validate_all(&self) -> Vec<(DbField, String)> {
        DbField::ALL
            .into_iter()
            .filter(|f| self.applies(*f))
            .filter_map(|f| self.validate_field(f).map(|msg| (f, msg)))
            .collect()
    }

    pub fn reset_for_next_acquisition(&mut self) {
        self.case.reset_per_run();
        self.clock.reset_per_run();
        self.output.reset_per_run();
        self.set_focus(DbField::EvidenceNumber);
    }
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

    #[test]
    fn validates_ingest_form_and_resets_per_run() {
        let mut f = IngestForm::with_targets(vec![MountChoice {
            mount_point: PathBuf::from("/media/target/sdc1"),
            source: "/dev/sdc1".into(),
            read_only: false,
            free_bytes: Some(500 << 30),
        }]);
        let errs: Vec<IngestField> = f.validate_all().into_iter().map(|(k, _)| k).collect();
        assert!(errs.contains(&IngestField::CaseNumber));
        assert!(errs.contains(&IngestField::EvidenceNumber));
        assert!(errs.contains(&IngestField::Examiner));
        assert!(errs.contains(&IngestField::Package));
        assert!(errs.contains(&IngestField::Provider));
        assert!(errs.contains(&IngestField::ReceivedAt));
        assert!(errs.contains(&IngestField::Channel));
        assert!(errs.contains(&IngestField::OutputPath));

        f.case.case = "VG 12345/26".into();
        f.case.evidence = "prod01".into();
        f.case.examiner = "KHK Muster".into();
        f.package = "/media/evidence/sdb1/pkg".into();
        f.package_probe = Some(PackageProbe {
            exists: true,
            is_dir: true,
            is_file: false,
        });
        f.provider = "Example Mail Inc.".into();
        f.received_at = "2026-10-17T12:00:00+02:00".into();
        f.channel = "e-CODEX".into();
        f.output.update_suggestion(&f.case.case, &f.case.evidence);
        assert_eq!(
            f.output.output_path,
            "/media/target/sdc1/VG_12345_26/prod01"
        );
        assert_eq!(
            f.utc_hint(IngestField::ReceivedAt).as_deref(),
            Some("UTC: 2026-10-17T10:00:00.000000000Z")
        );
        assert!(f.validate_all().is_empty(), "{:?}", f.validate_all());

        f.reset_for_next_acquisition();
        assert_eq!(f.case.case, "VG 12345/26");
        assert_eq!(f.case.examiner, "KHK Muster");
        assert!(f.case.evidence.is_empty());
        assert!(f.output.output_path.is_empty());
        assert_eq!(f.field, IngestField::EvidenceNumber);
    }

    #[test]
    fn parses_rclone_listremotes_and_validates_cloud_form() {
        let remotes = parse_rclone_listremotes("onedrive: onedrive\ncase_s3: s3\n\n");
        assert_eq!(
            remotes,
            vec![
                RcloneRemote {
                    name: "onedrive:".into(),
                    kind: "onedrive".into(),
                },
                RcloneRemote {
                    name: "case_s3:".into(),
                    kind: "s3".into(),
                },
            ]
        );

        let mut f = CloudForm::with_remotes(
            remotes,
            vec![MountChoice {
                mount_point: PathBuf::from("/media/target/sdc1"),
                source: "/dev/sdc1".into(),
                read_only: false,
                free_bytes: Some(500 << 30),
            }],
        );
        assert_eq!(f.source, "onedrive:");
        f.source = "onedrive:Docs/2026".into();
        f.toggle_regular(CloudField::RemotePicker, true);
        assert_eq!(f.source, "case_s3:Docs/2026");

        f.case.case = "VG 12345/26".into();
        f.case.evidence = "cloud01".into();
        f.case.examiner = "KHK Muster".into();
        f.output.update_suggestion(&f.case.case, &f.case.evidence);
        assert!(f.validate_all().is_empty(), "{:?}", f.validate_all());

        f.source = "/local/path".into();
        assert!(f.validate_field(CloudField::Source).is_some());
    }

    #[test]
    fn db_form_conditional_fields_and_conn_key() {
        let mut f = DbForm::default();
        assert_eq!(f.engine, crate::db::Engine::Postgres);
        assert!(f.applies(DbField::Serializable));
        assert!(!f.applies(DbField::BinlogPosition));
        assert!(f.focus_order().contains(&DbField::Serializable));
        assert!(!f.focus_order().contains(&DbField::BinlogPosition));

        let k1 = f.conn_key();
        f.toggle_regular(DbField::Engine, true);
        assert_eq!(f.engine, crate::db::Engine::Mariadb);
        assert!(!f.applies(DbField::Serializable));
        assert!(f.applies(DbField::BinlogPosition));
        assert_ne!(f.conn_key(), k1);

        f.port = "99999".into();
        assert!(f.validate_field(DbField::Port).is_some());
        f.port = "3306".into();
        assert!(f.validate_field(DbField::Port).is_none());
    }

    #[test]
    fn shared_form_state_syncs_across_modes() {
        let mut files = valid_form();
        files.legal_basis = "AG Musterstadt 12 Gs 34/26".into();
        files.include = vec!["Docs/**".into()];
        files.md5 = true;
        files.reference_time = "2027-01-15T08:00:05Z".into();
        files.reference_how = "DCF77".into();
        files.commit_reference_time_at(1_800_000_000_000_000_000);

        let shared = files.export_shared();

        let mut cloud = CloudForm::default();
        cloud.import_shared(&shared);
        assert_eq!(cloud.case.case, "VG 12345/26");
        assert_eq!(cloud.case.examiner, "KHK Muster");
        assert_eq!(cloud.scope.legal_basis, "AG Musterstadt 12 Gs 34/26");
        assert_eq!(cloud.scope.include, vec!["Docs/**".to_string()]);
        assert!(cloud.output.md5);
        assert_eq!(
            cloud.clock.reference_entered_ns,
            Some(1_800_000_000_000_000_000)
        );

        let mut db = DbForm::default();
        db.import_shared(&shared);
        assert_eq!(db.case.case, "VG 12345/26");
        assert_eq!(db.case.examiner, "KHK Muster");
        assert_eq!(db.legal_basis, "AG Musterstadt 12 Gs 34/26");
        assert!(db.output.md5);
    }
}
