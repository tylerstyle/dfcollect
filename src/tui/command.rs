//! Building the equivalent `dfcollect` command lines from TUI forms,
//! quoting them for display and OSC 52 copying, and parsing them through the
//! same `clap` definitions as the CLI.

use crate::{
    args::{Cli, CloudArgs, Command, DbArgs, FilesArgs, IngestArgs, TimeBasis, UnknownTimeArg},
    tui::{
        autocomplete::expand_tilde,
        form::{
            CaseFields, ClockFields, CloudField, CloudForm, DbField, DbForm, FilesField, FilesForm,
            IngestField, IngestForm, OutputFields, ScopeFields,
        },
    },
};
use clap::{error::ContextKind, Parser};
use std::path::Path;

fn abs_path_str(raw: &str) -> String {
    let expanded = expand_tilde(Path::new(raw));
    std::path::absolute(&expanded)
        .unwrap_or(expanded)
        .display()
        .to_string()
}

fn push_opt(argv: &mut Vec<String>, flag: &str, long_flag: &str, val: &str) {
    if val.starts_with('-') {
        argv.push(format!("{long_flag}={val}"));
    } else {
        argv.push(flag.to_string());
        argv.push(val.to_string());
    }
}

fn push_case_args(argv: &mut Vec<String>, case: &CaseFields) {
    if !case.case.trim().is_empty() {
        push_opt(argv, "-C", "--case", case.case.trim());
    }
    if !case.evidence.trim().is_empty() {
        push_opt(argv, "-E", "--evidence", case.evidence.trim());
    }
    if !case.examiner.trim().is_empty() {
        push_opt(argv, "-e", "--examiner", case.examiner.trim());
    }
    if !case.description.trim().is_empty() {
        push_opt(
            argv,
            "--description",
            "--description",
            case.description.trim(),
        );
    }
    if !case.notes.trim().is_empty() {
        push_opt(argv, "--notes", "--notes", case.notes.trim());
    }
}

fn push_clock_args(argv: &mut Vec<String>, clock: &ClockFields) {
    if !clock.reference_time.trim().is_empty() {
        push_opt(
            argv,
            "--reference-time",
            "--reference-time",
            clock.reference_time.trim(),
        );
    }
    if !clock.reference_how.trim().is_empty() {
        push_opt(
            argv,
            "--reference-how",
            "--reference-how",
            clock.reference_how.trim(),
        );
    }
}

fn push_output_flags(argv: &mut Vec<String>, output: &OutputFields) {
    if output.md5 {
        argv.push("--md5".into());
    }
    if output.sha1 {
        argv.push("--sha1".into());
    }
    if output.compress {
        argv.push("--compress".into());
    }
    if output.allow_tmpfs {
        argv.push("--allow-tmpfs".into());
    }
}

fn push_scope_args(argv: &mut Vec<String>, scope: &ScopeFields, emit_time_basis: bool) {
    if !scope.scope_file.trim().is_empty() {
        argv.push("--scope".into());
        argv.push(abs_path_str(scope.scope_file.trim()));
    }
    if !scope.legal_basis.trim().is_empty() {
        push_opt(
            argv,
            "--legal-basis",
            "--legal-basis",
            scope.legal_basis.trim(),
        );
    }
    for inc in &scope.include {
        let p = inc.trim();
        if !p.is_empty() {
            push_opt(argv, "--include", "--include", p);
        }
    }
    for exc in &scope.exclude {
        let p = exc.trim();
        if !p.is_empty() {
            push_opt(argv, "--exclude", "--exclude", p);
        }
    }
    if !scope.not_before.trim().is_empty() {
        push_opt(
            argv,
            "--not-before",
            "--not-before",
            scope.not_before.trim(),
        );
    }
    if !scope.not_after.trim().is_empty() {
        push_opt(argv, "--not-after", "--not-after", scope.not_after.trim());
    }
    if emit_time_basis {
        match scope.time_basis {
            TimeBasis::Modified => {}
            TimeBasis::Accessed => {
                argv.push("--time-basis".into());
                argv.push("accessed".into());
            }
            TimeBasis::Changed => {
                argv.push("--time-basis".into());
                argv.push("changed".into());
            }
            TimeBasis::Birth => {
                argv.push("--time-basis".into());
                argv.push("birth".into());
            }
        }
    }
    if scope.list_out_of_scope {
        argv.push("--list-out-of-scope".into());
    }
}

/// Build the equivalent `dfcollect files ...` argument vector with only the
/// options set on `form`.
pub fn files_argv(form: &FilesForm) -> Vec<String> {
    let mut argv = vec!["dfcollect".to_string(), "files".to_string()];

    let src = form.source_path.trim();
    if !src.is_empty() {
        argv.push(abs_path_str(src));
    }

    let out = form.output_path.trim();
    if !out.is_empty() {
        argv.push("-o".into());
        argv.push(abs_path_str(out));
    }

    if !form.case.trim().is_empty() {
        push_opt(&mut argv, "-C", "--case", form.case.trim());
    }
    if !form.evidence.trim().is_empty() {
        push_opt(&mut argv, "-E", "--evidence", form.evidence.trim());
    }
    if !form.examiner.trim().is_empty() {
        push_opt(&mut argv, "-e", "--examiner", form.examiner.trim());
    }
    if !form.description.trim().is_empty() {
        push_opt(
            &mut argv,
            "--description",
            "--description",
            form.description.trim(),
        );
    }
    if !form.notes.trim().is_empty() {
        push_opt(&mut argv, "--notes", "--notes", form.notes.trim());
    }

    if !form.scope_file.trim().is_empty() {
        argv.push("--scope".into());
        argv.push(abs_path_str(form.scope_file.trim()));
    }
    if !form.legal_basis.trim().is_empty() {
        push_opt(
            &mut argv,
            "--legal-basis",
            "--legal-basis",
            form.legal_basis.trim(),
        );
    }
    for inc in &form.include {
        let p = inc.trim();
        if !p.is_empty() {
            push_opt(&mut argv, "--include", "--include", p);
        }
    }
    for exc in &form.exclude {
        let p = exc.trim();
        if !p.is_empty() {
            push_opt(&mut argv, "--exclude", "--exclude", p);
        }
    }
    if !form.not_before.trim().is_empty() {
        push_opt(
            &mut argv,
            "--not-before",
            "--not-before",
            form.not_before.trim(),
        );
    }
    if !form.not_after.trim().is_empty() {
        push_opt(
            &mut argv,
            "--not-after",
            "--not-after",
            form.not_after.trim(),
        );
    }
    match form.time_basis {
        TimeBasis::Modified => {}
        TimeBasis::Accessed => {
            argv.push("--time-basis".into());
            argv.push("accessed".into());
        }
        TimeBasis::Changed => {
            argv.push("--time-basis".into());
            argv.push("changed".into());
        }
        TimeBasis::Birth => {
            argv.push("--time-basis".into());
            argv.push("birth".into());
        }
    }
    match form.unknown_time {
        UnknownTimeArg::Exclude => {}
        UnknownTimeArg::Include => {
            argv.push("--unknown-time".into());
            argv.push("include".into());
        }
    }
    if form.list_out_of_scope {
        argv.push("--list-out-of-scope".into());
    }

    if !form.reference_time.trim().is_empty() {
        push_opt(
            &mut argv,
            "--reference-time",
            "--reference-time",
            form.reference_time.trim(),
        );
    }
    if !form.reference_how.trim().is_empty() {
        push_opt(
            &mut argv,
            "--reference-how",
            "--reference-how",
            form.reference_how.trim(),
        );
    }

    if form.md5 {
        argv.push("--md5".into());
    }
    if form.sha1 {
        argv.push("--sha1".into());
    }
    if form.compress {
        argv.push("--compress".into());
    }
    if form.allow_tmpfs {
        argv.push("--allow-tmpfs".into());
    }
    if form.allow_writable_source {
        argv.push("--allow-writable-source".into());
    }

    argv
}

/// Build the equivalent `dfcollect ingest ...` argument vector with only the
/// options set on `form`.
pub fn ingest_argv(form: &IngestForm) -> Vec<String> {
    let mut argv = vec!["dfcollect".to_string(), "ingest".to_string()];

    let pkg = form.package.trim();
    if !pkg.is_empty() {
        argv.push(abs_path_str(pkg));
    }

    if !form.provider.trim().is_empty() {
        push_opt(&mut argv, "--provider", "--provider", form.provider.trim());
    }
    if !form.received_at.trim().is_empty() {
        push_opt(
            &mut argv,
            "--received-at",
            "--received-at",
            form.received_at.trim(),
        );
    }
    if !form.channel.trim().is_empty() {
        push_opt(&mut argv, "--channel", "--channel", form.channel.trim());
    }
    if !form.reference.trim().is_empty() {
        push_opt(
            &mut argv,
            "--reference",
            "--reference",
            form.reference.trim(),
        );
    }
    for h in &form.hashes {
        let p = h.trim();
        if !p.is_empty() {
            argv.push("--hashes".into());
            argv.push(abs_path_str(p));
        }
    }
    if form.allow_unlisted {
        argv.push("--allow-unlisted".into());
    }
    if !form.legal_basis.trim().is_empty() {
        push_opt(
            &mut argv,
            "--legal-basis",
            "--legal-basis",
            form.legal_basis.trim(),
        );
    }

    let out = form.output.output_path.trim();
    if !out.is_empty() {
        argv.push("-o".into());
        argv.push(abs_path_str(out));
    }

    push_case_args(&mut argv, &form.case);
    push_clock_args(&mut argv, &form.clock);
    push_output_flags(&mut argv, &form.output);

    argv
}

/// Build the equivalent `dfcollect cloud ...` argument vector with only the
/// options set on `form`.
pub fn cloud_argv(form: &CloudForm) -> Vec<String> {
    let mut argv = vec!["dfcollect".to_string(), "cloud".to_string()];

    if !form.rclone_config.trim().is_empty() {
        argv.push("--rclone-config".into());
        argv.push(abs_path_str(form.rclone_config.trim()));
    }
    for a in &form.rclone_args {
        let trimmed = a.trim();
        if !trimmed.is_empty() {
            push_opt(&mut argv, "--rclone-arg", "--rclone-arg", trimmed);
        }
    }

    let out = form.output.output_path.trim();
    if !out.is_empty() {
        argv.push("-o".into());
        argv.push(abs_path_str(out));
    }

    push_case_args(&mut argv, &form.case);
    push_scope_args(&mut argv, &form.scope, false);
    push_clock_args(&mut argv, &form.clock);
    push_output_flags(&mut argv, &form.output);

    let src = form.source.trim();
    if !src.is_empty() {
        if src.starts_with('-') {
            argv.push("--".into());
        }
        argv.push(src.to_string());
    }

    argv
}

/// Build the equivalent `dfcollect db ...` argument vector with only the
/// options set on `form`. Never includes a password.
pub fn db_argv(form: &DbForm) -> Vec<String> {
    let mut argv = vec![
        "dfcollect".to_string(),
        "db".to_string(),
        form.engine.as_cli_str().to_string(),
    ];

    if !form.host.trim().is_empty() {
        push_opt(&mut argv, "--host", "--host", form.host.trim());
    }
    if !form.port.trim().is_empty() {
        push_opt(&mut argv, "--port", "--port", form.port.trim());
    }
    if !form.user.trim().is_empty() {
        push_opt(&mut argv, "-u", "--user", form.user.trim());
    }
    if !form.password_file.trim().is_empty() {
        argv.push("--password-file".into());
        argv.push(abs_path_str(form.password_file.trim()));
    }
    if form.no_password {
        argv.push("--no-password".into());
    }
    if form.tls != crate::db::Tls::Prefer {
        argv.push("--tls".into());
        argv.push(form.tls.as_cli_str().into());
    }
    for d in &form.databases {
        let trimmed = d.trim();
        if !trimmed.is_empty() {
            push_opt(&mut argv, "--database", "--database", trimmed);
        }
    }
    if !form.legal_basis.trim().is_empty() {
        push_opt(
            &mut argv,
            "--legal-basis",
            "--legal-basis",
            form.legal_basis.trim(),
        );
    }
    if form.engine == crate::db::Engine::Postgres && form.serializable {
        argv.push("--serializable".into());
    }
    if form.engine == crate::db::Engine::Mariadb && form.binlog_position {
        argv.push("--binlog-position".into());
    }

    let out = form.output.output_path.trim();
    if !out.is_empty() {
        argv.push("-o".into());
        argv.push(abs_path_str(out));
    }

    push_case_args(&mut argv, &form.case);
    push_clock_args(&mut argv, &form.clock);
    push_output_flags(&mut argv, &form.output);

    argv
}

/// Build the equivalent `dfcollect verify DIR` argument vector.
pub fn verify_argv(dir: &Path) -> Vec<String> {
    let abs = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    vec![
        "dfcollect".into(),
        "verify".into(),
        abs.display().to_string(),
    ]
}

fn is_safe_bare(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | ':' | '=' | '@' | '%' | '+' | ',' | '-')
        })
}

/// Quote an argument vector as a single-line POSIX shell command.
pub fn shell_quote(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if is_safe_bare(arg) {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse `argv` with `Cli::try_parse_from`; on error, associate the clap message
/// with its form field via `ContextKind::InvalidArg` when possible.
pub fn parse_files_argv(
    argv: &[String],
) -> std::result::Result<FilesArgs, (Option<FilesField>, String)> {
    match Cli::try_parse_from(argv) {
        Ok(Cli {
            command: Some(Command::Files(args)),
        }) => Ok(*args),
        Ok(_) => Err((None, "command did not parse as `dfcollect files`".into())),
        Err(e) => {
            let invalid_arg = e
                .get(ContextKind::InvalidArg)
                .map(ToString::to_string)
                .unwrap_or_default();
            let field = if invalid_arg.contains("<SOURCE>") {
                Some(FilesField::SourcePath)
            } else if invalid_arg.contains("--output") || invalid_arg.contains("-o ") {
                Some(FilesField::OutputPath)
            } else if invalid_arg.contains("--case") || invalid_arg.contains("-C ") {
                Some(FilesField::CaseNumber)
            } else if invalid_arg.contains("--evidence") || invalid_arg.contains("-E ") {
                Some(FilesField::EvidenceNumber)
            } else if invalid_arg.contains("--examiner") || invalid_arg.contains("-e ") {
                Some(FilesField::Examiner)
            } else if invalid_arg.contains("--description") {
                Some(FilesField::Description)
            } else if invalid_arg.contains("--notes") {
                Some(FilesField::Notes)
            } else if invalid_arg.contains("--scope") {
                Some(FilesField::ScopeFile)
            } else if invalid_arg.contains("--legal-basis") {
                Some(FilesField::LegalBasis)
            } else if invalid_arg.contains("--include") {
                Some(FilesField::Includes)
            } else if invalid_arg.contains("--exclude") {
                Some(FilesField::Excludes)
            } else if invalid_arg.contains("--not-before") {
                Some(FilesField::NotBefore)
            } else if invalid_arg.contains("--not-after") {
                Some(FilesField::NotAfter)
            } else if invalid_arg.contains("--time-basis") {
                Some(FilesField::TimeBasis)
            } else if invalid_arg.contains("--unknown-time") {
                Some(FilesField::UnknownTime)
            } else if invalid_arg.contains("--reference-time") {
                Some(FilesField::ReferenceTime)
            } else if invalid_arg.contains("--reference-how") {
                Some(FilesField::ReferenceHow)
            } else {
                None
            };
            let msg = e
                .to_string()
                .lines()
                .next()
                .unwrap_or("invalid arguments")
                .to_string();
            Err((field, msg))
        }
    }
}

/// Parse `argv` as `dfcollect ingest`.
pub fn parse_ingest_argv(
    argv: &[String],
) -> std::result::Result<IngestArgs, (Option<IngestField>, String)> {
    match Cli::try_parse_from(argv) {
        Ok(Cli {
            command: Some(Command::Ingest(args)),
        }) => Ok(*args),
        Ok(_) => Err((None, "command did not parse as `dfcollect ingest`".into())),
        Err(e) => {
            let invalid_arg = e
                .get(ContextKind::InvalidArg)
                .map(ToString::to_string)
                .unwrap_or_default();
            let field = if invalid_arg.contains("<PACKAGE>") {
                Some(IngestField::Package)
            } else if invalid_arg.contains("--provider") {
                Some(IngestField::Provider)
            } else if invalid_arg.contains("--received-at") {
                Some(IngestField::ReceivedAt)
            } else if invalid_arg.contains("--channel") {
                Some(IngestField::Channel)
            } else if invalid_arg.contains("--reference-time") {
                Some(IngestField::ReferenceTime)
            } else if invalid_arg.contains("--reference-how") {
                Some(IngestField::ReferenceHow)
            } else if invalid_arg.contains("--reference") {
                Some(IngestField::Reference)
            } else if invalid_arg.contains("--hashes") {
                Some(IngestField::Hashes)
            } else if invalid_arg.contains("--legal-basis") {
                Some(IngestField::LegalBasis)
            } else if invalid_arg.contains("--output") || invalid_arg.contains("-o ") {
                Some(IngestField::OutputPath)
            } else if invalid_arg.contains("--case") || invalid_arg.contains("-C ") {
                Some(IngestField::CaseNumber)
            } else if invalid_arg.contains("--evidence") || invalid_arg.contains("-E ") {
                Some(IngestField::EvidenceNumber)
            } else if invalid_arg.contains("--examiner") || invalid_arg.contains("-e ") {
                Some(IngestField::Examiner)
            } else {
                None
            };
            let msg = e
                .to_string()
                .lines()
                .next()
                .unwrap_or("invalid arguments")
                .to_string();
            Err((field, msg))
        }
    }
}

/// Parse `argv` as `dfcollect cloud`.
pub fn parse_cloud_argv(
    argv: &[String],
) -> std::result::Result<CloudArgs, (Option<CloudField>, String)> {
    match Cli::try_parse_from(argv) {
        Ok(Cli {
            command: Some(Command::Cloud(args)),
        }) => Ok(*args),
        Ok(_) => Err((None, "command did not parse as `dfcollect cloud`".into())),
        Err(e) => {
            let invalid_arg = e
                .get(ContextKind::InvalidArg)
                .map(ToString::to_string)
                .unwrap_or_default();
            let field = if invalid_arg.contains("REMOTE:PATH") || invalid_arg.contains("<SOURCE>") {
                Some(CloudField::Source)
            } else if invalid_arg.contains("--rclone-config") {
                Some(CloudField::RcloneConfig)
            } else if invalid_arg.contains("--rclone-arg") {
                Some(CloudField::RcloneArgs)
            } else if invalid_arg.contains("--output") || invalid_arg.contains("-o ") {
                Some(CloudField::OutputPath)
            } else if invalid_arg.contains("--case") || invalid_arg.contains("-C ") {
                Some(CloudField::CaseNumber)
            } else if invalid_arg.contains("--evidence") || invalid_arg.contains("-E ") {
                Some(CloudField::EvidenceNumber)
            } else if invalid_arg.contains("--examiner") || invalid_arg.contains("-e ") {
                Some(CloudField::Examiner)
            } else if invalid_arg.contains("--scope") {
                Some(CloudField::ScopeFile)
            } else if invalid_arg.contains("--include") {
                Some(CloudField::Includes)
            } else if invalid_arg.contains("--exclude") {
                Some(CloudField::Excludes)
            } else if invalid_arg.contains("--not-before") {
                Some(CloudField::NotBefore)
            } else if invalid_arg.contains("--not-after") {
                Some(CloudField::NotAfter)
            } else if invalid_arg.contains("--reference-time") {
                Some(CloudField::ReferenceTime)
            } else if invalid_arg.contains("--reference-how") {
                Some(CloudField::ReferenceHow)
            } else {
                None
            };
            let msg = e
                .to_string()
                .lines()
                .next()
                .unwrap_or("invalid arguments")
                .to_string();
            Err((field, msg))
        }
    }
}

/// Parse `argv` as `dfcollect db`.
pub fn parse_db_argv(argv: &[String]) -> std::result::Result<DbArgs, (Option<DbField>, String)> {
    match Cli::try_parse_from(argv) {
        Ok(Cli {
            command: Some(Command::Db(args)),
        }) => Ok(*args),
        Ok(_) => Err((None, "command did not parse as `dfcollect db`".into())),
        Err(e) => {
            let invalid_arg = e
                .get(ContextKind::InvalidArg)
                .map(ToString::to_string)
                .unwrap_or_default();
            let field = if invalid_arg.contains("<ENGINE>") {
                Some(DbField::Engine)
            } else if invalid_arg.contains("--host") {
                Some(DbField::Host)
            } else if invalid_arg.contains("--port") {
                Some(DbField::Port)
            } else if invalid_arg.contains("--user") || invalid_arg.contains("-u ") {
                Some(DbField::User)
            } else if invalid_arg.contains("--password-file") {
                Some(DbField::PasswordFile)
            } else if invalid_arg.contains("--no-password") {
                Some(DbField::NoPassword)
            } else if invalid_arg.contains("--tls") {
                Some(DbField::Tls)
            } else if invalid_arg.contains("--database") {
                Some(DbField::Databases)
            } else if invalid_arg.contains("--legal-basis") {
                Some(DbField::LegalBasis)
            } else if invalid_arg.contains("--output") || invalid_arg.contains("-o ") {
                Some(DbField::OutputPath)
            } else if invalid_arg.contains("--case") || invalid_arg.contains("-C ") {
                Some(DbField::CaseNumber)
            } else if invalid_arg.contains("--evidence") || invalid_arg.contains("-E ") {
                Some(DbField::EvidenceNumber)
            } else if invalid_arg.contains("--examiner") || invalid_arg.contains("-e ") {
                Some(DbField::Examiner)
            } else if invalid_arg.contains("--reference-time") {
                Some(DbField::ReferenceTime)
            } else if invalid_arg.contains("--reference-how") {
                Some(DbField::ReferenceHow)
            } else {
                None
            };
            let msg = e
                .to_string()
                .lines()
                .next()
                .unwrap_or("invalid arguments")
                .to_string();
            Err((field, msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{CaseArgs, ClockArgs, ScopeArgs};
    use std::path::PathBuf;

    #[test]
    fn files_argv_round_trips_through_clap_and_posix_sh() {
        let mut form = FilesForm {
            case: "VG 12345/26 'A'".into(),
            evidence: "share 01".into(),
            examiner: "KHK Müller".into(),
            description: " home share & 'docs' ".into(),
            notes: String::new(),
            source_path: "/media/evidence/sdb1/Prüfungen 2026".into(),
            output_path: "/media/target/sdc1/VG_12345_26/share_01".into(),
            legal_basis: "AG Musterstadt 12 Gs 34/26 of 2026-10-01".into(),
            include: vec![
                "Documents/**".into(),
                "Desktop/*.pdf".into(),
                "a 'b'/*.txt".into(),
            ],
            exclude: vec!["Documents/Private/**".into()],
            not_before: "2026-01-01T00:00:00+01:00".into(),
            not_after: "2026-07-01T00:00:00+02:00".into(),
            time_basis: TimeBasis::Birth,
            unknown_time: UnknownTimeArg::Include,
            list_out_of_scope: true,
            reference_time: "2026-10-17T12:00:00Z".into(),
            reference_how: "DCF77 radio clock".into(),
            md5: true,
            sha1: true,
            compress: true,
            allow_tmpfs: true,
            allow_writable_source: true,
            ..FilesForm::default()
        };

        let argv = files_argv(&form);
        // Optional empty fields (--notes, --scope) are not emitted
        assert!(!argv.iter().any(|a| a == "--notes" || a == "--scope"));

        let parsed = parse_files_argv(&argv).unwrap();
        let expected = FilesArgs {
            source: PathBuf::from("/media/evidence/sdb1/Prüfungen 2026"),
            output: PathBuf::from("/media/target/sdc1/VG_12345_26/share_01"),
            case: CaseArgs {
                case: "VG 12345/26 'A'".into(),
                evidence: "share 01".into(),
                examiner: "KHK Müller".into(),
                description: Some("home share & 'docs'".into()),
                notes: None,
            },
            scope: ScopeArgs {
                scope: None,
                legal_basis: Some("AG Musterstadt 12 Gs 34/26 of 2026-10-01".into()),
                include: vec![
                    "Documents/**".into(),
                    "Desktop/*.pdf".into(),
                    "a 'b'/*.txt".into(),
                ],
                exclude: vec!["Documents/Private/**".into()],
                not_before: Some("2026-01-01T00:00:00+01:00".into()),
                not_after: Some("2026-07-01T00:00:00+02:00".into()),
                time_basis: TimeBasis::Birth,
                unknown_time: UnknownTimeArg::Include,
                list_out_of_scope: true,
            },
            clock: ClockArgs {
                reference_time: Some("2026-10-17T12:00:00Z".into()),
                reference_how: Some("DCF77 radio clock".into()),
            },
            md5: true,
            sha1: true,
            compress: true,
            allow_tmpfs: true,
            allow_writable_source: true,
            dry_run: false,
            json: false,
        };
        assert_eq!(parsed, expected);

        // POSIX shell round-trip via `sh -c 'printf "%s\0" "$@"' sh <quoted>`
        let quoted = shell_quote(&argv);
        if let Ok(out) = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s\\0' {}", quoted))
            .output()
        {
            if out.status.success() {
                let mut split: Vec<String> = out
                    .stdout
                    .split(|b| *b == 0)
                    .map(|s| String::from_utf8(s.to_vec()).unwrap())
                    .collect();
                assert_eq!(split.pop().as_deref(), Some(""));
                assert_eq!(split, argv);
            }
        }

        // Values starting with `-` (notes `- x`, description `--`, include `-foo/**`, examiner `-`)
        form.examiner = "-".into();
        form.description = "--".into();
        form.notes = "- x".into();
        form.include = vec!["-foo/**".into()];
        let dash_argv = files_argv(&form);
        assert!(dash_argv.contains(&"--examiner=-".to_string()));
        assert!(dash_argv.contains(&"--description=--".to_string()));
        assert!(dash_argv.contains(&"--notes=- x".to_string()));
        assert!(dash_argv.contains(&"--include=-foo/**".to_string()));
        let dash_parsed = parse_files_argv(&dash_argv).unwrap();
        assert_eq!(dash_parsed.case.examiner, "-");
        assert_eq!(dash_parsed.case.description.as_deref(), Some("--"));
        assert_eq!(dash_parsed.case.notes.as_deref(), Some("- x"));
        assert_eq!(dash_parsed.scope.include, vec!["-foo/**"]);

        // Relative paths become absolute in argv
        form.source_path = "rel_src".into();
        form.output_path = "rel_out".into();
        form.scope_file = "rel_scope.json".into();
        form.include.clear();
        form.exclude.clear();
        form.legal_basis.clear();
        form.not_before.clear();
        form.not_after.clear();
        form.time_basis = TimeBasis::Modified;
        form.unknown_time = UnknownTimeArg::Exclude;
        form.list_out_of_scope = false;
        let rel_argv = files_argv(&form);
        let rel_parsed = parse_files_argv(&rel_argv).unwrap();
        assert!(rel_parsed.source.is_absolute());
        assert!(rel_parsed.output.is_absolute());
        assert!(rel_parsed.scope.scope.as_ref().unwrap().is_absolute());
    }

    #[test]
    fn parse_files_argv_maps_clap_error_to_specific_field_via_context_kind() {
        let bad_argv: Vec<String> = vec![
            "dfcollect".into(),
            "files".into(),
            "/media/evidence/sdb1".into(),
            "-o".into(),
            "/media/target/sdc1/out".into(),
            "-C".into(),
            "VG 12345/26".into(),
            "-E".into(),
            "ev01".into(),
            "-e".into(),
            "KHK Muster".into(),
            "--time-basis".into(),
            "invalid-basis".into(),
        ];
        let (field, msg) = parse_files_argv(&bad_argv).unwrap_err();
        assert_eq!(field, Some(FilesField::TimeBasis), "msg: {msg}");

        // Missing --reference-how when --reference-time is given maps to ReferenceHow, not SourcePath
        let missing_how: Vec<String> = vec![
            "dfcollect".into(),
            "files".into(),
            "/media/evidence/sdb1".into(),
            "-o".into(),
            "/media/target/sdc1/out".into(),
            "-C".into(),
            "VG 12345/26".into(),
            "-E".into(),
            "ev01".into(),
            "-e".into(),
            "KHK Muster".into(),
            "--reference-time".into(),
            "2026-10-17T12:00:00Z".into(),
        ];
        let (field2, msg2) = parse_files_argv(&missing_how).unwrap_err();
        assert_ne!(field2, Some(FilesField::SourcePath), "msg: {msg2}");
    }

    #[test]
    fn ingest_argv_round_trips_through_clap() {
        let mut form = IngestForm::default();
        form.case.case = "VG 12345/26".into();
        form.case.evidence = "prod01".into();
        form.case.examiner = "KHK Muster".into();
        form.case.description = "-desc".into();
        form.package = "/media/evidence/sdb1/pkg".into();
        form.provider = "-Example Mail Inc.".into();
        form.received_at = "2026-10-17T10:00:00Z".into();
        form.channel = "e-CODEX".into();
        form.reference = "EPOC-2026-99".into();
        form.hashes = vec!["/media/evidence/sdb1/SHA256SUMS".into()];
        form.allow_unlisted = true;
        form.legal_basis = "Reg (EU) 2023/1543".into();
        form.output.output_path = "/media/target/sdc1/VG_12345_26/prod01".into();
        form.output.md5 = true;
        form.output.sha1 = true;
        form.output.compress = true;
        form.output.allow_tmpfs = true;
        form.clock.reference_time = "2026-10-17T10:00:05Z".into();
        form.clock.reference_how = "DCF77".into();

        let argv = ingest_argv(&form);
        assert!(argv.contains(&"--provider=-Example Mail Inc.".to_string()));
        assert!(argv.contains(&"--description=-desc".to_string()));
        let parsed = parse_ingest_argv(&argv).unwrap();
        assert_eq!(parsed.package, PathBuf::from("/media/evidence/sdb1/pkg"));
        assert_eq!(parsed.provider, "-Example Mail Inc.");
        assert_eq!(parsed.received_at, "2026-10-17T10:00:00Z");
        assert_eq!(parsed.channel, "e-CODEX");
        assert_eq!(parsed.reference.as_deref(), Some("EPOC-2026-99"));
        assert_eq!(
            parsed.hashes,
            vec![PathBuf::from("/media/evidence/sdb1/SHA256SUMS")]
        );
        assert!(parsed.allow_unlisted);
        assert_eq!(parsed.legal_basis.as_deref(), Some("Reg (EU) 2023/1543"));
        assert_eq!(
            parsed.output,
            PathBuf::from("/media/target/sdc1/VG_12345_26/prod01")
        );
        assert!(parsed.md5 && parsed.sha1 && parsed.compress && parsed.allow_tmpfs);
        assert_eq!(
            parsed.clock.reference_time.as_deref(),
            Some("2026-10-17T10:00:05Z")
        );
        assert_eq!(parsed.clock.reference_how.as_deref(), Some("DCF77"));
    }

    #[test]
    fn cloud_argv_round_trips_through_clap() {
        let mut form = CloudForm::default();
        form.case.case = "VG 12345/26".into();
        form.case.evidence = "cloud01".into();
        form.case.examiner = "KHK Muster".into();
        form.rclone_config = "/etc/rclone.conf".into();
        form.source = "onedrive:Documents/2026".into();
        form.rclone_args = vec!["--drive-shared-with-me".into(), "--fast-list".into()];
        form.output.output_path = "/media/target/sdc1/VG_12345_26/cloud01".into();
        form.scope.include = vec!["Reports/**".into()];
        form.scope.exclude = vec!["Reports/Drafts/**".into()];
        form.scope.not_before = "2026-01-01T00:00:00Z".into();
        form.scope.not_after = "2026-07-01T00:00:00Z".into();
        form.scope.list_out_of_scope = true;
        form.output.md5 = true;

        let argv = cloud_argv(&form);
        assert!(argv.contains(&"--rclone-arg=--drive-shared-with-me".to_string()));
        assert!(!argv.iter().any(|a| a == "--time-basis"));
        let parsed = parse_cloud_argv(&argv).unwrap();
        assert_eq!(parsed.source, "onedrive:Documents/2026");
        assert_eq!(
            parsed.rclone_config.as_deref(),
            Some(Path::new("/etc/rclone.conf"))
        );
        assert_eq!(
            parsed.rclone_args,
            vec!["--drive-shared-with-me", "--fast-list"]
        );
        assert_eq!(parsed.scope.include, vec!["Reports/**"]);
        assert_eq!(parsed.scope.exclude, vec!["Reports/Drafts/**"]);
        assert!(parsed.scope.list_out_of_scope);
        assert!(parsed.md5);
    }

    #[test]
    fn db_argv_round_trips_through_clap_and_respects_engine_conditional_flags() {
        let mut form = DbForm::default();
        form.case.case = "VG 12345/26".into();
        form.case.evidence = "db01".into();
        form.case.examiner = "KHK Muster".into();
        form.engine = crate::db::Engine::Postgres;
        form.host = "db.example.org".into();
        form.port = "5433".into();
        form.user = "auditor".into();
        form.password_file = "/run/secrets/db_pw".into();
        form.tls = crate::db::Tls::Verify;
        form.databases = vec!["sales".into(), "-odd_db".into()];
        form.legal_basis = "AG Musterstadt 12 Gs 34/26".into();
        form.serializable = true;
        form.binlog_position = true; // should NOT be emitted for postgres
        form.output.output_path = "/media/target/sdc1/VG_12345_26/db01".into();

        let pg_argv = db_argv(&form);
        assert!(pg_argv.contains(&"--serializable".to_string()));
        assert!(!pg_argv.contains(&"--binlog-position".to_string()));
        assert!(pg_argv.contains(&"--database=-odd_db".to_string()));
        let pg_parsed = parse_db_argv(&pg_argv).unwrap();
        assert_eq!(pg_parsed.engine, crate::db::Engine::Postgres);
        assert_eq!(pg_parsed.host, "db.example.org");
        assert_eq!(pg_parsed.port, Some(5433));
        assert_eq!(pg_parsed.user, "auditor");
        assert_eq!(
            pg_parsed.password_file.as_deref(),
            Some(Path::new("/run/secrets/db_pw"))
        );
        assert!(!pg_parsed.no_password);
        assert_eq!(pg_parsed.tls, crate::db::Tls::Verify);
        assert_eq!(pg_parsed.databases, vec!["sales", "-odd_db"]);
        assert!(pg_parsed.serializable);
        assert!(!pg_parsed.binlog_position);

        // Switch to MariaDB with --no-password
        form.engine = crate::db::Engine::Mariadb;
        form.password_file.clear();
        form.no_password = true;
        let maria_argv = db_argv(&form);
        assert!(!maria_argv.contains(&"--serializable".to_string()));
        assert!(maria_argv.contains(&"--binlog-position".to_string()));
        assert!(maria_argv.contains(&"--no-password".to_string()));
        let maria_parsed = parse_db_argv(&maria_argv).unwrap();
        assert_eq!(maria_parsed.engine, crate::db::Engine::Mariadb);
        assert!(maria_parsed.no_password);
        assert!(maria_parsed.binlog_position);
        assert!(!maria_parsed.serializable);
    }
}
