//! Building the equivalent `dfcollect files` command line from [`FilesForm`],
//! quoting it for display and OSC 52 copying, and parsing it through the
//! same `clap` definitions as the CLI.

use crate::{
    args::{Cli, Command, FilesArgs, TimeBasis, UnknownTimeArg},
    tui::{
        autocomplete::expand_tilde,
        form::{FilesField, FilesForm},
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
}
