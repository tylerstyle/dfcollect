//! dfcollect: logical forensic acquisition with scope, per-item hashes,
//! manifest and audit records (dfcore).

mod args;
mod cloud;
mod common;
mod console;
mod container;
mod db;
mod files;
mod gmail;
mod graph;
mod http;
mod ingest;
mod m365logs;
mod mail;
mod meta;
mod oauth;
mod provider_hash;
mod scope;
mod tui;
mod verify;

use clap::{CommandFactory, Parser};
use common::{human_bytes, Phase, Progress, RunCtx, Stop};
use std::{
    io::IsTerminal,
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub const TOOL: &str = "dfcollect";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Invalid arguments: exit code 2, nothing written.
#[derive(Debug)]
pub struct Usage(pub String);

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

static STOP: Stop = Stop::new();

extern "C" fn on_signal(_: libc::c_int) {
    STOP.signal.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe
        unsafe {
            libc::signal(sig, on_signal as *const () as libc::sighandler_t);
        }
    }
}

pub(crate) fn print(json: bool, summary: &serde_json::Value) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    if json {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(summary).unwrap_or_default()
        );
        return;
    }
    if let Some(map) = summary.as_object() {
        for (k, v) in map {
            let shown = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let _ = writeln!(out, "{k:>22}: {shown}");
        }
    }
}

/// Columns of the terminal on stderr, if it is one.
fn stderr_columns() -> Option<usize> {
    // SAFETY: a zeroed winsize is a valid out-parameter for TIOCGWINSZ
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and out-pointer
    let ok = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
    (ok && ws.ws_col > 0).then_some(ws.ws_col as usize)
}

/// The progress line: counts, then as much of the current path as fits.
fn progress_line(p: &Progress, columns: usize) -> String {
    let counts = match p.phase() {
        Phase::Listing => format!(
            "listing: {} entries, {} files in scope ({})",
            p.entries.load(Ordering::Relaxed),
            p.files.load(Ordering::Relaxed),
            human_bytes(p.bytes.load(Ordering::Relaxed)),
        ),
        Phase::Copying => format!(
            "{} files done, {} copied, {} out of scope, {} errors",
            p.files.load(Ordering::Relaxed),
            human_bytes(p.bytes.load(Ordering::Relaxed)),
            p.out_of_scope.load(Ordering::Relaxed),
            p.errors.load(Ordering::Relaxed),
        ),
        Phase::CheckingContainer => format!(
            "checking the container: {} read",
            human_bytes(p.check_bytes.load(Ordering::Relaxed))
        ),
        Phase::Finishing | Phase::Done => "closing the records".into(),
        Phase::SigningIn => "waiting for the sign-in".into(),
        Phase::Waiting => p.stage(),
    };
    let mut line = counts;
    if p.phase() == Phase::Copying {
        let current = p.current();
        let room = columns.saturating_sub(line.chars().count() + 3);
        if room > 8 && !current.is_empty() {
            let n = current.chars().count();
            let shown: String = if n > room {
                let tail: String = current.chars().skip(n - (room - 1)).collect();
                format!("…{tail}")
            } else {
                current
            };
            line.push_str("  ");
            line.push_str(&shown);
        }
    }
    line.chars().take(columns.saturating_sub(1)).collect()
}

/// Run `work`, with a progress line on stderr when stderr is a terminal and
/// the result is not JSON.
fn with_progress<T>(json: bool, work: impl FnOnce(Option<&Progress>) -> T) -> T {
    let columns = match stderr_columns() {
        Some(c) if !json && std::io::stderr().is_terminal() => c,
        _ => return work(None),
    };
    let progress = Progress::default();
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut ticks = 0u32;
            while !done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                ticks += 1;
                if ticks.is_multiple_of(5) {
                    eprint!("\r\x1b[K{}", progress_line(&progress, columns));
                }
            }
            if ticks >= 5 {
                eprint!("\r\x1b[K");
            }
        });
        let result = work(Some(&progress));
        done.store(true, Ordering::Relaxed);
        result
    })
}

fn main() -> ExitCode {
    let cli = args::Cli::parse();
    install_signal_handlers();
    let Some(command) = &cli.command else {
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            return match tui::run(&STOP) {
                Ok(code) => ExitCode::from(code),
                Err(e) => {
                    // The terminal may be gone (hangup): don't panic on EIO
                    use std::io::Write;
                    let _ = writeln!(std::io::stderr(), "Error: {e:#}");
                    ExitCode::from(4)
                }
            };
        }
        eprint!("{}", args::Cli::command().render_help());
        return ExitCode::from(2);
    };
    let result = match command {
        args::Command::Files(a) if a.dry_run => {
            with_progress(a.json, |p| files::preview(a, &RunCtx::cli(&STOP, p))).map(|pv| {
                print(a.json, &pv.summary());
                pv.stopped.as_ref().map_or(0, |_| 8)
            })
        }
        args::Command::Files(a) => {
            with_progress(a.json, |p| files::run_with(a, &RunCtx::cli(&STOP, p))).map(|o| {
                print(a.json, &o.summary);
                o.code
            })
        }
        args::Command::Imap(a) if a.dry_run => {
            mail::preview(a, &RunCtx::cli(&STOP, None)).map(|(pv, _)| {
                print(a.json, &pv.summary());
                pv.stopped.as_ref().map_or(0, |_| 8)
            })
        }
        args::Command::Imap(a) => mail::run_with(a, &RunCtx::cli(&STOP, None)).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Graph(a) if a.dry_run => {
            graph::preview(a, &RunCtx::cli(&STOP, None)).map(|(pv, _)| {
                print(a.json, &pv.summary());
                pv.stopped.as_ref().map_or(0, |_| 8)
            })
        }
        args::Command::Graph(a) => graph::run_with(a, &RunCtx::cli(&STOP, None)).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Cloud(a) if a.dry_run => {
            cloud::preview(a, &RunCtx::cli(&STOP, None)).map(|pv| {
                print(a.json, &pv.summary());
                pv.stopped.as_ref().map_or(0, |_| 8)
            })
        }
        args::Command::Cloud(a) => cloud::run_with(a, &RunCtx::cli(&STOP, None)).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Db(a) if a.dry_run => {
            db::preview(a, &RunCtx::cli(&STOP, None)).map(|(pv, _)| {
                print(a.json, &pv.summary());
                if pv.missing.is_empty() {
                    0
                } else {
                    2
                }
            })
        }
        args::Command::Db(a) => db::run_with(a, &RunCtx::cli(&STOP, None)).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::M365Logs(a) => m365logs::run_with(a, &RunCtx::cli(&STOP, None)).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Gmail(a) if a.dry_run => {
            gmail::preview(a, &RunCtx::cli(&STOP, None)).map(|(pv, _)| {
                print(a.json, &pv.summary());
                pv.stopped.as_ref().map_or(0, |_| 8)
            })
        }
        args::Command::Gmail(a) => gmail::run_with(a, &RunCtx::cli(&STOP, None)).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Ingest(a) if a.dry_run => {
            ingest::preview(a, &RunCtx::cli(&STOP, None)).map(|pv| {
                print(a.json, &pv.summary());
                pv.stopped.as_ref().map_or(0, |_| 8)
            })
        }
        args::Command::Ingest(a) => ingest::run_with(a, &RunCtx::cli(&STOP, None)).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Verify(a) => {
            with_progress(a.json, |p| verify::run_with(&a.dir, &RunCtx::cli(&STOP, p))).map(|o| {
                print(a.json, &o.summary);
                o.code
            })
        }
    };
    match result {
        Ok(code) => ExitCode::from(code),
        // Stopped before a collection existed (a preview, a query, a sign-in)
        Err(_) if STOP.is_set() => {
            let (reason, code) = STOP.reason().unwrap_or_else(|| ("stopped".into(), 8));
            eprintln!("Stopped: {reason}");
            ExitCode::from(code)
        }
        Err(e) => {
            let code = if e.downcast_ref::<Usage>().is_some() {
                2
            } else if dfcore::is_refusal(&e) {
                3
            } else {
                4
            };
            eprintln!("Error: {e:#}");
            ExitCode::from(code)
        }
    }
}
