//! dfcollect: logical forensic acquisition with scope, per-item hashes,
//! manifest and audit records (dfcore).

mod args;
mod common;
mod container;
mod files;
mod graph;
mod http;
mod mail;
mod meta;
mod oauth;
mod scope;
mod verify;

use clap::Parser;
use std::{
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
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

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe
        unsafe {
            libc::signal(sig, on_signal as *const () as libc::sighandler_t);
        }
    }
}

fn print(json: bool, summary: &serde_json::Value) {
    if json {
        println!(
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
            println!("{k:>22}: {shown}");
        }
    }
}

fn main() -> ExitCode {
    let cli = args::Cli::parse();
    install_signal_handlers();
    let result = match &cli.command {
        args::Command::Files(a) => files::run(a, &STOP).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Imap(a) => mail::run(a, &STOP).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Graph(a) => graph::run(a, &STOP).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
        args::Command::Verify(a) => verify::run(&a.dir).map(|o| {
            print(a.json, &o.summary);
            o.code
        }),
    };
    match result {
        Ok(code) => ExitCode::from(code),
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
