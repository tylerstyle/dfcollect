//! How a run talks to the examiner: it asks for a secret, shows sign-in
//! instructions, reads a pasted redirect URL and reports notices (HTTP
//! waits, per-log status, warnings). The CLI uses the terminal
//! ([`TermConsole`]); the TUI shows its own screens. A secret never goes
//! through a notice.

use crate::Usage;
use anyhow::Result;
use std::sync::{
    mpsc::{self, Receiver},
    Mutex,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Something is going on (a wait, a query that was created)
    Info,
    /// A part is done (a log with its record count)
    Done,
    Warning,
}

impl Level {
    pub fn tag(self) -> &'static str {
        match self {
            Level::Info => "[*]",
            Level::Done => "[✓]",
            Level::Warning => "[!]",
        }
    }
}

/// A secret the run needs because no file was given for it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretAsk {
    /// "IMAP password for alice@example.org: "
    pub prompt: String,
    /// The option that would have given it from a file
    pub file_flag: &'static str,
}

/// Sign-in instructions for the examiner
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignIn {
    /// Microsoft identity platform: open `uri` (on any device) and enter `code`
    DeviceCode {
        /// The service's own instruction text
        message: String,
        uri: String,
        code: String,
        /// When the code expires (Unix ns)
        expires_at_ns: i128,
    },
    /// Open `url` in a browser here (the redirect reaches a loopback
    /// listener) or on another device and paste the redirect URL
    Browser { url: String, expires_at_ns: i128 },
}

impl SignIn {
    pub fn warning(&self) -> &'static str {
        match self {
            SignIn::DeviceCode { .. } => {
                "Signing in can notify the account holder (new sign-in alerts)."
            }
            SignIn::Browser { .. } => {
                "Signing in can notify the account holder (new sign-in / third-party access alerts)."
            }
        }
    }
}

/// The examiner cancelled a question the run needed answered (a secret);
/// nothing was acquired
#[derive(Debug)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled by the examiner before anything was acquired")
    }
}

impl std::error::Error for Cancelled {}

/// A secret from `ask`, or `Err(Cancelled)`
pub fn need_secret(console: &dyn Console, ask: SecretAsk) -> Result<Zeroizing<String>> {
    console.secret(&ask)?.ok_or_else(|| Cancelled.into())
}

pub trait Console: Send + Sync {
    /// A secret, read without echo. `Ok(None)`: the examiner cancelled
    fn secret(&self, ask: &SecretAsk) -> Result<Option<Zeroizing<String>>>;
    /// Sign-in instructions are ready; the run now waits for the sign-in
    fn sign_in(&self, s: &SignIn);
    /// A redirect URL the examiner pasted (browser sign-in), if any yet
    fn pasted(&self) -> Option<String>;
    /// The sign-in is over, whatever its outcome
    fn sign_in_done(&self);
    /// Text only: never pass a secret
    fn notice(&self, level: Level, text: &str);
}

/// The CLI's console: the terminal, as dfcollect always talked to it. Notices
/// go to stderr; stdout carries only the result.
#[derive(Default)]
pub struct TermConsole {
    pasted: Mutex<Option<Receiver<String>>>,
}

impl Console for TermConsole {
    fn secret(&self, ask: &SecretAsk) -> Result<Option<Zeroizing<String>>> {
        prompt_secret(&ask.prompt, ask.file_flag).map(Some)
    }

    fn sign_in(&self, s: &SignIn) {
        eprintln!("[!] {}", s.warning());
        match s {
            SignIn::DeviceCode { message, .. } => eprintln!("[?] {message}"),
            SignIn::Browser { url, .. } => {
                eprintln!("[?] Open this URL in a browser (or on another device and paste the redirect URL here):");
                eprintln!("{url}");
                self.read_pasted_lines();
            }
        }
    }

    fn pasted(&self) -> Option<String> {
        let guard = self.pasted.lock().ok()?;
        guard.as_ref()?.try_recv().ok()
    }

    fn sign_in_done(&self) {}

    fn notice(&self, level: Level, text: &str) {
        eprintln!("{} {text}", level.tag());
    }
}

impl TermConsole {
    /// The first non-empty line on stdin, read on a thread of its own (the
    /// run polls [`Console::pasted`] between its other checks)
    fn read_pasted_lines(&self) {
        let Ok(mut slot) = self.pasted.lock() else {
            return;
        };
        if slot.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                line.clear();
                match stdin.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            let _ = tx.send(trimmed.to_string());
                            break;
                        }
                    }
                }
            }
        });
        *slot = Some(rx);
    }
}

/// A console without an examiner at hand: no secret can be asked and no
/// sign-in completed; notices are kept for the caller. The TUI uses it for
/// modes that need neither (files, verify).
#[derive(Default)]
pub struct QuietConsole {
    pub notices: Mutex<Vec<(Level, String)>>,
}

impl Console for QuietConsole {
    fn secret(&self, ask: &SecretAsk) -> Result<Option<Zeroizing<String>>> {
        Err(Usage(format!(
            "no examiner to ask for it; use {} ({})",
            ask.file_flag,
            ask.prompt.trim_end_matches([':', ' '])
        ))
        .into())
    }

    fn sign_in(&self, _: &SignIn) {}

    fn pasted(&self) -> Option<String> {
        None
    }

    fn sign_in_done(&self) {}

    fn notice(&self, level: Level, text: &str) {
        if let Ok(mut n) = self.notices.lock() {
            n.push((level, text.to_string()));
        }
    }
}

/// Ask on the terminal without echo.
pub(crate) fn prompt_secret(prompt: &str, file_flag: &str) -> Result<Zeroizing<String>> {
    use std::io::{BufRead, Write};
    use std::os::fd::AsRawFd;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            Usage(format!(
                "no terminal to ask for the password; use {file_flag}"
            ))
        })?;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is a plain C struct, filled by tcgetattr
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and out-pointer
    let have_term = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let saved = term;
    if have_term {
        term.c_lflag &= !libc::ECHO;
        // SAFETY: valid fd and termios
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut out = &tty;
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = Zeroizing::new(String::new());
    let read = std::io::BufReader::new(&tty).read_line(&mut line);
    if have_term {
        // SAFETY: restores the settings read above
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    }
    writeln!(out)?;
    read?;
    let end = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(end);
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_terminal_wording_stays() {
        let device = SignIn::DeviceCode {
            message: "m".into(),
            uri: "u".into(),
            code: "c".into(),
            expires_at_ns: 0,
        };
        assert_eq!(
            device.warning(),
            "Signing in can notify the account holder (new sign-in alerts)."
        );
        let browser = SignIn::Browser {
            url: "u".into(),
            expires_at_ns: 0,
        };
        assert_eq!(
            browser.warning(),
            "Signing in can notify the account holder (new sign-in / third-party access alerts)."
        );
        assert_eq!(
            [Level::Info, Level::Done, Level::Warning].map(Level::tag),
            ["[*]", "[✓]", "[!]"]
        );
    }

    #[test]
    fn a_quiet_console_keeps_notices_and_asks_nothing() {
        let c = QuietConsole::default();
        c.notice(Level::Warning, "WARNING: x");
        assert_eq!(
            c.notices.lock().unwrap().as_slice(),
            [(Level::Warning, "WARNING: x".to_string())]
        );
        let e = c
            .secret(&SecretAsk {
                prompt: "Database password: ".into(),
                file_flag: "--password-file",
            })
            .unwrap_err();
        assert!(e.downcast_ref::<Usage>().is_some(), "{e:#}");
        assert!(format!("{e:#}").contains("--password-file"), "{e:#}");
        assert!(c.pasted().is_none());
    }
}
