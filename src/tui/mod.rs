//! Terminal UI for `dfcollect` (`files` and `verify`).
//!
//! Raw mode and the alternate screen (without mouse capture, so hashes and
//! paths remain selectable in the terminal) are restored on every exit path,
//! including panics and signals.

pub mod app;
pub mod autocomplete;
pub mod command;
pub mod form;
pub mod input;
pub mod mounts;
pub mod ui;

use crate::common::Stop;
use anyhow::Result;
use app::{panic_message, App};
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, Write},
    sync::{atomic::Ordering, Arc, Mutex},
    thread::ThreadId,
    time::Duration,
};

/// Event poll and redraw interval (100 ms, as specified in design §4).
const TICK: Duration = Duration::from_millis(100);

/// Panics from background worker threads captured while the alternate screen is active.
static BACKGROUND_PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// How the panic hook routes a panic depending on which thread panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicRoute {
    /// UI thread: restore the terminal immediately and print the panic.
    RestoreAndPrint,
    /// Worker thread: keep the message until the alternate screen is closed.
    Keep,
}

pub fn panic_route(ui_thread: ThreadId, current: ThreadId) -> PanicRoute {
    if current == ui_thread {
        PanicRoute::RestoreAndPrint
    } else {
        PanicRoute::Keep
    }
}

pub fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

/// Result of polling `STDIN_FILENO` with `libc::poll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollStdin {
    Ready,
    Timeout,
    Interrupted,
    Hangup,
}

/// Poll fd 0 (stdin) before calling into crossterm.
///
/// Crossterm 0.29's unix mio event source (`src/event/source/unix/mio.rs:94-121`)
/// loops forever when the controlling terminal hangs up and `tty.read` returns
/// `Ok(0)` or `Err(EIO)`, because that loop only breaks on `WouldBlock`. Calling
/// `libc::poll` on `STDIN_FILENO` first lets us detect `POLLHUP | POLLERR | POLLNVAL`
/// and take the headless wait-and-exit path instead of spinning at 100% CPU.
///
/// Note on the remaining race: if a hangup occurs in the narrow window after
/// `libc::poll` returns `POLLIN` and before `crossterm::event::read` finishes
/// reading the tty, crossterm could still enter its read loop. The acquisition
/// and verification workers run on their own OS thread and close the manifest
/// and audit record independently, so the evidence is safe either way.
fn poll_stdin(timeout: Duration) -> PollStdin {
    let mut pfd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    // SAFETY: `pfd` is a valid single `pollfd` struct on the stack.
    let ret = unsafe { libc::poll(&mut pfd, 1, ms) };
    if ret < 0 {
        if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            PollStdin::Interrupted
        } else {
            PollStdin::Hangup
        }
    } else if (pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
        PollStdin::Hangup
    } else if (pfd.revents & libc::POLLIN) != 0 {
        PollStdin::Ready
    } else {
        PollStdin::Timeout
    }
}

/// Run the interactive TUI with the process-wide [`Stop`] flags.
pub fn run(stop: &'static Stop) -> Result<u8> {
    let ui_thread = std::thread::current().id();
    let prev_hook = Arc::new(std::panic::take_hook());
    let hook_clone = Arc::clone(&prev_hook);
    std::panic::set_hook(Box::new(move |panic_info| {
        match panic_route(ui_thread, std::thread::current().id()) {
            PanicRoute::RestoreAndPrint => {
                restore_terminal();
                hook_clone(panic_info);
            }
            PanicRoute::Keep => {
                if let Ok(mut kept) = BACKGROUND_PANICS.lock() {
                    kept.push(panic_info.to_string());
                }
            }
        }
    }));

    let mut app = App::new(stop);
    let loop_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_loop(&mut app)));

    if loop_res.is_err() && app.is_worker_running() {
        // Ensure any running worker finishes closing its manifest and audit record
        stop.examiner.store(true, Ordering::Relaxed);
        app.wait_for_worker();
    }

    if !app.headless {
        restore_terminal();
    }

    let _ = std::panic::take_hook();
    if let Ok(prev) = Arc::try_unwrap(prev_hook) {
        std::panic::set_hook(prev);
    }

    let kept: Vec<String> = BACKGROUND_PANICS
        .lock()
        .map(|mut k| std::mem::take(&mut *k))
        .unwrap_or_default();
    if !app.headless {
        for p in kept {
            let _ = writeln!(
                io::stderr().lock(),
                "dfcollect: internal error in worker thread: {p}"
            );
        }
    }

    match loop_res {
        Err(payload) => Err(anyhow::anyhow!(
            "internal error: the terminal UI stopped ({})",
            panic_message(payload.as_ref())
        )),
        Ok(Err(e)) => Err(e),
        Ok(Ok(())) => {
            if let Some(outcome) = app.signal_outcome.take() {
                if !app.headless {
                    crate::print(false, &outcome.summary);
                }
                return Ok(outcome.code);
            }
            if app.headless {
                if let Some(res) = &app.result_data {
                    return Ok(res.code);
                }
                if let Some(rep) = &app.verify_state.report {
                    return Ok(rep.code);
                }
            }
            Ok(0)
        }
    }
}

fn run_loop(app: &mut App) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        if !app.headless {
            if let Some(b64) = app.pending_osc52.take() {
                let _ = write!(terminal.backend_mut(), "\x1b]52;c;{b64}\x07");
                let _ = terminal.backend_mut().flush();
            }
            if terminal.draw(|frame| ui::render(frame, app)).is_err() {
                app.headless = true;
                if app.is_worker_running() {
                    app.wait_for_worker();
                }
                break;
            }
        }

        if app.stop.signal.load(Ordering::Relaxed) {
            if app.is_worker_running() {
                app.wait_for_worker();
            }
            break;
        }

        if !app.headless {
            match poll_stdin(TICK) {
                PollStdin::Hangup => {
                    app.headless = true;
                    if app.is_worker_running() {
                        app.wait_for_worker();
                    }
                    break;
                }
                PollStdin::Interrupted | PollStdin::Timeout => {}
                PollStdin::Ready => {
                    loop {
                        match event::poll(Duration::ZERO) {
                            Ok(true) => match event::read() {
                                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                                    app.handle_key(key);
                                }
                                Ok(_) => {}
                                Err(_) => {
                                    if !app.stop.signal.load(Ordering::Relaxed) {
                                        app.headless = true;
                                    }
                                    if app.is_worker_running() {
                                        app.wait_for_worker();
                                    }
                                    break;
                                }
                            },
                            Ok(false) => break,
                            Err(_) => {
                                if !app.stop.signal.load(Ordering::Relaxed) {
                                    app.headless = true;
                                }
                                if app.is_worker_running() {
                                    app.wait_for_worker();
                                }
                                break;
                            }
                        }
                        if app.should_quit || app.stop.signal.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    if app.headless {
                        break;
                    }
                }
            }
        } else {
            std::thread::sleep(TICK);
        }

        app.tick();

        if app.should_quit {
            if app.is_worker_running() {
                app.wait_for_worker();
            }
            break;
        }
    }

    if app.headless {
        // The terminal is gone. Dropping `terminal` would try to show the
        // cursor and `eprintln!` the failure, which panics on a hung-up tty.
        std::mem::forget(terminal);
    } else {
        let _ = terminal.show_cursor();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ui_thread_panic_routes_to_restore_and_print() {
        let ui = std::thread::current().id();
        assert_eq!(panic_route(ui, ui), PanicRoute::RestoreAndPrint);
        let worker = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        assert_eq!(panic_route(ui, worker), PanicRoute::Keep);
    }
}
