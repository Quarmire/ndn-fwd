//! The terminal program: connect to the daemon, draw, read keys; the
//! driver does the rest.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use ndn_tui::app::{Key, Msg};
use ndn_tui::driver::Driver;
use ndn_tui::ui;

/// The admin and power-user terminal UI of this device: trusted prefixes,
/// their members, invites and approvals, data, connections.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// The daemon's configuration file: its management socket is read
    /// from it, and the policy its certificate-authority entries state goes
    /// into a new trusted prefix and a schema update.
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    /// The daemon's management socket (instead of the configuration's).
    #[arg(long)]
    socket: Option<String>,
}

/// The configuration `-c` names, read.
fn config_of(args: &Args) -> Result<Option<ndn_config::ForwarderConfig>, String> {
    let Some(path) = &args.config else {
        return Ok(None);
    };
    let toml = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    toml.parse()
        .map(Some)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn key_of(e: event::KeyEvent) -> Option<Key> {
    if e.kind != KeyEventKind::Press {
        return None;
    }
    Some(match e.code {
        KeyCode::Char('c') if e.modifiers.contains(KeyModifiers::CONTROL) => Key::Interrupt,
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Backspace => Key::Backspace,
        _ => return None,
    })
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let config = match config_of(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::from(2);
        }
    };
    let socket = args.socket.clone().unwrap_or_else(|| {
        config.as_ref().map_or_else(
            || ndn_config::ManagementConfig::default().face_socket,
            |c| c.management.face_socket.clone(),
        )
    });
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(socket, config)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(socket: String, config: Option<ndn_config::ForwarderConfig>) -> Result<(), String> {
    let mut driver = Driver::connect(&socket, config)
        .await
        .map_err(|f| format!("No daemon to manage at {socket}. {}", f.words()))?;
    let mut terminal = ratatui::init();
    let keys = driver.sender();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            let Event::Key(k) = ev else { continue };
            let Some(key) = key_of(k) else { continue };
            if keys.blocking_send(Msg::Key(key)).is_err() {
                return;
            }
        }
    });
    let result = loop {
        if let Err(e) = terminal.draw(|f| ui::draw(f, &driver.app)) {
            break Err(format!("cannot draw: {e}"));
        }
        if driver.quit() {
            break Ok(());
        }
        // Redraw at least each second (the times shown are relative).
        driver.next(Duration::from_secs(1)).await;
    };
    ratatui::restore();
    result
}
