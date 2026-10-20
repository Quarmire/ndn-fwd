//! The app's event loop without a terminal: messages in (keys, listings,
//! events, command results, secret prompts), effects carried out. The
//! terminal program draws between messages; a test drives it directly and
//! waits for what it expects ([`Driver::settle`]).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::app::{App, Effect, Msg};
use crate::daemon::{Daemon, Failure};
use crate::exec::Runner;
use crate::live;
use crate::model::Listing;
use crate::root::{SecretAsk, TuiSecrets};

/// The app, the daemon it manages and the work under way.
pub struct Driver {
    pub app: App,
    runner: Arc<Runner>,
    tx: mpsc::Sender<Msg>,
    rx: mpsc::Receiver<Msg>,
    /// Listings being read; a listing asked for meanwhile is read again
    /// right after.
    reading: HashSet<Listing>,
    again: HashSet<Listing>,
    quit: bool,
}

impl Driver {
    /// Connect to the daemon at `socket`, follow its streams, and start the
    /// first load; `config` is the daemon's configuration, when known (the
    /// policy a new prefix or a schema update states).
    pub async fn connect(
        socket: &str,
        config: Option<ndn_config::ForwarderConfig>,
    ) -> Result<Self, Failure> {
        let daemon = Arc::new(Daemon::connect(socket).await?);
        let (tx, rx) = mpsc::channel::<Msg>(256);
        let (updates, mut updates_rx) = mpsc::channel(256);
        live::spawn(socket.to_owned(), updates);
        let forward = tx.clone();
        tokio::spawn(async move {
            while let Some(u) = updates_rx.recv().await {
                if forward.send(Msg::Update(u)).await.is_err() {
                    return;
                }
            }
        });
        let (asks, mut asks_rx) = mpsc::channel::<SecretAsk>(4);
        let forward = tx.clone();
        tokio::spawn(async move {
            while let Some(ask) = asks_rx.recv().await {
                if forward.send(Msg::Secret(ask)).await.is_err() {
                    return;
                }
            }
        });
        let runner = Arc::new(Runner {
            daemon,
            secrets: Arc::new(TuiSecrets::new(asks)),
            config,
        });
        let app = App::new(socket);
        let mut driver = Self {
            app,
            runner,
            tx,
            rx,
            reading: HashSet::new(),
            again: HashSet::new(),
            quit: false,
        };
        let start = driver.app.start();
        driver.execute(start);
        Ok(driver)
    }

    /// A sender of messages to this driver (e.g. keys read elsewhere).
    pub fn sender(&self) -> mpsc::Sender<Msg> {
        self.tx.clone()
    }

    /// Whether the app asked to quit.
    pub fn quit(&self) -> bool {
        self.quit
    }

    /// Carry out `effects`.
    pub fn execute(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Quit => self.quit = true,
                Effect::Load(listing) => {
                    if !self.reading.insert(listing) {
                        self.again.insert(listing);
                        continue;
                    }
                    let (runner, tx, pib) = (
                        Arc::clone(&self.runner),
                        self.tx.clone(),
                        self.app.pib.clone(),
                    );
                    tokio::spawn(async move {
                        let update = runner.daemon.load(listing, pib.as_deref()).await;
                        let _ = tx.send(Msg::Update(update)).await;
                    });
                }
                Effect::Run(command) => {
                    let (runner, tx, pib) = (
                        Arc::clone(&self.runner),
                        self.tx.clone(),
                        self.app.pib.clone(),
                    );
                    tokio::spawn(async move {
                        let msg = runner.run(command, pib).await;
                        let _ = tx.send(msg).await;
                    });
                }
            }
        }
    }

    /// Hand `msg` to the app and carry out what it asks.
    pub fn handle(&mut self, msg: Msg) {
        if let Msg::Update(update) = &msg
            && let Some(listing) = update.listing()
        {
            self.reading.remove(&listing);
            if self.again.remove(&listing) {
                self.execute(vec![Effect::Load(listing)]);
            }
        }
        let effects = self.app.handle(msg);
        self.execute(effects);
    }

    /// Wait up to `wait` for the next message and handle it; `false` when
    /// none came.
    pub async fn next(&mut self, wait: Duration) -> bool {
        match tokio::time::timeout(wait, self.rx.recv()).await {
            Ok(Some(msg)) => {
                self.handle(msg);
                true
            }
            _ => false,
        }
    }

    /// Handle messages until `done` holds of the app (checked after each)
    /// and no listing is being read, or `within` passes: whether it held.
    pub async fn settle(&mut self, within: Duration, done: impl Fn(&App) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if done(&self.app) && self.reading.is_empty() {
                return true;
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return done(&self.app);
            }
            self.next(left.min(Duration::from_millis(200))).await;
        }
    }
}
