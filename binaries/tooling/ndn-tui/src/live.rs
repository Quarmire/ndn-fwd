//! Following the daemon's two change-notification streams, each on a
//! management connection of its own, as [`Update`]s for the model.

use std::time::Duration;

use ndn_cert::report::TrustEvent;
use ndn_ipc::events::{EventSubscription, Notice, StreamEvent};
use ndn_mgmt_wire::events::LinkEvent;
use tokio::sync::mpsc;

use crate::daemon::Failure;
use crate::model::{Stream, Update};

/// How long one long-poll waits for the next event.
const POLL: Duration = Duration::from_secs(30);
/// How long to wait before following a stream again after it failed.
const RETRY: Duration = Duration::from_secs(3);

/// Follow both streams of the daemon at `socket` until `updates` closes.
pub fn spawn(socket: String, updates: mpsc::Sender<Update>) {
    tokio::spawn(follow::<TrustEvent>(
        socket.clone(),
        Stream::Trust,
        updates.clone(),
        |seq, event| Update::Trust { seq, event },
    ));
    tokio::spawn(follow::<LinkEvent>(
        socket,
        Stream::Links,
        updates,
        |seq, event| Update::Link { seq, event },
    ));
}

/// Follow one stream: every event in order, a resync whenever the stream
/// asks for one (and first), a note when it fails (then follow again).
pub async fn follow<E: StreamEvent>(
    socket: String,
    stream: Stream,
    updates: mpsc::Sender<Update>,
    event: fn(u64, E) -> Update,
) {
    loop {
        let mut subscription = match EventSubscription::<E>::connect(&socket).await {
            Ok(s) => s,
            Err(e) => {
                if updates
                    .send(Update::StreamDown(stream, Failure::from(e)))
                    .await
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        loop {
            let update = match subscription.next(POLL).await {
                Ok(None) => continue,
                Ok(Some(Notice::Resync { .. })) => Update::Resync(stream),
                Ok(Some(Notice::Event { seq, event: e })) => event(seq, e),
                Err(e) => {
                    if updates
                        .send(Update::StreamDown(stream, Failure::from(e)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    tokio::time::sleep(RETRY).await;
                    break;
                }
            };
            if updates.send(update).await.is_err() {
                return;
            }
        }
    }
}
