//! The links change-notification stream
//! (`/localhost/nfd/links/notifications`): each second the daemon reads
//! its links as `links/list` lists them and publishes, for every link whose
//! state changed, a `link-changed` event carrying its state now (paths up,
//! direct-path state, mode, relay state, asleep, down) — and `link-gone`
//! for a link no longer listed. Timers, counters, addresses and texts are
//! left out: a client reads them with `links/list`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ndn_link::Links;
use ndn_mgmt::{EventSink, LinkEvent};
use ndn_mgmt_wire::LinkEntry;
use ndn_mgmt_wire::events::LinkState;
use tokio_util::sync::CancellationToken;

/// How often the links are read.
const SAMPLE: Duration = Duration::from_secs(1);

/// Publish the changes of `links` to `sink` until `cancel`.
pub(crate) fn spawn(
    links: Arc<Links>,
    sink: Arc<dyn EventSink<LinkEvent>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut known = BTreeMap::new();
        let mut tick = tokio::time::interval(SAMPLE);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tick.tick() => {}
            }
            let now = states(&crate::links_mgmt::listing(links.report()).links);
            for event in changes(&known, &now) {
                sink.publish(event);
            }
            known = now;
        }
    });
}

/// Each listed link's state, by label.
fn states(entries: &[LinkEntry]) -> BTreeMap<String, LinkState> {
    entries
        .iter()
        .map(|e| (e.label.clone(), state(e)))
        .collect()
}

fn state(entry: &LinkEntry) -> LinkState {
    let mut paths: Vec<String> = entry.paths.iter().map(|p| p.kind.clone()).collect();
    paths.sort();
    paths.dedup();
    LinkState {
        label: entry.label.clone(),
        key: entry
            .key
            .map(|k| k.iter().map(|b| format!("{b:02x}")).collect()),
        device: entry.device.as_ref().map(ToString::to_string),
        paths,
        direct: entry.direct_state.clone(),
        mode: entry.mode.clone(),
        relay: entry.relay.as_ref().map(|r| r.state.clone()),
        asleep: entry.asleep.is_some(),
        down: entry.down.as_ref().map(|d| d.code.clone()),
    }
}

/// The events taking `before` to `after`: each new or changed link's state,
/// then each link gone.
fn changes(
    before: &BTreeMap<String, LinkState>,
    after: &BTreeMap<String, LinkState>,
) -> Vec<LinkEvent> {
    let changed = after
        .iter()
        .filter(|(label, now)| before.get(*label) != Some(now))
        .map(|(_, now)| LinkEvent::LinkChanged(now.clone()));
    let gone = before
        .iter()
        .filter(|(label, _)| !after.contains_key(*label))
        .map(|(label, was)| LinkEvent::LinkGone {
            label: label.clone(),
            key: was.key.clone(),
        });
    changed.chain(gone).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(label: &str, direct: &str) -> LinkState {
        LinkState {
            label: label.into(),
            key: Some("ab".repeat(32)),
            device: Some("/home/bob/node/pi".into()),
            paths: vec!["link".into()],
            direct: direct.into(),
            mode: Some("always".into()),
            relay: None,
            asleep: false,
            down: None,
        }
    }

    fn by_label(links: &[LinkState]) -> BTreeMap<String, LinkState> {
        links.iter().map(|l| (l.label.clone(), l.clone())).collect()
    }

    #[test]
    fn only_new_changed_and_gone_links_are_published() {
        let before = by_label(&[link("pi", "trying"), link("vps", "up"), link("old", "up")]);
        let after = by_label(&[link("pi", "up"), link("vps", "up"), link("phone", "none")]);
        let events = changes(&before, &after);
        assert_eq!(
            events,
            vec![
                LinkEvent::LinkChanged(link("phone", "none")),
                LinkEvent::LinkChanged(link("pi", "up")),
                LinkEvent::LinkGone {
                    label: "old".into(),
                    key: Some("ab".repeat(32)),
                },
            ]
        );
        assert!(changes(&after, &after).is_empty(), "no change, no event");
    }
}
