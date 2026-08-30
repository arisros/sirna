//! The rendezvous relay.
//!
//! Two peers — a reader who wants a key and the owner who holds it — need to
//! exchange a handful of frames, and neither can reach the other directly. This
//! introduces them and copies bytes between them. That is all it does.
//!
//! **It is untrusted, deliberately and by design.** It sees every frame, and
//! nothing here tries to pretend otherwise: the frames are opaque, the key
//! inside them is sealed to the reader's public key, and a relay that
//! substitutes a peer changes the short authentication string the two humans
//! compare. The protection lives in `sirna_core::release`, not here.
//!
//! Because it is untrusted, it is also deliberately forgetful: no persistence,
//! no logging of frame contents, and a topic that disappears the moment the
//! exchange ends or the clock runs out.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// A topic dies after this long regardless of what is happening on it. An
/// owner who never answers must not hold a socket open indefinitely, and a
/// reader who walks away must not leave one behind.
const TOPIC_TTL: Duration = Duration::from_secs(300);

/// Two peers per topic and no more. A third connection is a mistake or an
/// attempt to eavesdrop; either way it is refused rather than quietly joined.
const MAX_PEERS: usize = 2;

/// Frames are small — a public key, a sealed key, a receipt. A generous cap
/// still rules out someone using the relay as free bandwidth.
const MAX_FRAME: usize = 8 * 1024;

type Peer = (u64, mpsc::UnboundedSender<Message>);

#[derive(Default)]
pub struct Relay {
    topics: Mutex<HashMap<String, Vec<Peer>>>,
    next_id: AtomicU64,
}

impl Relay {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn join(&self, topic: &str, tx: mpsc::UnboundedSender<Message>) -> Option<u64> {
        let mut topics = self.topics.lock().unwrap_or_else(|e| e.into_inner());
        let peers = topics.entry(topic.to_string()).or_default();
        if peers.len() >= MAX_PEERS {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        peers.push((id, tx));
        Some(id)
    }

    fn leave(&self, topic: &str, id: u64) {
        let mut topics = self.topics.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(peers) = topics.get_mut(topic) {
            peers.retain(|(peer, _)| *peer != id);
            // An empty topic is removed rather than kept: the map must not grow
            // with a row per message anyone ever tried to read.
            if peers.is_empty() {
                topics.remove(topic);
            }
        }
    }

    /// Copy a frame to the other peer. Never back to the sender — an echo would
    /// make both sides think they had heard from someone.
    fn forward(&self, topic: &str, from: u64, msg: Message) -> usize {
        let topics = self.topics.lock().unwrap_or_else(|e| e.into_inner());
        let Some(peers) = topics.get(topic) else {
            return 0;
        };
        let mut sent = 0;
        for (id, tx) in peers {
            if *id != from && tx.send(msg.clone()).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub fn topic_count(&self) -> usize {
        self.topics.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

pub async fn handler<S: crate::store::BlobStore>(
    ws: WebSocketUpgrade,
    Path(id): Path<String>,
    State(st): State<crate::api::Shared<S>>,
) -> Response {
    ws.on_upgrade(move |socket| run(socket, id, st.relay.clone()))
}

async fn run(socket: WebSocket, topic: String, relay: Arc<Relay>) {
    // Ids come from the blob endpoint and are server-generated hex. Anything
    // else would let a caller pick a topic name and sit on it.
    if topic.len() != 32 || !topic.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }

    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let Some(me) = relay.join(&topic, tx) else {
        // A third peer. Say so and close rather than leaving it hanging.
        let _ = sink.send(Message::Text("full".into())).await;
        let _ = sink.close().await;
        return;
    };
    debug!(%topic, peer = me, "joined");

    // Outbound: whatever the other peer sends.
    let out = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Inbound, bounded by the topic's lifetime.
    let pump = async {
        while let Some(Ok(msg)) = stream.next().await {
            match &msg {
                Message::Binary(b) if b.len() > MAX_FRAME => {
                    warn!(%topic, len = b.len(), "frame over the cap; closing");
                    break;
                }
                Message::Text(t) if t.len() > MAX_FRAME => break,
                Message::Close(_) => break,
                // Frame contents are never logged. The relay is untrusted, and
                // a log line is a place bytes go to survive.
                _ => {}
            }
            relay.forward(&topic, me, msg);
        }
    };

    tokio::select! {
        _ = pump => {}
        _ = tokio::time::sleep(TOPIC_TTL) => {
            debug!(%topic, peer = me, "timed out");
        }
    }

    relay.leave(&topic, me);
    out.abort();
    debug!(%topic, peer = me, "left");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_third_peer_is_refused() {
        let relay = Relay::new();
        let (a, _ra) = mpsc::unbounded_channel();
        let (b, _rb) = mpsc::unbounded_channel();
        let (c, _rc) = mpsc::unbounded_channel();

        assert!(relay.join("topic", a).is_some());
        assert!(relay.join("topic", b).is_some());
        assert!(
            relay.join("topic", c).is_none(),
            "a rendezvous is between exactly two peers"
        );
    }

    #[test]
    fn a_frame_never_echoes_to_its_sender() {
        let relay = Relay::new();
        let (a, mut ra) = mpsc::unbounded_channel();
        let (b, mut rb) = mpsc::unbounded_channel();

        let id_a = relay.join("t", a).unwrap();
        relay.join("t", b).unwrap();

        assert_eq!(relay.forward("t", id_a, Message::Text("hello".into())), 1);
        assert!(
            rb.try_recv().is_ok(),
            "the other peer should have received it"
        );
        assert!(
            ra.try_recv().is_err(),
            "an echo would make a peer think it had heard from someone"
        );
    }

    #[test]
    fn an_empty_topic_is_forgotten() {
        // Otherwise the map grows a row for every message anyone ever opened.
        let relay = Relay::new();
        let (a, _ra) = mpsc::unbounded_channel();
        let id = relay.join("t", a).unwrap();
        assert_eq!(relay.topic_count(), 1);

        relay.leave("t", id);
        assert_eq!(relay.topic_count(), 0);
    }

    #[test]
    fn forwarding_into_a_topic_that_does_not_exist_is_harmless() {
        let relay = Relay::new();
        assert_eq!(relay.forward("nope", 0, Message::Text("x".into())), 0);
    }
}
