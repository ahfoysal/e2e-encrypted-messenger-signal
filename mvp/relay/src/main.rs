//! Dumb WebSocket relay for the Signal-MVP messenger.
//!
//! The server is intentionally oblivious: it holds per-handle pre-key
//! bundles and forwards opaque `Envelope` messages between two connected
//! clients. All crypto (X3DH, Double Ratchet, AEAD) runs on the clients;
//! the relay only sees base64 blobs.
//!
//! Wire format is JSON `RelayMsg` (see `crypto::wire`).
//!
//! Run:
//!     cargo run --bin relay -- 127.0.0.1:9000

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use crypto::wire::{BundleWire, RelayMsg};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

type Tx = mpsc::UnboundedSender<Message>;

#[derive(Default)]
struct Hub {
    /// Who is connected right now.
    peers: HashMap<String, Tx>,
    /// Last-published bundle per handle.
    bundles: HashMap<String, BundleWire>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9000".into())
        .parse()?;

    let listener = TcpListener::bind(addr).await?;
    eprintln!("[relay] listening on ws://{}", addr);

    let hub: Arc<Mutex<Hub>> = Arc::new(Mutex::new(Hub::default()));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let hub = hub.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer_addr, hub).await {
                eprintln!("[relay] {} closed: {:#}", peer_addr, e);
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer_addr: SocketAddr,
    hub: Arc<Mutex<Hub>>,
) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Per-connection outbound channel — server tasks push messages onto it,
    // and this task drains it into the WebSocket.
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut my_handle: Option<String> = None;

    while let Some(frame) = ws_rx.next().await {
        let frame = match frame {
            Ok(f) => f,
            Err(_) => break,
        };
        let text = match frame {
            Message::Text(t) => t,
            Message::Binary(_) | Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
            Message::Frame(_) => continue,
        };

        let msg: RelayMsg = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(e) => {
                let _ = tx.send(Message::Text(serde_json::to_string(&RelayMsg::Error {
                    reason: format!("bad json: {e}"),
                })?));
                continue;
            }
        };

        match msg {
            RelayMsg::Hello { who } => {
                my_handle = Some(who.clone());
                let mut hub = hub.lock().await;
                hub.peers.insert(who.clone(), tx.clone());
                eprintln!("[relay] {} registered as '{}'", peer_addr, who);
            }
            RelayMsg::PublishBundle { who, bundle } => {
                let mut hub = hub.lock().await;
                hub.bundles.insert(who.clone(), bundle);
                eprintln!("[relay] bundle published for '{}'", who);
            }
            RelayMsg::FetchBundle { who } => {
                let hub = hub.lock().await;
                let bundle = hub.bundles.get(&who).cloned();
                let reply = RelayMsg::Bundle {
                    who: who.clone(),
                    bundle,
                };
                tx.send(Message::Text(serde_json::to_string(&reply)?))?;
            }
            RelayMsg::Envelope { from, to, msg } => {
                let hub = hub.lock().await;
                if let Some(peer_tx) = hub.peers.get(&to) {
                    let deliver = RelayMsg::Deliver { from, msg };
                    let _ = peer_tx.send(Message::Text(serde_json::to_string(&deliver)?));
                } else {
                    let _ = tx.send(Message::Text(serde_json::to_string(&RelayMsg::Error {
                        reason: format!("peer '{to}' not connected"),
                    })?));
                }
            }
            RelayMsg::Bundle { .. } | RelayMsg::Deliver { .. } | RelayMsg::Error { .. } => {
                // Server-originated; ignore if sent by client.
            }
        }
    }

    // Clean up registration.
    if let Some(h) = my_handle {
        let mut hub = hub.lock().await;
        hub.peers.remove(&h);
        eprintln!("[relay] '{}' disconnected", h);
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}
