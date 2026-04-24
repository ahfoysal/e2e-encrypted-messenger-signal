//! Hardened WebSocket relay for the Signal-MVP messenger (M5).
//!
//! Upgrades over M2:
//!   * **Multi-device routing** — handles are indexed by `(handle, device_id)`
//!     so a user can have several live connections. Senders specify
//!     `to_device` in `Envelope`, and the relay fans out accordingly.
//!   * **Token-bucket rate limiting** — each connection has its own bucket
//!     (default: burst 30, refill 10/s) to mitigate flood / amplification.
//!   * **TLS** — optionally terminate TLS via `--tls-cert <pem> --tls-key <pem>`
//!     using `tokio-rustls`. Without those flags, the relay runs plaintext
//!     (useful when fronted by Tor or a reverse proxy).
//!   * **Persistent queue** — offline recipients (no live connection for
//!     `(to, to_device)`) have their incoming `Deliver`s persisted in
//!     `sled` at `--db <path>` (default `./relay-queue.sled`) and flushed
//!     on their next `Hello`.
//!   * **Disappearing messages** — each `Envelope` carries
//!     `expires_at_unix_ms`. The relay refuses already-expired messages on
//!     ingress, and drops expired entries during queue drain / periodic GC.
//!
//! Run:
//!     cargo run --bin relay -- 127.0.0.1:9000
//!     cargo run --bin relay -- 127.0.0.1:9443 --tls-cert cert.pem --tls-key key.pem

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use crypto::disappearing::is_expired;
use crypto::wire::{BundleWire, RelayMsg};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;

use relay::queue::PersistentQueue;
use relay::rate_limit::TokenBucket;

type Tx = mpsc::UnboundedSender<Message>;

/// A single live connection, keyed by `(handle, device_id)`.
#[derive(Clone)]
struct LiveConn {
    tx: Tx,
}

#[derive(Default)]
struct Hub {
    /// Who is connected right now, indexed by `(handle, device_id)`.
    peers: HashMap<(String, u32), LiveConn>,
    /// Last-published bundle per `(handle, device_id)`.
    bundles: HashMap<(String, u32), BundleWire>,
}

struct RelayOpts {
    bind: SocketAddr,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    db_path: String,
    bucket_capacity: u32,
    bucket_refill_per_sec: f64,
}

fn parse_opts() -> Result<RelayOpts> {
    let mut args = std::env::args().skip(1);
    let mut bind: Option<SocketAddr> = None;
    let mut tls_cert = None;
    let mut tls_key = None;
    let mut db_path = "./relay-queue.sled".to_string();
    let mut bucket_capacity = 30u32;
    let mut bucket_refill_per_sec = 10.0f64;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--tls-cert" => tls_cert = args.next(),
            "--tls-key" => tls_key = args.next(),
            "--db" => {
                db_path = args.next().ok_or_else(|| anyhow!("--db needs value"))?;
            }
            "--rate-capacity" => {
                bucket_capacity = args
                    .next()
                    .ok_or_else(|| anyhow!("--rate-capacity needs value"))?
                    .parse()?;
            }
            "--rate-refill" => {
                bucket_refill_per_sec = args
                    .next()
                    .ok_or_else(|| anyhow!("--rate-refill needs value"))?
                    .parse()?;
            }
            "-h" | "--help" => {
                eprintln!(
                    "relay [<bind>] [--tls-cert <pem> --tls-key <pem>] [--db <path>] \
                     [--rate-capacity N] [--rate-refill N]"
                );
                std::process::exit(0);
            }
            other => {
                if bind.is_none() {
                    bind = Some(other.parse().context("bind address")?);
                } else {
                    return Err(anyhow!("unknown arg: {other}"));
                }
            }
        }
    }

    Ok(RelayOpts {
        bind: bind.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap()),
        tls_cert,
        tls_key,
        db_path,
        bucket_capacity,
        bucket_refill_per_sec,
    })
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs_file = std::fs::File::open(cert_path).context("opening TLS cert file")?;
    let mut reader = std::io::BufReader::new(certs_file);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .context("parsing TLS certs")?;

    let key_file = std::fs::File::open(key_path).context("opening TLS key file")?;
    let mut reader = std::io::BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)
        .context("parsing TLS key")?
        .ok_or_else(|| anyhow!("no private key found in {key_path}"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS server config")?;
    Ok(Arc::new(config))
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = parse_opts()?;
    let hub: Arc<Mutex<Hub>> = Arc::new(Mutex::new(Hub::default()));
    let queue = Arc::new(PersistentQueue::open(&opts.db_path)?);

    let listener = TcpListener::bind(opts.bind).await?;
    let scheme = if opts.tls_cert.is_some() { "wss" } else { "ws" };
    eprintln!("[relay] listening on {}://{}", scheme, opts.bind);
    eprintln!("[relay] queue db: {}", opts.db_path);
    eprintln!(
        "[relay] rate limit: capacity={} refill={}/s",
        opts.bucket_capacity, opts.bucket_refill_per_sec
    );

    // Periodic GC of expired queue entries.
    {
        let q = queue.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                match q.gc_expired() {
                    Ok(n) if n > 0 => eprintln!("[relay] gc: dropped {n} expired messages"),
                    Ok(_) => {}
                    Err(e) => eprintln!("[relay] gc error: {e:#}"),
                }
            }
        });
    }

    let tls_acceptor = match (opts.tls_cert.as_deref(), opts.tls_key.as_deref()) {
        (Some(c), Some(k)) => Some(tokio_rustls::TlsAcceptor::from(load_tls_config(c, k)?)),
        (None, None) => None,
        _ => return Err(anyhow!("both --tls-cert and --tls-key are required for TLS")),
    };

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let hub = hub.clone();
        let queue = queue.clone();
        let bucket_capacity = opts.bucket_capacity;
        let bucket_refill = opts.bucket_refill_per_sec;
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let result = if let Some(acc) = tls_acceptor {
                match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        handle_conn(tls_stream, peer_addr, hub, queue, bucket_capacity, bucket_refill)
                            .await
                    }
                    Err(e) => {
                        eprintln!("[relay] TLS handshake failed for {peer_addr}: {e}");
                        return;
                    }
                }
            } else {
                handle_conn(stream, peer_addr, hub, queue, bucket_capacity, bucket_refill).await
            };
            if let Err(e) = result {
                eprintln!("[relay] {} closed: {:#}", peer_addr, e);
            }
        });
    }
}

async fn handle_conn<S>(
    stream: S,
    peer_addr: SocketAddr,
    hub: Arc<Mutex<Hub>>,
    queue: Arc<PersistentQueue>,
    bucket_capacity: u32,
    bucket_refill_per_sec: f64,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut bucket = TokenBucket::new(bucket_capacity, bucket_refill_per_sec);
    let mut my_key: Option<(String, u32)> = None;

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

        // Rate limit every inbound frame, no exceptions.
        if !bucket.try_acquire() {
            let _ = tx.send(Message::Text(serde_json::to_string(&RelayMsg::Error {
                reason: "rate limit exceeded".to_string(),
            })?));
            continue;
        }

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
            RelayMsg::Hello { who, device_id } => {
                let key = (who.clone(), device_id);
                my_key = Some(key.clone());
                {
                    let mut hub = hub.lock().await;
                    hub.peers.insert(key.clone(), LiveConn { tx: tx.clone() });
                }
                eprintln!("[relay] {} registered as '{}#{}'", peer_addr, who, device_id);

                // Flush any queued messages.
                match queue.drain(&who, device_id) {
                    Ok(items) => {
                        if !items.is_empty() {
                            eprintln!(
                                "[relay] flushing {} queued messages to '{}#{}'",
                                items.len(),
                                who,
                                device_id
                            );
                        }
                        for qm in items {
                            let _ = tx.send(Message::Text(qm.payload_json));
                        }
                    }
                    Err(e) => eprintln!("[relay] queue drain error: {e:#}"),
                }
            }
            RelayMsg::PublishBundle {
                who,
                bundle,
                device_id,
            } => {
                let mut hub = hub.lock().await;
                hub.bundles.insert((who.clone(), device_id), bundle);
                eprintln!("[relay] bundle published for '{}#{}'", who, device_id);
            }
            RelayMsg::FetchBundle { who } => {
                // For compatibility we return the device_id=0 bundle if
                // present, otherwise any bundle under that handle. Clients
                // that want a specific device use `FetchBundle` with the
                // handle formatted as `name#device` — simple for MVP.
                let (name, device_id) = parse_handle_device(&who);
                let hub = hub.lock().await;
                let bundle = hub
                    .bundles
                    .get(&(name.to_string(), device_id))
                    .cloned()
                    .or_else(|| {
                        hub.bundles
                            .iter()
                            .find(|((h, _), _)| h == name)
                            .map(|(_, b)| b.clone())
                    });
                let reply = RelayMsg::Bundle {
                    who: who.clone(),
                    bundle,
                };
                tx.send(Message::Text(serde_json::to_string(&reply)?))?;
            }
            RelayMsg::Envelope {
                from,
                to,
                msg,
                from_device,
                to_device,
                expires_at_unix_ms,
            } => {
                // TTL check on ingress.
                if is_expired(expires_at_unix_ms) {
                    let _ = tx.send(Message::Text(serde_json::to_string(&RelayMsg::Error {
                        reason: "message already expired".to_string(),
                    })?));
                    continue;
                }

                // Build the Deliver frame that every target device gets.
                let deliver = RelayMsg::Deliver {
                    from: from.clone(),
                    msg: msg.clone(),
                    from_device,
                    expires_at_unix_ms,
                };
                let deliver_json = serde_json::to_string(&deliver)?;

                // If `to_device == 0` we fan out to *every* registered
                // device under `to` that we know about (live or queued).
                let live_and_bundled_targets: Vec<u32> = {
                    let hub = hub.lock().await;
                    let mut devices: std::collections::BTreeSet<u32> =
                        std::collections::BTreeSet::new();
                    for ((h, d), _) in hub.peers.iter() {
                        if h == &to {
                            devices.insert(*d);
                        }
                    }
                    for ((h, d), _) in hub.bundles.iter() {
                        if h == &to {
                            devices.insert(*d);
                        }
                    }
                    if to_device == 0 {
                        devices.into_iter().collect()
                    } else {
                        vec![to_device]
                    }
                };

                if live_and_bundled_targets.is_empty() {
                    // No device known at all — queue for device_id=0 so
                    // whichever device registers first picks it up.
                    let _ = queue.enqueue(&to, to_device, deliver_json.clone(), expires_at_unix_ms);
                    continue;
                }

                let hub_guard = hub.lock().await;
                for d in live_and_bundled_targets {
                    if let Some(conn) = hub_guard.peers.get(&(to.clone(), d)) {
                        let _ = conn.tx.send(Message::Text(deliver_json.clone()));
                    } else {
                        // Offline device — persist.
                        let _ = queue.enqueue(&to, d, deliver_json.clone(), expires_at_unix_ms);
                    }
                }
            }
            RelayMsg::Bundle { .. } | RelayMsg::Deliver { .. } | RelayMsg::Error { .. } => {
                // Server-originated; ignore if sent by client.
            }
        }
    }

    if let Some(key) = my_key {
        let mut hub = hub.lock().await;
        hub.peers.remove(&key);
        eprintln!("[relay] '{}#{}' disconnected", key.0, key.1);
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}

/// Accept handles of the form `name` or `name#device_id` (used by
/// `FetchBundle` only — the structured `Hello`/`Envelope` carry device_id
/// as their own field).
fn parse_handle_device(s: &str) -> (&str, u32) {
    if let Some((name, dev)) = s.split_once('#') {
        let d: u32 = dev.parse().unwrap_or(0);
        (name, d)
    } else {
        (s, 0)
    }
}
